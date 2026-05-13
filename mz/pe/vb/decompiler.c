#include "decompiler.h"
#include "pe/format.h"
#include "pe/vb/components.h"
#include "pe/vb/format.h"
#include <string.h>

static const RDInstruction PE_VB_ENTRY_MATCH[] = {
    {.mnemonic = "push", .operands = {[0] = {.kind = RD_OP_ADDR}}},
    {.mnemonic = "call", .operands = {[0] = {.kind = RD_OP_ADDR}}},
};

static const RDInstruction PE_VB_EVENT_ENTRY[] = {
    {
        .mnemonic = "sub",
        .operands = {[0] = {.kind = RD_OP_DISPL}, [1] = {.kind = RD_OP_IMM}},
    },
    {
        .mnemonic = "jmp",
        .operands = {[0] = {.kind = RD_OP_ADDR}},
    },
};

typedef struct PEVBAnalyzer {
    RDContext* context;
    RDReader* reader;
    RDAddress base;
    PEVBHeader header;
    PEVBProjectInfo proj_info;
    PEVBGuiTable gui_table;
    PEVBObjectTable object_table;
    PEVBObjectTree object_tree;
    PEVBPublicObjectDescriptor pub_obj_descr;
} PEVBAnalyzer;

static inline bool
_pe_vb_has_optional_info(const PEVBPublicObjectDescriptor* descr,
                         const PEVBObjectInfo* objinfo, const RDContext* ctx) {
    return descr->lpObjectInfo + rd_size_of(ctx, "PE_VB_OBJECT_INFO", 0) !=
           objinfo->lpConstants;
}

static void _pe_vb_apply_header_str(const PEVBAnalyzer* a, u32 offset,
                                    const char* name) {
    if(!offset) return;

    RDAddress address = a->base + offset;
    usize n;

    rd_reader_seek(a->reader, address);
    if(!rd_reader_read_str(a->reader, &n)) return;

    rd_library_type(a->context, address, "char", n + 1, RD_TYPE_NONE);
    rd_library_name(a->context, address, name);
}

static void _pe_vb_decompiler_decode(RDAddress address, const char* name,
                                     RDContext* ctx) {
    RDInstruction instrs[2];
    if(!rd_decode_n(ctx, address, instrs, rd_count_of(instrs))) return;

    if(!rd_instr_match_n(ctx, instrs, PE_VB_EVENT_ENTRY,
                         rd_count_of(PE_VB_EVENT_ENTRY)))
        return;

    RDAddress event_ep = instrs[1].operands[0].addr;
    rd_library_function(ctx, event_ep, name);
}

static void _pe_vb_decompiler_events(const PEVBPublicObjectDescriptor* descr,
                                     const PEVBControlInfo* ctrlinfo,
                                     RDReader* r, RDContext* ctx) {
    if(!descr->lpszObjectName || !ctrlinfo->lpGuid || !ctrlinfo->lpszName ||
       !ctrlinfo->lpEventInfo)
        return;

    rd_reader_seek(r, descr->lpszObjectName);
    char* objname = rd_strdup(rd_reader_read_str(r, NULL));

    rd_reader_seek(r, ctrlinfo->lpszName);
    char* ctrlname = rd_strdup(rd_reader_read_str(r, NULL));

    PEGUID guid;
    rd_reader_seek(r, ctrlinfo->lpGuid);
    if(!pe_vb_read_guid(r, &guid)) goto cleanup;

    const PEVBComponent* c = pe_vb_components_find(&guid);
    if(!c) goto cleanup;

    PEVBEventInfo evinfo;
    rd_reader_seek(r, ctrlinfo->lpEventInfo);
    if(!pe_vb_read_event_info(r, &evinfo)) goto cleanup;

    const char* const* events = c->events;

    while(*events) {
        const char* n = rd_format("%s_%s_%s", objname, ctrlname, *events);

        u32 event_va;
        if(!rd_reader_read_le32(r, &event_va)) break;
        if(event_va) _pe_vb_decompiler_decode((RDAddress)event_va, n, ctx);
        events++;
    }

cleanup:
    rd_free(ctrlname);
    rd_free(objname);
}

static bool _pe_vb_decompiler_controls(const PEVBPublicObjectDescriptor* descr,
                                       const PEVBObjectInfoOptional* objinfo,
                                       RDReader* r, RDContext* ctx) {

    RDAddress address = objinfo->lpControls;
    usize n = rd_size_of(ctx, "PE_VB_CONTROL_INFO", 0);

    for(u32 i = 0; i < objinfo->dwControlCount; i++) {
        rd_reader_seek(r, address);

        PEVBControlInfo ctrlinfo;

        if(pe_vb_read_control_info(r, &ctrlinfo))
            _pe_vb_decompiler_events(descr, &ctrlinfo, r, ctx);

        address += n;
    }

    return !rd_reader_has_error(r);
}

static bool _pe_vb_decompiler_obj(RDAddress address, RDReader* r,
                                  RDContext* ctx) {
    PEVBPublicObjectDescriptor descr;
    if(!pe_vb_read_public_object_descriptor(r, &descr)) return false;

    rd_library_type(ctx, address, "PE_VB_PUBLIC_OBJECT_DESCRIPTOR", 0,
                    RD_TYPE_NONE);

    if(descr.lpObjectInfo) {
        rd_reader_seek(r, descr.lpObjectInfo);

        PEVBObjectInfo objinfo;
        if(!pe_vb_read_object_info(r, &objinfo) ||
           !_pe_vb_has_optional_info(&descr, &objinfo, ctx))
            goto done;

        rd_reader_seek(r, descr.lpObjectInfo);
        PEVBObjectInfoOptional opt_objinfo;

        if(!pe_vb_read_object_info_optional(r, &opt_objinfo) ||
           !opt_objinfo.lpControls)
            goto done;

        return _pe_vb_decompiler_controls(&descr, &opt_objinfo, r, ctx);
    }

done:
    return !rd_reader_has_error(r);
}

static bool pe_vb_decompiler_is_enabled(RDContext* ctx,
                                        const struct RDAnalyzerPlugin* plugin) {
    RD_UNUSED(plugin);

    const RDLoaderPlugin* lplugin = rd_get_loader_plugin(ctx);
    if(strcmp(lplugin->id, PE_PLUGIN_ID) != 0) return false;

    PEFormat* pe = (PEFormat*)rd_get_loader(ctx);

    return pe && (pe->classification == PE_CLASS_VISUAL_BASIC_5 ||
                  pe->classification == PE_CLASS_VISUAL_BASIC_6);
}

static void pe_vb_decompiler_execute(RDContext* ctx) {
    RDAddress ep;
    if(!rd_get_entry_point(ctx, &ep)) return;

    RDInstruction instrs[rd_count_of(PE_VB_ENTRY_MATCH)] = {0};
    if(!rd_decode_n(ctx, ep, instrs, rd_count_of(instrs))) return;

    if(!rd_instr_match_n(ctx, instrs, PE_VB_ENTRY_MATCH,
                         rd_count_of(PE_VB_ENTRY_MATCH)))
        return;

    pe_vb_register_types(ctx);

    PEVBAnalyzer a = {
        .context = ctx,
        .reader = rd_get_reader(ctx),
        .base = instrs[0].operands[0].addr,
    };

    rd_reader_seek(a.reader, a.base);

    if(!pe_vb_read_header(a.reader, &a.header) ||
       strncmp("VB5!", a.header.szVbMagic, PE_VB_SIGNATURE_SIZE) != 0)
        return;

    _pe_vb_apply_header_str(&a, a.header.bszProjectDescription, "vb_proj_desc");
    _pe_vb_apply_header_str(&a, a.header.bszProjectExeName, "vb_proj_exe");
    _pe_vb_apply_header_str(&a, a.header.bszProjectHelpFile, "vb_proj_help");
    _pe_vb_apply_header_str(&a, a.header.bszProjectName, "vb_proj_name");
    rd_library_type(ctx, a.base, "PE_VB_HEADER", 0, RD_TYPE_NONE);

    PEVBProjectInfo projinfo = {0};

    if(a.header.lpProjectData) {
        rd_reader_seek(a.reader, a.header.lpProjectData);

        if(pe_vb_read_project_info(a.reader, &a.proj_info)) {
            rd_library_type(ctx, a.header.lpProjectData, "PE_VB_PROJECT_INFO",
                            0, RD_TYPE_NONE);
        }
    }

    if(a.proj_info.lpObjectTable) {
        rd_reader_seek(a.reader, a.proj_info.lpObjectTable);

        if(pe_vb_read_object_table(a.reader, &a.object_table)) {
            rd_library_type(ctx, a.proj_info.lpObjectTable,
                            "PE_VB_OBJECT_TABLE", 0, RD_TYPE_NONE);
        }
    }

    if(a.object_table.lpObjectTreeInfo) {
        rd_reader_seek(a.reader, a.object_table.lpObjectTreeInfo);

        if(pe_vb_read_object_tree(a.reader, &a.object_tree)) {
            rd_library_type(ctx, a.object_table.lpObjectTreeInfo,
                            "PE_VB_OBJECT_TREE", 0, RD_TYPE_NONE);
        }
    }

    if(a.object_table.lpPubObjArray) {
        RDAddress address = a.object_table.lpPubObjArray;
        usize sz = rd_size_of(ctx, "PE_VB_PUBLIC_OBJECT_DESCRIPTOR", 0);

        for(u16 i = 0; i < a.object_table.wTotalObjects; i++) {
            rd_reader_seek(a.reader, address);
            if(!_pe_vb_decompiler_obj(address, a.reader, ctx)) break;
            address += sz;
        }
    }
}

const RDAnalyzerPlugin PE_VB_DECOMPILER = {
    .level = RD_API_LEVEL,
    .id = "win_pe_vb",
    .name = "Decompile VB5/6",
    .flags = RD_AF_SELECTED | RD_AF_RUNONCE,
    .order = 1000,
    .is_enabled = pe_vb_decompiler_is_enabled,
    .execute = pe_vb_decompiler_execute,
};
