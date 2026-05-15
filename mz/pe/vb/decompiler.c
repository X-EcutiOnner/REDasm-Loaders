#include "decompiler.h"
#include "pe/format.h"
#include "pe/vb/components.h"
#include "pe/vb/format.h"
#include "pe/vb/ordinals.h"
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

static inline bool
_pe_vb_has_optional_info(const PEVBPublicObjectDescriptor* descr,
                         const PEVBObjectInfo* objinfo, const RDContext* ctx) {
    return descr->lpObjectInfo + rd_size_of(ctx, "PE_VB_OBJECT_INFO", 0) !=
           objinfo->lpConstants;
}

static void _pe_vb_apply_header_str(RDAddress vb_base, RDReader* r, u32 offset,
                                    const char* name, RDContext* ctx) {
    if(!offset) return;

    RDAddress address = vb_base + offset;
    usize n;

    rd_reader_seek(r, address);
    if(!rd_reader_read_str(r, &n)) return;

    rd_library_type(ctx, address, "char", n + 1, RD_TYPE_NONE);
    rd_library_name(ctx, address, name);
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

    const RDKBObject* c = pe_vb_components_find(&guid);
    if(!c) goto cleanup;

    PEVBEventInfo evinfo;
    rd_reader_seek(r, ctrlinfo->lpEventInfo);
    if(!pe_vb_read_event_info(r, &evinfo)) goto cleanup;

    rd_library_type(ctx, ctrlinfo->lpEventInfo, "PE_VB_EVENT_INFO", 0,
                    RD_TYPE_NONE);

    if(evinfo.lpEVENT_SINK_QueryInterface) {
        rd_library_function(ctx, evinfo.lpEVENT_SINK_QueryInterface,
                            "EVENT_SINK_QueryInterface");
    }

    if(evinfo.lpEVENT_SINK_AddRef) {
        rd_library_function(ctx, evinfo.lpEVENT_SINK_AddRef,
                            "EVENT_SINK_AddRef");
    }

    if(evinfo.lpEVENT_SINK_Release) {
        rd_library_function(ctx, evinfo.lpEVENT_SINK_Release,
                            "EVENT_SINK_Release");
    }

    const RDKBObject* events = rd_kbobject_get_array(c, "events");

    const RDKBObject* it;
    rd_kbobject_each(it, events) {
        u32 event_va;
        if(!rd_reader_read_le32(r, &event_va)) break;
        if(!event_va) continue;

        const char* e = rd_kbobject_to_str(it);
        if(!e) break;

        const char* n = rd_format("%s_%s_%s", objname, ctrlname, e);
        _pe_vb_decompiler_decode((RDAddress)event_va, n, ctx);
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

        if(pe_vb_read_control_info(r, &ctrlinfo)) {
            rd_library_type(ctx, address, "PE_VB_CONTROL_INFO", 0,
                            RD_TYPE_NONE);
            _pe_vb_decompiler_events(descr, &ctrlinfo, r, ctx);
        }

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

        rd_library_type(ctx, descr.lpObjectInfo, "PE_VB_OBJECT_INFO_OPTIONAL",
                        0, RD_TYPE_NONE);

        return _pe_vb_decompiler_controls(&descr, &opt_objinfo, r, ctx);
    }

done:
    return !rd_reader_has_error(r);
}

static void _pe_rename_imports(RDContext* ctx) {
    RDAddressSlice imports = rd_get_all_imported(ctx);

    const RDAddress* it;
    rd_slice_each(it, imports) {
        RDImported imp;
        if(!rd_get_imported(ctx, *it, &imp)) continue;

        const char* name = pe_vb_ordinals_get_name(&imp);
        if(name) rd_set_imported(ctx, *it, imp.module, name);
    }
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

    rd_kb_load_types("pe/vb/types", ctx);

    RDReader* r = rd_get_reader(ctx);
    RDAddress vb_base = instrs[0].operands[0].addr;

    PEVBHeader vb_header;
    PEVBProjectInfo proj_info;
    PEVBGuiTable gui_table;
    PEVBObjectTable object_table;
    PEVBObjectTree object_tree;
    PEVBPublicObjectDescriptor pub_obj_descr;

    rd_reader_seek(r, vb_base);

    if(!pe_vb_read_header(r, &vb_header) ||
       strncmp("VB5!", vb_header.szVbMagic, PE_VB_SIGNATURE_SIZE) != 0)
        return;

    _pe_rename_imports(ctx);

    _pe_vb_apply_header_str(vb_base, r, vb_header.bszProjectDescription,
                            "vb_proj_desc", ctx);
    _pe_vb_apply_header_str(vb_base, r, vb_header.bszProjectExeName,
                            "vb_proj_exe", ctx);
    _pe_vb_apply_header_str(vb_base, r, vb_header.bszProjectHelpFile,
                            "vb_proj_help", ctx);
    _pe_vb_apply_header_str(vb_base, r, vb_header.bszProjectName,
                            "vb_proj_name", ctx);

    rd_library_type(ctx, vb_base, "PE_VB_HEADER", 0, RD_TYPE_NONE);

    PEVBProjectInfo projinfo = {0};

    if(vb_header.lpProjectData) {
        rd_reader_seek(r, vb_header.lpProjectData);

        if(pe_vb_read_project_info(r, &proj_info)) {
            rd_library_type(ctx, vb_header.lpProjectData, "PE_VB_PROJECT_INFO",
                            0, RD_TYPE_NONE);
        }
    }

    if(proj_info.lpObjectTable) {
        rd_reader_seek(r, proj_info.lpObjectTable);

        if(pe_vb_read_object_table(r, &object_table)) {
            rd_library_type(ctx, proj_info.lpObjectTable, "PE_VB_OBJECT_TABLE",
                            0, RD_TYPE_NONE);
        }
    }

    if(object_table.lpObjectTreeInfo) {
        rd_reader_seek(r, object_table.lpObjectTreeInfo);

        if(pe_vb_read_object_tree(r, &object_tree)) {
            rd_library_type(ctx, object_table.lpObjectTreeInfo,
                            "PE_VB_OBJECT_TREE", 0, RD_TYPE_NONE);
        }
    }

    if(object_table.lpPubObjArray) {
        RDAddress address = object_table.lpPubObjArray;
        usize sz = rd_size_of(ctx, "PE_VB_PUBLIC_OBJECT_DESCRIPTOR", 0);

        for(u16 i = 0; i < object_table.wTotalObjects; i++) {
            rd_reader_seek(r, address);
            if(!_pe_vb_decompiler_obj(address, r, ctx)) break;
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
