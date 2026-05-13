#include "imports.h"
#include <string.h>

#define PE_ORDINAL_FLAG64 0x8000000000000000ULL
#define PE_ORDINAL_FLAG32 0x80000000

typedef struct PEThunk {
    union {
        u64 rva;
        u16 ordinal;
    };

    bool is_ord;
} PEThunk;

static bool _pe_read_thunk(RDAddress va, RDReader* r, const PEFormat* pe,
                           PEThunk* thunk) {
    rd_reader_seek(r, va);

    if(pe->bits == 64) {
        if(rd_reader_read_le64(r, &thunk->rva)) {
            thunk->is_ord = !!(thunk->rva & PE_ORDINAL_FLAG64);
            if(thunk->is_ord) thunk->ordinal = thunk->rva & 0xFFFF;
        }
    }
    else {
        u32 t;
        if(rd_reader_read_le32(r, &t)) {
            thunk->is_ord = !!(t & PE_ORDINAL_FLAG32);
            thunk->rva = (u64)t;
            if(thunk->is_ord) thunk->ordinal = thunk->rva & 0xFFFF;
        }
    }

    return !rd_reader_has_error(r);
}

static void _pe_read_thunks(RDContext* ctx, const PEFormat* pe, RDReader* r,
                            const char* module, RDAddress oft_va,
                            RDAddress ft_va) {
    rd_reader_seek(r, ft_va);

    while(true) {
        PEThunk oft_thunk, ft_thunk;
        if(!_pe_read_thunk(oft_va, r, pe, &oft_thunk)) break;
        if(!_pe_read_thunk(ft_va, r, pe, &ft_thunk)) break;

        if(!oft_thunk.rva) { // null terminator: type both slots
            rd_library_type(ctx, oft_va, pe->thunk_type, 0, RD_TYPE_NONE);
            rd_library_type(ctx, ft_va, pe->thunk_type, 0, RD_TYPE_NONE);
            break;
        }

        rd_library_type(ctx, oft_va, pe->thunk_type, 0, RD_TYPE_PTR);
        rd_library_type(ctx, ft_va, pe->thunk_type, 0, RD_TYPE_PTR);

        if(!oft_thunk.is_ord) {
            RDAddress thunkva;
            pe_from_rva(pe, oft_thunk.rva, &thunkva);

            rd_reader_seek(r, thunkva);
            rd_reader_read_le16(r, NULL); // skip hint

            usize n;
            const char* name = rd_reader_read_str(r, &n);

            rd_library_type(ctx, thunkva, "u16", 0, RD_TYPE_NONE);
            rd_library_type(ctx, thunkva + sizeof(u16), "char", n + 1,
                            RD_TYPE_NONE);

            rd_library_name(ctx, thunkva,
                            rd_format("%s_%s_hint", module, name));

            rd_library_name(ctx, thunkva + sizeof(u16),
                            rd_format("%s_%s_name", module, name));

            rd_set_imported(ctx, ft_va, module, name);

            if(oft_va != ft_va) {
                rd_library_name(ctx, oft_va,
                                rd_format("oft_%s_%s", module, name));
            }
        }
        else
            rd_set_imported_ord(ctx, ft_va, module, oft_thunk.ordinal);

        ft_va += pe->thunk_size;
        oft_va += pe->thunk_size;
    }
}

void pe_imports_register_types(RDContext* ctx) {
    // clang-format off
    RDTypeDef* importdescr = rd_typedef_create_struct("PE_IMPORT_DESCRIPTOR", ctx);
    rd_typedef_add_member(importdescr, "u32", "OriginalFirstThunk", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(importdescr, "u32", "TimeDateStamp", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(importdescr, "u32", "ForwarderChain", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(importdescr, "u32", "Name", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(importdescr, "u32", "FirstThunk", 0, RD_TYPE_NONE, ctx);
    rd_typedef_register(importdescr, ctx);
    // clang-format on
}

bool pe_imports_read_descriptor(RDReader* r, PEImportDescriptor* desc) {
    rd_reader_read_le32(r, &desc->OriginalFirstThunk);
    rd_reader_read_le32(r, &desc->TimeDateStamp);
    rd_reader_read_le32(r, &desc->ForwarderChain);
    rd_reader_read_le32(r, &desc->Name);
    rd_reader_read_le32(r, &desc->FirstThunk);
    if(rd_reader_has_error(r)) return false;

    return desc->Name && (desc->OriginalFirstThunk || desc->FirstThunk);
}

bool pe_imports_read(RDContext* ctx, const PEFormat* pe) {
    PEDataDirectory d = pe->datadir[PE_DIRECTORY_ENTRY_IMPORT];

    RDAddress va;
    if(!pe_from_rva(pe, d.VirtualAddress, &va)) return false;

    RDReader* r = rd_get_reader(ctx);
    rd_reader_seek(r, va);

    PEImportDescriptor desc;
    while(pe_imports_read_descriptor(r, &desc)) {
        rd_library_type(ctx, va, "PE_IMPORT_DESCRIPTOR", 0, RD_TYPE_NONE);

        RDAddress name_va;
        char* mod = rd_strdup(pe_imports_get_descriptor_name(r, pe, &desc));

        if(mod) {
            rd_library_type(ctx, name_va, "char", strlen(mod) + 1,
                            RD_TYPE_NONE);
        }
        else
            continue;

        RDAddress ft_va, oft_va;
        bool has_ft = pe_from_rva(pe, desc.FirstThunk, &ft_va);
        bool has_oft = pe_from_rva(pe, desc.OriginalFirstThunk, &oft_va);

        if(!has_oft) oft_va = ft_va;
        if(!has_ft) ft_va = oft_va;
        if(has_oft && has_ft) _pe_read_thunks(ctx, pe, r, mod, oft_va, ft_va);

        rd_free(mod);
        va += rd_size_of(ctx, "PE_IMPORT_DESCRIPTOR", 0);
        rd_reader_seek(r, va);
    }

    return true;
}

const char* pe_imports_get_descriptor_name(RDReader* r, const PEFormat* pe,
                                           const PEImportDescriptor* desc) {
    RDAddress name_va;
    char* module = NULL;

    if(pe_from_rva(pe, desc->Name, &name_va)) {
        usize n;
        rd_reader_seek(r, name_va);
        return rd_reader_peek_str(r, &n);
    }

    return NULL;
}
