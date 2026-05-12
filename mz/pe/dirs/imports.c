#include "imports.h"
#include <string.h>

#define PE_ORDINAL_FLAG64 0x8000000000000000ULL
#define PE_ORDINAL_FLAG32 0x80000000

static void _pe_read_thunks(RDContext* ctx, const PEFormat* pe, RDReader* r,
                            const char* module, RDAddress va, bool isft) {
    bool is64 = pe_get_bits(pe) == 64;
    const int THUNK_SIZE = is64 ? sizeof(u64) : sizeof(u32);
    const char* thunktype = is64 ? "u64" : "u32";
    const char* prefix = isft ? "ft_" : "oft_";

    rd_reader_seek(r, va);

    while(true) {
        RDAddress addr = rd_reader_get_pos(r);
        u64 thunk = 0;

        if(is64) {
            rd_reader_read_le64(r, &thunk);
        }
        else {
            u32 t;
            rd_reader_read_le32(r, &t);
            thunk = (u64)t;
        }

        if(rd_reader_has_error(r)) break;

        if(!thunk) {
            rd_library_type(ctx, addr, thunktype, 0, RD_TYPE_NONE);
            break;
        }

        bool is_ord =
            !!(thunk & (is64 ? PE_ORDINAL_FLAG64 : PE_ORDINAL_FLAG32));

        rd_library_type(ctx, addr, thunktype, 0, RD_TYPE_PTR);

        if(is_ord) {
            if(isft)
                rd_set_imported_ord(ctx, addr, module, NULL, thunk & 0xFFFF);
            else {
                rd_library_name(ctx, addr,
                                rd_format("%s%s_ord%u", prefix, module,
                                          (u32)(thunk & 0xFFFF)));
            }
        }
        else {
            RDAddress thunkva;
            pe_from_rva(pe, thunk, &thunkva);

            rd_reader_seek(r, thunkva);
            rd_reader_read_le16(r, NULL); // skip hint

            usize n;
            const char* name = rd_reader_read_str(r, &n);

            rd_library_type(ctx, thunkva, "u16", 0, RD_TYPE_NONE);
            rd_library_type(ctx, thunkva + sizeof(u16), "char", n + 1,
                            RD_TYPE_NONE);

            rd_library_name(ctx, thunkva,
                            rd_format("%s%s_%s_hint", prefix, module, name));

            rd_library_name(ctx, thunkva + sizeof(u16),
                            rd_format("%s%s_%s_name", prefix, module, name));

            if(isft)
                rd_set_imported(ctx, addr, module, name);
            else {
                rd_library_name(ctx, addr,
                                rd_format("%s%s_%s", prefix, module, name));
            }
        }

        rd_reader_seek(r, addr + THUNK_SIZE);
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

        if(has_oft) _pe_read_thunks(ctx, pe, r, mod, oft_va, false);
        if(has_ft) _pe_read_thunks(ctx, pe, r, mod, ft_va, true);

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
