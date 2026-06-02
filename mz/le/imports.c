#include "imports.h"
#include "le/format.h"

#define LE_IMPORT_SLOT(num_objects, mod_idx)                                   \
    ((RDAddress)((num_objects) + 1 + (mod_idx)) * LE_SEG_SLOT)

LEImportSlice le_importslice_create(const LEFormat* le, RDContext* ctx) {
    u32 n = le->header.num_impmods;
    if(!n) return (LEImportSlice){0};

    LEImportSlice s = {
        .names = (char**)rd_alloc0(n, sizeof(char*)),
        .imports = rd_alloc0(n, sizeof(LEImport)),
        .length = n,
    };

    if(!n || !le->header.impmod_off) return s;

    RDReader* r = rd_get_input_reader(ctx);
    rd_reader_seek(r, (u64)le->base + le->header.impmod_off);

    for(u32 i = 0; i < n; i++) {
        u8 len;
        rd_reader_read_byte(r, &len);
        if(rd_reader_has_error(r) || !len) break;

        char* name = rd_alloc(len + 1);
        rd_reader_read(r, name, len);
        name[len] = '\0';
        if(rd_reader_has_error(r)) {
            rd_free(name);
            break;
        }

        s.names[i] = name;

        RDAddress base = LE_IMPORT_SLOT(le->header.num_objects, i);
        s.imports[i].base = base;
        s.imports[i].next_off = 0;

        // map synthetic import segment: label space only, no file backing
        rd_map_segment_n(ctx, name, base, LE_SEG_SLOT, RD_SP_R);
    }

    return s;
}

void le_importslice_destroy(LEImportSlice* self) {
    for(usize i = 0; i < self->length; i++)
        rd_free(self->names[i]);

    rd_free((void*)self->names);
    rd_free(self->imports);
    self->length = 0;
}

RDAddress le_importslice_resolve(const LEImportSlice* self, RDContext* ctx,
                                 u16 mod_idx, const char* sym_name) {
    if(!mod_idx || mod_idx > (u16)self->length) return 0;

    const char* mod_name = self->names[mod_idx - 1];
    const char* hint = rd_get_imported_hint(ctx, sym_name);

    // deduplication: already registered from a previous fixup
    RDAddress addr;
    if(rd_get_address(ctx, hint, &addr)) return addr;

    LEImport* mod = &self->imports[mod_idx - 1]; // mod_idx is 1-based
    addr = mod->base + mod->next_off;
    mod->next_off += sizeof(u32);

    rd_set_imported(ctx, addr, mod_name, sym_name);
    return addr;
}

RDAddress le_importslice_resolve_ord(const LEImportSlice* self, RDContext* ctx,
                                     u16 mod_idx, u32 ordinal) {
    if(!mod_idx || mod_idx > (u16)self->length) return 0;

    const char* mod_name = self->names[mod_idx - 1];
    const char* hint = rd_get_imported_ord_hint(ctx, mod_name, ordinal);

    // deduplication: already registered from a previous fixup
    RDAddress addr;
    if(rd_get_address(ctx, hint, &addr)) return addr;

    LEImport* mod = &self->imports[mod_idx - 1]; // mod_idx is 1-based
    addr = mod->base + mod->next_off;
    mod->next_off += sizeof(u32);

    rd_set_imported_ord(ctx, addr, mod_name, ordinal);
    return addr;
}

const char* le_import_proc_name(const LEFormat* le, RDReader* r, u32 name_off) {
    if(!le->header.impproc_off) return NULL;

    u64 pos = (u64)le->base + le->header.impproc_off + name_off;
    rd_reader_seek(r, pos);

    u8 len;
    rd_reader_read_byte(r, &len);
    if(rd_reader_has_error(r) || !len) return NULL;

    len &= 0x7F; // top bit reserved per spec

    char name[128];
    rd_reader_read(r, name, len);
    name[len] = '\0';
    if(rd_reader_has_error(r)) return NULL;

    return rd_format("%.*s", (int)len, name);
}
