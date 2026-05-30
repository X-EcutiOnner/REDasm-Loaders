#pragma once

#include <redasm/redasm.h>

typedef struct LEFormat LEFormat;

typedef struct LEImport {
    RDAddress base;
    u32 next_off;
} LEImport;

typedef struct LEImportSlice {
    char** names;
    LEImport* imports;
    usize length;
} LEImportSlice;

LEImportSlice le_importslice_create(const LEFormat* le, RDContext* ctx);
void le_importslice_destroy(LEImportSlice* self);
RDAddress le_importslice_resolve(const LEImportSlice* self, RDContext* ctx,
                                 u16 mod_idx, const char* sym_name);
RDAddress le_importslice_resolve_ord(const LEImportSlice* self, RDContext* ctx,
                                     u16 mod_idx, u32 ordinal);
const char* le_import_proc_name(const LEFormat* le, RDReader* r, u32 name_off);
