#pragma once

#include "ne/format.h"

typedef struct NEImport {
    RDAddress base; // flat base of this module's import segment
    u16 next_off;   // next free byte offset in the slot (grows by sizeof(u16))
} NEImport;

typedef struct NEModuleSlice {
    char** names;
    NEImport* imports;
    usize length;
} NEModuleSlice;

NEModuleSlice ne_moduleslice_create(NEFormat* ne, RDContext* ctx);
void ne_moduleslice_destroy(NEModuleSlice* self);
void ne_moduleslice_build_imports(NEModuleSlice* self, NEFormat* ne,
                                  RDContext* ctx);
RDAddress ne_moduleslice_resolve_import(NEModuleSlice* self, RDContext* ctx,
                                        u16 mod_idx, const char* sym_name);
