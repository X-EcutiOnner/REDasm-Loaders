#pragma once

#include "ne/format.h"

typedef struct NEOrdinalSlice {
    RDAddress* data;
    u16 length;
} NEEntrySlice;

NEEntrySlice ne_entryslice_create(NEFormat* ne, RDContext* ctx);
void ne_entryslice_destroy(NEEntrySlice* self);
