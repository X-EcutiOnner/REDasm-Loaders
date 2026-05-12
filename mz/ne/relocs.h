#pragma once

#include "ne/format.h"
#include "ne/modules.h"

void ne_load_relocs(NEFormat* ne, RDContext* ctx, u32 file_off, u16 seg_idx,
                    u16 seg_bytes, NEModuleSlice* modules);
