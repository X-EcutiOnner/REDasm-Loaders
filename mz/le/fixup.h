#pragma once

#include "le/format.h"

void le_fixup_apply(const LEFormat* le, RDAddress page_va, u32 page_idx,
                    RDReader* r, RDContext* ctx);
