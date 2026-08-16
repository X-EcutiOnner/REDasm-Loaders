#pragma once

#include <redasm/redasm.h>

void zx_setup_string_terminators(RDContext* ctx);
void zx_set_entry_point(RDContext* ctx, RDAddress ep);
