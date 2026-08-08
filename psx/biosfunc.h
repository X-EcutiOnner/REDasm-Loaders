#pragma once

#include <redasm/redasm.h>

void psx_bios_autorename_hook(RDContext* ctx, const RDHookEvent* e,
                              void* userdata);
