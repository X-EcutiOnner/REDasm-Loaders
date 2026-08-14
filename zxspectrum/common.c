#include "common.h"

void zx_set_entry_point(RDContext* ctx, RDAddress ep) {
    if(ep < 0x4000) {
        RD_LOG_WARN("entry point 0x%04x falls inside ROM, snapshot was "
                    "captured mid-ROM execution, disassembly cannot start here",
                    ep);

        return;
    }

    rd_set_entry_point(ctx, ep, NULL);
}
