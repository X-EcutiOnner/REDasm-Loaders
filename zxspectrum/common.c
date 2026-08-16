#include "common.h"

static const u8 STRING_TERMS[] = {0xFF, 0x00};

void zx_setup_string_terminators(RDContext* ctx) {
    rd_set_string_terminators(ctx, STRING_TERMS, rd_count_of(STRING_TERMS));
}

void zx_set_entry_point(RDContext* ctx, RDAddress ep) {
    if(ep < 0x4000) {
        RD_LOG_WARN("entry point 0x%04x falls inside ROM, snapshot was "
                    "captured mid-ROM execution, disassembly cannot start here",
                    ep);

        return;
    }

    rd_set_entry_point(ctx, ep, NULL);
}
