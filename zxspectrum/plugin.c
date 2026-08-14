#include "sna/sna.h"
#include "z80/z80.h"
#include <redasm/redasm.h>

void rd_plugin_create(void) {
    rd_register_loader(&SNA_LOADER);
    rd_register_loader(&Z80_LOADER);
}

const char* rd_plugin_version(void) { return "1.0"; }
