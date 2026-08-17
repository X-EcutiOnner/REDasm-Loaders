#include "nrom.h"
#include <redasm/redasm.h>

void rd_plugin_create(void) { rd_register_loader(&NROM_LOADER); }

const char* rd_plugin_version(void) { return "1.0"; }
