#include "dalvik/dalvik.h"
#include "dex/dex.h"
#include <redasm/redasm.h>

static void android_module_load(void) {
    rd_register_processor(&DALVIK);
    rd_register_loader(&DEX);
}

RD_MODULE_EXPORT = {
    .api_version = RD_API_VERSION,
    .load = android_module_load,
};
