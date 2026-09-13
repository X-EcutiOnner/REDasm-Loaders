#pragma once

#include "dex/format.h"

typedef struct Dalvik {
    bool is_valid;
    DEXHeader header;
    char reg_buf[8];

    // sections that exist only in map_list since 038
    u32 call_site_ids_off, call_site_ids_size;
    u32 method_handles_off, method_handles_size;

    RDScratchBuffer* raw_buf;
    RDScratchBuffer* string_buf;
    RDScratchBuffer* index_buf;
} Dalvik;
