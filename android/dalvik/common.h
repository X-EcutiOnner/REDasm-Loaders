#pragma once

#include "dex/format.h"

typedef struct Dalvik {
    bool is_valid;
    DEXHeader header;
    char reg_buf[8];

    RDScratchBuffer* raw_buf;
    RDScratchBuffer* string_buf;
} Dalvik;
