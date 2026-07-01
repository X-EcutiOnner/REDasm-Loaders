#pragma once

#include "pe/format.h"
#include <redasm/redasm.h>

typedef struct PERuntimeFunctionEntry {
    u32 BeginAddress;
    u32 EndAddress;
    u32 UnwindInfoAddress; // or UnwindData
} PERuntimeFunctionEntry;

bool pe_read_exceptions_dir(RDContext* ctx, PEFormat* pe);
