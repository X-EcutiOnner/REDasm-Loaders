#pragma once

#include "pe/format.h"
#include <redasm/redasm.h>

typedef struct PECorHeader {
    u32 cb;
    u16 MajorRuntimeVersion, MinorRuntimeVersion;
} PECorHeader;

int pe_dotnet_get_major(RDContext* ctx, const PEFormat* pe);
