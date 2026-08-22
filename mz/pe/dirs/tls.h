#pragma once

#include "pe/format.h"

typedef struct PETlsDirectory32 {
    u32 StartAddressOfRawData;
    u32 EndAddressOfRawData;
    u32 AddressOfIndex;
    u32 AddressOfCallBacks;
    u32 SizeOfZeroFill;
    u32 Characteristics;
} PETlsDirectory32;

typedef struct PETlsDirectory64 {
    u64 StartAddressOfRawData;
    u64 EndAddressOfRawData;
    u64 AddressOfIndex;
    u64 AddressOfCallBacks;
    u32 SizeOfZeroFill;
    u32 Characteristics;
} PETlsDirectory64;

bool pe_read_tls_dir(RDContext* ctx, PEFormat* pe);
