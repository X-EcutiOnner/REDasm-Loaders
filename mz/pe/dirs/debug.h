#pragma once

#include "pe/format.h"

typedef struct PEDebugDirectory {
    u32 Characteristics;
    u32 TimeDateStamp;
    u16 MajorVersion;
    u16 MinorVersion;
    u32 Type;
    u32 SizeOfData;
    u32 AddressOfRawData;
    u32 PointerToRawData;
} PEDebugDirectory;

typedef struct CvInfoPdb20 {
    u32 CvSignature;
    u32 Offset;
    u32 Signature;
    u32 Age;
} CvInfoPdb20;

typedef struct CvInfoPdb70 {
    u32 CvSignature;
    u8 Signature[16]; // GUID
    u32 Age;
} CvInfoPdb70;

bool pe_read_debug_dir(RDContext* ctx, PEFormat* pe);
