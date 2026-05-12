#pragma once

#include "pe/format.h"

typedef struct PEImportDescriptor {
    u32 OriginalFirstThunk;
    u32 TimeDateStamp;
    u32 ForwarderChain;
    u32 Name;
    u32 FirstThunk;
} PEImportDescriptor;

typedef struct PEImportByName {
    u16 Hint;
    u8 Name[1];
} PEImportByName;

typedef u32 PEThunkData32;
typedef u64 PEThunkData64;

void pe_register_imports_types(RDContext* ctx);
bool pe_read_imports(RDContext* ctx, PEFormat* pe);
