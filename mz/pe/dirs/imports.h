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

void pe_imports_register_types(RDContext* ctx);
bool pe_imports_read(RDContext* ctx, const PEFormat* pe);
bool pe_imports_read_descriptor(RDReader* r, PEImportDescriptor* desc);
const char* pe_imports_get_descriptor_name(RDReader* r, const PEFormat* pe,
                                           const PEImportDescriptor* desc);
