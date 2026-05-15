#pragma once

#include "pe/format.h"

typedef struct PEResourceDirectory {
    u32 Characteristics;
    u32 TimeDateStamp;
    u16 MajorVersion;
    u16 MinorVersion;
    u16 NumberOfNamedEntries;
    u16 NumberOfIdEntries;
} PEResourceDirectory;

typedef struct PEResourceDirectoryEntry {
    u32 NameOffset;
    u32 OffsetToData;
} PEResourceDirectoryEntry;

typedef struct PEResourceDataEntry {
    u32 OffsetToData;
    u32 Size;
    u32 CodePage;
    u32 Reserved;
} PEResourceDataEntry;

bool pe_resources_read(RDContext* ctx, PEFormat* pe);
