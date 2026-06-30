#pragma once

#include <redasm/redasm.h>

#define PE_RICH_PRODID(c) ((u16)((c) >> 16))
#define PE_RICH_BUILD(c) ((u16)((c) & 0xFFFF))

#define PE_RICH_PRODID_C 0x0104
#define PE_RICH_PRODID_CPP 0x0105

typedef struct PEFormat PEFormat;

typedef struct PERichRecord {
    u32 comp_id;
    u32 count;
} PERichRecord;

typedef enum PERichStatus {
    PE_RICH_ABSENT = 0, // no Rich/DanS markers found at all
    PE_RICH_OK,         // present, decoded, checksum matches
    PE_RICH_CORRUPTED,  // markers found, decoded, but checksum mismatch
} PERichStatus;

void pe_parse_richheader(RDContext* ctx, PEFormat* pe);
