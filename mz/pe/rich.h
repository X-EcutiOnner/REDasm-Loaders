#pragma once

#include <redasm/redasm.h>

#define PE_RICH_PRODID(c) ((u16)((c) >> 16))
#define PE_RICH_BUILD(c) ((u16)((c) & 0xFFFF))

#define PE_RICH_PRODID_1310P_C 0x004c
#define PE_RICH_PRODID_1310P_CPP 0x004d
#define PE_RICH_PRODID_1310_C 0x005f
#define PE_RICH_PRODID_1310_CPP 0x0060
#define PE_RICH_PRODID_1400_C 0x006d
#define PE_RICH_PRODID_1400_CPP 0x006e
#define PE_RICH_PRODID_1500_C 0x0083
#define PE_RICH_PRODID_1500_CPP 0x0084
#define PE_RICH_PRODID_1600_C 0x00aa
#define PE_RICH_PRODID_1600_CPP 0x00ab
#define PE_RICH_PRODID_1610_C 0x00bc
#define PE_RICH_PRODID_1610_CPP 0x00bd
#define PE_RICH_PRODID_1700_C 0x00ce
#define PE_RICH_PRODID_1700_CPP 0x00cf
#define PE_RICH_PRODID_1800_C 0x00e0
#define PE_RICH_PRODID_1800_CPP 0x00e1
#define PE_RICH_PRODID_1810_C 0x00f2
#define PE_RICH_PRODID_1810_CPP 0x00f3
#define PE_RICH_PRODID_1900_C 0x0104
#define PE_RICH_PRODID_1900_CPP 0x0105

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
