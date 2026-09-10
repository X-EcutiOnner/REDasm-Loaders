#pragma once

#include <redasm/redasm.h>

#define DALVIK_PAYLOAD_PACKED_SWITCH 0x0100
#define DALVIK_PAYLOAD_SPARSE_SWITCH 0x0200
#define DALVIK_PAYLOAD_FILL_ARRAY_DATA 0x0300

typedef enum {
    DALVIK_ID_CONST_WIDE_HIGH16 = 0x19,
    DALVIK_ID_PACKED_SWITCH = 0x2B,
    DALVIK_ID_SPARSE_SWITCH = 0x2C,
    DALVIK_ID_FILL_ARRAY_DATA = 0x26,
} DalvikInstructionId;

typedef enum {
    DALVIK_FMT_INVALID = 0,
    DALVIK_FMT_10X,
    DALVIK_FMT_12X,
    DALVIK_FMT_11N,
    DALVIK_FMT_11X,
    DALVIK_FMT_10T,
    DALVIK_FMT_20T,
    DALVIK_FMT_22X,
    DALVIK_FMT_21T,
    DALVIK_FMT_21S,
    DALVIK_FMT_21H,
    DALVIK_FMT_21C,
    DALVIK_FMT_23X,
    DALVIK_FMT_22B,
    DALVIK_FMT_22T,
    DALVIK_FMT_22S,
    DALVIK_FMT_22C,
    DALVIK_FMT_30T,
    DALVIK_FMT_32X,
    DALVIK_FMT_31I,
    DALVIK_FMT_31T,
    DALVIK_FMT_31C,
    DALVIK_FMT_35C,
    DALVIK_FMT_3RC,
    DALVIK_FMT_45CC,
    DALVIK_FMT_4RCC,
    DALVIK_FMT_51L,
    DALVIK_FMT_COUNT,
} DalvikFormat;

typedef enum DalvikIndexKind {
    DALVIK_IDX_NONE = 0,
    DALVIK_IDX_STRING,
    DALVIK_IDX_TYPE,
    DALVIK_IDX_FIELD,
    DALVIK_IDX_METHOD,
    DALVIK_IDX_METHOD_PROTO,  // 45cc/4rcc: method index + proto index
    DALVIK_IDX_CALL_SITE,     // 038+
    DALVIK_IDX_METHOD_HANDLE, // 039+
    DALVIK_IDX_PROTO,         // 039+
} DalvikIndexKind;

typedef struct DalvikOpcode {
    const char* mnemonic; // NULL for unused opcodes
    u8 format;
    u8 index_kind;
    u16 flow;
} DalvikOpcode;

typedef struct DalvikFormatInfo {
    u8 units; // instruction length in 16-bit code units
} DalvikFormatInfo;

extern const DalvikOpcode DALVIK_OPCODES[256];
extern const DalvikFormatInfo DALVIK_FORMATS[DALVIK_FMT_COUNT];
