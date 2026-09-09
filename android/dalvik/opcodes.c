#include "opcodes.h"

const DalvikFormatInfo DALVIK_FORMATS[DALVIK_FMT_COUNT] = {
    [DALVIK_FMT_INVALID] = {0}, [DALVIK_FMT_10X] = {1},  [DALVIK_FMT_12X] = {1},
    [DALVIK_FMT_11N] = {1},     [DALVIK_FMT_11X] = {1},  [DALVIK_FMT_10T] = {1},
    [DALVIK_FMT_20T] = {2},     [DALVIK_FMT_22X] = {2},  [DALVIK_FMT_21T] = {2},
    [DALVIK_FMT_21S] = {2},     [DALVIK_FMT_21H] = {2},  [DALVIK_FMT_21C] = {2},
    [DALVIK_FMT_23X] = {2},     [DALVIK_FMT_22B] = {2},  [DALVIK_FMT_22T] = {2},
    [DALVIK_FMT_22S] = {2},     [DALVIK_FMT_22C] = {2},  [DALVIK_FMT_30T] = {3},
    [DALVIK_FMT_32X] = {3},     [DALVIK_FMT_31I] = {3},  [DALVIK_FMT_31T] = {3},
    [DALVIK_FMT_31C] = {3},     [DALVIK_FMT_35C] = {3},  [DALVIK_FMT_3RC] = {3},
    [DALVIK_FMT_45CC] = {4},    [DALVIK_FMT_4RCC] = {4}, [DALVIK_FMT_51L] = {5},
};

#define OP(fmt, idx, fl) DALVIK_FMT_##fmt, DALVIK_IDX_##idx, fl

// clang-format off
const DalvikOpcode DALVIK_OPCODES[256] = {
    // --- move / return ---
    [0x00] = {"nop",                    OP(10X, NONE,   RD_IF_NOP)},
    [0x01] = {"move",                   OP(12X, NONE,   RD_IF_NONE)},
    [0x02] = {"move/from16",            OP(22X, NONE,   RD_IF_NONE)},
    [0x03] = {"move/16",                OP(32X, NONE,   RD_IF_NONE)},
    [0x04] = {"move-wide",              OP(12X, NONE,   RD_IF_NONE)},
    [0x05] = {"move-wide/from16",       OP(22X, NONE,   RD_IF_NONE)},
    [0x06] = {"move-wide/16",           OP(32X, NONE,   RD_IF_NONE)},
    [0x07] = {"move-object",            OP(12X, NONE,   RD_IF_NONE)},
    [0x08] = {"move-object/from16",     OP(22X, NONE,   RD_IF_NONE)},
    [0x09] = {"move-object/16",         OP(32X, NONE,   RD_IF_NONE)},
    [0x0A] = {"move-result",            OP(11X, NONE,   RD_IF_NONE)},
    [0x0B] = {"move-result-wide",       OP(11X, NONE,   RD_IF_NONE)},
    [0x0C] = {"move-result-object",     OP(11X, NONE,   RD_IF_NONE)},
    [0x0D] = {"move-exception",         OP(11X, NONE,   RD_IF_NONE)},
    [0x0E] = {"return-void",            OP(10X, NONE,   RD_IF_STOP)},
    [0x0F] = {"return",                 OP(11X, NONE,   RD_IF_STOP)},
    [0x10] = {"return-wide",            OP(11X, NONE,   RD_IF_STOP)},
    [0x11] = {"return-object",          OP(11X, NONE,   RD_IF_STOP)},

    // --- constants ---
    [0x12] = {"const/4",                OP(11N, NONE,   RD_IF_NONE)},
    [0x13] = {"const/16",               OP(21S, NONE,   RD_IF_NONE)},
    [0x14] = {"const",                  OP(31I, NONE,   RD_IF_NONE)},
    [0x15] = {"const/high16",           OP(21H, NONE,   RD_IF_NONE)},
    [0x16] = {"const-wide/16",          OP(21S, NONE,   RD_IF_NONE)},
    [0x17] = {"const-wide/32",          OP(31I, NONE,   RD_IF_NONE)},
    [0x18] = {"const-wide",             OP(51L, NONE,   RD_IF_NONE)},
    [0x19] = {"const-wide/high16",      OP(21H, NONE,   RD_IF_NONE)},
    [0x1A] = {"const-string",           OP(21C, STRING, RD_IF_NONE)},
    [0x1B] = {"const-string/jumbo",     OP(31C, STRING, RD_IF_NONE)},
    [0x1C] = {"const-class",            OP(21C, TYPE,   RD_IF_NONE)},

    // --- monitors, casts, arrays ---
    [0x1D] = {"monitor-enter",          OP(11X, NONE,   RD_IF_NONE)},
    [0x1E] = {"monitor-exit",           OP(11X, NONE,   RD_IF_NONE)},
    [0x1F] = {"check-cast",             OP(21C, TYPE,   RD_IF_NONE)},
    [0x20] = {"instance-of",            OP(22C, TYPE,   RD_IF_NONE)},
    [0x21] = {"array-length",           OP(12X, NONE,   RD_IF_NONE)},
    [0x22] = {"new-instance",           OP(21C, TYPE,   RD_IF_NONE)},
    [0x23] = {"new-array",              OP(22C, TYPE,   RD_IF_NONE)},
    [0x24] = {"filled-new-array",       OP(35C, TYPE,   RD_IF_NONE)},
    [0x25] = {"filled-new-array/range", OP(3RC, TYPE,   RD_IF_NONE)},

    // 31t, but the target is a fill-array-data-payload: DATA, not a branch
    [0x26] = {"fill-array-data",        OP(31T, NONE,   RD_IF_NONE)},

    [0x27] = {"throw",                  OP(11X, NONE,   RD_IF_STOP)},

    // --- control flow ---
    [0x28] = {"goto",                   OP(10T, NONE,   RD_IF_JUMP)},
    [0x29] = {"goto/16",                OP(20T, NONE,   RD_IF_JUMP)},
    [0x2A] = {"goto/32",                OP(30T, NONE,   RD_IF_JUMP)},

    // multi-way: falls through to the next instruction on no match
    [0x2B] = {"packed-switch",          OP(31T, NONE,   RD_IF_JUMP_COND)},
    [0x2C] = {"sparse-switch",          OP(31T, NONE,   RD_IF_JUMP_COND)},

    // --- comparisons ---
    [0x2D] = {"cmpl-float",             OP(23X, NONE,   RD_IF_NONE)},
    [0x2E] = {"cmpg-float",             OP(23X, NONE,   RD_IF_NONE)},
    [0x2F] = {"cmpl-double",            OP(23X, NONE,   RD_IF_NONE)},
    [0x30] = {"cmpg-double",            OP(23X, NONE,   RD_IF_NONE)},
    [0x31] = {"cmp-long",               OP(23X, NONE,   RD_IF_NONE)},

    // --- conditional branches ---
    [0x32] = {"if-eq",                  OP(22T, NONE,   RD_IF_JUMP_COND)},
    [0x33] = {"if-ne",                  OP(22T, NONE,   RD_IF_JUMP_COND)},
    [0x34] = {"if-lt",                  OP(22T, NONE,   RD_IF_JUMP_COND)},
    [0x35] = {"if-ge",                  OP(22T, NONE,   RD_IF_JUMP_COND)},
    [0x36] = {"if-gt",                  OP(22T, NONE,   RD_IF_JUMP_COND)},
    [0x37] = {"if-le",                  OP(22T, NONE,   RD_IF_JUMP_COND)},
    [0x38] = {"if-eqz",                 OP(21T, NONE,   RD_IF_JUMP_COND)},
    [0x39] = {"if-nez",                 OP(21T, NONE,   RD_IF_JUMP_COND)},
    [0x3A] = {"if-ltz",                 OP(21T, NONE,   RD_IF_JUMP_COND)},
    [0x3B] = {"if-gez",                 OP(21T, NONE,   RD_IF_JUMP_COND)},
    [0x3C] = {"if-gtz",                 OP(21T, NONE,   RD_IF_JUMP_COND)},
    [0x3D] = {"if-lez",                 OP(21T, NONE,   RD_IF_JUMP_COND)},

    // 0x3E - 0x43 unused

    // --- array access ---
    [0x44] = {"aget",                   OP(23X, NONE,   RD_IF_NONE)},
    [0x45] = {"aget-wide",              OP(23X, NONE,   RD_IF_NONE)},
    [0x46] = {"aget-object",            OP(23X, NONE,   RD_IF_NONE)},
    [0x47] = {"aget-boolean",           OP(23X, NONE,   RD_IF_NONE)},
    [0x48] = {"aget-byte",              OP(23X, NONE,   RD_IF_NONE)},
    [0x49] = {"aget-char",              OP(23X, NONE,   RD_IF_NONE)},
    [0x4A] = {"aget-short",             OP(23X, NONE,   RD_IF_NONE)},
    [0x4B] = {"aput",                   OP(23X, NONE,   RD_IF_NONE)},
    [0x4C] = {"aput-wide",              OP(23X, NONE,   RD_IF_NONE)},
    [0x4D] = {"aput-object",            OP(23X, NONE,   RD_IF_NONE)},
    [0x4E] = {"aput-boolean",           OP(23X, NONE,   RD_IF_NONE)},
    [0x4F] = {"aput-byte",              OP(23X, NONE,   RD_IF_NONE)},
    [0x50] = {"aput-char",              OP(23X, NONE,   RD_IF_NONE)},
    [0x51] = {"aput-short",             OP(23X, NONE,   RD_IF_NONE)},

    // --- instance fields ---
    [0x52] = {"iget",                   OP(22C, FIELD,  RD_IF_NONE)},
    [0x53] = {"iget-wide",              OP(22C, FIELD,  RD_IF_NONE)},
    [0x54] = {"iget-object",            OP(22C, FIELD,  RD_IF_NONE)},
    [0x55] = {"iget-boolean",           OP(22C, FIELD,  RD_IF_NONE)},
    [0x56] = {"iget-byte",              OP(22C, FIELD,  RD_IF_NONE)},
    [0x57] = {"iget-char",              OP(22C, FIELD,  RD_IF_NONE)},
    [0x58] = {"iget-short",             OP(22C, FIELD,  RD_IF_NONE)},
    [0x59] = {"iput",                   OP(22C, FIELD,  RD_IF_NONE)},
    [0x5A] = {"iput-wide",              OP(22C, FIELD,  RD_IF_NONE)},
    [0x5B] = {"iput-object",            OP(22C, FIELD,  RD_IF_NONE)},
    [0x5C] = {"iput-boolean",           OP(22C, FIELD,  RD_IF_NONE)},
    [0x5D] = {"iput-byte",              OP(22C, FIELD,  RD_IF_NONE)},
    [0x5E] = {"iput-char",              OP(22C, FIELD,  RD_IF_NONE)},
    [0x5F] = {"iput-short",             OP(22C, FIELD,  RD_IF_NONE)},

    // --- static fields ---
    [0x60] = {"sget",                   OP(21C, FIELD,  RD_IF_NONE)},
    [0x61] = {"sget-wide",              OP(21C, FIELD,  RD_IF_NONE)},
    [0x62] = {"sget-object",            OP(21C, FIELD,  RD_IF_NONE)},
    [0x63] = {"sget-boolean",           OP(21C, FIELD,  RD_IF_NONE)},
    [0x64] = {"sget-byte",              OP(21C, FIELD,  RD_IF_NONE)},
    [0x65] = {"sget-char",              OP(21C, FIELD,  RD_IF_NONE)},
    [0x66] = {"sget-short",             OP(21C, FIELD,  RD_IF_NONE)},
    [0x67] = {"sput",                   OP(21C, FIELD,  RD_IF_NONE)},
    [0x68] = {"sput-wide",              OP(21C, FIELD,  RD_IF_NONE)},
    [0x69] = {"sput-object",            OP(21C, FIELD,  RD_IF_NONE)},
    [0x6A] = {"sput-boolean",           OP(21C, FIELD,  RD_IF_NONE)},
    [0x6B] = {"sput-byte",              OP(21C, FIELD,  RD_IF_NONE)},
    [0x6C] = {"sput-char",              OP(21C, FIELD,  RD_IF_NONE)},
    [0x6D] = {"sput-short",             OP(21C, FIELD,  RD_IF_NONE)},

    // --- invocation ---
    [0x6E] = {"invoke-virtual",         OP(35C, METHOD, RD_IF_CALL)},
    [0x6F] = {"invoke-super",           OP(35C, METHOD, RD_IF_CALL)},
    [0x70] = {"invoke-direct",          OP(35C, METHOD, RD_IF_CALL)},
    [0x71] = {"invoke-static",          OP(35C, METHOD, RD_IF_CALL)},
    [0x72] = {"invoke-interface",       OP(35C, METHOD, RD_IF_CALL)},

    // 0x73 unused

    [0x74] = {"invoke-virtual/range",   OP(3RC, METHOD, RD_IF_CALL)},
    [0x75] = {"invoke-super/range",     OP(3RC, METHOD, RD_IF_CALL)},
    [0x76] = {"invoke-direct/range",    OP(3RC, METHOD, RD_IF_CALL)},
    [0x77] = {"invoke-static/range",    OP(3RC, METHOD, RD_IF_CALL)},
    [0x78] = {"invoke-interface/range", OP(3RC, METHOD, RD_IF_CALL)},

    // 0x79 - 0x7A unused

    // --- unary ops and conversions ---
    [0x7B] = {"neg-int",                OP(12X, NONE,   RD_IF_NONE)},
    [0x7C] = {"not-int",                OP(12X, NONE,   RD_IF_NONE)},
    [0x7D] = {"neg-long",               OP(12X, NONE,   RD_IF_NONE)},
    [0x7E] = {"not-long",               OP(12X, NONE,   RD_IF_NONE)},
    [0x7F] = {"neg-float",              OP(12X, NONE,   RD_IF_NONE)},
    [0x80] = {"neg-double",             OP(12X, NONE,   RD_IF_NONE)},
    [0x81] = {"int-to-long",            OP(12X, NONE,   RD_IF_NONE)},
    [0x82] = {"int-to-float",           OP(12X, NONE,   RD_IF_NONE)},
    [0x83] = {"int-to-double",          OP(12X, NONE,   RD_IF_NONE)},
    [0x84] = {"long-to-int",            OP(12X, NONE,   RD_IF_NONE)},
    [0x85] = {"long-to-float",          OP(12X, NONE,   RD_IF_NONE)},
    [0x86] = {"long-to-double",         OP(12X, NONE,   RD_IF_NONE)},
    [0x87] = {"float-to-int",           OP(12X, NONE,   RD_IF_NONE)},
    [0x88] = {"float-to-long",          OP(12X, NONE,   RD_IF_NONE)},
    [0x89] = {"float-to-double",        OP(12X, NONE,   RD_IF_NONE)},
    [0x8A] = {"double-to-int",          OP(12X, NONE,   RD_IF_NONE)},
    [0x8B] = {"double-to-long",         OP(12X, NONE,   RD_IF_NONE)},
    [0x8C] = {"double-to-float",        OP(12X, NONE,   RD_IF_NONE)},
    [0x8D] = {"int-to-byte",            OP(12X, NONE,   RD_IF_NONE)},
    [0x8E] = {"int-to-char",            OP(12X, NONE,   RD_IF_NONE)},
    [0x8F] = {"int-to-short",           OP(12X, NONE,   RD_IF_NONE)},

    // --- binary ops (three-register) ---
    [0x90] = {"add-int",                OP(23X, NONE,   RD_IF_NONE)},
    [0x91] = {"sub-int",                OP(23X, NONE,   RD_IF_NONE)},
    [0x92] = {"mul-int",                OP(23X, NONE,   RD_IF_NONE)},
    [0x93] = {"div-int",                OP(23X, NONE,   RD_IF_NONE)},
    [0x94] = {"rem-int",                OP(23X, NONE,   RD_IF_NONE)},
    [0x95] = {"and-int",                OP(23X, NONE,   RD_IF_NONE)},
    [0x96] = {"or-int",                 OP(23X, NONE,   RD_IF_NONE)},
    [0x97] = {"xor-int",                OP(23X, NONE,   RD_IF_NONE)},
    [0x98] = {"shl-int",                OP(23X, NONE,   RD_IF_NONE)},
    [0x99] = {"shr-int",                OP(23X, NONE,   RD_IF_NONE)},
    [0x9A] = {"ushr-int",               OP(23X, NONE,   RD_IF_NONE)},
    [0x9B] = {"add-long",               OP(23X, NONE,   RD_IF_NONE)},
    [0x9C] = {"sub-long",               OP(23X, NONE,   RD_IF_NONE)},
    [0x9D] = {"mul-long",               OP(23X, NONE,   RD_IF_NONE)},
    [0x9E] = {"div-long",               OP(23X, NONE,   RD_IF_NONE)},
    [0x9F] = {"rem-long",               OP(23X, NONE,   RD_IF_NONE)},
    [0xA0] = {"and-long",               OP(23X, NONE,   RD_IF_NONE)},
    [0xA1] = {"or-long",                OP(23X, NONE,   RD_IF_NONE)},
    [0xA2] = {"xor-long",               OP(23X, NONE,   RD_IF_NONE)},
    [0xA3] = {"shl-long",               OP(23X, NONE,   RD_IF_NONE)},
    [0xA4] = {"shr-long",               OP(23X, NONE,   RD_IF_NONE)},
    [0xA5] = {"ushr-long",              OP(23X, NONE,   RD_IF_NONE)},
    [0xA6] = {"add-float",              OP(23X, NONE,   RD_IF_NONE)},
    [0xA7] = {"sub-float",              OP(23X, NONE,   RD_IF_NONE)},
    [0xA8] = {"mul-float",              OP(23X, NONE,   RD_IF_NONE)},
    [0xA9] = {"div-float",              OP(23X, NONE,   RD_IF_NONE)},
    [0xAA] = {"rem-float",              OP(23X, NONE,   RD_IF_NONE)},
    [0xAB] = {"add-double",             OP(23X, NONE,   RD_IF_NONE)},
    [0xAC] = {"sub-double",             OP(23X, NONE,   RD_IF_NONE)},
    [0xAD] = {"mul-double",             OP(23X, NONE,   RD_IF_NONE)},
    [0xAE] = {"div-double",             OP(23X, NONE,   RD_IF_NONE)},
    [0xAF] = {"rem-double",             OP(23X, NONE,   RD_IF_NONE)},

    // --- binary ops (two-address) ---
    [0xB0] = {"add-int/2addr",          OP(12X, NONE,   RD_IF_NONE)},
    [0xB1] = {"sub-int/2addr",          OP(12X, NONE,   RD_IF_NONE)},
    [0xB2] = {"mul-int/2addr",          OP(12X, NONE,   RD_IF_NONE)},
    [0xB3] = {"div-int/2addr",          OP(12X, NONE,   RD_IF_NONE)},
    [0xB4] = {"rem-int/2addr",          OP(12X, NONE,   RD_IF_NONE)},
    [0xB5] = {"and-int/2addr",          OP(12X, NONE,   RD_IF_NONE)},
    [0xB6] = {"or-int/2addr",           OP(12X, NONE,   RD_IF_NONE)},
    [0xB7] = {"xor-int/2addr",          OP(12X, NONE,   RD_IF_NONE)},
    [0xB8] = {"shl-int/2addr",          OP(12X, NONE,   RD_IF_NONE)},
    [0xB9] = {"shr-int/2addr",          OP(12X, NONE,   RD_IF_NONE)},
    [0xBA] = {"ushr-int/2addr",         OP(12X, NONE,   RD_IF_NONE)},
    [0xBB] = {"add-long/2addr",         OP(12X, NONE,   RD_IF_NONE)},
    [0xBC] = {"sub-long/2addr",         OP(12X, NONE,   RD_IF_NONE)},
    [0xBD] = {"mul-long/2addr",         OP(12X, NONE,   RD_IF_NONE)},
    [0xBE] = {"div-long/2addr",         OP(12X, NONE,   RD_IF_NONE)},
    [0xBF] = {"rem-long/2addr",         OP(12X, NONE,   RD_IF_NONE)},
    [0xC0] = {"and-long/2addr",         OP(12X, NONE,   RD_IF_NONE)},
    [0xC1] = {"or-long/2addr",          OP(12X, NONE,   RD_IF_NONE)},
    [0xC2] = {"xor-long/2addr",         OP(12X, NONE,   RD_IF_NONE)},
    [0xC3] = {"shl-long/2addr",         OP(12X, NONE,   RD_IF_NONE)},
    [0xC4] = {"shr-long/2addr",         OP(12X, NONE,   RD_IF_NONE)},
    [0xC5] = {"ushr-long/2addr",        OP(12X, NONE,   RD_IF_NONE)},
    [0xC6] = {"add-float/2addr",        OP(12X, NONE,   RD_IF_NONE)},
    [0xC7] = {"sub-float/2addr",        OP(12X, NONE,   RD_IF_NONE)},
    [0xC8] = {"mul-float/2addr",        OP(12X, NONE,   RD_IF_NONE)},
    [0xC9] = {"div-float/2addr",        OP(12X, NONE,   RD_IF_NONE)},
    [0xCA] = {"rem-float/2addr",        OP(12X, NONE,   RD_IF_NONE)},
    [0xCB] = {"add-double/2addr",       OP(12X, NONE,   RD_IF_NONE)},
    [0xCC] = {"sub-double/2addr",       OP(12X, NONE,   RD_IF_NONE)},
    [0xCD] = {"mul-double/2addr",       OP(12X, NONE,   RD_IF_NONE)},
    [0xCE] = {"div-double/2addr",       OP(12X, NONE,   RD_IF_NONE)},
    [0xCF] = {"rem-double/2addr",       OP(12X, NONE,   RD_IF_NONE)},

    // --- 16-bit literal ops ---
    // 0xD1 is rsub-int (reverse subtract), NOT sub-int/lit16
    [0xD0] = {"add-int/lit16",          OP(22S, NONE,   RD_IF_NONE)},
    [0xD1] = {"rsub-int",               OP(22S, NONE,   RD_IF_NONE)},
    [0xD2] = {"mul-int/lit16",          OP(22S, NONE,   RD_IF_NONE)},
    [0xD3] = {"div-int/lit16",          OP(22S, NONE,   RD_IF_NONE)},
    [0xD4] = {"rem-int/lit16",          OP(22S, NONE,   RD_IF_NONE)},
    [0xD5] = {"and-int/lit16",          OP(22S, NONE,   RD_IF_NONE)},
    [0xD6] = {"or-int/lit16",           OP(22S, NONE,   RD_IF_NONE)},
    [0xD7] = {"xor-int/lit16",          OP(22S, NONE,   RD_IF_NONE)},

    // --- 8-bit literal ops ---
    [0xD8] = {"add-int/lit8",           OP(22B, NONE,   RD_IF_NONE)},
    [0xD9] = {"rsub-int/lit8",          OP(22B, NONE,   RD_IF_NONE)},
    [0xDA] = {"mul-int/lit8",           OP(22B, NONE,   RD_IF_NONE)},
    [0xDB] = {"div-int/lit8",           OP(22B, NONE,   RD_IF_NONE)},
    [0xDC] = {"rem-int/lit8",           OP(22B, NONE,   RD_IF_NONE)},
    [0xDD] = {"and-int/lit8",           OP(22B, NONE,   RD_IF_NONE)},
    [0xDE] = {"or-int/lit8",            OP(22B, NONE,   RD_IF_NONE)},
    [0xDF] = {"xor-int/lit8",           OP(22B, NONE,   RD_IF_NONE)},
    [0xE0] = {"shl-int/lit8",           OP(22B, NONE,   RD_IF_NONE)},
    [0xE1] = {"shr-int/lit8",           OP(22B, NONE,   RD_IF_NONE)},
    [0xE2] = {"ushr-int/lit8",          OP(22B, NONE,   RD_IF_NONE)},

    // 0xE3 - 0xF9 unused in standard DEX.
    // dexopt used this range for quickened opcodes (iget-quick and friends),
    // so a memory-dumped DEX may contain them: render as unknown, never
    // reject the whole function.

    // --- 038+ / 039+ ---
    // Decoded unconditionally regardless of the file's declared version:
    // the version field is producer metadata and obfuscators lie about it.
    [0xFA] = {"invoke-polymorphic",       OP(45CC, METHOD_PROTO,   RD_IF_CALL)},
    [0xFB] = {"invoke-polymorphic/range", OP(4RCC, METHOD_PROTO,   RD_IF_CALL)},
    [0xFC] = {"invoke-custom",            OP(35C,  CALL_SITE,      RD_IF_CALL)},
    [0xFD] = {"invoke-custom/range",      OP(3RC,  CALL_SITE,      RD_IF_CALL)},
    [0xFE] = {"const-method-handle",      OP(21C,  METHOD_HANDLE,  RD_IF_NONE)},
    [0xFF] = {"const-method-type",        OP(21C,  PROTO,          RD_IF_NONE)},
};
// clang-format on

#undef OP
