#pragma once

#include <redasm/redasm.h>

#define TAP_FILENAME_LENGTH 10

typedef struct TapBlockHeader {
    u8 type;
    char filename[TAP_FILENAME_LENGTH];
    u16 data_length;

    union {
        u16 param1;
        u16 address;
        u16 start_line_no;
    };

    u16 param2; // CODE: unused (0x8000) PROGRAM: autostart line
    u8 checksum;
} TapBlockHeader;

typedef enum {
    TAP_TYPE_PROGRAM = 0,
    TAP_TYPE_NUM_ARRAY = 1,
    TAP_TYPE_CHAR_ARRAY = 2,
    TAP_TYPE_BYTES_CODE = 3,

    TAP_TYPE_INVALID = 0xFF,
} TapBlockType;

bool tap_read_block_header(RDReader* r, TapBlockHeader* v);
const char* tap_trim_filename(const char* filename, char* out, usize outlen);
