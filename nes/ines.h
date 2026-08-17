#pragma once

#include <redasm/redasm.h>

typedef struct INesHeader {
    u8 prg_units; // 16KB units
    u8 chr_units; // 8KB units
    u8 flags6;
    u8 flags7;
    u16 mapper;
    bool has_trainer;
    bool four_screen;
    bool battery;

    // Resolved file offsets/sizes, computed once here so every mapper
    // loader gets them for free instead of re-deriving trainer/offset math.
    u32 prg_offset;
    u32 prg_size;
    u32 chr_offset;
    u32 chr_size;
} INesHeader;

bool ines_parse_header(RDReader* r, INesHeader* out);
