#pragma once

#include <redasm/redasm.h>

#define SNA_48K_SNAPSHOT 49179
#define SNA_128K_SNAPSHOT 131103
#define SNA_128K_EXT_SNAPSHOT 147487

typedef struct SNAHeader {
    u8 i;
    u16 hl_, de_, bc_, af_;
    u16 hl, de, bc, ix, iy;
    u8 int_flag;
    u8 r;
    u16 af, sp;
    u8 int_mode;
    u8 border_color;
} SNAHeader;

typedef struct SNAFormat {
    SNAHeader header;
    usize length;
} SNAFormat;

bool sna_read_header(RDReader* r, SNAHeader* v);
void sna_init_registers(RDContext* ctx, const SNAFormat* sna);
bool sna_load_48k(RDContext* ctx, RDReader* r, const SNAFormat* sna);
