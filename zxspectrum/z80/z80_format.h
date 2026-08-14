#pragma once

#include <redasm/redasm.h>

#define Z80_HEADER_LEN_V2 23
#define Z80_HEADER_LEN_V3 54
#define Z80_HEADER_LEN_V3_EXT 55

typedef struct Z80HeaderBase {
    u8 a;
    u8 f;
    u16 bc;
    u16 hl;
    u16 pc;
    u16 sp;
    u8 i;
    u8 r;
    u8 flags;
    u16 de;
    u16 bc_;
    u16 de_;
    u16 hl_;
    u8 a_;
    u8 f_;
    u16 iy;
    u16 ix;
    u8 iff1;
    u8 iff2;
    u8 im_flags;
} Z80HeaderBase;

typedef struct Z80HeaderExt {
    u16 length;
    u16 pc;
    u8 hw_mode;

    union {
        u8 state;
        u8 last_out;
    };

    u8 rom_paged;
    u8 flags;
    u8 last_out_fffd;
    u8 audio_regs[16];

    struct {
        u16 t_state_l;
        u8 t_state_h;
        u8 flag_byte_spec;
        u8 mgt_rom_paged;
        u8 multface_rom_paged;
        u8 is_rom_l;
        u8 is_rom_h;
        u8 joy_mapping[10];
        u8 kbd_mapping[10];
        u8 mgt_type;
        u8 disciple_button_state;
        u8 disciple_flags;
    } v3;

    union {
        u8 out_1ffd;
    } v3_ext;
} Z80HeaderExt;

typedef struct Z80Format {
    Z80HeaderBase hdr_base;
    Z80HeaderExt hdr_ext;
    usize body_start;
    int version;
} Z80Format;

void z80_init_registers(RDContext* ctx, const Z80Format* z80);
bool z80_read_header_base(RDReader* r, Z80HeaderBase* v);
bool z80_read_header_ext(RDReader* r, Z80HeaderExt* v);
bool z80_load_v1(RDContext* ctx, RDReader* r, Z80Format* z80);
bool z80_load_v2_v3(RDContext* ctx, RDReader* r, Z80Format* z80);
