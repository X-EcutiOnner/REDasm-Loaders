#include "ines.h"

#define INES_HEADER_SIZE 16
#define INES_TRAINER_SIZE 512
#define INES_PRG_UNIT 0x4000 // 16KB
#define INES_CHR_UNIT 0x2000 // 8KB

bool ines_parse_header(RDReader* r, INesHeader* out) {
    rd_reader_seek(r, 0);

    if(!rd_reader_expect_byte(r, 'N') || !rd_reader_expect_byte(r, 'E') ||
       !rd_reader_expect_byte(r, 'S') || !rd_reader_expect_byte(r, 0x1A))
        return false;

    u8 prg_units, chr_units, flags6, flags7;
    if(!rd_reader_read_byte(r, &prg_units)) return false;
    if(!rd_reader_read_byte(r, &chr_units)) return false;
    if(!rd_reader_read_byte(r, &flags6)) return false;
    if(!rd_reader_read_byte(r, &flags7)) return false;

    if(!prg_units)
        return false; // PRG-ROM is mandatory; CHR==0 just means CHR RAM

    *out = (INesHeader){
        .prg_units = prg_units,
        .chr_units = chr_units,
        .flags6 = flags6,
        .flags7 = flags7,
        .mapper = (u16)((flags7 & 0xF0) | (flags6 >> 4)),
        .has_trainer = (flags6 & 0x04) != 0,
        .four_screen = (flags6 & 0x08) != 0,
        .battery = (flags6 & 0x02) != 0,
    };

    rd_reader_seek(r, INES_HEADER_SIZE);

    out->prg_offset =
        (u32)rd_reader_tell(r) + (out->has_trainer ? INES_TRAINER_SIZE : 0);
    out->prg_size = (u32)out->prg_units * INES_PRG_UNIT;
    out->chr_offset = out->prg_offset + out->prg_size;
    out->chr_size = (u32)out->chr_units * INES_CHR_UNIT;

    // Header claims more data than the file actually holds, reject rather than
    // let a later rd_map_input_n silently short-read garbage.
    usize need = out->chr_offset + out->chr_size;
    if(need > rd_reader_get_length(r)) return false;

    return true;
}
