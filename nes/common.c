#include "common.h"

void nes_map_memory(RDContext* ctx) {
    rd_map_segment(ctx, "RAM", 0x0000, 0x0800, RD_SP_RW);

    rd_map_segment(ctx, "PPUREG", 0x2000, 0x2008, RD_SP_RW);
    rd_library_name(ctx, 0x2000, "PPUCTRL");
    rd_library_name(ctx, 0x2001, "PPUMASK");
    rd_library_name(ctx, 0x2002, "PPUSTATUS");
    rd_library_name(ctx, 0x2003, "OAMADDR");
    rd_library_name(ctx, 0x2004, "OAMDATA");
    rd_library_name(ctx, 0x2005, "PPUSCROLL");
    rd_library_name(ctx, 0x2006, "PPUADDR");
    rd_library_name(ctx, 0x2007, "PPUDATA");

    rd_map_segment(ctx, "APUREG", 0x4000, 0x4018, RD_SP_RW);
    rd_library_name(ctx, 0x4014, "OAMDMA");
    rd_library_name(ctx, 0x4016, "JOY1");
    rd_library_name(ctx, 0x4017, "JOY2");
}
