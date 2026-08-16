#include "basic.h"
#include <ctype.h>

#define TOK_NUMBER_INT 0x0E
#define TOK_NUMBER_FLOAT 0x7E

static const char* const ZX_BASIC_TOKEN_NAMES[] = {
    [0xA3] = "SPECTRUM", [0xA4] = "PLAY",    [0xA5] = "RND",
    [0xA6] = "INKEY$",   [0xA7] = "PI",      [0xA8] = "FN",
    [0xA9] = "POINT",    [0xAA] = "SCREEN$", [0xAB] = "ATTR",
    [0xAC] = "AT",       [0xAD] = "TAB",     [0xAE] = "VAL$",
    [0xAF] = "CODE",     [0xB0] = "VAL",     [0xB1] = "LEN",
    [0xB2] = "SIN",      [0xB3] = "COS",     [0xB4] = "TAN",
    [0xB5] = "ASN",      [0xB6] = "ACS",     [0xB7] = "ATN",
    [0xB8] = "LN",       [0xB9] = "EXP",     [0xBA] = "INT",
    [0xBB] = "SQR",      [0xBC] = "SGN",     [0xBD] = "ABS",
    [0xBE] = "PEEK",     [0xBF] = "IN",      [0xC0] = "USR",
    [0xC1] = "STR$",     [0xC2] = "CHR$",    [0xC3] = "NOT",
    [0xC4] = "BIN",      [0xC5] = "OR",      [0xC6] = "AND",
    [0xC7] = "<=",       [0xC8] = ">=",      [0xC9] = "<>",
    [0xCA] = "LINE",     [0xCB] = "THEN",    [0xCC] = "TO",
    [0xCD] = "STEP",     [0xCE] = "DEF FN",  [0xCF] = "CAT",
    [0xD0] = "FORMAT",   [0xD1] = "MOVE",    [0xD2] = "ERASE",
    [0xD3] = "OPEN #",   [0xD4] = "CLOSE #", [0xD5] = "MERGE",
    [0xD6] = "VERIFY",   [0xD7] = "BEEP",    [0xD8] = "CIRCLE",
    [0xD9] = "INK",      [0xDA] = "PAPER",   [0xDB] = "FLASH",
    [0xDC] = "BRIGHT",   [0xDD] = "INVERSE", [0xDE] = "OVER",
    [0xDF] = "OUT",      [0xE0] = "LPRINT",  [0xE1] = "LLIST",
    [0xE2] = "STOP",     [0xE3] = "READ",    [0xE4] = "DATA",
    [0xE5] = "RESTORE",  [0xE6] = "NEW",     [0xE7] = "BORDER",
    [0xE8] = "CONTINUE", [0xE9] = "DIM",     [0xEA] = "REM",
    [0xEB] = "FOR",      [0xEC] = "GO TO",   [0xED] = "GO SUB",
    [0xEE] = "INPUT",    [0xEF] = "LOAD",    [0xF0] = "LIST",
    [0xF1] = "LET",      [0xF2] = "PAUSE",   [0xF3] = "NEXT",
    [0xF4] = "POKE",     [0xF5] = "PRINT",   [0xF6] = "PLOT",
    [0xF7] = "RUN",      [0xF8] = "SAVE",    [0xF9] = "RANDOMIZE",
    [0xFA] = "IF",       [0xFB] = "CLS",     [0xFC] = "DRAW",
    [0xFD] = "CLEAR",    [0xFE] = "RETURN",  [0xFF] = "COPY",
};

const char* zx_basic_emit_line(const u8* data, usize len, RDScratchBuffer* sb) {
    usize i = 0;

    rd_scratch_clear(sb);

    while(i < len) {
        u8 b = data[i];

        if(b == TOK_NUMBER_INT || b == TOK_NUMBER_FLOAT) {
            i += 6; // marker + 5-byte payload, not display text
            continue;
        }

        if(b >= 0xA3 && ZX_BASIC_TOKEN_NAMES[b]) {
            if(!rd_scratch_is_empty(sb) && *rd_scratch_last(sb) != ' ')
                rd_scratch_putchar(sb, ' ');

            rd_scratch_puts(sb, ZX_BASIC_TOKEN_NAMES[b]);

            i++;
            continue;
        }

        rd_scratch_putchar(sb, isprint(b) ? (char)b : '.');
        i++;
    }

    return rd_scratch_data(sb);
}

void zx_basic_attach_lines(RDContext* ctx, RDAddress address,
                           RDScratchBuffer* sb) {
    const char* data = rd_scratch_data(sb);
    usize len = rd_scratch_length(sb);
    usize i = 0;

    while(i + 4 <= len) {
        u16 line_num = ((u8)data[i] << 8) | (u8)data[i + 1]; // big-endian
        u16 line_len =
            (u8)data[i + 2] | ((u8)data[i + 3] << 8); // little-endian
        usize content_start = i + 4;

        if(content_start + line_len > len) break; // truncated, stop safely

        usize render_len = line_len;
        if(render_len > 0 && data[content_start + render_len - 1] == 0x0D)
            render_len--; // drop the trailing NEWLINE token from display

        RDScratchBuffer* linebuf = rd_scratch_create();
        rd_scratch_puts(linebuf, rd_to_dec(line_num));
        rd_scratch_puts(linebuf, " ");
        zx_basic_emit_line((const u8*)data + content_start, render_len,
                           linebuf);

        rd_add_comment_before(ctx, address, rd_scratch_data(linebuf));
        rd_scratch_destroy(linebuf);

        i = content_start + line_len;
    }
}
