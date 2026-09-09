#include "mutf8.h"

#define DEX_REPLACEMENT_CHAR 0xFFFD

// encode one code point as UTF-8
static void _dex_str_put(RDScratchBuffer* buf, u32 cp) {
    if(cp < 0x80) {
        rd_scratch_push(buf, (char)cp);
    }
    else if(cp < 0x800) {
        rd_scratch_push(buf, (char)(0xC0 | (cp >> 6)));
        rd_scratch_push(buf, (char)(0x80 | (cp & 0x3F)));
    }
    else if(cp < 0x10000) {
        rd_scratch_push(buf, (char)(0xE0 | (cp >> 12)));
        rd_scratch_push(buf, (char)(0x80 | ((cp >> 6) & 0x3F)));
        rd_scratch_push(buf, (char)(0x80 | (cp & 0x3F)));
    }
    else {
        rd_scratch_push(buf, (char)(0xF0 | (cp >> 18)));
        rd_scratch_push(buf, (char)(0x80 | ((cp >> 12) & 0x3F)));
        rd_scratch_push(buf, (char)(0x80 | ((cp >> 6) & 0x3F)));
        rd_scratch_push(buf, (char)(0x80 | (cp & 0x3F)));
    }
}

static usize _dex_mutf8_decode(const u8* p, usize avail, u32* cp) {
    if(!avail) return 0;

    u8 b0 = p[0];

    if(b0 < 0x80) { // 1 byte: 0x01-0x7F (0x00 never appears)
        *cp = b0;
        return 1;
    }

    if((b0 & 0xE0) == 0xC0) { // 2 bytes
        if(avail < 2 || (p[1] & 0xC0) != 0x80) return 0;
        *cp = (u32)((b0 & 0x1F) << 6) | (u32)(p[1] & 0x3F);
        return 2;
    }

    if((b0 & 0xF0) == 0xE0) { // 3 bytes
        if(avail < 3 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80)
            return 0;

        *cp = (u32)((b0 & 0x0F) << 12) | (u32)((p[1] & 0x3F) << 6) |
              (u32)(p[2] & 0x3F);
        return 3;
    }

    // MUTF-8 has no four-byte sequences, and 0x80-0xBF / 0xF8+ are invalid
    return 0;
}

bool dex_mutf8_to_utf8(const RDScratchBuffer* raw, RDScratchBuffer* str) {
    rd_scratch_clear(str);

    usize i = 0, n = rd_scratch_length(raw);
    const u8* src_raw = (const u8*)rd_scratch_data(raw);

    while(i < n) {
        u32 cp;
        usize used = _dex_mutf8_decode(&src_raw[i], n - i, &cp);
        if(!used) goto fail;
        i += used;

        // C0 80: an embedded U+0000, which a C string cannot carry
        if(!cp) cp = DEX_REPLACEMENT_CHAR;

        // high surrogate: look for its partner and recombine
        if(cp >= 0xD800 && cp <= 0xDBFF) {
            u32 lo;
            usize used2 = _dex_mutf8_decode(&src_raw[i], n - i, &lo);

            if(used2 && lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                i += used2;
            }
            else
                cp = DEX_REPLACEMENT_CHAR; // unpaired high surrogate
        }
        else if(cp >= 0xDC00 && cp <= 0xDFFF)
            cp = DEX_REPLACEMENT_CHAR; // orphaned low surrogate

        _dex_str_put(str, cp);
    }

    rd_scratch_push(str, '\0');
    return true;

fail:
    rd_scratch_clear(str);
    return false;
}
