#include "rich.h"
#include "pe/format.h"

#define PE_RICH_MARKER 0x68636952 // "Rich"
#define PE_RICH_DANS 0x536E6144   // "DanS"

typedef struct PERichParse {
    u32* buffer;
    usize length;
    u32 key;
    u32 rich_idx;
    u32 dans_idx;
} PERichParse;

static u32 _pe_calculate_checksum(PERichParse* p, PEFormat* pe) {
    const u8* start = (u8*)p->buffer;
    const u8* end = (u8*)&p->buffer[p->dans_idx];
    u32 chksum = p->dans_idx * sizeof(u32), i = 0;

    for(const u8* p = start; p < end; p++, i++)
        chksum += rd_rol32(*p, i);

    for(i = 0; i < pe->rich_header.length; i++) {
        chksum += rd_rol32(pe->rich_header.data[i].comp_id,
                           pe->rich_header.data[i].count);
    }

    return chksum;
}

static bool _pe_read_richheader(RDContext* ctx, const PEFormat* pe,
                                PERichParse* p) {
    RDReader* r = rd_get_input_reader(ctx);
    usize n_bytes = pe->dosheader.e_lfanew - sizeof(u32);
    if(n_bytes >= rd_reader_get_length(r)) return false;

    usize n = n_bytes / sizeof(u32);

    (*p) = (PERichParse){
        .buffer = (u32*)rd_alloc(n_bytes),
        .length = n,
        .rich_idx = n,
        .dans_idx = n,
    };

    rd_reader_seek(r, 0);

    if(!rd_reader_read(r, p->buffer, n_bytes)) return false;

    for(usize i = 0; i < n; i++) {
        if(p->buffer[i] == PE_RICH_MARKER) {
            p->rich_idx = i;
            break;
        }
    }

    if(p->rich_idx == n || p->rich_idx + 1 >= n) return false;

    p->key = p->buffer[p->rich_idx + 1];

    for(usize i = 0; i < p->rich_idx; i++) {
        if((p->buffer[i] ^ p->key) == PE_RICH_DANS) {
            p->dans_idx = i;
            break;
        }
    }

    if(p->dans_idx == n) return false;

    p->buffer[0xf] = 0; // zero out e_lfanew for checksum calculation
    return true;
}

void pe_parse_richheader(RDContext* ctx, PEFormat* pe) {
    PERichParse s = {0};

    if(!_pe_read_richheader(ctx, pe, &s)) {
        pe->rich_header.status =
            (s.length == s.rich_idx || s.dans_idx == s.length)
                ? PE_RICH_ABSENT
                : PE_RICH_CORRUPTED;

        goto cleanup;
    }

    usize start = s.dans_idx + 1 + 3;
    usize rec_count = (s.rich_idx - start) / 2;

    pe->rich_header.data =
        rec_count ? rd_alloc(rec_count * sizeof(PERichRecord)) : NULL;
    pe->rich_header.length = rec_count;

    for(usize i = 0; i < rec_count; i++) {
        usize pos = start + (i * 2);
        pe->rich_header.data[i].comp_id = s.buffer[pos] ^ s.key;
        pe->rich_header.data[i].count = s.buffer[pos + 1] ^ s.key;

        rd_log(RD_LOG_INFO, "PE_RICH", "(%08x, %08x)",
               pe->rich_header.data[i].comp_id, pe->rich_header.data[i].count);
    }

    u32 computed = _pe_calculate_checksum(&s, pe);
    pe->rich_header.status =
        (computed == s.key) ? PE_RICH_OK : PE_RICH_CORRUPTED;

    pe->rich_header.checksum = s.key;

cleanup:
    rd_free(s.buffer);
}
