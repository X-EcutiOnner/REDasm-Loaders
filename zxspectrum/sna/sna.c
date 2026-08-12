#include "sna.h"

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

static bool _sna_read_header(RDReader* r, SNAHeader* v) {
    rd_reader_read_byte(r, &v->i);
    rd_reader_read_le16(r, &v->hl_);
    rd_reader_read_le16(r, &v->de_);
    rd_reader_read_le16(r, &v->bc_);
    rd_reader_read_le16(r, &v->af_);
    rd_reader_read_le16(r, &v->hl);
    rd_reader_read_le16(r, &v->de);
    rd_reader_read_le16(r, &v->bc);
    rd_reader_read_le16(r, &v->ix);
    rd_reader_read_le16(r, &v->iy);
    rd_reader_read_byte(r, &v->int_flag);
    rd_reader_read_byte(r, &v->r);
    rd_reader_read_le16(r, &v->af);
    rd_reader_read_le16(r, &v->sp);
    rd_reader_read_byte(r, &v->int_mode);
    rd_reader_read_byte(r, &v->border_color);
    return !rd_reader_has_error(r);
}

static bool _sna_parse(RDLoader* ldr, const RDLoaderRequest* req) {
    if(rd_stricmp(req->ext, "sna") != 0) return false;

    SNAFormat* sna = (SNAFormat*)ldr;
    usize len = rd_reader_get_length(req->input);

    switch(len) {
        case SNA_48K_SNAPSHOT:
        case SNA_128K_SNAPSHOT:
        case SNA_128K_EXT_SNAPSHOT: sna->length = len; return true;

        default: break;
    }

    return false;
}

static bool _sna_load(RDLoader* ldr, RDContext* ctx) {
    static const u8 STRING_TERMS[] = {0xFF};
    rd_set_string_terminators(ctx, STRING_TERMS, rd_count_of(STRING_TERMS));

    SNAFormat* sna = (SNAFormat*)ldr;
    RDReader* r = rd_get_input_reader(ctx);
    if(!_sna_read_header(r, &sna->header)) return false;

    // initialize registers
    rd_set_regval(ctx, "i", sna->header.i);
    rd_set_regval(ctx, "hl'", sna->header.hl_);
    rd_set_regval(ctx, "de'", sna->header.de_);
    rd_set_regval(ctx, "bc'", sna->header.bc_);
    rd_set_regval(ctx, "af'", sna->header.af_);
    rd_set_regval(ctx, "hl", sna->header.hl);
    rd_set_regval(ctx, "de", sna->header.de);
    rd_set_regval(ctx, "bc", sna->header.bc);
    rd_set_regval(ctx, "iy", sna->header.iy);
    rd_set_regval(ctx, "ix", sna->header.ix);
    rd_set_regval(ctx, "r", sna->header.r);
    rd_set_regval(ctx, "af", sna->header.af);
    rd_set_regval(ctx, "sp", sna->header.sp);

    usize ram_dump_len = sna->length - rd_reader_tell(r);

    // map whole 64k Z80 address space
    rd_map_segment_n(ctx, "RAM", 0, 0x10000, RD_SP_RWX);
    rd_map_input_n(ctx, rd_reader_tell(r), 0x4000, ram_dump_len);

    u16 ep;
    if(rd_read_le16(ctx, sna->header.sp, &ep))
        rd_set_entry_point(ctx, ep, NULL);

    return true;
}

static RDLoader* _sna_create(const struct RDLoaderPlugin* ldr) {
    RD_UNUSED(ldr);
    return rd_alloc0(1, sizeof(SNAFormat));
}

static void _sna_destroy(RDLoader* ldr) { rd_free(ldr); }

static const char* _sna_get_processor(const RDLoader* ldr) {
    RD_UNUSED(ldr);
    return "z80";
}

static const char* _sna_get_name(const RDLoader* ldr) {
    const SNAFormat* sna = (const SNAFormat*)ldr;

    switch(sna->length) {
        case SNA_48K_SNAPSHOT: return "ZX Spectrum 48K snapshot";
        case SNA_128K_SNAPSHOT: return "ZX Spectrum 128K snapshot";

        case SNA_128K_EXT_SNAPSHOT:
            return "ZX Spectrum 128K snapshot (extended)";

        default: break;
    }

    return "ZX Spectrum Snapshot";
}

const RDLoaderPlugin SNA_LOADER = {
    .level = RD_API_LEVEL,
    .id = "zx_spectrum_sna",
    .create = _sna_create,
    .destroy = _sna_destroy,
    .parse = _sna_parse,
    .load = _sna_load,
    .get_processor = _sna_get_processor,
    .get_name = _sna_get_name,
};
