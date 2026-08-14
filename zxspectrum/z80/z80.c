#include "z80.h"
#include "z80/z80_format.h"

static bool _z80_parse(RDLoader* ldr, const RDLoaderRequest* req) {
    if(rd_stricmp(req->ext, "z80") != 0) return false;

    Z80Format* z80 = (Z80Format*)ldr;
    if(!z80_read_header_base(req->input, &z80->hdr_base)) return false;

    u8 int_mode = z80->hdr_base.im_flags & 0x03;
    if(int_mode > 2) return false;

    if(z80->hdr_base.pc != 0) {
        z80->version = 1;
    }
    else {
        if(!z80_read_header_ext(req->input, &z80->hdr_ext)) return false;

        if(z80->hdr_ext.hw_mode > 1) {
            RD_LOG_WARN(
                "z80: hardware mode %d not supported yet (48k-class only)",
                z80->hdr_ext.hw_mode);
            return false;
        }

        if(z80->hdr_ext.length == Z80_HEADER_LEN_V2)
            z80->version = 2;
        else if(z80->hdr_ext.length == Z80_HEADER_LEN_V3 ||
                z80->hdr_ext.length == Z80_HEADER_LEN_V3_EXT)
            z80->version = 3;
        else
            return false;
    }

    z80->body_start = rd_reader_tell(req->input);
    return true;
}

static bool _z80_load(RDLoader* ldr, RDContext* ctx) {
    static const u8 STRING_TERMS[] = {0xFF, 0x00};
    rd_set_string_terminators(ctx, STRING_TERMS, rd_count_of(STRING_TERMS));

    Z80Format* z80 = (Z80Format*)ldr;
    RDReader* r = rd_get_input_reader(ctx);

    switch(z80->version) {
        case 1: return z80_load_v1(ctx, r, z80);

        case 2:
        case 3: return z80_load_v2_v3(ctx, r, z80);

        default: break;
    }

    RD_LOG_FAIL("unsupported version %d", z80->version);
    return false;
}

static RDLoader* _z80_create(const struct RDLoaderPlugin* ldr) {
    RD_UNUSED(ldr);
    return rd_alloc0(1, sizeof(Z80Format));
}

static void _z80_destroy(RDLoader* ldr) { rd_free(ldr); }

static const char* _z80_get_processor(const RDLoader* ldr) {
    RD_UNUSED(ldr);
    return "z80";
}

static const char* _z80_get_name(const RDLoader* ldr) {
    const Z80Format* z80 = (const Z80Format*)ldr;
    return rd_format("ZX Spectrum Z80 v%d snapshot", z80->version);
}

const RDLoaderPlugin Z80_LOADER = {
    .level = RD_API_LEVEL,
    .id = "zx_spectrum_z80",
    .create = _z80_create,
    .destroy = _z80_destroy,
    .parse = _z80_parse,
    .load = _z80_load,
    .get_processor = _z80_get_processor,
    .get_name = _z80_get_name,
};
