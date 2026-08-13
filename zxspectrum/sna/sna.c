#include "sna.h"
#include "sna_format.h"

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
    if(!sna_read_header(r, &sna->header)) return false;

    sna_init_registers(ctx, sna);

    switch(sna->length) {
        case SNA_48K_SNAPSHOT: return sna_load_48k(ctx, r, sna);
        // case SNA_128K_SNAPSHOT: break;
        // case SNA_128K_EXT_SNAPSHOT: break;
        default: break;
    }

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
