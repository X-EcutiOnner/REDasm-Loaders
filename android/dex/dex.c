#include "dex.h"
#include "dex/classes.h"
#include "dex/format.h"
#include "dex/map.h"
#include "dex/strings.h"
#include <inttypes.h>

static void _dex_type_table(RDContext* ctx, u32 off, u32 size,
                            const char* tname) {
    if(!off && !size) return; // absent section, legal

    if(!off || !size) {
        RD_LOG_WARN("'%s' has off=%" PRIu32 " size=%" PRIu32
                    " (must be both zero or both non-zero)",
                    tname, off, size);
        return;
    }

    rd_library_type(ctx, off, tname, size, RD_TYPE_NONE);
}

static void _dex_name_methods(RDContext* ctx, RDReader* r, DEXFormat* dex) {
    for(u32 i = 0; i < dex->header.method_ids_size; i++) {
        const char* n = dex_method_name(r, dex, i);

        if(!n) {
            RD_LOG_WARN("cannot build a name for method %" PRIu32, i);
            continue;
        }

        u64 addr = dex->header.method_ids_off + ((u64)i * DEX_METHOD_ID_SIZE);
        rd_auto_name(ctx, addr, n);
    }
}

static void _dex_name_types(RDContext* ctx, RDReader* r, DEXFormat* dex) {
    for(u32 i = 0; i < dex->header.type_ids_size; i++) {
        const char* n = dex_type_name(r, dex, i);

        if(!n) {
            RD_LOG_WARN("cannot build a name for type %" PRIu32, i);
            continue;
        }

        u64 addr = dex->header.type_ids_off + ((u64)i * DEX_TYPE_ID_SIZE);
        rd_auto_name(ctx, addr, n);
    }
}

static bool dex_parse(RDLoader* ldr, const RDLoaderRequest* req) {
    DEXFormat* dex = (DEXFormat*)ldr;

    dex->version = dex_read_header(req->input, &dex->header);
    if(!dex->version) return false;

    return dex_validate_header(req->input, dex);
}

static bool dex_load(RDLoader* ldr, RDContext* ctx) {
    DEXFormat* dex = (DEXFormat*)ldr;
    RDReader* r = rd_get_input_reader(ctx);

    if(!dex_validate_checksum(r, dex))
        RD_LOG_WARN("DEX checksum mismatch (file may be packed or patched)");

    if(!dex_validate_signature(r, dex))
        RD_LOG_WARN("DEX signature mismatch (file may be packed or patched)");

    DEXMap map;
    if(!dex_read_map(r, dex, &map)) return false;
    if(!dex_map_segments(ctx, dex, &map)) return false;

    rd_kb_load(ctx, "os/android/dex");
    rd_library_type(ctx, 0, "DEX_HEADER", 0, RD_TYPE_NONE);

    // clang-format off
    _dex_type_table(ctx, dex->header.string_ids_off, dex->header.string_ids_size, "DEX_STRING_ID");
    _dex_type_table(ctx, dex->header.type_ids_off, dex->header.type_ids_size, "DEX_TYPE_ID");
    _dex_type_table(ctx, dex->header.proto_ids_off, dex->header.proto_ids_size, "DEX_PROTO_ID");
    _dex_type_table(ctx, dex->header.field_ids_off, dex->header.field_ids_size, "DEX_FIELD_ID");
    _dex_type_table(ctx, dex->header.method_ids_off, dex->header.method_ids_size, "DEX_METHOD_ID");
    _dex_type_table(ctx, dex->header.class_defs_off, dex->header.class_defs_size, "DEX_CLASS_DEF");
    // clang-format on

    r = rd_get_reader(ctx);
    dex_walk_classes(ctx, r, dex);
    _dex_name_methods(ctx, r, dex);
    _dex_name_types(ctx, r, dex);

    return true;
}

static RDLoader* dex_create(const RDLoaderPlugin* plugin) {
    RD_UNUSED(plugin);

    DEXFormat* dex = (DEXFormat*)rd_alloc0(1, sizeof(DEXFormat));
    dex->raw_buf = rd_scratch_create();
    dex->string_buf = rd_scratch_create();
    dex->name_buf = rd_scratch_create();
    return (RDLoader*)dex;
}

static void dex_destroy(RDLoader* ldr) {
    DEXFormat* dex = (DEXFormat*)ldr;
    rd_scratch_destroy(dex->name_buf);
    rd_scratch_destroy(dex->string_buf);
    rd_scratch_destroy(dex->raw_buf);
    rd_free(dex);
}

static const char* dex_get_name(const RDLoader* ldr) {
    const DEXFormat* dex = (const DEXFormat*)ldr;
    return rd_format("Android DEX Version %03" PRIu32, dex->version);
}

static const char* dex_get_processor(const RDLoader* ldr) {
    RD_UNUSED(ldr);
    return "android_dalvik";
}

const RDLoaderPlugin DEX = {
    .id = "android_dex",
    .create = dex_create,
    .destroy = dex_destroy,
    .parse = dex_parse,
    .load = dex_load,
    .get_name = dex_get_name,
    .get_processor = dex_get_processor,
};
