#include "map.h"
#include <inttypes.h>

typedef struct DEXMapTypeInfo {
    u16 type;
    const char* name;
    u32 perm;
} DEXMapTypeInfo;

/*
 * Everything is read-only except code_item:
 * DEX has no writable image and no BSS, since every section is backed by file
 * bytes.
 */
static const DEXMapTypeInfo MAP_TYPES[] = {
    {DEX_TYPE_HEADER_ITEM, "HEADER", RD_SP_R},
    {DEX_TYPE_STRING_ID_ITEM, "STR_IDS", RD_SP_R},
    {DEX_TYPE_TYPE_ID_ITEM, "TYPE_IDS", RD_SP_R},
    {DEX_TYPE_PROTO_ID_ITEM, "PROTO_IDS", RD_SP_R},
    {DEX_TYPE_FIELD_ID_ITEM, "FIELD_IDS", RD_SP_R},
    {DEX_TYPE_METHOD_ID_ITEM, "METHOD_IDS", RD_SP_R},
    {DEX_TYPE_CLASS_DEF_ITEM, "CLASS_DEFS", RD_SP_R},
    {DEX_TYPE_CALL_SITE_ID_ITEM, "CALL_SITE_IDS", RD_SP_R},
    {DEX_TYPE_METHOD_HANDLE_ITEM, "METHOD_HANDLES", RD_SP_R},
    {DEX_TYPE_MAP_LIST, "MAP", RD_SP_R},
    {DEX_TYPE_TYPE_LIST, "TYPE_LISTS", RD_SP_R},
    {DEX_TYPE_ANNOTATION_SET_REF_LIST, "ANN_SET_REFS", RD_SP_R},
    {DEX_TYPE_ANNOTATION_SET_ITEM, "ANN_SETS", RD_SP_R},
    {DEX_TYPE_CLASS_DATA_ITEM, "CLASS_DATA", RD_SP_R},
    {DEX_TYPE_CODE_ITEM, "CODE", RD_SP_RX},
    {DEX_TYPE_STRING_DATA_ITEM, "STRINGS", RD_SP_R},
    {DEX_TYPE_DEBUG_INFO_ITEM, "DEBUG_INFO", RD_SP_R},
    {DEX_TYPE_ANNOTATION_ITEM, "ANNOTATIONS", RD_SP_R},
    {DEX_TYPE_ENCODED_ARRAY_ITEM, "ENCODED_ARRAYS", RD_SP_R},
    {DEX_TYPE_ANNOTATIONS_DIRECTORY_ITEM, "ANN_DIRS", RD_SP_R},
    {DEX_TYPE_HIDDENAPI_CLASS_DATA_ITEM, "HIDDENAPI", RD_SP_R},
};

static const DEXMapTypeInfo* _dex_map_type_info(u16 type) {
    for(usize i = 0; i < sizeof(MAP_TYPES) / sizeof(MAP_TYPES[0]); i++) {
        if(MAP_TYPES[i].type == type) return &MAP_TYPES[i];
    }

    return NULL;
}

const DEXMapItem* dex_map_find(const DEXMap* map, u16 type) {
    for(u32 i = 0; i < map->count; i++) {
        if(map->items[i].type == type) return &map->items[i];
    }

    return NULL;
}

bool dex_read_map(RDReader* r, const DEXFormat* dex, DEXMap* map) {
    map->count = 0;

    if(!dex->header.map_off) {
        RD_LOG_FAIL("no map_list (map_off is zero)");
        return false;
    }

    rd_reader_save(r);
    rd_reader_seek(r, dex->header.map_off);

    u32 count = 0;
    if(!rd_reader_read_le32(r, &count)) goto fail;

    if(!count) {
        RD_LOG_FAIL("map_list is empty");
        goto fail;
    }

    if(count > DEX_MAX_MAP_ITEMS) {
        RD_LOG_FAIL("map_list has %" PRIu32 " entries (max %d)", count,
                    DEX_MAX_MAP_ITEMS);
        goto fail;
    }

    // the table itself must fit inside the file
    u64 tablesize = (u64)count * DEX_MAP_ITEM_SIZE;

    if((u64)dex->header.map_off + sizeof(u32) + tablesize >
       dex->header.file_size) {
        RD_LOG_FAIL("map_list extends past file_size");
        goto fail;
    }

    for(u32 i = 0; i < count; i++) {
        DEXMapItem* it = &map->items[i];

        rd_reader_read_le16(r, &it->type);
        rd_reader_read_le16(r, &it->unused);
        rd_reader_read_le32(r, &it->size);
        rd_reader_read_le32(r, &it->offset);

        if(rd_reader_has_error(r)) {
            RD_LOG_FAIL("truncated map_list at entry %" PRIu32, i);
            goto fail;
        }

        if(it->offset >= dex->header.file_size) {
            RD_LOG_FAIL("map entry %" PRIu32 " (type %04" PRIx16
                        ") offset %" PRIu32 " is out of bounds",
                        i, it->type, it->offset);
            goto fail;
        }

        /*
         * Extents are derived from consecutive offsets, so strictly
         * ascending order is a hard requirement, not a nicety.
         * Out-of-order entries would produce overlapping or negative-length
         * segments. The spec requires sorting by offset; enforce it rather than
         * trust.
         */
        if(i && it->offset <= map->items[i - 1].offset) {
            RD_LOG_FAIL("map_list is not sorted by offset at entry %" PRIu32,
                        i);
            goto fail;
        }

        // each type may appear at most once
        for(u32 j = 0; j < i; j++) {
            if(map->items[j].type == it->type) {
                RD_LOG_FAIL("duplicate map entry type %04" PRIx16, it->type);
                goto fail;
            }
        }

        map->count++;
    }

    if(map->items[0].offset) {
        RD_LOG_WARN("first map entry starts at %" PRIu32
                    ", bytes before it will be unmapped",
                    map->items[0].offset);
    }

    rd_reader_restore(r);
    return true;

fail:
    map->count = 0;
    rd_reader_restore(r);
    return false;
}

bool dex_map_segments(RDContext* ctx, const DEXFormat* dex, const DEXMap* map) {
    if(!map->count) return false;

    bool ok = false;

    for(u32 i = 0; i < map->count; i++) {
        const DEXMapItem* it = &map->items[i];

        /*
         * Item sizes are counts, not byte lengths, so an entry's extent runs
         * to the next entry's offset (and the last runs to file_size).
         * Any inter-section alignment padding is absorbed into the preceding
         * segment, which leaves the address space gap-free.
         */
        u32 end = (i + 1 < map->count) ? map->items[i + 1].offset
                                       : dex->header.file_size;

        if(end <= it->offset) continue; // sortedness was checked; be safe

        u32 size = end - it->offset;
        const DEXMapTypeInfo* info = _dex_map_type_info(it->type);
        const char* name;
        u32 perm;

        if(info) {
            name = info->name;
            perm = info->perm;
        }
        else {
            /*
             * Unknown type from a newer DEX revision.
             * Map it anyway: dropping it would leave an address-space hole and
             * make its bytes unreachable, which is worse than an oddly-named
             * segment.
             */
            name = rd_format("MAP_%04" PRIX16, it->type);
            perm = RD_SP_R;
            RD_LOG_WARN("unknown map type %04" PRIx16 " @ %" PRIu32, it->type,
                        it->offset);
        }

        // addresses are file offsets: the whole DEX is mapped 1:1, so the
        // processor can resolve table indices by arithmetic alone
        if(!rd_map_segment_n(ctx, name, it->offset, size, perm)) {
            RD_LOG_FAIL("cannot map segment '%s' @ %" PRIu32, name, it->offset);
            continue;
        }

        // DEX has no BSS; every section is backed by file bytes
        rd_map_input_n(ctx, it->offset, it->offset, size);
        ok = true;
    }

    return ok;
}
