#pragma once

#include "constants.h"
#include "format.h"

typedef struct DEXMapItem {
    u16 type;
    u16 unused;
    u32 size;   // item COUNT, not bytes
    u32 offset; // from start of file
} DEXMapItem;

typedef struct DEXMap {
    DEXMapItem items[DEX_MAX_MAP_ITEMS];
    u32 count;
} DEXMap;

bool dex_read_map(RDReader* r, const DEXFormat* dex, DEXMap* map);
bool dex_map_segments(RDContext* ctx, const DEXFormat* dex, const DEXMap* map);
const DEXMapItem* dex_map_find(const DEXMap* map, u16 type);
