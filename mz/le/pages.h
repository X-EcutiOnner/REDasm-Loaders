#pragma once

#include "le/format.h"

#define LE_PAGE_ALIGN 0x1000U

#define LE_PAGE_PRELOAD 0
#define LE_PAGE_ITERATED 1
#define LE_PAGE_INVALID 2
#define LE_PAGE_ZEROED 3
#define LE_PAGE_RANGE 4

static inline u32 le_get_page_size(const LEFormat* le) {
    return le->header.page_size ? le->header.page_size : LE_PAGE_ALIGN;
}

bool le_read_page(RDReader* r, const LEFormat* le, LEPage* v);
u32 le_get_page_entry_size(const LEFormat* le);
