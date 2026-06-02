#include "pages.h"

#define LE_PAGE_ENTRY_SIZE_LX sizeof(u64)
#define LE_PAGE_ENTRY_SIZE_LE sizeof(u32)

static_assert(sizeof(LEPageLE) == LE_PAGE_ENTRY_SIZE_LE,
              "LE Executable page size mismatch");

static_assert(sizeof(LEPageLX) == LE_PAGE_ENTRY_SIZE_LX,
              "LX Executable page size mismatch");

bool le_read_page(RDReader* r, const LEFormat* le, LEPage* v) {
    if(le->is_lx) {
        rd_reader_read_le32(r, &v->lx.page_offset);
        rd_reader_read_le16(r, &v->lx.data_size);
        rd_reader_read_le16(r, &v->lx.flags);
    }
    else {
        rd_reader_read(r, &v->le.page_num, sizeof(v->le.page_num));
        rd_reader_read_byte(r, &v->le.flags);
    }

    return !rd_reader_has_error(r);
}

u32 le_get_page_entry_size(const LEFormat* le) {
    return le->is_lx ? LE_PAGE_ENTRY_SIZE_LX : LE_PAGE_ENTRY_SIZE_LE;
}
