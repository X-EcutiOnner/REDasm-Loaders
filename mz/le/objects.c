#include "objects.h"
#include "le/fixup.h"
#include "le/format.h"
#include "le/pages.h"
#include "le/vxd.h"
#include <inttypes.h>

#define LE_MEM_ALIGN 0x1000U

static RDAddress _le_unbound_base(const LEFormat* le) {
    if(le_is_vxd(le)) return 0xC0000000U; // VxD: system arena
    return 0x00010000U;                   // DOS4GW: private arena
}

static const char* _le_object_name(const LEObject* obj, u32 idx) {
    if(obj->name[0]) return rd_format("%.4s", obj->name);

    const char* prefix;
    if(obj->flags & LE_OBJ_RESOURCE)
        prefix = "RSRC";
    else if(obj->flags & LE_OBJ_EXECUTABLE)
        prefix = "CODE";
    else
        prefix = "DATA";

    return rd_format("%s%" PRIu32, prefix, idx);
}

static RDSegmentPerm _le_object_perm(const LEObject* obj) {
    if(obj->flags & LE_OBJ_HAS_INVALID) return RD_SP_NONE;

    u32 perm = RD_SP_NONE;
    if(obj->flags & LE_OBJ_READABLE) perm |= RD_SP_R;
    if(obj->flags & LE_OBJ_WRITEABLE) perm |= RD_SP_W;
    if(obj->flags & LE_OBJ_EXECUTABLE) perm |= RD_SP_X;
    return perm;
}

static bool _le_read_object(RDReader* r, LEObject* v) {
    rd_reader_read_le32(r, &v->size);
    rd_reader_read_le32(r, &v->addr);
    rd_reader_read_le32(r, &v->flags);
    rd_reader_read_le32(r, &v->mapidx);
    rd_reader_read_le32(r, &v->mapsize);
    rd_reader_read(r, &v->name, sizeof(v->name));

    return !rd_reader_has_error(r);
}

static bool _le_object_map_pages(RDReader* r, const LEFormat* le,
                                 const LEObject* obj, RDContext* ctx) {
    u32 page_sz = le_get_page_size(le);
    RDAddress address = obj->addr;

    rd_reader_seek(r, le->base + le->header.objmap_off +
                          ((obj->mapidx - 1) * le_get_page_entry_size(le)));

    for(u32 i = 0; i < obj->mapsize; i++, address += page_sz) {
        LEPage page;
        if(!le_read_page(r, le, &page)) return false;

        RDOffset offset;
        u32 size;
        u32 flags;

        if(le->is_lx) {
            const LEPageLX* lxp = &page.lx;
            offset = le->header.page_off +
                     (lxp->page_offset << le->header.page_shift);
            size = (u32)lxp->data_size;
            flags = lxp->flags;
        }
        else {
            const LEPageLE* lep = &page.le;
            flags = lep->flags;

            // page_num is a 24-bit big-endian 1-based index
            u32 page_num = ((u32)lep->page_num[0] << 16) |
                           ((u32)lep->page_num[1] << 8) | (u32)lep->page_num[2];

            if(!page_num) continue;

            offset = le->header.page_off + ((RDOffset)(page_num - 1) * page_sz);

            // size: page_size for all pages except the last one of the module
            // last_page field holds the actual byte count of the final page
            size = (page_num == le->header.num_pages && le->header.last_page)
                       ? le->header.last_page
                       : page_sz;
        }

        if(!offset || !size) continue;
        if(obj->size < size) size = obj->size; // map only required data

        switch(flags) {
            case LE_PAGE_PRELOAD: {
                rd_map_input_n(ctx, offset, address, size);

                if(page_sz > size) rd_fill(ctx, address + size, page_sz - size);

                break;
            }

            case LE_PAGE_INVALID:
            case LE_PAGE_ZEROED: rd_fill(ctx, address, size); break;

            default: {
                rd_log(RD_LOG_WARN, LE_PLUGIN_ID, "unhandled page type: %04x",
                       flags);
                break;
            }
        }

        rd_reader_save(r);
        le_fixup_apply(le, address, obj->mapidx - 1 + i, r, ctx);
        rd_reader_restore(r);
    }

    return true;
}

LEObjectSlice le_objectslice_create(const LEFormat* le) {
    u32 n = le->header.num_objects;
    if(!n) return (LEObjectSlice){0};

    return (LEObjectSlice){
        .data = rd_alloc0(n, sizeof(LEObject)),
        .length = n,
    };
}

void le_objectslice_destroy(LEObjectSlice* self) {
    rd_free(self->data);
    self->length = 0;
}

bool le_segments_load(LEFormat* le, RDContext* ctx) {
    if(!le->header.objtab_off || !le->header.num_objects) return true;

    RDReader* r = rd_get_input_reader(ctx);
    rd_reader_seek(r, le->base + le->header.objtab_off);

    u32 cursor = _le_unbound_base(le);

    // read all objects first...
    rd_reader_save(r);
    for(u32 i = 0; i < le->header.num_objects; i++) {
        LEObject* obj = &le->objects.data[i];
        if(!_le_read_object(r, obj)) return false;
        obj->addr = cursor;
        cursor += rd_align_up(obj->size, LE_MEM_ALIGN);
    }
    rd_reader_restore(r);

    // ...and then load pages
    for(u32 i = 0; i < le->objects.length; i++) {
        const LEObject* obj = &le->objects.data[i];

        RDSegmentPerm perm = _le_object_perm(obj);
        if(perm == RD_SP_NONE) continue;

        usize size = rd_align_up(obj->size, le_get_page_size(le));
        const char* name = _le_object_name(obj, i + 1);
        rd_map_segment_n(ctx, name, obj->addr, size, perm);

        rd_reader_save(r);
        _le_object_map_pages(r, le, obj, ctx);
        rd_reader_restore(r);
    }

    return !rd_reader_has_error(r);
}
