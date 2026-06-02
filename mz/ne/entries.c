#include "entries.h"

NEEntrySlice ne_entryslice_create(NEFormat* ne, RDContext* ctx) {
    const NEHeader* hdr = &ne->header;

    // Upper Bound: max entries = EntryTableLength / 3 (min entry size)
    u32 max_ordinals = (hdr->EntryTableLength / 3) + 1;

    NEEntrySlice entries = {
        .data = rd_alloc0(max_ordinals, sizeof(RDAddress)),
    };

    RDReader* r = rd_get_input_reader(ctx);
    u32 et_base = ne->base + hdr->EntryTableOffset;
    u32 et_end = et_base + hdr->EntryTableLength;
    u32 pos = et_base;
    u16 ordinal = 0; // next ordinal to assign (1-based, stored at index-1)

    while(pos < et_end) {
        rd_reader_seek(r, pos);

        u8 count, seg_indicator;
        rd_reader_read_byte(r, &count);
        rd_reader_read_byte(r, &seg_indicator);
        if(rd_reader_has_error(r)) break;

        pos += sizeof(u16);
        if(!count) break; // end of entry table

        if(seg_indicator == 0x00) {
            // Unused entries: ordinals are assigned but have no address.
            // Advance ordinal counter, no bytes follow.
            ordinal += count;
            continue;
        }

        for(u8 i = 0; i < count; i++) {
            ordinal++;

            if(seg_indicator == 0xFF) {
                // Movable segment entry:
                // flags(1) + int3f(2) + segnum(1) + offset(2)
                u8 flags, seg_num_byte;
                u16 int3fh, offset;
                rd_reader_read_byte(r, &flags);
                rd_reader_read_le16(r, &int3fh);
                rd_reader_read_byte(r, &seg_num_byte);
                rd_reader_read_le16(r, &offset);
                if(rd_reader_has_error(r)) goto done;

                pos += (2 * sizeof(u8)) + (2 * sizeof(u16));

                if(ordinal <= max_ordinals && seg_num_byte &&
                   seg_num_byte <= hdr->SegCount) {
                    entries.data[ordinal - 1] =
                        ne_seg_address(seg_num_byte, offset);
                }
            }
            else {
                // Fixed segment entry: flags(1) + offset(2)
                u8 flags;
                u16 offset;
                rd_reader_read_byte(r, &flags);
                rd_reader_read_le16(r, &offset);
                if(rd_reader_has_error(r)) goto done;

                pos += sizeof(u8) + sizeof(u16);

                if(ordinal <= max_ordinals && seg_indicator <= hdr->SegCount) {
                    entries.data[ordinal - 1] =
                        ne_seg_address(seg_indicator, offset);
                }
            }
        }
    }

done:
    entries.length = ordinal;
    return entries;
}

void ne_entryslice_destroy(NEEntrySlice* self) {
    rd_free(self->data);
    self->length = 0;
}
