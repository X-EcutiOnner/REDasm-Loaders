#include "format.h"
#include <stdio.h>

bool ne_read_header(RDReader* r, NEHeader* h) {
    rd_reader_read_u8(r, &h->MajLinkerVersion);
    rd_reader_read_u8(r, &h->MinLinkerVersion);
    rd_reader_read_le16(r, &h->EntryTableOffset);
    rd_reader_read_le16(r, &h->EntryTableLength);
    rd_reader_read_le32(r, &h->FileLoadCRC);
    rd_reader_read_u8(r, &h->ProgramFlags);
    rd_reader_read_u8(r, &h->AppFlags);
    rd_reader_read_u8(r, &h->AutoDataSegIndex);
    rd_reader_read_u8(r, &h->Reserved);
    rd_reader_read_le16(r, &h->InitHeapSize);
    rd_reader_read_le16(r, &h->InitStackSize);
    rd_reader_read_le32(r, &h->EntryPoint);
    rd_reader_read_le32(r, &h->InitStack);
    rd_reader_read_le16(r, &h->SegCount);
    rd_reader_read_le16(r, &h->ModRefs);
    rd_reader_read_le16(r, &h->NoResNamesTabSiz);
    rd_reader_read_le16(r, &h->SegTableOffset);
    rd_reader_read_le16(r, &h->ResTableOffset);
    rd_reader_read_le16(r, &h->ResidNamesTableOffset);
    rd_reader_read_le16(r, &h->ModRefTableOffset);
    rd_reader_read_le16(r, &h->ImportNamesTableOffset);
    rd_reader_read_le32(r, &h->NonResNamesTableOffset);
    rd_reader_read_le16(r, &h->MovableEntryCount);
    rd_reader_read_le16(r, &h->FileAlnSzShftCnt);
    rd_reader_read_le16(r, &h->ResTableCount);
    rd_reader_read_u8(r, &h->TargetOS);
    rd_reader_read_u8(r, &h->OS2EXEFlags);
    rd_reader_read_le16(r, &h->ReturnThunksOffset);
    rd_reader_read_le16(r, &h->SegRefThunksOffset);
    rd_reader_read_le16(r, &h->MinCodeSwapSize);
    rd_reader_read_le16(r, &h->ExpWinVer);

    return !rd_reader_has_error(r);
}

bool ne_load_segments(NEFormat* ne, RDContext* ctx) {
    RDReader* r = rd_get_input_reader(ctx);
    u32 segtab_off = ne->base + ne->header.SegTableOffset;
    u32 sector_size = 1U << ne->header.FileAlnSzShftCnt;

    for(u16 i = 0; i < ne->header.SegCount; i++) {
        rd_reader_seek(r, segtab_off + (i * 8U));

        NESegEntry seg;
        rd_reader_read_le16(r, &seg.SectorBase);
        rd_reader_read_le16(r, &seg.SegBytes);
        rd_reader_read_le16(r, &seg.SegFlags);
        rd_reader_read_le16(r, &seg.MinAlloc);
        if(rd_reader_has_error(r)) return false;

        u16 seg_num = i + 1; // NE segment indices are 1-based
        u32 file_size = seg.SegBytes ? seg.SegBytes : 0x10000U;
        u32 alloc_size = seg.MinAlloc ? seg.MinAlloc : 0x10000U;

        RDAddress base = ne_seg_address(seg_num, 0);
        u32 perm = (seg.SegFlags & NE_SEGFLAG_DATA) ? RD_SP_RW : RD_SP_RX;

        char name[8] = {0};
        snprintf(name, sizeof(name), perm & RD_SP_X ? "CSEG%02u" : "DSEG%02u",
                 seg_num);

        rd_map_segment_n(ctx, name, base, alloc_size, perm);

        // SectorBase == 0 means no file data (BSS-like)
        // Segment is mapped but left without backing data
        if(seg.SectorBase) {
            u32 file_off = (u32)seg.SectorBase * sector_size;
            rd_map_input_n(ctx, file_off, base, file_size);
        }
    }

    return true;
}
