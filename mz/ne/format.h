#pragma once

#include "common/common.h"
#include <redasm/redasm.h>

// References
// - https://wiki.osdev.org/NE
// - http://justsolve.archiveteam.org/wiki/New_Executable

// Each NE segment is given a 64KB slot in a synthetic flat address space.
// Segment N (1-based) is placed at N * NE_SEG_SLOT.
// Slot 0 is intentionally left empty so the index can be used directly.
#define NE_SEG_SLOT 0x10000U

// Segment flags
#define NE_SEGFLAG_DATA 0x0001
#define NE_SEGFLAG_HAS_RELOCS 0x0100

// AppFlags
#define NE_APPFLAG_DLL 0x80

typedef struct NEHeader {
    u8 MajLinkerVersion;
    u8 MinLinkerVersion;
    u16 EntryTableOffset;
    u16 EntryTableLength;
    u32 FileLoadCRC;
    u8 ProgramFlags;
    u8 AppFlags;
    u8 AutoDataSegIndex;
    u8 Reserved;
    u16 InitHeapSize;
    u16 InitStackSize;
    u32 EntryPoint; // high word = CS (seg index), low word = IP
    u32 InitStack;  // high word = SS (seg index), low word = SP
    u16 SegCount;
    u16 ModRefs;
    u16 NoResNamesTabSiz;
    u16 SegTableOffset;
    u16 ResTableOffset;
    u16 ResidNamesTableOffset;
    u16 ModRefTableOffset;
    u16 ImportNamesTableOffset;
    u32 NonResNamesTableOffset; // absolute file offset
    u16 MovableEntryCount;
    u16 FileAlnSzShftCnt;
    u16 ResTableCount;
    u8 TargetOS;
    u8 OS2EXEFlags;
    u16 ReturnThunksOffset;
    u16 SegRefThunksOffset;
    u16 MinCodeSwapSize;
    u16 ExpWinVer;
} NEHeader;

// clang-format off
typedef struct NESegEntry {
    u16 SectorBase; // offset in sectors; byte offset = SectorBase << FileAlnSzShftCnt
    u16 SegBytes;   // length in file; 0 means 64KB
    u16 SegFlags;
    u16 MinAlloc;   // min allocation in bytes; 0 means 64KB
} NESegEntry;
// clang-format on

typedef struct NEFormat {
    MZDosHeader dosheader;
    NEHeader header;
    u32 base;
} NEFormat;

// Compute the flat address of a segment-relative reference.
// seg_idx is 1-based (as stored in the NE format).
static inline RDAddress ne_seg_address(u16 seg_idx, u16 offset) {
    return ((RDAddress)seg_idx * NE_SEG_SLOT) + offset;
}

bool ne_read_header(RDReader* r, NEHeader* h);
bool ne_load_segments(NEFormat* ne, RDContext* ctx);
