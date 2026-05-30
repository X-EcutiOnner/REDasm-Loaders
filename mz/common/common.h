#pragma once

#include <redasm/redasm.h>

#define MZ_DOS_SIGNATURE 0x5A4D
#define MZ_NE_SIGNATURE 0x454E
#define MZ_LE_SIGNATURE 0x454C
#define MZ_LX_SIGNATURE 0x584C
#define MZ_NT_SIGNATURE 0x00004550

typedef struct MZDosHeader {
    u16 e_magic, e_cblp, e_cp, e_crlc, e_cparhdr;
    u16 e_minalloc, e_maxalloc;
    u16 e_ss, e_sp, e_csum, e_ip, e_cs;
    u16 e_lfarlc, e_ovno, e_res[4];
    u16 e_oemid, e_oeminfo, e_res2[10];
    u32 e_lfanew;
} MZDosHeader;

bool mz_read_dos_header(RDReader* r, MZDosHeader* dh);
u32 mz_match_signature(RDReader* r, const MZDosHeader* dh, u32 sig);
