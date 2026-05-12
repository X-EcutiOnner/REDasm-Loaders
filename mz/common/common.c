#include "common.h"

bool mz_read_dos_header(RDReader* r, MZDosHeader* dh) {
    rd_reader_read_le16(r, &dh->e_magic);
    if(dh->e_magic != MZ_DOS_SIGNATURE) return false;

    rd_reader_read_le16(r, &dh->e_cblp);
    rd_reader_read_le16(r, &dh->e_cp);
    rd_reader_read_le16(r, &dh->e_crlc);
    rd_reader_read_le16(r, &dh->e_cparhdr);
    rd_reader_read_le16(r, &dh->e_minalloc);
    rd_reader_read_le16(r, &dh->e_maxalloc);
    rd_reader_read_le16(r, &dh->e_ss);
    rd_reader_read_le16(r, &dh->e_sp);
    rd_reader_read_le16(r, &dh->e_csum);
    rd_reader_read_le16(r, &dh->e_ip);
    rd_reader_read_le16(r, &dh->e_cs);
    rd_reader_read_le16(r, &dh->e_lfarlc);
    rd_reader_read_le16(r, &dh->e_ovno);

    for(int i = 0; i < rd_count_of(dh->e_res); i++)
        rd_reader_read_le16(r, &dh->e_res[i]);

    rd_reader_read_le16(r, &dh->e_oemid);
    rd_reader_read_le16(r, &dh->e_oeminfo);

    for(int i = 0; i < rd_count_of(dh->e_res2); i++)
        rd_reader_read_le16(r, &dh->e_res2[i]);

    rd_reader_read_le32(r, &dh->e_lfanew);

    return !rd_reader_has_error(r);
}

u32 mz_match_signature(RDReader* r, const MZDosHeader* dh, u32 sig) {
    if(!dh->e_lfanew) return sig == 0; // no extended header: plain MZ

    rd_reader_seek(r, dh->e_lfanew);

    u16 sig16;
    if(!rd_reader_read_le16(r, &sig16)) return false;

    // PE needs all 4 bytes ("PE\0\0")
    if(sig == MZ_NT_SIGNATURE) {
        u16 hi;
        if(!rd_reader_read_le16(r, &hi)) return false;
        return sig16 == (u16)MZ_NT_SIGNATURE && hi == 0x0000;
    }

    return sig16 == (u16)sig;
}
