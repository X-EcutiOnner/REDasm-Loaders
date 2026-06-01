#include "dotnet.h"

static RDOffset _pe_rva_to_offset(const PEFormat* pe, RDAddress rva) {
    for(u16 i = 0; i < pe->fileheader.NumberOfSections; i++) {
        const PESectionHeader* s = &pe->sections[i];
        if(!s->VirtualSize || !s->SizeOfRawData) continue;

        if(rva >= s->VirtualAddress &&
           rva < (s->VirtualAddress + s->VirtualSize)) {
            return (rva - s->VirtualAddress + s->PointerToRawData);
        }
    }

    return 0;
}

int pe_dotnet_get_major(RDReader* r, const PEFormat* pe) {
    PEDataDirectory d = pe->data_dirs[PE_DIRECTORY_ENTRY_DOTNET];
    if(!d.VirtualAddress || !d.Size) return 0;

    RDOffset off = _pe_rva_to_offset(pe, d.VirtualAddress);
    if(!off) return 0;

    rd_reader_seek(r, off);

    PECorHeader dotnet;
    rd_reader_read_le32(r, &dotnet.cb);
    rd_reader_read_le16(r, &dotnet.MajorRuntimeVersion);
    rd_reader_read_le16(r, &dotnet.MinorRuntimeVersion);

    if(rd_reader_has_error(r)) return 0;
    return dotnet.MajorRuntimeVersion;
}
