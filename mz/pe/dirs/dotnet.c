#include "dotnet.h"

int pe_dotnet_get_major(RDContext* ctx, const PEFormat* pe) {
    PEDataDirectory d = pe->datadir[PE_DIRECTORY_ENTRY_DOTNET];

    RDAddress va;
    if(!pe_from_rva(pe, d.VirtualAddress, &va)) return 0;

    RDReader* r = rd_get_reader(ctx);
    rd_reader_seek(r, va);

    PECorHeader dotnet;
    rd_reader_read_le32(r, &dotnet.cb);
    rd_reader_read_le16(r, &dotnet.MajorRuntimeVersion);
    rd_reader_read_le16(r, &dotnet.MinorRuntimeVersion);

    if(rd_reader_has_error(r)) return 0;
    return dotnet.MajorRuntimeVersion;
}
