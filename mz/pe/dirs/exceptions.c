#include "exceptions.h"
#include <inttypes.h>

static bool _pe_read_runtime_function_entry(RDReader* r,
                                            PERuntimeFunctionEntry* entry) {
    rd_reader_read_le32(r, &entry->BeginAddress);
    rd_reader_read_le32(r, &entry->EndAddress);
    rd_reader_read_le32(r, &entry->UnwindInfoAddress);
    return !rd_reader_has_error(r);
}

bool pe_read_exceptions(RDContext* ctx, PEFormat* pe) {
    // exception directory is only present on x64 (and Itanium)
    if(pe->bits != 64) return false;

    PEDataDirectory d = pe->datadir[PE_DIRECTORY_ENTRY_EXCEPTION];
    if(!d.VirtualAddress || !d.Size) return false;

    RDAddress va;
    if(!pe_from_rva(pe, d.VirtualAddress, &va)) return false;

    RDReader* r = rd_get_reader(ctx);
    rd_reader_seek(r, va);

    while(rd_reader_tell(r) < va + d.Size) {
        RDAddress entry_va = rd_reader_tell(r);

        PERuntimeFunctionEntry entry;
        if(!_pe_read_runtime_function_entry(r, &entry)) break;
        if(!entry.BeginAddress) continue;

        rd_library_type(ctx, entry_va, "PE_RUNTIME_FUNCTION_ENTRY", 0,
                        RD_TYPE_NONE);

        RDAddress func_va;
        if(!pe_from_rva(pe, entry.BeginAddress, &func_va)) continue;

        func_va = pe_norm(ctx, pe, func_va);
        rd_library_function(ctx, func_va, rd_format("exc_%" PRIx64, func_va));
    }

    return true;
}
