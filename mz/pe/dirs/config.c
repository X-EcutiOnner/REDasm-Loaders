#include "config.h"
#include <string.h>

static bool _pe_read_config_dir32(RDReader* r, PELoadConfigDirectory32* v) {
    rd_reader_read_le32(r, &v->Size);
    rd_reader_read_le32(r, &v->TimeDateStamp);
    rd_reader_read_le16(r, &v->MajorVersion);
    rd_reader_read_le16(r, &v->MinorVersion);
    rd_reader_read_le32(r, &v->GlobalFlagsClear);
    rd_reader_read_le32(r, &v->GlobalFlagsSet);
    rd_reader_read_le32(r, &v->CriticalSectionDefaultTimeout);
    rd_reader_read_le32(r, &v->DeCommitFreeBlockThreshold);
    rd_reader_read_le32(r, &v->DeCommitTotalFreeThreshold);
    rd_reader_read_le32(r, &v->LockPrefixTable);
    rd_reader_read_le32(r, &v->MaximumAllocationSize);
    rd_reader_read_le32(r, &v->VirtualMemoryThreshold);
    rd_reader_read_le32(r, &v->ProcessHeapFlags);
    rd_reader_read_le32(r, &v->ProcessAffinityMask);
    rd_reader_read_le16(r, &v->CSDVersion);
    rd_reader_read_le16(r, &v->Reserved1);
    rd_reader_read_le32(r, &v->EditList);
    rd_reader_read_le32(r, &v->SecurityCookie);
    rd_reader_read_le32(r, &v->SEHandlerTable);
    rd_reader_read_le32(r, &v->SEHandlerCount);
    rd_reader_read_le32(r, &v->GuardCFCheckFunctionPointer);
    rd_reader_read_le32(r, &v->Reserved2);
    rd_reader_read_le32(r, &v->GuardCFFunctionTable);
    rd_reader_read_le32(r, &v->GuardCFFunctionCount);
    rd_reader_read_le32(r, &v->GuardFlags);

    return !rd_reader_has_error(r);
}

static bool _pe_read_config_dir64(RDReader* r, PELoadConfigDirectory64* v) {
    rd_reader_read_le32(r, &v->Size);
    rd_reader_read_le32(r, &v->TimeDateStamp);
    rd_reader_read_le16(r, &v->MajorVersion);
    rd_reader_read_le16(r, &v->MinorVersion);
    rd_reader_read_le32(r, &v->GlobalFlagsClear);
    rd_reader_read_le32(r, &v->GlobalFlagsSet);
    rd_reader_read_le32(r, &v->CriticalSectionDefaultTimeout);
    rd_reader_read_le64(r, &v->DeCommitFreeBlockThreshold);
    rd_reader_read_le64(r, &v->DeCommitTotalFreeThreshold);
    rd_reader_read_le64(r, &v->LockPrefixTable);
    rd_reader_read_le64(r, &v->MaximumAllocationSize);
    rd_reader_read_le64(r, &v->VirtualMemoryThreshold);
    rd_reader_read_le64(r, &v->ProcessAffinityMask);
    rd_reader_read_le64(r, &v->ProcessHeapFlags);
    rd_reader_read_le16(r, &v->CSDVersion);
    rd_reader_read_le16(r, &v->Reserved1);
    rd_reader_read_le64(r, &v->EditList);
    rd_reader_read_le64(r, &v->SecurityCookie);
    rd_reader_read_le64(r, &v->SEHandlerTable);
    rd_reader_read_le64(r, &v->SEHandlerCount);
    rd_reader_read_le64(r, &v->GuardCFCheckFunctionPointer);
    rd_reader_read_le64(r, &v->Reserved2);
    rd_reader_read_le64(r, &v->GuardCFFunctionTable);
    rd_reader_read_le64(r, &v->GuardCFFunctionCount);
    rd_reader_read_le32(r, &v->GuardFlags);

    return !rd_reader_has_error(r);
}

bool pe_read_config_dir(RDContext* ctx, PEFormat* pe) {
    PEDataDirectory d = pe->data_dirs[PE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if(!d.VirtualAddress || !d.Size) return false;

    RDAddress va;
    if(!pe_from_rva(pe, d.VirtualAddress, &va)) return false;

    RDReader* r = rd_get_reader(ctx);
    rd_reader_seek(r, va);

    const char* proc = pe_get_processor((const RDLoader*)pe);
    bool is_x86 = proc && strstr(proc, "x86_") == proc;

    if(pe->bits == 32) {
        PELoadConfigDirectory32 configdir;
        if(!_pe_read_config_dir32(r, &configdir)) return false;

        rd_library_type(ctx, va, "PE_LOAD_CONFIG_DIRECTORY32", 0, RD_TYPE_NONE);
        rd_library_type(ctx, configdir.SecurityCookie, "u32", 0, RD_TYPE_NONE);
        rd_library_name(ctx, configdir.SecurityCookie, "__pe_security_cookie");

        if(is_x86 && configdir.SEHandlerTable) {
            rd_reader_seek(r, configdir.SEHandlerTable);

            for(u32 i = 0; i < configdir.SEHandlerCount; i++) {
                RDAddress curr = (RDAddress)rd_reader_tell(r);

                u32 rva;
                if(!rd_reader_read_le32(r, &rva)) break;

                rd_library_type(ctx, curr, "u32", 0, RD_TYPE_PTR);

                RDAddress va;
                if(!pe_from_rva(pe, (RDAddress)rva, &va)) continue;
                rd_library_function(ctx, va, NULL);
            }
        }
    }
    else {
        PELoadConfigDirectory64 configdir;
        if(!_pe_read_config_dir64(r, &configdir)) return false;

        rd_library_type(ctx, va, "PE_LOAD_CONFIG_DIRECTORY64", 0, RD_TYPE_NONE);
        rd_library_type(ctx, configdir.SecurityCookie, "u64", 0, RD_TYPE_NONE);
        rd_library_name(ctx, configdir.SecurityCookie, "__pe_security_cookie");

        if(is_x86 && configdir.SEHandlerTable) {
            rd_reader_seek(r, configdir.SEHandlerTable);

            for(u64 i = 0; i < configdir.SEHandlerCount; i++) {
                RDAddress curr = (RDAddress)rd_reader_tell(r);

                u64 rva;
                if(!rd_reader_read_le64(r, &rva)) break;

                rd_library_type(ctx, curr, "u64", 0, RD_TYPE_PTR);

                RDAddress va;
                if(!pe_from_rva(pe, (RDAddress)rva, &va)) continue;
                rd_library_function(ctx, va, NULL);
            }
        }
    }

    return !rd_reader_has_error(r);
}
