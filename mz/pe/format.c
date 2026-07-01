#include "format.h"

bool pe_from_rva(const PEFormat* pe, RDAddress rva, RDAddress* va) {
    if(!rva) return false;
    *va = pe->imagebase + rva;
    return true;
}

void pe_set_bits(PEFormat* pe) {
    switch(pe->fileheader.Machine) {
        case PE_FILE_MACHINE_AMD64: {
            pe->thunk_size = sizeof(u64);
            pe->thunk_type = "u64";
            pe->bits = 64;
            return;
        }

        case PE_FILE_MACHINE_ARM:
        case PE_FILE_MACHINE_ARMNT: {
            if(pe->opt32.Magic == PE_NT_OPTIONAL_HDR64_MAGIC) {
                pe->thunk_size = sizeof(u64);
                pe->thunk_type = "u64";
                pe->bits = 64;
                return;
            }

            break;
        }

        default: break;
    }

    pe->thunk_size = sizeof(u32);
    pe->thunk_type = "u32";
    pe->bits = 32;
}

bool pe_read_section_header(RDReader* r, PESectionHeader* s) {
    rd_reader_read(r, &s->Name, PE_SIZE_OF_SHORT_NAME);
    rd_reader_read_le32(r, &s->VirtualSize);
    rd_reader_read_le32(r, &s->VirtualAddress);
    rd_reader_read_le32(r, &s->SizeOfRawData);
    rd_reader_read_le32(r, &s->PointerToRawData);
    rd_reader_read_le32(r, &s->PointerToRelocations);
    rd_reader_read_le32(r, &s->PointerToLinenumbers);
    rd_reader_read_le16(r, &s->NumberOfRelocations);
    rd_reader_read_le16(r, &s->NumberOfLinenumbers);
    rd_reader_read_le32(r, &s->Characteristics);

    return !rd_reader_has_error(r);
}

RDAddress pe_norm(RDContext* ctx, const PEFormat* pe, RDAddress address) {
    if(pe->fileheader.Machine == PE_FILE_MACHINE_ARM ||
       pe->fileheader.Machine == PE_FILE_MACHINE_ARMNT) {
        if(address & 1) {
            rd_library_sregval(ctx, address & ~1, "T", 1);
            return address & ~1;
        }

        rd_library_sregval(ctx, address, "T", 0);
    }

    return address;
}

const char* pe_get_processor(const RDLoader* ldr) {
    const PEFormat* pe = (const PEFormat*)ldr;

    switch(pe->fileheader.Machine) {
        case PE_FILE_MACHINE_ARM:
        case PE_FILE_MACHINE_ARMNT: {
            if(pe->opt32.Magic == PE_NT_OPTIONAL_HDR64_MAGIC) return "arm64_le";
            return "arm32_le";
        }

        case PE_FILE_MACHINE_AMD64: return "x86_64";
        case PE_FILE_MACHINE_I386: return "x86_32";
        default: break;
    }

    return NULL;
}
