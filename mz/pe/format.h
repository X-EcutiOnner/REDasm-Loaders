#pragma once

#include "common/common.h"
#include "header.h"

typedef struct PEFormat {
    RDAddress imagebase;
    RDAddress entrypoint;
    MZDosHeader dosheader;
    PEFileHeader fileheader;

    union {
        PEOptionalHeader32 opt32;
        PEOptionalHeader64 opt64;
    };

    PEDataDirectory datadir[PE_NUMBER_OF_DIRECTORY_ENTRIES];
} PEFormat;

bool pe_from_rva(PEFormat* pe, RDAddress rva, RDAddress* va);
int pe_get_bits(PEFormat* pe);

bool pe_read_section_header(PEFormat* pe, RDReader* r, int idx,
                            PESectionHeader* s);

RDAddress pe_norm(RDContext* ctx, const PEFormat* pe, RDAddress address);
