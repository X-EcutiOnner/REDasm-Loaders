#pragma once

#include "common/common.h"
#include "header.h"
#include "pe/classifier.h"

#define PE_LOG_TAG "PE"

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

    PEClassification classification;
} PEFormat;

bool pe_from_rva(const PEFormat* pe, RDAddress rva, RDAddress* va);
int pe_get_bits(const PEFormat* pe);

bool pe_read_section_header(RDContext* ctx, PEFormat* pe, int idx,
                            PESectionHeader* s);

RDAddress pe_norm(RDContext* ctx, const PEFormat* pe, RDAddress address);
