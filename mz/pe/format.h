#pragma once

#include "common/common.h"
#include "header.h"
#include "pe/classifier.h"
#include "pe/rich.h"

#define PE_PLUGIN_ID "win_pe"

typedef struct PEFormat {
    RDAddress imagebase;
    RDAddress entrypoint;
    u32 section_align;

    MZDosHeader dosheader;
    PEFileHeader fileheader;

    union {
        PEOptionalHeader32 opt32;
        PEOptionalHeader64 opt64;
    };

    PESectionHeader* sections;
    PEDataDirectory data_dirs[PE_NUMBER_OF_DIRECTORY_ENTRIES];

    struct {
        PERichRecord* data;
        usize length;
        u32 checksum;
        PERichStatus status;
    } rich_header;

    PEClassification classification;
    const char* thunk_type;
    int thunk_size;
    int bits;
    int dotnet_version;
} PEFormat;

bool pe_from_rva(const PEFormat* pe, RDAddress rva, RDAddress* va);
void pe_set_bits(PEFormat* pe);
bool pe_read_section_header(RDReader* r, PESectionHeader* s);
RDAddress pe_norm(RDContext* ctx, const PEFormat* pe, RDAddress address);
const char* pe_get_processor(const RDLoader* ldr);
