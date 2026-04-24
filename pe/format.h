#pragma once

#include "header.h"

typedef struct PEFormat {
    u32 e_lfanew;
    RDAddress imagebase;
    RDAddress entrypoint;
    ImageFileHeader fileheader;

    union {
        ImageOptionalHeader32 opt32;
        ImageOptionalHeader64 opt64;
    };

    ImageDataDirectory datadir[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} PEFormat;

bool pe_from_rva(PEFormat* pe, RDAddress rva, RDAddress* va);
int pe_get_bits(PEFormat* pe);

bool pe_read_section_header(PEFormat* pe, RDReader* r, int idx,
                            ImageSectionHeader* s);
