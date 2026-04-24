#pragma once

#include <redasm/redasm.h>

#define ELF_EI_NIDENT 16

typedef struct ELFIdent {
    u8 ei_magic[4];
    u8 ei_class;
    u8 ei_data;
    u8 ei_version;
    u8 ei_osabi;
    u8 ei_abiversion;
    u8 pad[7];
} ELFIdent;

static_assert(sizeof(ELFIdent) == ELF_EI_NIDENT, "ELF Ident size mismatch");
