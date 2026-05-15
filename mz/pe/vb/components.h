#pragma once

#include "pe/vb/format.h"

typedef struct PEVBComponent {
    const char* name;
    const char* guid_str;
    const char* const* events;
} PEVBComponent;

const RDKBObject* pe_vb_components_find(const PEGUID* guid);
