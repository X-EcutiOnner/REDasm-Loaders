#pragma once

#include <redasm/redasm.h>

typedef enum {
    PE_CLASS_NONE = 0,
    PE_CLASS_MINGW,
    PE_CLASS_VISUAL_STUDIO,
    PE_CLASS_VISUAL_BASIC_5,
    PE_CLASS_VISUAL_BASIC_6,
    PE_CLASS_DOTNET_1,
    PE_CLASS_DOTNET_2_X,
    PE_CLASS_BORLAND_DELPHI,
    PE_CLASS_BORLAND_DELPHI_3,
    PE_CLASS_BORLAND_DELPHI_6,
    PE_CLASS_BORLAND_DELPHI_7,
    PE_CLASS_BORLAND_DELPHI_9,
    PE_CLASS_BORLAND_DELPHI_10,
    PE_CLASS_BORLAND_DELPHI_XE,
    PE_CLASS_BORLAND_DELPHI_XE2_6,
    PE_CLASS_BORLAND_CPP,
} PEClassificationKind;

typedef struct PEFormat PEFormat;

typedef struct PEClassification {
    PEClassificationKind kind;
    bool is_unicode;
    int mfc_version;
} PEClassification;

PEClassification pe_classify(const PEFormat* pe, RDContext* ctx);
void pe_classify_print(const PEClassification* c);
