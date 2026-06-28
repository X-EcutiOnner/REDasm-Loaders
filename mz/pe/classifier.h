#pragma once

#include <redasm/redasm.h>

typedef enum {
    PE_CLASS_NONE = 0,
    PE_CLASS_MINGW,
    PE_CLASS_VISUAL_BASIC_5,
    PE_CLASS_VISUAL_BASIC_6,
    PE_CLASS_VISUAL_STUDIO_4,
    PE_CLASS_VISUAL_STUDIO_5,
    PE_CLASS_VISUAL_STUDIO_6,
    PE_CLASS_VISUAL_STUDIO_2002,
    PE_CLASS_VISUAL_STUDIO_2003,
    PE_CLASS_VISUAL_STUDIO_2005,
    PE_CLASS_VISUAL_STUDIO_2008,
    PE_CLASS_VISUAL_STUDIO_2010,
    PE_CLASS_VISUAL_STUDIO_2012,
    PE_CLASS_VISUAL_STUDIO_2013,
    PE_CLASS_VISUAL_STUDIO_2015,
    PE_CLASS_VISUAL_STUDIO_2017,
    PE_CLASS_MFC_4_X,
    PE_CLASS_MFC_7,
    PE_CLASS_MFC_7_1,
    PE_CLASS_MFC_8,
    PE_CLASS_MFC_9,
    PE_CLASS_MFC_10,
    PE_CLASS_MFC_11,
    PE_CLASS_MFC_12,
    PE_CLASS_MFC_14,
    PE_CLASS_MFC_4_X_UNICODE,
    PE_CLASS_MFC_7_UNICODE,
    PE_CLASS_MFC_7_1_UNICODE,
    PE_CLASS_MFC_8_UNICODE,
    PE_CLASS_MFC_9_UNICODE,
    PE_CLASS_MFC_10_UNICODE,
    PE_CLASS_MFC_11_UNICODE,
    PE_CLASS_MFC_12_UNICODE,
    PE_CLASS_MFC_14_UNICODE,
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
} PEClassification;

typedef struct PEFormat PEFormat;

PEClassification pe_classify(const PEFormat* pe, RDContext* ctx);
void pe_classify_print(PEClassification c);

static inline bool pe_classification_is_visual_studio(PEClassification c) {
    return c >= PE_CLASS_VISUAL_STUDIO_4 && c <= PE_CLASS_VISUAL_STUDIO_2017;
}

static inline bool pe_classification_is_mfc(PEClassification c) {
    return c >= PE_CLASS_MFC_4_X && c <= PE_CLASS_MFC_14_UNICODE;
}

static inline bool pe_classification_is_visual_basic(PEClassification c) {
    return c == PE_CLASS_VISUAL_BASIC_5 || c == PE_CLASS_VISUAL_BASIC_6;
}

static inline bool pe_classification_is_unicode(PEClassification c) {
    if(pe_classification_is_visual_basic(c)) return true;
    return c >= PE_CLASS_MFC_4_X_UNICODE && c <= PE_CLASS_MFC_14_UNICODE;
}
