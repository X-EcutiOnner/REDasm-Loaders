#include "classifier.h"
#include "pe/dirs/imports.h"
#include "pe/format.h"

static const char* const PE_CLASSIFY_STRING[] = {
    [PE_CLASS_MINGW] = "MinGW",
    [PE_CLASS_VISUAL_BASIC_5] = "Visual Basic 5",
    [PE_CLASS_VISUAL_BASIC_6] = "Visual Basic 6",
    [PE_CLASS_VISUAL_STUDIO_4] = "Visual Studio 4",
    [PE_CLASS_VISUAL_STUDIO_5] = "Visual Studio 5",
    [PE_CLASS_VISUAL_STUDIO_6] = "Visual Studio 6",
    [PE_CLASS_VISUAL_STUDIO_2002] = "Visual Studio 2002",
    [PE_CLASS_VISUAL_STUDIO_2003] = "Visual Studio 2003",
    [PE_CLASS_VISUAL_STUDIO_2005] = "Visual Studio 2005",
    [PE_CLASS_VISUAL_STUDIO_2008] = "Visual Studio 2008",
    [PE_CLASS_VISUAL_STUDIO_2010] = "Visual Studio 2010",
    [PE_CLASS_VISUAL_STUDIO_2012] = "Visual Studio 2012",
    [PE_CLASS_VISUAL_STUDIO_2013] = "Visual Studio 2013",
    [PE_CLASS_VISUAL_STUDIO_2015] = "Visual Studio 2015",
    [PE_CLASS_VISUAL_STUDIO_2017] = "Visual Studio 2017",
    [PE_CLASS_MFC_4_X] = "Visual C++ 4.x or 6 (MFC 4.x)",
    [PE_CLASS_MFC_7] = "Visual C++ 2002 (MFC 7)",
    [PE_CLASS_MFC_7_1] = "Visual C++ 2003 (MFC 7.1)",
    [PE_CLASS_MFC_8] = "Visual C++ 2005 (MFC 8)",
    [PE_CLASS_MFC_9] = "Visual C++ 2008 (MFC 9)",
    [PE_CLASS_MFC_10] = "Visual C++ 2010 (MFC 10)",
    [PE_CLASS_MFC_11] = "Visual C++ 2012 (MFC 11)",
    [PE_CLASS_MFC_12] = "Visual C++ 2013 (MFC 12)",
    [PE_CLASS_MFC_14] = "Visual C++ >= 2015 (MFC 14)",
    [PE_CLASS_MFC_4_X_UNICODE] = "Visual C++ 4.x or 6 (MFC 4.x, Unicode)",
    [PE_CLASS_MFC_7_UNICODE] = "Visual C++ 2002 (MFC 7, Unicode)",
    [PE_CLASS_MFC_7_1_UNICODE] = "Visual C++ 2003 (MFC 7.1, Unicode)",
    [PE_CLASS_MFC_8_UNICODE] = "Visual C++ 2005 (MFC 8, Unicode)",
    [PE_CLASS_MFC_9_UNICODE] = "Visual C++ 2008 (MFC 9, Unicode)",
    [PE_CLASS_MFC_10_UNICODE] = "Visual C++ 2010 (MFC 10, Unicode)",
    [PE_CLASS_MFC_11_UNICODE] = "Visual C++ 2012 (MFC 11, Unicode)",
    [PE_CLASS_MFC_12_UNICODE] = "Visual C++ 2013 (MFC 12, Unicode)",
    [PE_CLASS_MFC_14_UNICODE] = "Visual C++ >= 2015 (MFC 14, Unicode)",
    [PE_CLASS_DOTNET_1] = ".NET 1.x",
    [PE_CLASS_DOTNET_2_X] = ".NET >= 2.x",
    [PE_CLASS_BORLAND_DELPHI] = "Borland Delphi",
    [PE_CLASS_BORLAND_DELPHI_3] = "Borland Delphi 3",
    [PE_CLASS_BORLAND_DELPHI_6] = "Borland Delphi 6",
    [PE_CLASS_BORLAND_DELPHI_7] = "Borland Delphi 7",
    [PE_CLASS_BORLAND_DELPHI_9] = "Borland Delphi 9",
    [PE_CLASS_BORLAND_DELPHI_10] = "Borland Delphi 10",
    [PE_CLASS_BORLAND_DELPHI_XE] = "Borland Delphi XE",
    [PE_CLASS_BORLAND_DELPHI_XE2_6] = "Borland Delphi XE 2.6",
    [PE_CLASS_BORLAND_CPP] = "Borland C++",
};

static PEClassification _pe_classify_imports(const PEFormat* pe,
                                             RDContext* ctx) {
    PEDataDirectory d = pe->data_dirs[PE_DIRECTORY_ENTRY_IMPORT];

    RDAddress va;
    if(!pe_from_rva(pe, d.VirtualAddress, &va)) return PE_CLASS_NONE;

    RDReader* r = rd_get_reader(ctx);
    rd_reader_seek(r, va);

    PEImportDescriptor desc;
    while(pe_imports_read_descriptor(r, &desc)) {
        rd_reader_save(r);
        const char* mod = pe_imports_get_descriptor_name(r, pe, &desc);
        rd_reader_restore(r);

        if(!mod) continue;

        if(!rd_stricmp(mod, "msvbvm50.dll")) return PE_CLASS_VISUAL_BASIC_5;
        if(!rd_stricmp(mod, "msvbvm60.dll")) return PE_CLASS_VISUAL_BASIC_6;

        if(rd_stristr(mod, "libstdc++") == mod) return PE_CLASS_MINGW;

        if(!rd_stricmp(mod, "mfc40.dll")) return PE_CLASS_MFC_4_X;
        if(!rd_stricmp(mod, "mfc40u.dll")) return PE_CLASS_MFC_4_X_UNICODE;

        if(!rd_stricmp(mod, "mfc70.dll")) return PE_CLASS_MFC_7;
        if(!rd_stricmp(mod, "mfc70u.dll")) return PE_CLASS_MFC_7_UNICODE;

        if(!rd_stricmp(mod, "mfc71.dll")) return PE_CLASS_MFC_7_1;
        if(!rd_stricmp(mod, "mfc71u.dll")) return PE_CLASS_MFC_7_1_UNICODE;

        if(!rd_stricmp(mod, "mfc80.dll")) return PE_CLASS_MFC_8;
        if(!rd_stricmp(mod, "mfc80u.dll")) return PE_CLASS_MFC_8_UNICODE;

        if(!rd_stricmp(mod, "mfc90.dll")) return PE_CLASS_MFC_9;
        if(!rd_stricmp(mod, "mfc90u.dll")) return PE_CLASS_MFC_9_UNICODE;

        if(!rd_stricmp(mod, "mfc100.dll")) return PE_CLASS_MFC_10;
        if(!rd_stricmp(mod, "mfc100u.dll")) return PE_CLASS_MFC_10_UNICODE;

        if(!rd_stricmp(mod, "mfc110.dll")) return PE_CLASS_MFC_11;
        if(!rd_stricmp(mod, "mfc110u.dll")) return PE_CLASS_MFC_11_UNICODE;

        if(!rd_stricmp(mod, "mfc120.dll")) return PE_CLASS_MFC_12;
        if(!rd_stricmp(mod, "mfc120u.dll")) return PE_CLASS_MFC_12_UNICODE;

        if(!rd_stricmp(mod, "mfc140.dll")) return PE_CLASS_MFC_14;
        if(!rd_stricmp(mod, "mfc140u.dll")) return PE_CLASS_MFC_14_UNICODE;

        if(!rd_stricmp(mod, "msvcp40.dll")) return PE_CLASS_VISUAL_STUDIO_4;
        if(!rd_stricmp(mod, "msvcp50.dll")) return PE_CLASS_VISUAL_STUDIO_5;

        if(!rd_stricmp(mod, "msvcp60.dll") || !rd_stricmp(mod, "msvcrt.dll"))
            return PE_CLASS_VISUAL_STUDIO_6;

        if(!rd_stricmp(mod, "msvcp70.dll") || !rd_stricmp(mod, "msvcr70.dll"))
            return PE_CLASS_VISUAL_STUDIO_2002;

        if(!rd_stricmp(mod, "msvcp71.dll") || !rd_stricmp(mod, "msvcr71.dll"))
            return PE_CLASS_VISUAL_STUDIO_2003;

        if(!rd_stricmp(mod, "msvcp80.dll") || !rd_stricmp(mod, "msvcr80.dll"))
            return PE_CLASS_VISUAL_STUDIO_2005;

        if(!rd_stricmp(mod, "msvcp90.dll") || !rd_stricmp(mod, "msvcr90.dll"))
            return PE_CLASS_VISUAL_STUDIO_2008;

        if(!rd_stricmp(mod, "msvcp100.dll") || !rd_stricmp(mod, "msvcr100.dll"))
            return PE_CLASS_VISUAL_STUDIO_2010;

        if(!rd_stricmp(mod, "msvcp110.dll") || !rd_stricmp(mod, "msvcr110.dll"))
            return PE_CLASS_VISUAL_STUDIO_2012;

        if(!rd_stricmp(mod, "msvcp120.dll") || !rd_stricmp(mod, "msvcr120.dll"))
            return PE_CLASS_VISUAL_STUDIO_2013;

        if(!rd_stricmp(mod, "msvcp140.dll") ||
           !rd_stricmp(mod, "msvcp140d.dll") ||
           !rd_stricmp(mod, "vcruntime140.dll"))
            return PE_CLASS_VISUAL_STUDIO_2015;

        if(!rd_stricmp(mod, "borlndmm.dll")) return PE_CLASS_BORLAND_DELPHI;

        if(!rd_stricmp(mod, "rtl60.bpl") || !rd_stricmp(mod, "vcl60.bpl"))
            return PE_CLASS_BORLAND_DELPHI_6;

        if(!rd_stricmp(mod, "rtl90.bpl") || !rd_stricmp(mod, "vcl90.bpl"))
            return PE_CLASS_BORLAND_DELPHI_9;

        if(!rd_stricmp(mod, "rtl100.bpl") || !rd_stricmp(mod, "vcl100.bpl"))
            return PE_CLASS_BORLAND_DELPHI_10;

        if(!rd_stricmp(mod, "rtl150.bpl") || !rd_stricmp(mod, "vcl150.bpl"))
            return PE_CLASS_BORLAND_DELPHI_XE;

        if(!rd_stricmp(mod, "rtl160.bpl") || !rd_stricmp(mod, "rtl170.bpl") ||
           !rd_stricmp(mod, "rtl180.bpl") || !rd_stricmp(mod, "rtl190.bpl") ||
           !rd_stricmp(mod, "vcl160.bpl") || !rd_stricmp(mod, "vcl170.bpl") ||
           !rd_stricmp(mod, "vcl180.bpl") || !rd_stricmp(mod, "vcl190.bpl"))
            return PE_CLASS_BORLAND_DELPHI_XE2_6;
    }

    return PE_CLASS_NONE;
}

PEClassification pe_classify(const PEFormat* pe, RDContext* ctx) {
    if(pe->dotnet_version == 1) return PE_CLASS_DOTNET_1;
    if(pe->dotnet_version > 1) return PE_CLASS_DOTNET_2_X;

    return _pe_classify_imports(pe, ctx);
}

void pe_classify_print(PEClassification c) {
    if(c >= rd_count_of(PE_CLASSIFY_STRING) || !PE_CLASSIFY_STRING[c]) return;
    rd_log(RD_LOG_INFO, PE_PLUGIN_ID, "detected %s", PE_CLASSIFY_STRING[c]);
}
