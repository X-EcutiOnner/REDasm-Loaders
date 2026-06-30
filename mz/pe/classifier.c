#include "classifier.h"
#include "pe/dirs/imports.h"
#include "pe/format.h"
#include <stdlib.h>

static const char* const PE_CLASSIFY_STRING[] = {
    [PE_CLASS_MINGW] = "MinGW",
    [PE_CLASS_VISUAL_BASIC_5] = "Visual Basic 5",
    [PE_CLASS_VISUAL_BASIC_6] = "Visual Basic 6",
    [PE_CLASS_VISUAL_STUDIO] = "Visual Studio",
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

static void _pe_parse_mfc_version(PEClassification* c, const char* mod) {
    const char* digits = mod + 3; // skip "mfc"
    char* p = NULL;
    int version = strtol(digits, &p, 10);
    if(version == 0) return;

    // unicode suffix: digits followed by 'u' before ".dll"
    c->is_unicode = (*p == 'u' || *p == 'U');
    c->mfc_version = version;
}

static void _pe_classify_imports(PEClassification* c, const PEFormat* pe,
                                 RDContext* ctx) {
    PEDataDirectory d = pe->data_dirs[PE_DIRECTORY_ENTRY_IMPORT];

    RDAddress va;
    if(!pe_from_rva(pe, d.VirtualAddress, &va)) return;

    RDReader* r = rd_get_reader(ctx);
    rd_reader_seek(r, va);

    PEImportDescriptor desc;
    while(pe_imports_read_descriptor(r, &desc)) {
        rd_reader_save(r);
        const char* mod = pe_imports_get_descriptor_name(r, pe, &desc);
        rd_reader_restore(r);

        if(!mod) continue;

        if(!rd_stricmp(mod, "msvbvm50.dll")) {
            c->kind = PE_CLASS_VISUAL_BASIC_5;
            c->is_unicode = true;
            break;
        }

        if(!rd_stricmp(mod, "msvbvm60.dll")) {
            c->kind = PE_CLASS_VISUAL_BASIC_6;
            c->is_unicode = true;
            break;
        }

        if(rd_stristr(mod, "libstdc++") == mod) {
            c->kind = PE_CLASS_MINGW;
            break;
        }

        if(rd_stristr(mod, "msvcp") == mod || rd_stristr(mod, "msvcr") == mod ||
           rd_stristr(mod, "vcruntime") == mod) {
            c->kind = PE_CLASS_VISUAL_STUDIO;
            return;
        }

        if(rd_stristr(mod, "mfc") == mod) {
            _pe_parse_mfc_version(c, mod);
            c->kind = PE_CLASS_VISUAL_STUDIO;
            return;
        }

        if(!rd_stricmp(mod, "borlndmm.dll")) {
            c->kind = PE_CLASS_BORLAND_DELPHI;
            return;
        }

        if(!rd_stricmp(mod, "rtl60.bpl") || !rd_stricmp(mod, "vcl60.bpl")) {
            c->kind = PE_CLASS_BORLAND_DELPHI_6;
            return;
        }

        if(!rd_stricmp(mod, "rtl90.bpl") || !rd_stricmp(mod, "vcl90.bpl")) {
            c->kind = PE_CLASS_BORLAND_DELPHI_9;
            return;
        }

        if(!rd_stricmp(mod, "rtl100.bpl") || !rd_stricmp(mod, "vcl100.bpl")) {
            c->kind = PE_CLASS_BORLAND_DELPHI_10;
            return;
        }

        if(!rd_stricmp(mod, "rtl150.bpl") || !rd_stricmp(mod, "vcl150.bpl")) {
            c->kind = PE_CLASS_BORLAND_DELPHI_XE;
            return;
        }

        if(!rd_stricmp(mod, "rtl160.bpl") || !rd_stricmp(mod, "rtl170.bpl") ||
           !rd_stricmp(mod, "rtl180.bpl") || !rd_stricmp(mod, "rtl190.bpl") ||
           !rd_stricmp(mod, "vcl160.bpl") || !rd_stricmp(mod, "vcl170.bpl") ||
           !rd_stricmp(mod, "vcl180.bpl") || !rd_stricmp(mod, "vcl190.bpl")) {
            c->kind = PE_CLASS_BORLAND_DELPHI_XE2_6;
            return;
        }
    }
}

static void _pe_classify_rich(PEClassification* c, const PEFormat* pe) {
    for(usize i = 0; i < pe->rich_header.length; i++) {
        u16 prod_id = PE_RICH_PRODID(pe->rich_header.data[i].comp_id);

        if(prod_id == PE_RICH_PRODID_CPP) {
            c->kind = PE_CLASS_VISUAL_STUDIO;
            break;
        }
    }
}

PEClassification pe_classify(const PEFormat* pe, RDContext* ctx) {
    PEClassification c = {
        .kind = PE_CLASS_NONE,
    };

    if(pe->dotnet_version == 1)
        c.kind = PE_CLASS_DOTNET_1;
    else if(pe->dotnet_version > 1)
        c.kind = PE_CLASS_DOTNET_2_X;
    else
        _pe_classify_imports(&c, pe, ctx);

    if(c.kind == PE_CLASS_NONE) _pe_classify_rich(&c, pe);

    return c;
}

void pe_classify_print(const PEClassification* c) {
    if(c->kind >= rd_count_of(PE_CLASSIFY_STRING) ||
       !PE_CLASSIFY_STRING[c->kind]) {
        return;
    }

    rd_log(RD_LOG_INFO, PE_PLUGIN_ID, "detected %s",
           PE_CLASSIFY_STRING[c->kind]);
}
