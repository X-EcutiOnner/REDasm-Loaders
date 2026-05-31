#pragma once

// https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/exeflat.h
// http://bitsavers.informatik.uni-stuttgart.de/pdf/ibm/pc/os2/OS2_OMF_and_LX_Object_Formats_Revision_8_199406.pdf

#include "common/common.h"
#include "le/imports.h"
#include "le/objects.h"
#include <redasm/redasm.h>

#define LE_PLUGIN_ID "mz_linear"
#define LE_SEG_SLOT 0x00010000U

#define LE_BYTEORDER_BIG 0x01
#define LE_RESERVED_LENGTH 20

#define LE_FLAG_NO_INTERNAL_FIXUPS 0x00000010
#define LE_FLAG_NO_EXTERNAL_FIXUPS 0x00000020

#define LE_MOD_MASK 0x38000
#define LE_MOD_EXE 0
#define LE_MOD_DLL 0x08000
#define LE_MOD_PDD 0x20000
#define LE_MOD_VDD 0x28000

#define LE_MOD_CPU_80286 1
#define LE_MOD_CPU_80386 2
#define LE_MOD_CPU_80486 3

#define LE_MOD_OS_OS2 1
#define LE_MOD_OS_WIN 2
#define LE_MOD_OS_DOS 3
#define LE_MOD_OS_WIN386 4


typedef struct LEHeader {
    u8 byte_order;
    u8 word_order;
    u32 level;
    u16 cpu_type;
    u16 os_type;
    u32 version;
    u32 flags;
    u32 num_pages;
    u32 eip_obj;
    u32 eip;
    u32 esp_obj;
    u32 esp;
    u32 page_size;

    union {
        u32 last_page;
        u32 page_shift;
    };

    u32 fixup_size;
    u32 fixup_cksum;
    u32 loader_size;
    u32 loader_cksum;
    u32 objtab_off;
    u32 num_objects;
    u32 objmap_off;
    u32 idmap_off;
    u32 rsrc_off;
    u32 num_rsrcs;
    u32 resname_off;
    u32 entry_off;
    u32 moddir_off;
    u32 num_moddirs;
    u32 fixpage_off;
    u32 fixrec_off;
    u32 impmod_off;
    u32 num_impmods;
    u32 impproc_off;
    u32 cksum_off;
    u32 page_off;
    u32 num_preload;
    u32 nonres_off;
    u32 nonres_size;
    u32 nonres_cksum;
    u32 autodata_obj;
    u32 debug_off;
    u32 debug_len;
    u32 num_inst_preload;
    u32 num_inst_demand;
    u32 heapsize;
    u32 stacksize;

    union {
        u8 reserved[LE_RESERVED_LENGTH];

        struct {
            u8 reserved1[8];
            u32 winresoff;
            u32 winreslen;
            u16 device_ID;
            u16 DDK_version;
        } vxd;
    };
} LEHeader;

typedef struct LEFormat {
    MZDosHeader dosheader;
    LEHeader header;

    u32 base;
    bool is_lx;

    LEImportSlice imports;
    LEObjectSlice objects;
} LEFormat;

static inline bool le_is_be(const LEHeader* h) {
    return h->byte_order == LE_BYTEORDER_BIG;
}

RDAddress le_seg_address(const LEFormat* le, u32 obj_idx, u32 offset);
void le_report_module_type(const LEFormat* le);
void le_report_cpu_type(const LEFormat* le);
void le_report_os_type(const LEFormat* le);

bool le_read_header(RDReader* r, LEHeader* v);
