#include "format.h"
#include <inttypes.h>

RDAddress le_seg_address(const LEFormat* le, u32 obj_idx, u32 offset) {
    if(!obj_idx || obj_idx > le->objects.length) return 0;
    return le->objects.data[obj_idx - 1].addr + offset;
}

void le_report_module_type(const LEFormat* le) {
    if((le->header.flags & LE_MOD_VDD) == LE_MOD_VDD)
        RD_LOG_INFO("Module Type: Virtual Device Driver (VxD)");
    else if((le->header.flags & LE_MOD_PDD) == LE_MOD_PDD)
        RD_LOG_INFO("Module Type: Physical Device Driver");
    else if(le->header.flags & LE_MOD_DLL)
        RD_LOG_INFO("Module Type: Dynamic module (DLL)");
    else
        RD_LOG_INFO("Module Type: Program module (EXE)");
}

void le_report_cpu_type(const LEFormat* le) {
    switch(le->header.cpu_type) {
        case LE_MOD_CPU_80286: RD_LOG_INFO("CPU Type: 80286 or greater"); break;
        case LE_MOD_CPU_80386: RD_LOG_INFO("CPU Type: 80386 or greater"); break;
        case LE_MOD_CPU_80486: RD_LOG_INFO("CPU Type: 80486 or greater"); break;

        default: {
            RD_LOG_WARN("CPU Type: Unknown %" PRIu16, le->header.cpu_type);
            break;
        }
    }
}

void le_report_os_type(const LEFormat* le) {
    switch(le->header.os_type) {
        case LE_MOD_OS_OS2: RD_LOG_INFO("OS: OS/2 required"); break;
        case LE_MOD_OS_WIN: RD_LOG_INFO("OS: Windows required"); break;
        case LE_MOD_OS_DOS: RD_LOG_INFO("OS: DOS required"); break;
        case LE_MOD_OS_WIN386: RD_LOG_INFO("OS: Windows 386 required"); break;

        default: {
            RD_LOG_INFO("OS: Unknown %d", (int)le->header.os_type);
            break;
        }
    }
}

bool le_read_header(RDReader* r, LEHeader* v) {
    rd_reader_read_byte(r, &v->byte_order);
    rd_reader_read_byte(r, &v->word_order);
    rd_reader_read_le32(r, &v->level);
    rd_reader_read_le16(r, &v->cpu_type);
    rd_reader_read_le16(r, &v->os_type);
    rd_reader_read_le32(r, &v->version);
    rd_reader_read_le32(r, &v->flags);
    rd_reader_read_le32(r, &v->num_pages);
    rd_reader_read_le32(r, &v->eip_obj);
    rd_reader_read_le32(r, &v->eip);
    rd_reader_read_le32(r, &v->esp_obj);
    rd_reader_read_le32(r, &v->esp);
    rd_reader_read_le32(r, &v->page_size);
    rd_reader_read_le32(r, &v->last_page);
    rd_reader_read_le32(r, &v->fixup_size);
    rd_reader_read_le32(r, &v->fixup_cksum);
    rd_reader_read_le32(r, &v->loader_size);
    rd_reader_read_le32(r, &v->loader_cksum);
    rd_reader_read_le32(r, &v->objtab_off);
    rd_reader_read_le32(r, &v->num_objects);
    rd_reader_read_le32(r, &v->objmap_off);
    rd_reader_read_le32(r, &v->idmap_off);
    rd_reader_read_le32(r, &v->rsrc_off);
    rd_reader_read_le32(r, &v->num_rsrcs);
    rd_reader_read_le32(r, &v->resname_off);
    rd_reader_read_le32(r, &v->entry_off);
    rd_reader_read_le32(r, &v->moddir_off);
    rd_reader_read_le32(r, &v->num_moddirs);
    rd_reader_read_le32(r, &v->fixpage_off);
    rd_reader_read_le32(r, &v->fixrec_off);
    rd_reader_read_le32(r, &v->impmod_off);
    rd_reader_read_le32(r, &v->num_impmods);
    rd_reader_read_le32(r, &v->impproc_off);
    rd_reader_read_le32(r, &v->cksum_off);
    rd_reader_read_le32(r, &v->page_off);
    rd_reader_read_le32(r, &v->num_preload);
    rd_reader_read_le32(r, &v->nonres_off);
    rd_reader_read_le32(r, &v->nonres_size);
    rd_reader_read_le32(r, &v->nonres_cksum);
    rd_reader_read_le32(r, &v->autodata_obj);
    rd_reader_read_le32(r, &v->debug_off);
    rd_reader_read_le32(r, &v->debug_len);
    rd_reader_read_le32(r, &v->num_inst_preload);
    rd_reader_read_le32(r, &v->num_inst_demand);
    rd_reader_read_le32(r, &v->heapsize);
    rd_reader_read_le32(r, &v->stacksize);
    rd_reader_read(r, &v->reserved, sizeof(v->reserved));

    return !rd_reader_has_error(r);
}
