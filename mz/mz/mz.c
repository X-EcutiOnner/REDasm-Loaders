#include "mz.h"
#include "common.h"
#include "hooks.h"
#include <stdlib.h>

// References
// - http://www.techhelpmanual.com/354-exe_file_header_layout.html
// - http://fileformats.archiveteam.org/wiki/MS-DOS_EXE

// DOS MZ EXE loads at a paragraph-aligned address.
// The conventional load segment is 0x0000, the OS picks the actual
// physical segment but for static analysis we fix it at 0.
#define MZ_LOAD_SEGMENT 0x0000
#define MZ_PARAGRAPH 16

typedef struct MZReloc {
    u16 offset;
    u16 segment;
} MZReloc;

static usize _mz_header_size(const ImageDosHeader* dh) {
    return (usize)dh->e_cparhdr * MZ_PARAGRAPH;
}

static usize _mz_image_size(const ImageDosHeader* dh) {
    usize size = (usize)dh->e_cp * 512;
    if(dh->e_cblp) size -= 512 - dh->e_cblp;
    return size;
}

// static void _mz_parse_relocs(const ImageDosHeader* dh, RDContext* ctx) {
//     if(!dh->e_lfarlc) return;
//
//     RDReader* r = rd_get_input_reader(ctx);
//     rd_reader_seek(r, dh->e_lfarlc);
//
//     for(u16 i = 0; i < dh->e_crlc; i++) {
//         MZReloc reloc;
//         rd_reader_read_le16(r, &reloc.offset);
//         rd_reader_read_le16(r, &reloc.segment);
//         if(rd_reader_has_error(r)) break;
//
//         // relocation target: (reloc.segment + load_segment) * 16 +
//         reloc.offset RDAddress target =
//             ((reloc.segment + MZ_LOAD_SEGMENT) * MZ_PARAGRAPH) +
//             reloc.offset;
//
//         // the word at target is a segment value baked by the linker.
//         // with MZ_LOAD_SEGMENT=0 it's already correct, just mark as data.
//         rd_auto_type(ctx, target, "u16", 1, RD_TYPE_NONE);
//     }
// }

static bool mz_parse(RDLoader* ldr, const RDLoaderRequest* req) {
    ImageDosHeader* dh = (ImageDosHeader*)ldr;
    if(!mz_read_dos_header(req->input, dh)) return false;

    u32 sig = mz_read_signature(req->input, dh);

    return sig != IMAGE_NT_SIGNATURE && (u16)sig != IMAGE_NE_SIGNATURE &&
           (u16)sig != IMAGE_LE_SIGNATURE;
}

static bool mz_load(RDLoader* ldr, RDContext* ctx) {
    mz_register_dos_hooks(ctx);

    ImageDosHeader* dh = (ImageDosHeader*)ldr;
    usize hdrbytes = _mz_header_size(dh);
    usize imgsize = _mz_image_size(dh) - hdrbytes;

    // Map the full 64KB real-mode address space as one segment
    // Load image starts at paragraph 0 (load segment fixed at 0x0000)
    RDAddress baseaddr = (RDAddress)MZ_LOAD_SEGMENT * MZ_PARAGRAPH;
    rd_map_segment(ctx, "MEM", baseaddr, baseaddr + 0x10000, RD_SP_RWX);
    rd_map_input_n(ctx, hdrbytes, baseaddr, imgsize);

    // _mz_parse_relocs(dh, ctx);

    RDAddress cs_base = (RDAddress)(dh->e_cs + MZ_LOAD_SEGMENT) * MZ_PARAGRAPH;
    RDAddress entry = cs_base + dh->e_ip;

    rd_library_regval(ctx, entry, "cs",
                      (RDRegValue)(dh->e_cs + MZ_LOAD_SEGMENT) * MZ_PARAGRAPH);
    rd_library_regval(ctx, entry, "ss",
                      (RDRegValue)(dh->e_ss + MZ_LOAD_SEGMENT) * MZ_PARAGRAPH);
    rd_library_regval(ctx, entry, "sp", dh->e_sp);

    rd_set_entry_point(ctx, entry, NULL);
    return true;
}

static RDLoader* mz_create(const RDLoaderPlugin* plugin) {
    RD_UNUSED(plugin);
    return calloc(1, sizeof(ImageDosHeader));
}

static void mz_destroy(RDLoader* ldr) { free(ldr); }

static const char* mz_get_processor(RDLoader* ldr, const RDContext* ctx) {
    RD_UNUSED(ldr);
    RD_UNUSED(ctx);
    return "x86_16_real";
}

const RDLoaderPlugin MZ_LOADER = {
    .level = RD_API_LEVEL,
    .id = "dos_mz",
    .name = "DOS MZ Executable",
    .create = mz_create,
    .destroy = mz_destroy,
    .parse = mz_parse,
    .load = mz_load,
    .get_processor = mz_get_processor,
};
