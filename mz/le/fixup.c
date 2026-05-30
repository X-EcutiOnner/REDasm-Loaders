#include "fixup.h"
#include "le/imports.h"

#define LE_FIXUP_SOURCE_MASK 0x0F
#define LE_FIXUP_SOURCE_BYTE 0x00
#define LE_FIXUP_SOURCE_UNDEFINED 0x01
#define LE_FIXUP_SOURCE_SEG 0x02
#define LE_FIXUP_SOURCE_PTR_32 0x03
// #define LE_FIXUP_SOURCE_UNDEFINED        0x04
#define LE_FIXUP_SOURCE_OFF_16 0x05
#define LE_FIXUP_SOURCE_PTR_48 0x06
#define LE_FIXUP_SOURCE_OFF_32 0x07
#define LE_FIXUP_SOURCE_OFF_32_REL 0x08

#define LE_FIXUP_TARGET_MASK 0x03
#define LE_FIXUP_TARGET_INTERNAL 0x00
#define LE_FIXUP_TARGET_EXT_ORD 0x01
#define LE_FIXUP_TARGET_EXT_NAME 0x02
#define LE_FIXUP_TARGET_INT_VIA_ENTRY 0x03

#define LE_FIXUP_SRCFLAG_FIXUP_TO_ALIAS 0x10
#define LE_FIXUP_SRCFLAG_LIST 0x20

#define LE_FIXUP_TGTFLAG_ADDITIVE_VAL 0x04
#define LE_FIXUP_TGTFLAG_INT_CHAIN 0x08
#define LE_FIXUP_TGTFLAG_OFF_32BIT 0x10
#define LE_FIXUP_TGTFLAG_ADD_32BIT 0x20
#define LE_FIXUP_TGTFLAG_OBJ_MOD_16BIT 0x40
#define LE_FIXUP_TGTFLAG_ORDINAL_8BIT 0x80

static void _le_patch_fixup(RDContext* ctx, u8 type, RDAddress address,
                            RDAddress target) {
    switch(type & LE_FIXUP_SOURCE_MASK) {
        case LE_FIXUP_SOURCE_OFF_32:
            rd_write_le32(ctx, address, (u32)target);
            break;

        case LE_FIXUP_SOURCE_OFF_32_REL:
            rd_write_le32(ctx, address,
                          (u32)(target - (address + sizeof(u32))));
            break;

        case LE_FIXUP_SOURCE_OFF_16:
            rd_write_le16(ctx, address, (u16)target);
            break;

        case LE_FIXUP_SOURCE_SEG:
        case LE_FIXUP_SOURCE_PTR_32:
        case LE_FIXUP_SOURCE_PTR_48: {
            rd_log(RD_LOG_WARN, LE_PLUGIN_ID,
                   "unhandled fixup source type 0x%02x at 0x%08x",
                   type & LE_FIXUP_SOURCE_MASK, (u32)address);
            break;
        }

        default: break;
    }
}

void le_fixup_apply(const LEFormat* le, RDAddress page_va, u32 page_idx,
                    RDReader* r, RDContext* ctx) {
    if(!le->header.fixpage_off || !le->header.fixrec_off) return;

    // Fixup Page Table: array of u32 offsets into the Fixup Record Table.
    // Entry [page_idx] = start offset of this page's fixups.
    // Entry [page_idx+1] = start offset of next page's fixups = our end.
    u32 fixup_page_base = le->base + le->header.fixpage_off;
    rd_reader_seek(r, fixup_page_base + (page_idx * sizeof(u32)));

    u32 fixup_start_off, fixup_end_off;
    rd_reader_read_le32(r, &fixup_start_off);
    rd_reader_read_le32(r, &fixup_end_off);

    u32 fixup_base = le->base + le->header.fixrec_off;
    u32 fixup_start = fixup_base + fixup_start_off;
    u32 fixup_end = fixup_base + fixup_end_off;
    if(fixup_start == fixup_end) return;

    rd_reader_seek(r, fixup_start);

    while(rd_reader_tell(r) < fixup_end) {
        u8 src_type, flags;
        rd_reader_read_u8(r, &src_type);
        rd_reader_read_u8(r, &flags);

        bool has_srclist = (src_type & LE_FIXUP_SRCFLAG_LIST) != 0;

        u16 src_off = 0;
        u8 src_cnt = 0;

        if(has_srclist)
            rd_reader_read_u8(r, &src_cnt);
        else
            rd_reader_read_le16(r, &src_off);

        RDAddress src_addr = page_va + (i16)src_off;
        RDAddress current_target = 0;

        // target type determines what follows
        switch(flags & LE_FIXUP_TARGET_MASK) {
            case LE_FIXUP_TARGET_INTERNAL: {
                u16 obj_idx;

                if(flags & LE_FIXUP_TGTFLAG_OBJ_MOD_16BIT) {
                    rd_reader_read_le16(r, &obj_idx);
                }
                else {
                    u8 b;
                    rd_reader_read_u8(r, &b);
                    obj_idx = b;
                }

                u32 tgt_off = 0;

                if((src_type & LE_FIXUP_SOURCE_MASK) != LE_FIXUP_SOURCE_SEG) {
                    if(flags & LE_FIXUP_TGTFLAG_OFF_32BIT) {
                        rd_reader_read_le32(r, &tgt_off);
                    }
                    else {
                        u16 off16;
                        rd_reader_read_le16(r, &off16);
                        tgt_off = (u32)off16;
                    }
                }

                current_target = le_seg_address(obj_idx, tgt_off);
                break;
            }

            case LE_FIXUP_TARGET_EXT_ORD: {
                u16 mod_idx;
                if(flags & LE_FIXUP_TGTFLAG_OBJ_MOD_16BIT) {
                    rd_reader_read_le16(r, &mod_idx);
                }
                else {
                    u8 b;
                    rd_reader_read_u8(r, &b);
                    mod_idx = b;
                }

                u32 ordinal;

                if(flags & LE_FIXUP_TGTFLAG_ORDINAL_8BIT) {
                    u8 b;
                    rd_reader_read_u8(r, &b);
                    ordinal = b;
                }
                else {
                    u16 b;
                    rd_reader_read_le16(r, &b);
                    ordinal = b;
                }

                current_target = le_importslice_resolve_ord(&le->imports, ctx,
                                                            mod_idx, ordinal);
                break;
            }

            case LE_FIXUP_TARGET_EXT_NAME: {
                u16 mod_idx;
                if(flags & LE_FIXUP_TGTFLAG_OBJ_MOD_16BIT)
                    rd_reader_read_le16(r, &mod_idx);
                else {
                    u8 b;
                    rd_reader_read_u8(r, &b);
                    mod_idx = b;
                }

                u32 name_off;
                if(flags & LE_FIXUP_TGTFLAG_OFF_32BIT)
                    rd_reader_read_le32(r, &name_off);
                else {
                    u16 b;
                    rd_reader_read_le16(r, &b);
                    name_off = b;
                }

                rd_reader_begin(r);
                const char* proc = le_import_proc_name(le, r, name_off);
                rd_reader_end(r);

                current_target =
                    le_importslice_resolve(&le->imports, ctx, mod_idx, proc);

                break;
            }

            case LE_FIXUP_TARGET_INT_VIA_ENTRY: {
                u16 entry_ord;
                if(flags & LE_FIXUP_TGTFLAG_OBJ_MOD_16BIT) {
                    rd_reader_read_le16(r, &entry_ord);
                }
                else {
                    u8 b;
                    rd_reader_read_u8(r, &b);
                    entry_ord = b;
                }

                rd_log(RD_LOG_WARN, LE_PLUGIN_ID,
                       "INT_VIA_ENTRY fixup (ordinal %u) not yet implemented",
                       entry_ord);
                break;
            }

            default: break;
        }

        // consume additive
        if(flags & LE_FIXUP_TGTFLAG_ADDITIVE_VAL) {
            if(flags & LE_FIXUP_TGTFLAG_ADD_32BIT) {
                u32 v;
                rd_reader_read_le32(r, &v);
            }
            else {
                u16 v;
                rd_reader_read_le16(r, &v);
            }
        }

        // srclist comes last
        if(has_srclist) {
            for(u8 i = 0; i < src_cnt; i++) {
                i16 off;
                rd_reader_read_le16(r, (u16*)&off);
                if(current_target)
                    _le_patch_fixup(ctx, src_type, page_va + off,
                                    current_target);
            }
        }
        else if(current_target)
            _le_patch_fixup(ctx, src_type, src_addr, current_target);

        if(rd_reader_has_error(r)) break;
    }
}
