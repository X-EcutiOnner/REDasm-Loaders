#include "exports.h"

#define LE_BUNDLE_UNUSED 0x00    // gap in ordinal sequence
#define LE_BUNDLE_16BIT 0x01     // 16-bit entry
#define LE_BUNDLE_286GATE 0x02   // 286 call gate (rare, 16-bit compat)
#define LE_BUNDLE_32BIT 0x03     // 32-bit entry, common
#define LE_BUNDLE_FORWARDER 0x04 // forwarder to another module

/* Name table format (both resident and non-resident):
 *   u8  len         byte count of name, 0 = end of table
 *   u8  name[len]   NOT null-terminated
 *   u16 ordinal     ordinal this name maps to (0 = module name, skip)
 *
 * Returns the address for a given ordinal by walking the entry table.
 * ordinal is 1-based. Returns 0 if not found.
 */
static RDAddress _le_entry_address(const LEFormat* le, RDReader* r,
                                   u16 ordinal) {
    if(!le->header.entry_off) return 0;

    u64 pos = (u64)le->base + le->header.entry_off;
    rd_reader_seek(r, pos);

    u16 ord = 1; // ordinals are 1-based, assigned sequentially

    for(;;) {
        u8 count, type;
        rd_reader_read_byte(r, &count);
        rd_reader_read_byte(r, &type);

        if(rd_reader_has_error(r) || count == 0) break; // end of table

        u8 bundle_type = type & 0x7F; // bit 7 = "exported via entry table" flag

        if(bundle_type == LE_BUNDLE_UNUSED) {
            // Gap: advance ordinal counter, no data follows
            ord += count;
            continue;
        }

        // Non-unused bundles: read object index (u16, 1-based) shared by all
        // entries in this bundle
        u16 obj_idx;
        rd_reader_read_le16(r, &obj_idx);

        for(u8 i = 0; i < count; i++) {
            u8 entry_flags;
            u32 entry_off = 0;

            rd_reader_read_byte(
                r,
                &entry_flags); // per-entry flags (exported, uses shared data)

            switch(bundle_type) {
                case LE_BUNDLE_16BIT: {
                    u16 off16;
                    rd_reader_read_le16(r, &off16);
                    entry_off = off16;
                    break;
                }

                case LE_BUNDLE_32BIT: {
                    rd_reader_read_le32(r, &entry_off);
                    break;
                }

                case LE_BUNDLE_286GATE: {
                    // callgate: u16 offset + u16 callgate selector, skip
                    u16 v;
                    rd_reader_read_le16(r, &v);
                    rd_reader_read_le16(r, &v);
                    ord++;
                    continue;
                }

                case LE_BUNDLE_FORWARDER: {
                    // forwarder: u16 module_ord + u32 proc_name_or_ord, skip
                    u16 v;
                    rd_reader_read_le16(r, &v);
                    u32 w;
                    rd_reader_read_le32(r, &w);
                    ord++;
                    continue;
                }

                default: break;
            }

            if(ord == ordinal) return le_seg_address(le, obj_idx, entry_off);

            ord++;
        }

        if(rd_reader_has_error(r)) break;
    }

    return 0;
}

static void _le_read_name_table(const LEFormat* le, RDReader* r, u64 table_off,
                                RDContext* ctx) {
    if(!table_off) return;

    rd_reader_seek(r, table_off);

    for(;;) {
        u8 len;
        rd_reader_read_byte(r, &len);
        if(rd_reader_has_error(r) || len == 0) break; // end of table

        char name[256];
        rd_reader_read(r, name, len);
        name[len] = '\0';

        u16 ordinal;
        rd_reader_read_le16(r, &ordinal);

        if(rd_reader_has_error(r)) break;

        // ordinal 0 = module name entry, not a function export, skip
        if(ordinal == 0) continue;

        rd_reader_save(r);
        RDAddress addr = _le_entry_address(le, r, ordinal);
        rd_reader_restore(r);

        if(addr) {
            rd_set_external(ctx, addr, NULL, RD_EXT_EXPORTED);
            rd_library_name(ctx, addr, name);
        }
    }
}

void le_exports_read(const LEFormat* le, RDContext* ctx) {
    RDReader* r = rd_get_input_reader(ctx);

    // Resident name table: offset relative to LE header base
    _le_read_name_table(le, r, (u64)le->base + le->header.resname_off, ctx);

    // Non-resident name table: offset is FILE-ABSOLUTE, not LE-header-relative
    if(le->header.nonres_off && le->header.nonres_size)
        _le_read_name_table(le, r, (u64)le->header.nonres_off, ctx);
}

RDAddress le_exports_entry(const LEFormat* le, u16 ordinal, RDContext* ctx) {
    RDReader* r = rd_get_input_reader(ctx);
    return _le_entry_address(le, r, ordinal);
}
