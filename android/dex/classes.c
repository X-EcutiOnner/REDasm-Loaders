#include "classes.h"
#include "strings.h"
#include <inttypes.h>

#define DEX_CODE_ITEM_HEADER_SIZE 0x10

typedef struct DEXCodeItem {
    u16 registers_size;
    u16 ins_size;
    u16 outs_size;
    u16 tries_size;
    u32 debug_info_off;
    u32 insns_size;
} DEXCodeItem;

static bool _dex_read_code_item(RDReader* r, DEXCodeItem* v) {
    rd_reader_read_le16(r, &v->registers_size);
    rd_reader_read_le16(r, &v->ins_size);
    rd_reader_read_le16(r, &v->outs_size);
    rd_reader_read_le16(r, &v->tries_size);
    rd_reader_read_le32(r, &v->debug_info_off);
    rd_reader_read_le32(r, &v->insns_size);
    return !rd_reader_has_error(r);
}

static bool _dex_get_class_def(RDReader* r, const DEXFormat* dex, u32 idx,
                               DEXClassDef* cd) {
    if(idx >= dex->header.class_defs_size) return false;

    rd_reader_save(r);
    rd_reader_seek(r, dex->header.class_defs_off +
                          ((u64)idx * DEX_CLASS_DEF_SIZE));

    bool ok = dex_read_class_def(r, cd);
    rd_reader_restore(r);
    return ok;
}

static void _dex_emit_method(RDContext* ctx, RDReader* r, DEXFormat* dex,
                             u32 methodidx, u32 code_off) {
    char* name = rd_strdup(dex_method_name(r, dex, methodidx));

    u64 addr =
        dex->header.method_ids_off + ((u64)methodidx * DEX_METHOD_ID_SIZE);

    if(!code_off) {
        rd_set_external(ctx, addr, NULL, RD_EXT_IMPORTED);
        if(name) rd_library_name(ctx, addr, name);

        rd_free(name);
        return;
    }

    if(code_off >= dex->header.file_size) {
        RD_LOG_WARN("method %" PRIu32 " has an out-of-bounds code_off %" PRIu32,
                    methodidx, code_off);
        rd_free(name);
        return;
    }

    DEXCodeItem ci;
    rd_reader_save(r);
    rd_reader_seek(r, code_off);
    bool ok = _dex_read_code_item(r, &ci);
    rd_reader_restore(r);

    if(!ok) {
        RD_LOG_WARN("method %" PRIu32 " has a truncated code_item", methodidx);
        rd_free(name);
        return;
    }

    rd_library_type(ctx, code_off, "DEX_CODE_ITEM", 0, RD_TYPE_NONE);

    u64 insns = (u64)code_off + DEX_CODE_ITEM_HEADER_SIZE;
    u64 end = insns + ((u64)ci.insns_size * 2);

    if(!ci.insns_size || end > dex->header.file_size) {
        RD_LOG_WARN("method %" PRIu32 " has an invalid insns range", methodidx);
        rd_free(name);
        return;
    }

    rd_library_name(ctx, addr, rd_format("%s_entry", name));
    if(name) rd_library_name(ctx, insns, name);
    rd_set_function(ctx, insns);

    rd_free(name);
}

static bool _dex_walk_methods(RDContext* ctx, RDReader* r, DEXFormat* dex,
                              u64 count) {
    u64 methodidx = 0;

    for(u64 i = 0; i < count; i++) {
        RDULeb128 diff, flags, codeoff;

        if(!rd_reader_read_uleb128(r, &diff) ||
           !rd_reader_read_uleb128(r, &flags) ||
           !rd_reader_read_uleb128(r, &codeoff)) {
            RD_LOG_WARN("truncated encoded_method");
            return false;
        }

        methodidx += diff.value;

        if(methodidx >= dex->header.method_ids_size) {
            RD_LOG_WARN("encoded_method index %" PRIu64 " out of range",
                        methodidx);
            return false;
        }

        if(codeoff.value > UINT32_MAX) {
            RD_LOG_WARN("encoded_method has an implausible code_off");
            return false;
        }

        _dex_emit_method(ctx, r, dex, (u32)methodidx, (u32)codeoff.value);
    }

    return true;
}

static bool _dex_skip_fields(RDReader* r, u64 count) {
    for(u64 i = 0; i < count; i++) {
        RDULeb128 diff, flags;

        if(!rd_reader_read_uleb128(r, &diff) ||
           !rd_reader_read_uleb128(r, &flags))
            return false;
    }

    return true;
}

static bool _dex_walk_class_data(RDContext* ctx, RDReader* r, DEXFormat* dex,
                                 u32 class_data_off) {
    if(class_data_off >= dex->header.file_size) return false;

    bool ok = false;
    rd_reader_save(r);
    rd_reader_seek(r, class_data_off);

    RDULeb128 nstatic, ninstance, ndirect, nvirtual;

    if(!rd_reader_read_uleb128(r, &nstatic) ||
       !rd_reader_read_uleb128(r, &ninstance) ||
       !rd_reader_read_uleb128(r, &ndirect) ||
       !rd_reader_read_uleb128(r, &nvirtual)) {
        RD_LOG_WARN("truncated class_data_item at %" PRIu32, class_data_off);
        goto done;
    }

    // a corrupt count must not turn into a long walk over garbage
    if(nstatic.value + ninstance.value > dex->header.field_ids_size ||
       ndirect.value + nvirtual.value > dex->header.method_ids_size) {
        RD_LOG_WARN("class_data_item at %" PRIu32
                    " declares implausible counts",
                    class_data_off);
        goto done;
    }

    if(!_dex_skip_fields(r, nstatic.value) ||
       !_dex_skip_fields(r, ninstance.value)) {
        RD_LOG_WARN("truncated encoded_field list");
        goto done;
    }

    if(!_dex_walk_methods(ctx, r, dex, ndirect.value)) goto done;
    if(!_dex_walk_methods(ctx, r, dex, nvirtual.value)) goto done;

    ok = true;

done:
    rd_reader_restore(r);
    return ok;
}

bool dex_walk_classes(RDContext* ctx, RDReader* r, DEXFormat* dex) {
    u32 walked = 0;

    for(u32 i = 0; i < dex->header.class_defs_size; i++) {
        DEXClassDef cd;

        if(!_dex_get_class_def(r, dex, i, &cd)) {
            RD_LOG_WARN("cannot read class_def %" PRIu32, i);
            continue;
        }

        const char* cls = dex_type_descriptor(r, dex, cd.class_idx);
        // legal: a class with no fields and no methods, e.g. an annotation
        if(!cd.class_data_off) continue;

        if(_dex_walk_class_data(ctx, r, dex, cd.class_data_off)) walked++;
    }

    return true;
}
