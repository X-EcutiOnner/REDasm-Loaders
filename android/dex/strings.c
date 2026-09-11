#include "strings.h"
#include "dex/mutf8.h"
#include <inttypes.h>
#include <string.h>

#define DEX_NAME_SEP '_'
#define DEX_SHORTY_SEP '@'

static const char* _dex_primitive_name(char c) {
    switch(c) {
        case 'V': return "void";
        case 'Z': return "boolean";
        case 'B': return "byte";
        case 'S': return "short";
        case 'C': return "char";
        case 'I': return "int";
        case 'J': return "long";
        case 'F': return "float";
        case 'D': return "double";
        default: return NULL;
    }
}

static void _dex_append_sanitized(RDScratchBuffer* buf, const char* s) {
    for(; *s; s++) {
        char c = *s;

        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '$';

        rd_scratch_push(buf, ok ? c : DEX_NAME_SEP);
    }
}

static void _dex_append_type_name(RDScratchBuffer* buf, const char* desc) {
    usize dims = 0;

    while(*desc == '[') {
        dims++;
        desc++;
    }

    if(*desc == 'L') {
        const char* start = desc + 1;
        const char* end = strchr(start, ';');
        if(!end) end = start + strlen(start);

        // simple name only: everything after the last package separator
        const char* simple = start;

        for(const char* p = start; p < end; p++) {
            if(*p == '/') simple = p + 1;
        }

        for(const char* p = simple; p < end; p++) {
            char c = *p;

            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '$';

            rd_scratch_push(buf, ok ? c : DEX_NAME_SEP);
        }
    }
    else {
        const char* prim = _dex_primitive_name(*desc);

        if(prim)
            rd_scratch_puts(buf, prim);
        else
            _dex_append_sanitized(buf, desc); // unknown: keep it visible
    }

    for(usize i = 0; i < dims; i++)
        rd_scratch_puts(buf, "_arr");
}

static bool _dex_get_type_descriptor_idx(RDReader* r, const DEXFormat* dex,
                                         u32 typeidx, u32* stridx) {
    if(typeidx >= dex->header.type_ids_size) {
        RD_LOG_FAIL("type index %" PRIu32 " out of range (%" PRIu32 ")",
                    typeidx, dex->header.type_ids_size);
        return false;
    }

    bool ok = false;
    rd_reader_save(r);
    rd_reader_seek(r, dex->header.type_ids_off + ((u64)typeidx * sizeof(u32)));

    DEXTypeId tid;

    if(dex_read_type_id(r, &tid)) {
        if(stridx) *stridx = tid.descriptor_idx;
        ok = true;
    }

    rd_reader_restore(r);
    return ok;
}

static bool _dex_get_field_id(RDReader* r, const DEXFormat* dex, u32 fieldidx,
                              DEXFieldId* fid) {
    if(fieldidx >= dex->header.field_ids_size) {
        RD_LOG_FAIL("field index %" PRIu32 " out of range (%" PRIu32 ")",
                    fieldidx, dex->header.field_ids_size);
        return false;
    }

    rd_reader_save(r);
    rd_reader_seek(r, dex->header.field_ids_off +
                          ((u64)fieldidx * DEX_FIELD_ID_SIZE));

    bool ok = dex_read_field_id(r, fid);
    rd_reader_restore(r);
    return ok;
}

static bool _dex_get_proto_id(RDReader* r, const DEXFormat* dex, u32 protoidx,
                              DEXProtoId* pid) {
    if(protoidx >= dex->header.proto_ids_size) {
        RD_LOG_FAIL("proto index %" PRIu32 " out of range (%" PRIu32 ")",
                    protoidx, dex->header.proto_ids_size);
        return false;
    }

    rd_reader_save(r);
    rd_reader_seek(r, dex->header.proto_ids_off +
                          ((u64)protoidx * DEX_PROTO_ID_SIZE));

    bool ok = dex_read_proto_id(r, pid);
    rd_reader_restore(r);
    return ok;
}

static bool _dex_get_method_id(RDReader* r, const DEXFormat* dex, u32 methodidx,
                               DEXMethodId* mid) {
    if(methodidx >= dex->header.method_ids_size) {
        RD_LOG_FAIL("method index %" PRIu32 " out of range (%" PRIu32 ")",
                    methodidx, dex->header.method_ids_size);
        return false;
    }

    rd_reader_save(r);
    rd_reader_seek(r, dex->header.method_ids_off +
                          ((u64)methodidx * DEX_METHOD_ID_SIZE));

    bool ok = dex_read_method_id(r, mid);
    rd_reader_restore(r);
    return ok;
}

bool dex_get_string_offset(RDReader* r, const DEXHeader* hdr, u32 idx,
                           u32* off) {
    if(idx >= hdr->string_ids_size) {
        RD_LOG_FAIL("string index %" PRIu32 " out of range (%" PRIu32 ")", idx,
                    hdr->string_ids_size);
        return false;
    }

    u32 dataoff = 0;
    bool ok = false;

    rd_reader_save(r);
    rd_reader_seek(r, hdr->string_ids_off + ((u64)idx * sizeof(u32)));

    if(rd_reader_read_le32(r, &dataoff)) {
        if(dataoff < hdr->file_size) {
            if(off) *off = dataoff;
            ok = true;
        }
        else {
            RD_LOG_FAIL("string %" PRIu32 " data offset %" PRIu32
                        " is out of bounds",
                        idx, dataoff);
        }
    }

    rd_reader_restore(r);
    return ok;
}

bool dex_string_extent(RDReader* r, const DEXHeader* hdr, u32 dataoff,
                       RDAddress* text, usize* nbytes) {
    if(dataoff >= hdr->file_size) return false;

    bool ok = false;
    rd_reader_save(r);
    rd_reader_seek(r, dataoff);

    RDULeb128 utf16size;
    if(!rd_reader_read_uleb128(r, &utf16size)) goto done;

    // an implausible declared length is corruption, not a long string
    if(utf16size.value > hdr->file_size) goto done;

    /*
     * utf16_size counts UTF-16 code units, not bytes: MUTF-8 uses up to
     * three bytes per unit, so it bounds the scan rather than sizing it.
     * The terminator is what actually ends the data.
     * MUTF-8 encodes an embedded U+0000 as C0 80 precisely so a bare NUL never
     * appears.
     */
    usize maxbytes = (usize)utf16size.value * 3;
    usize n = 0;

    while(n <= maxbytes) {
        u8 b;
        if(!rd_reader_read_byte(r, &b)) goto done; // truncated

        if(!b) {
            ok = true;
            break;
        }

        n++;
    }

    if(!ok) goto done;

    if(text) *text = dataoff + utf16size.length;
    if(nbytes) *nbytes = n;

done:
    rd_reader_restore(r);
    return ok;
}

const char* dex_read_string_to(RDReader* r, const DEXHeader* hdr, u32 idx,
                               RDScratchBuffer* raw, RDScratchBuffer* buf) {
    bool ok = false;
    usize maxbytes = 0, n = 0;

    u32 dataoff;
    if(!dex_get_string_offset(r, hdr, idx, &dataoff)) return NULL;

    rd_reader_save(r);
    rd_reader_seek(r, dataoff);

    RDULeb128 utf16size;
    if(!rd_reader_read_uleb128(r, &utf16size)) {
        RD_LOG_FAIL("string %" PRIu32 " has a bad length prefix", idx);
        goto fail;
    }

    if(utf16size.value > hdr->file_size) {
        RD_LOG_FAIL("string %" PRIu32 " declares an invalid length", idx);
        goto fail;
    }

    maxbytes = (usize)utf16size.value * 3;

    rd_scratch_clear(raw);
    rd_scratch_reserve(raw, maxbytes);

    while(n <= maxbytes) {
        u8 b;
        if(!rd_reader_read_byte(r, &b)) break; // truncated at EOF

        if(!b) {
            ok = true;
            break;
        }

        rd_scratch_putchar(raw, (char)b);
        n++;
    }

    if(!ok) {
        RD_LOG_FAIL("string %" PRIu32 " is unterminated or too long", idx);
        goto fail;
    }

    ok = dex_mutf8_to_utf8(raw, buf);

    if(!ok) {
        RD_LOG_FAIL("string %" PRIu32 " has a malformed encoding", idx);
        goto fail;
    }

    rd_reader_restore(r);
    return rd_scratch_data(buf);

fail:
    rd_reader_restore(r);
    return NULL;
}

const char* dex_read_string(RDReader* r, DEXFormat* dex, u32 idx,
                            RDScratchBuffer* buf) {
    return dex_read_string_to(r, &dex->header, idx, dex->raw_buf, buf);
}

const char* dex_type_descriptor(RDReader* r, DEXFormat* dex, u32 typeidx) {
    u32 stridx;
    if(!_dex_get_type_descriptor_idx(r, dex, typeidx, &stridx)) return NULL;
    return dex_read_string(r, dex, stridx, dex->string_buf);
}

const char* dex_type_name(RDReader* r, DEXFormat* dex, u32 typeidx) {
    const char* desc = dex_type_descriptor(r, dex, typeidx);
    if(!desc) return NULL;

    rd_scratch_clear(dex->name_buf);
    _dex_append_type_name(dex->name_buf, desc);
    rd_scratch_push(dex->name_buf, '\0');
    return rd_scratch_data(dex->name_buf);
}

const char* dex_method_name(RDReader* r, DEXFormat* dex, u32 methodidx) {
    DEXMethodId mid;
    if(!_dex_get_method_id(r, dex, methodidx, &mid)) return NULL;

    DEXProtoId pid;
    if(!_dex_get_proto_id(r, dex, mid.proto_idx, &pid)) return NULL;

    rd_scratch_clear(dex->name_buf);

    const char* cls = dex_type_descriptor(r, dex, mid.class_idx);
    if(!cls) return NULL;
    _dex_append_type_name(dex->name_buf, cls);

    rd_scratch_push(dex->name_buf, DEX_NAME_SEP);

    const char* name = dex_read_string(r, dex, mid.name_idx, dex->string_buf);
    if(!name) return NULL;
    _dex_append_sanitized(dex->name_buf, name);

    rd_scratch_push(dex->name_buf, DEX_SHORTY_SEP);

    const char* shorty =
        dex_read_string(r, dex, pid.shorty_idx, dex->string_buf);
    if(!shorty) return NULL;
    _dex_append_sanitized(dex->name_buf, shorty);

    rd_scratch_push(dex->name_buf, '\0');
    return rd_scratch_data(dex->name_buf);
}

const char* dex_field_name(RDReader* r, DEXFormat* dex, u32 fieldidx) {
    DEXFieldId fid;
    if(!_dex_get_field_id(r, dex, fieldidx, &fid)) return NULL;

    rd_scratch_clear(dex->name_buf);

    const char* cls = dex_type_descriptor(r, dex, fid.class_idx);
    if(!cls) return NULL;
    _dex_append_type_name(dex->name_buf, cls);

    rd_scratch_push(dex->name_buf, DEX_NAME_SEP);

    const char* name = dex_read_string(r, dex, fid.name_idx, dex->string_buf);
    if(!name) return NULL;
    _dex_append_sanitized(dex->name_buf, name);

    rd_scratch_push(dex->name_buf, '\0');
    return rd_scratch_data(dex->name_buf);
}

const char* dex_proto_name(RDReader* r, DEXFormat* dex, u32 protoidx) {
    DEXProtoId pid;
    if(!_dex_get_proto_id(r, dex, protoidx, &pid)) return NULL;

    const char* shorty =
        dex_read_string(r, dex, pid.shorty_idx, dex->string_buf);
    if(!shorty) return NULL;

    rd_scratch_clear(dex->name_buf);
    rd_scratch_puts(dex->name_buf, "proto_");
    _dex_append_sanitized(dex->name_buf, shorty);
    rd_scratch_push(dex->name_buf, '\0');
    return rd_scratch_data(dex->name_buf);
}
