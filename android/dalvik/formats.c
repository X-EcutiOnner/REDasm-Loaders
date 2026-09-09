#include "formats.h"

static bool _dalvik_index_to_address(const RDContext* ctx, const Dalvik* dalvik,
                                     u8 kind, u32 idx, RDAddress* addr) {
    if(!dalvik->is_valid) return false;

    const DEXHeader* h = &dalvik->header;

    if(kind == DALVIK_IDX_STRING) {
        if(idx >= h->string_ids_size) return false;

        u32 dataoff;
        if(!rd_read_le32(ctx,
                         h->string_ids_off + ((u64)idx * DEX_STRING_ID_SIZE),
                         &dataoff))
            return false;

        *addr = dataoff;
        return true;
    }

    u32 off, size, stride;

    switch(kind) {
        case DALVIK_IDX_TYPE:
            off = h->type_ids_off;
            size = h->type_ids_size;
            stride = DEX_TYPE_ID_SIZE;
            break;

        case DALVIK_IDX_PROTO:
            off = h->proto_ids_off;
            size = h->proto_ids_size;
            stride = DEX_PROTO_ID_SIZE;
            break;

        case DALVIK_IDX_FIELD:
            off = h->field_ids_off;
            size = h->field_ids_size;
            stride = DEX_FIELD_ID_SIZE;
            break;

        case DALVIK_IDX_METHOD:
        case DALVIK_IDX_METHOD_PROTO: // 45cc/4rcc: BBBB is the method index
            off = h->method_ids_off;
            size = h->method_ids_size;
            stride = DEX_METHOD_ID_SIZE;
            break;

        /*
         * call_site_ids and method_handles have no header fields.
         * They were added in 038 and exist only in map_list, which the
         * processor does not read. Fall back to the raw index.
         */
        case DALVIK_IDX_CALL_SITE:
        case DALVIK_IDX_METHOD_HANDLE:
        default: return false;
    }

    if(idx >= size) return false;

    *addr = (RDAddress)off + ((u64)idx * stride);
    return true;
}

static void _dalvik_set_index_operand(const RDContext* ctx,
                                      const Dalvik* dalvik, RDOperand* op,
                                      u8 kind, u32 idx) {
    RDAddress addr;

    if(_dalvik_index_to_address(ctx, dalvik, kind, idx, &addr)) {
        op->kind = RD_OP_ADDR;
        op->addr = addr;
    }
    else {
        op->kind = DALVIK_OP_INDEX;
        op->cnst = idx;
    }

    // the kind drives rendering; the index is kept because an address does
    // not lead back to it
    op->userdata1 = kind;
    op->userdata2 = idx;
}

const char* dalvik_index_prefix(u8 kind) {
    switch(kind) {
        case DALVIK_IDX_STRING: return "string@";
        case DALVIK_IDX_TYPE: return "type@";
        case DALVIK_IDX_FIELD: return "field@";
        case DALVIK_IDX_METHOD: return "meth@";
        case DALVIK_IDX_PROTO: return "proto@";
        case DALVIK_IDX_METHOD_PROTO: return "method_proto@";
        case DALVIK_IDX_CALL_SITE: return "call_site@";
        case DALVIK_IDX_METHOD_HANDLE: return "method_handle@";
        default: return "idx@";
    }
}

bool dalvik_decode_21c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    _dalvik_set_index_operand(ctx, dalvik, &instr->operands[1],
                              info->index_kind, unit1);

    return true;
}

bool dalvik_decode_35c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* op, u16 unit0,
                       const Dalvik* dalvik) {
    u16 unit1, unit2;
    if(!rd_read_le16(ctx, instr->address + dalvik_u2b(1), &unit1)) return false;
    if(!rd_read_le16(ctx, instr->address + dalvik_u2b(2), &unit2)) return false;

    u8 count = (u8)((unit0 >> 12) & 0xF);
    if(count > 5) return false; // A is capped at 5 by the format

    instr->operands[0].kind = DALVIK_OP_REGLIST;
    instr->operands[0].count = (u8)((unit0 >> 12) & 0xF);
    instr->operands[0].cnst = (u64)unit2 | ((u64)((unit0 >> 8) & 0xF) << 16);

    RDOperand* ref = &instr->operands[1];
    RDAddress addr;

    if(_dalvik_index_to_address(ctx, dalvik, op->index_kind, unit1, &addr)) {
        ref->kind = RD_OP_ADDR;
        ref->addr = addr;
    }
    else {
        // no valid header, or the index is out of range: keep the raw value
        // visible rather than dropping the operand
        ref->kind = DALVIK_OP_INDEX;
        ref->cnst = unit1;
        ref->userdata1 = op->index_kind;
    }

    return true;
}
