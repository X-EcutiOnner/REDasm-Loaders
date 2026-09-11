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

        RDULeb128 len;
        if(!rd_read_uleb128(ctx, dataoff, &len)) return false;

        *addr = dataoff + len.length;
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

bool dalvik_decode_10t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(ctx);
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    i8 off = (i8)((unit0 >> 8) & 0xFF);

    instr->operands[0].kind = RD_OP_ADDR;
    instr->operands[0].addr = instr->address + ((i64)off * 2);
    return true;
}

bool dalvik_decode_21h(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    i64 v = (instr->id == DALVIK_ID_CONST_WIDE_HIGH16)
                ? ((i64)unit1 << 48)
                : (i64)((i32)((u32)unit1 << 16));

    rd_instr_set_op_scnst(instr, 1, v);
    return true;
}

bool dalvik_decode_21s(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    rd_instr_set_op_scnst(instr, 1, (i16)unit1);
    return true;
}

bool dalvik_decode_11n(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(ctx);
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    i8 lit = (i8)((unit0 >> 12) & 0xF);
    if(lit & 0x8) lit = (i8)(lit | 0xF0);

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xF;

    rd_instr_set_op_scnst(instr, 1, lit);
    return true;
}

bool dalvik_decode_11x(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(ctx);
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;
    return true;
}

bool dalvik_decode_12x(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(ctx);
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xF;

    instr->operands[1].kind = RD_OP_REG;
    instr->operands[1].reg = (unit0 >> 12) & 0xF;
    return true;
}

bool dalvik_decode_20t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(unit0);
    RD_UNUSED(dalvik);

    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_ADDR;
    instr->operands[0].addr = instr->address + ((i64)(i16)unit1 * 2);
    return true;
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

bool dalvik_decode_21t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    instr->operands[1].kind = RD_OP_ADDR;
    instr->operands[1].addr = instr->address + ((i64)(i16)unit1 * 2);
    return true;
}

bool dalvik_decode_22b(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    instr->operands[1].kind = RD_OP_REG;
    instr->operands[1].reg = unit1 & 0xFF;

    rd_instr_set_op_scnst(instr, 2, (i8)((unit1 >> 8) & 0xFF));
    return true;
}

bool dalvik_decode_22c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xF;

    instr->operands[1].kind = RD_OP_REG;
    instr->operands[1].reg = (unit0 >> 12) & 0xF;

    _dalvik_set_index_operand(ctx, dalvik, &instr->operands[2],
                              info->index_kind, unit1);
    return true;
}

bool dalvik_decode_22s(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xF;

    instr->operands[1].kind = RD_OP_REG;
    instr->operands[1].reg = (unit0 >> 12) & 0xF;

    rd_instr_set_op_scnst(instr, 2, (i16)unit1);
    return true;
}

bool dalvik_decode_22t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xF;

    instr->operands[1].kind = RD_OP_REG;
    instr->operands[1].reg = (unit0 >> 12) & 0xF;

    instr->operands[2].kind = RD_OP_ADDR;
    instr->operands[2].addr = instr->address + ((i16)unit1 * 2UL);
    return true;
}

bool dalvik_decode_22x(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    instr->operands[1].kind = RD_OP_REG;
    instr->operands[1].reg = unit1;
    return true;
}

bool dalvik_decode_23x(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u16 unit1;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    instr->operands[1].kind = RD_OP_REG;
    instr->operands[1].reg = unit1 & 0xFF;

    instr->operands[2].kind = RD_OP_REG;
    instr->operands[2].reg = (unit1 >> 8) & 0xFF;
    return true;
}

bool dalvik_decode_30t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(unit0);
    RD_UNUSED(dalvik);

    u16 unit1, unit2;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;
    if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * 2), &unit2))
        return false;

    i32 off = (i32)(((u32)unit2 << 16) | unit1);

    instr->operands[0].kind = RD_OP_ADDR;
    instr->operands[0].addr = instr->address + ((i64)off * 2);
    return true;
}

bool dalvik_decode_31c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    u16 unit1, unit2;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;
    if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * 2), &unit2))
        return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    _dalvik_set_index_operand(ctx, dalvik, &instr->operands[1],
                              info->index_kind, ((u32)unit2 << 16) | unit1);
    return true;
}

bool dalvik_decode_31i(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u16 unit1, unit2;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;
    if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * 2), &unit2))
        return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    rd_instr_set_op_scnst(instr, 1, (i32)(((u32)unit2 << 16) | unit1));
    return true;
}

bool dalvik_decode_31t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u16 unit1, unit2;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;
    if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * 2), &unit2))
        return false;

    i32 off = (i32)(((u32)unit2 << 16) | unit1);

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    instr->operands[1].kind = RD_OP_ADDR;
    instr->operands[1].addr = instr->address + ((i64)off * 2);
    return true;
}

bool dalvik_decode_32x(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(unit0);
    RD_UNUSED(dalvik);

    u16 unit1, unit2;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;
    if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * 2), &unit2))
        return false;

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = unit1;

    instr->operands[1].kind = RD_OP_REG;
    instr->operands[1].reg = unit2;
    return true;
}

bool dalvik_decode_35c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
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

    if(_dalvik_index_to_address(ctx, dalvik, info->index_kind, unit1, &addr)) {
        ref->kind = RD_OP_ADDR;
        ref->addr = addr;
    }
    else {
        // no valid header, or the index is out of range: keep the raw value
        // visible rather than dropping the operand
        ref->kind = DALVIK_OP_INDEX;
        ref->cnst = unit1;
        ref->userdata1 = info->index_kind;
    }

    return true;
}

bool dalvik_decode_3rc(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    u16 unit1, unit2;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;
    if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * 2), &unit2))
        return false;

    instr->operands[0].kind = DALVIK_OP_REGRANGE;
    instr->operands[0].reg = unit2;
    instr->operands[0].count = (u8)((unit0 >> 8) & 0xFF);

    _dalvik_set_index_operand(ctx, dalvik, &instr->operands[1],
                              info->index_kind, unit1);
    return true;
}

bool dalvik_decode_45cc(const RDContext* ctx, RDInstruction* instr,
                        const DalvikOpcode* info, u16 unit0,
                        const Dalvik* dalvik) {
    RD_UNUSED(info);

    u16 unit1, unit2, unit3;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;
    if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * 2), &unit2))
        return false;
    if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * 3), &unit3))
        return false;

    u8 a = (u8)((unit0 >> 12) & 0xF);
    if(a > 5) return false;

    // same packing as 35c: unit2 verbatim, G lifted out of unit0
    instr->operands[0].kind = DALVIK_OP_REGLIST;
    instr->operands[0].count = a;
    instr->operands[0].cnst = (u64)unit2 | ((u64)((unit0 >> 8) & 0xF) << 16);

    _dalvik_set_index_operand(ctx, dalvik, &instr->operands[1],
                              DALVIK_IDX_METHOD, unit1);

    _dalvik_set_index_operand(ctx, dalvik, &instr->operands[2],
                              DALVIK_IDX_PROTO, unit3);
    return true;
}

bool dalvik_decode_4rcc(const RDContext* ctx, RDInstruction* instr,
                        const DalvikOpcode* info, u16 unit0,
                        const Dalvik* dalvik) {
    RD_UNUSED(info);

    u16 unit1, unit2, unit3;
    if(!rd_read_le16(ctx, instr->address + sizeof(u16), &unit1)) return false;
    if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * 2), &unit2))
        return false;
    if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * 3), &unit3))
        return false;

    instr->operands[0].kind = DALVIK_OP_REGRANGE;
    instr->operands[0].reg = unit2;
    instr->operands[0].count = (u8)((unit0 >> 8) & 0xFF);

    _dalvik_set_index_operand(ctx, dalvik, &instr->operands[1],
                              DALVIK_IDX_METHOD, unit1);

    _dalvik_set_index_operand(ctx, dalvik, &instr->operands[2],
                              DALVIK_IDX_PROTO, unit3);
    return true;
}

bool dalvik_decode_51l(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik) {
    RD_UNUSED(info);
    RD_UNUSED(dalvik);

    u64 v = 0;

    for(usize i = 0; i < 4; i++) {
        u16 u;
        if(!rd_read_le16(ctx, instr->address + (sizeof(u16) * (i + 1)), &u))
            return false;

        v |= (u64)u << (i * 16);
    }

    instr->operands[0].kind = RD_OP_REG;
    instr->operands[0].reg = (unit0 >> 8) & 0xFF;

    rd_instr_set_op_scnst(instr, 1, (i64)v);
    return true;
}
