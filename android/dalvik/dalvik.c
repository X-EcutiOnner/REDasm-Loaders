#include "dalvik.h"
#include "dalvik/formats.h"
#include "dalvik/opcodes.h"
#include <stdio.h>

#define DALVIK_MAX_REG 0xFFFF

static void dalvik_setup(RDContext* ctx, RDProcessor* p) {
    Dalvik* dalvik = (Dalvik*)p;

    RDReader* r = rd_get_reader(ctx);
    rd_reader_seek(r, 0);
    dalvik->is_valid = dex_read_header(r, &dalvik->header) != 0;
}

static RDProcessor* dalvik_create(const RDProcessorPlugin* plugin) {
    RD_UNUSED(plugin);

    Dalvik* dalvik = (Dalvik*)rd_alloc0(1, sizeof(Dalvik));
    dalvik->raw_buf = rd_scratch_create();
    dalvik->string_buf = rd_scratch_create();
    return (RDProcessor*)dalvik;
}

static void dalvik_destroy(RDProcessor* p) {
    Dalvik* dalvik = (Dalvik*)p;
    rd_scratch_destroy(dalvik->string_buf);
    rd_scratch_destroy(dalvik->raw_buf);
    rd_free(dalvik);
}

static void dalvik_decode(RDContext* ctx, RDInstruction* instr,
                          RDProcessor* p) {
    Dalvik* dalvik = (Dalvik*)p;

    u16 unit0;
    if(!rd_read_le16(ctx, instr->address, &unit0)) return;

    u8 opcode = (u8)(unit0 & 0xFF);
    if(!opcode && (unit0 >> 8)) return; // switch/array payload

    const DalvikOpcode* op = &DALVIK_OPCODES[opcode];
    if(!op->mnemonic) return;

    switch(op->format) {
        case DALVIK_FMT_21C: {
            if(!dalvik_decode_21c(ctx, instr, op, unit0, dalvik)) return;
            break;
        }

        case DALVIK_FMT_35C: {
            if(!dalvik_decode_35c(ctx, instr, op, unit0, dalvik)) return;
            break;
        }

        default: break;
    }

    instr->id = opcode;
    instr->length = dalvik_u2b(DALVIK_FORMATS[op->format].units);
    instr->mnemonic = op->mnemonic;
    instr->flow = op->flow;
}

static void dalvik_emulate(RDContext* ctx, const RDInstruction* instr,
                           RDProcessor* p) {
    RD_UNUSED(p);

    if(rd_instr_can_flow(instr)) rd_flow(ctx, instr->address + instr->length);
}

static bool dalvik_render_operand(RDRenderer* r, const RDInstruction* instr,
                                  int idx, RDProcessor* p) {
    Dalvik* dalvik = (Dalvik*)p;
    RDContext* ctx = rd_renderer_get_context(r);
    const RDOperand* op = &instr->operands[idx];

    switch(op->kind) {
        case DALVIK_OP_REGLIST: {
            rd_renderer_norm(r, "{");

            for(u16 i = 0; i < op->count; i++) {
                if(i) rd_renderer_norm(r, ",");
                rd_renderer_reg(r, dalvik_reglist_reg(op->cnst, i));
            }

            rd_renderer_norm(r, "}");
            return true;
        }

        case DALVIK_OP_REGRANGE: {
            rd_renderer_norm(r, "{");
            rd_renderer_reg(r, op->reg);

            if(op->count > 1) {
                rd_renderer_norm(r, " .. ");
                rd_renderer_reg(r, (op->reg + op->count - 1));
            }

            rd_renderer_norm(r, "}");
            return true;
        }

        case DALVIK_OP_INDEX: {
            rd_renderer_norm(r, dalvik_index_prefix((u8)op->userdata1));
            rd_renderer_num(r, (i64)op->cnst, 16, 4, RD_NUM_DEFAULT);
            return true;
        }

        case RD_OP_ADDR: {
            if(op->userdata1 != DALVIK_IDX_STRING) break;

            const char* str = dalvik_read_string(ctx, dalvik, op->userdata2);
            if(!str) break;

            rd_renderer_str(r, str, true);
            return true;
        }

        default: break;
    }

    return false;
}

static const char* dalvik_get_mnemonic(const RDInstruction* instr,
                                       RDProcessor* p) {
    RD_UNUSED(p);
    return instr->mnemonic;
}

static bool dalvik_query_reg(RDQueryReg* q, RDProcessor* p) {
    Dalvik* dalvik = (Dalvik*)p;

    switch(q->kind) {
        case RD_QUERY_REG_BY_ID: {
            if(q->id > DALVIK_MAX_REG) return false;

            snprintf(dalvik->reg_buf, sizeof(dalvik->reg_buf), "v%u",
                     (unsigned)q->id);
            q->name = dalvik->reg_buf;
            break;
        }

        case RD_QUERY_REG_BY_NAME: {
            if(!q->name || q->name[0] != 'v' || !q->name[1]) return false;

            unsigned long v = 0;

            for(const char* s = q->name + 1; *s; s++) {
                if(*s < '0' || *s > '9') return false;
                v = (v * 10) + (unsigned long)(*s - '0');
                if(v > DALVIK_MAX_REG) return false;
            }

            q->id = (RDReg)v;
            break;
        }

        default: return false;
    }

    // no sub-registers: a Dalvik register is always accessed whole
    if(q->want & RD_QUERY_REG_WANT_MASK) {
        q->mask.mask = RD_REGMASK_FULL;
        q->mask.shift = 0;
    }

    // no aliases either: vN is its own canonical form
    if(q->want & RD_QUERY_REG_WANT_CANONICAL) q->canonical_name = q->name;

    return true;
}

const RDProcessorPlugin DALVIK = {
    .id = "android_dalvik",
    .name = "Dalvik",
    .ptr_size = sizeof(u32),
    .create = dalvik_create,
    .destroy = dalvik_destroy,
    .setup = dalvik_setup,
    .get_mnemonic = dalvik_get_mnemonic,
    .query_reg = dalvik_query_reg,
    .decode = dalvik_decode,
    .emulate = dalvik_emulate,
    .render_operand = dalvik_render_operand,
};
