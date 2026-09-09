#pragma once

#include "dalvik/common.h"
#include "dalvik/opcodes.h"
#include <redasm/redasm.h>

typedef enum {
    DALVIK_OP_REGLIST = RD_OP_USERBASE, // up to 5 nibble regs
    DALVIK_OP_REGRANGE,                 // first + count
    DALVIK_OP_INDEX,
} DalvikOperands;

static inline u16 dalvik_u2b(usize u) { return u * sizeof(u16); }

static inline u8 dalvik_reglist_reg(u64 v, u8 i) {
    return (u8)((v >> (i * 4)) & 0xF);
}

const char* dalvik_index_prefix(u8 kind);

bool dalvik_decode_21c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_35c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* op, u16 unit0, const Dalvik* dalvik);
