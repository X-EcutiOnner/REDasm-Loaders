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

bool dalvik_decode_10t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_11n(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_11x(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_12x(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_20t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_21c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_21h(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_21s(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_21t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_22b(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_22c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_22s(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_22t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_22x(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_23x(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_30t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_31c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_31i(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_31t(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_32x(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_35c(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_3rc(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
bool dalvik_decode_51l(const RDContext* ctx, RDInstruction* instr,
                       const DalvikOpcode* info, u16 unit0,
                       const Dalvik* dalvik);
