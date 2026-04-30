#include "hooks.h"

static void _x86_read_com_string(RDContext* ctx, RDAddress addr) {
    usize count = 0;
    u8 b;

    while(rd_read_u8(ctx, addr + count, &b) && b != '$')
        count++;

    count++; // include '$'

    if(count > 1) rd_library_type(ctx, addr, "char", count, RD_TYPE_NONE);
}

static void _x86_dos_int_hook(RDContext* ctx, RDInstruction* instr) {
    if(instr->operands[0].kind != RD_OP_IMM) return;

    switch(instr->operands[0].imm) {
        case 0x21: {
            RDReg reg_ah = rd_get_register_id(ctx, "ah");

            RDRegValue ah;
            if(!rd_get_regval(ctx, instr->address, reg_ah, &ah)) return;

            if(ah == 0x09) { // print string
                RDReg reg_dx = rd_get_register_id(ctx, "dx");
                RDRegValue dx;
                if(!rd_get_regval(ctx, instr->address, reg_dx, &dx)) return;
                _x86_read_com_string(ctx, (RDAddress)dx);
            }
            else if(ah == 0x4c) // standard exit
                instr->flow = RD_IF_STOP;
            break;
        }

        case 0x20: // Terminate program
        case 0x27: // Terminate and stay resident
            instr->flow = RD_IF_STOP;
            break;

        default: break;
    }
}

void mz_register_dos_hooks(RDContext* ctx) {
    rd_register_instruction_hook(ctx, "x86.int", _x86_dos_int_hook);
}
