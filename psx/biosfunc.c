#include "biosfunc.h"

static const char* psx_bios_lookup(u8 sel, u8 fn) {
    const RDKBObject* kb = rd_kb_load("psx/bios");

    const char* str = rd_format("bios.sel.%02x", sel);
    const char* sel_str = rd_kbobject_get_str(kb, str);
    if(!sel_str) return NULL;

    str = rd_format("%s.%02x", sel_str, fn);
    return rd_kbobject_get_str(kb, str);
}

void psx_bios_autorename_hook(RDContext* ctx) {
    RDFunctionSlice functions = rd_get_all_functions(ctx);
    RDIL* rdil = rd_il_create(ctx, NULL);

    const RDFunction** it;
    rd_slice_each(it, functions) {
        const RDFunction* f = *it;
        if(rd_function_get_n_instructions(f) != 3) continue;

        rd_il_assign(rdil, f);
        if(!rd_il_run(rdil)) continue;

        RDRegValue t1, t2;
        if(!rd_il_get_regval(rdil, "$t1", &t1)) continue;
        if(!rd_il_get_regval(rdil, "$t2", &t2)) continue;

        const char* name = psx_bios_lookup(t2, t1);

        if(name) {
            RDAddress func_addr = rd_function_get_address(f);
            rd_library_name(ctx, func_addr, name);
        }
    }

    rd_il_destroy(rdil);
}
