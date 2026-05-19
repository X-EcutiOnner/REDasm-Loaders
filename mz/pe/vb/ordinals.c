#include "ordinals.h"

const char* pe_vb_ordinals_get_name(RDContext* ctx, const RDImported* imp) {
    if(!imp->module || !imp->ordinal.has_value) return NULL;

    const RDKBObject* kb = NULL;

    if(!rd_stricmp(imp->module, "msvbvm50.dll"))
        kb = rd_kb_load(ctx, "pe/ordinals/msvbvm50");
    else if(!rd_stricmp(imp->module, "msvbvm60.dll"))
        kb = rd_kb_load(ctx, "pe/ordinals/msvbvm60");

    if(kb) return rd_kbobject_get_str(kb, rd_to_dec(imp->ordinal.value));
    return NULL;
}
