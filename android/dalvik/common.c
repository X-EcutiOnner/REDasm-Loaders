#include "common.h"
#include "dex/strings.h"

const char* dalvik_read_string(RDContext* ctx, Dalvik* dalvik, u32 idx) {
    RDReader* r = rd_get_reader(ctx);

    return dex_read_string_to(r, &dalvik->header, idx, dalvik->raw_buf,
                              dalvik->string_buf);
}
