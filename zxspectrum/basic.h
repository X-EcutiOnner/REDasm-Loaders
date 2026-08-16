#pragma once

#include <redasm/redasm.h>

const char* zx_basic_emit_line(const u8* data, usize len, RDScratchBuffer* sb);
void zx_basic_attach_lines(RDContext* ctx, RDAddress address,
                           RDScratchBuffer* sb);
