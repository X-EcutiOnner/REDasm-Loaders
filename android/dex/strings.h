#pragma once

#include "dex/format.h"

bool dex_get_string_offset(RDReader* r, const DEXHeader* hdr, u32 idx,
                           u32* off);
bool dex_string_extent(RDReader* r, const DEXHeader* hdr, u32 dataoff,
                       RDAddress* text, usize* nbytes);

const char* dex_read_string(RDReader* r, DEXFormat* dex, u32 idx,
                            RDScratchBuffer* buf);
const char* dex_read_string_to(RDReader* r, const DEXHeader* hdr, u32 idx,
                               RDScratchBuffer* raw, RDScratchBuffer* buf);

const char* dex_type_descriptor(RDReader* r, DEXFormat* dex, u32 typeidx);
const char* dex_type_name(RDReader* r, DEXFormat* dex, u32 typeidx);
const char* dex_method_name(RDReader* r, DEXFormat* dex, u32 methodidx);
const char* dex_field_name(RDReader* r, DEXFormat* dex, u32 fieldidx);
