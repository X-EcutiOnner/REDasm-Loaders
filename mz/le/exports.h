#pragma once

#include "le/format.h"

void le_exports_read(const LEFormat* le, RDContext* ctx);
RDAddress le_exports_entry(const LEFormat* le, u16 ordinal, RDContext* ctx);
