#pragma once

#include <redasm/redasm.h>

// Resolve a Win16 import ordinal to its function name.
// - module: module name from the NE module reference table (case-insensitive)
// - ordinal: the ordinal number from the relocation record
// Returns the function name string, or NULL if not known.
const char* mz_win16_ordinal_lookup(const char* module, u16 ordinal);
