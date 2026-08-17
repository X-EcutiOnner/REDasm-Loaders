#pragma once

#include <redasm/redasm.h>

// NROM == iNES mapper 0.
// No bank switching the simplest possible NES board, and the baseline every
// other mapper loader builds on top of.
extern const RDLoaderPlugin NROM_LOADER;
