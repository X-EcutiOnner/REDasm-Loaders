#pragma once

#include <redasm/redasm.h>

#define LE_OBJ_READABLE 0x0001
#define LE_OBJ_WRITEABLE 0x0002
#define LE_OBJ_EXECUTABLE 0x0004
#define LE_OBJ_RESOURCE 0x0008
#define LE_OBJ_DISCARDABLE 0x0010
#define LE_OBJ_SHARABLE 0x0020
#define LE_OBJ_HAS_PRELOAD 0x0040
#define LE_OBJ_HAS_INVALID 0x0080
#define LE_OBJ_PERM_SWAPPABLE 0x0100 // LE
#define LE_OBJ_HAS_ZERO_FILL 0x0100  // LX
#define LE_OBJ_PERM_RESIDENT 0x0200
#define LE_OBJ_PERM_CONTIGUOUS 0x0300 // LX
#define LE_OBJ_PERM_LOCKABLE 0x0400
#define LE_OBJ_ALIAS_REQUIRED 0x1000
#define LE_OBJ_BIG 0x2000
#define LE_OBJ_CONFORMING 0x4000
#define LE_OBJ_IOPL 0x8000

typedef struct LEFormat LEFormat;

typedef struct LEObject {
    u32 size;
    u32 addr;
    u32 flags;
    u32 mapidx;
    u32 mapsize;
    char name[4];
} LEObject;

typedef struct LEObjectSlice {
    LEObject* data;
    usize length;
} LEObjectSlice;

LEObjectSlice le_objectslice_create(const LEFormat* le);
void le_objectslice_destroy(LEObjectSlice* self);
bool le_segments_load(LEFormat* le, RDContext* ctx);
