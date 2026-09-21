#pragma once

#include "pe/format.h"

typedef struct PELoadConfigDirectory32 {
    u32 Size, TimeDateStamp;
    u16 MajorVersion, MinorVersion;
    u32 GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout;
    u32 DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold;
    u32 LockPrefixTable;
    u32 MaximumAllocationSize, VirtualMemoryThreshold;
    u32 ProcessHeapFlags, ProcessAffinityMask;
    u16 CSDVersion, Reserved1;
    u32 EditList;
    u32 SecurityCookie;
    u32 SEHandlerTable;
    u32 SEHandlerCount;
    u32 GuardCFCheckFunctionPointer;
    u32 Reserved2;
    u32 GuardCFFunctionTable;
    u32 GuardCFFunctionCount, GuardFlags;
} PELoadConfigDirectory32;

typedef struct PELoadConfigDirectory64 {
    u32 Size, TimeDateStamp;
    u16 MajorVersion, MinorVersion;
    u32 GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout;
    u64 DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold;
    u64 LockPrefixTable;
    u64 MaximumAllocationSize, VirtualMemoryThreshold;
    u64 ProcessAffinityMask;
    u32 ProcessHeapFlags;
    u16 CSDVersion, Reserved1;
    u64 EditList;
    u64 SecurityCookie;
    u64 SEHandlerTable;
    u64 SEHandlerCount;
    u64 GuardCFCheckFunctionPointer;
    u64 Reserved2;
    u64 GuardCFFunctionTable;
    u64 GuardCFFunctionCount;
    u32 GuardFlags;
} PELoadConfigDirectory64;

bool pe_read_config_dir(RDContext* ctx, PEFormat* pe);
