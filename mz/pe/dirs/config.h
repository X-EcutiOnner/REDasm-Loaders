#pragma once

#include "pe/format.h"

typedef struct PELoadConfigDirectory32 {
    u32 Size, TimeDateStamp;
    u16 MajorVersion, MinorVersion;
    u32 GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout;
    u32 DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold;
    u32 LockPrefixTable; // VA
    u32 MaximumAllocationSize, VirtualMemoryThreshold;
    u32 ProcessHeapFlags, ProcessAffinityMask;
    u16 CSDVersion, Reserved1;
    u32 EditList;       // VA
    u32 SecurityCookie; // VA
    u32 SEHandlerTable; // VA
    u32 SEHandlerCount;
    u32 GuardCFCheckFunctionPointer; // VA
    u32 Reserved2;
    u32 GuardCFFunctionTable; // VA
    u32 GuardCFFunctionCount, GuardFlags;
} PELoadConfigDirectory32;

typedef struct PELoadConfigDirectory64 {
    u32 Size, TimeDateStamp;
    u16 MajorVersion, MinorVersion;
    u32 GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout;
    u64 DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold;
    u64 LockPrefixTable; // VA
    u64 MaximumAllocationSize, VirtualMemoryThreshold;
    u64 ProcessAffinityMask, ProcessHeapFlags;
    u16 CSDVersion, Reserved1;
    u64 EditList;       // VA
    u64 SecurityCookie; // VA
    u64 SEHandlerTable; // VA
    u64 SEHandlerCount;
    u64 GuardCFCheckFunctionPointer; // VA
    u64 Reserved2;
    u64 GuardCFFunctionTable; // VA
    u64 GuardCFFunctionCount;
    u32 GuardFlags;
} PELoadConfigDirectory64;

bool pe_read_config_dir(RDContext* ctx, PEFormat* pe);
