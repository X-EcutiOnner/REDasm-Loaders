#pragma once

#include "le/format.h"
#include <redasm/redasm.h>

typedef struct VxDDescBlock {
    u32 DDB_Next;
    u16 DDB_SDK_Version;
    u16 DDB_Req_Device_Number;
    u8 DDB_Dev_Major_Version;
    u8 DDB_Dev_Minor_Version;
    u16 DDB_Flags;
    char DDB_Name[8];
    u32 DDB_Init_Order;
    u32 DDB_Control_Proc;
    u32 DDB_V86_API_Proc;
    u32 DDB_PM_API_Proc;
    u32 DDB_V86_API_CSIP;
    u32 DDB_PM_API_CSIP;
    u32 DDB_Reference_Data;
    u32 DDB_Service_Table_Ptr;
    u32 DDB_Service_Table_Size;
    u32 DDB_Win32_Service_Table;
    u32 DDB_Prev;
    u32 DDB_Size;
    u32 DDB_Reserved1;
    u32 DDB_Reserved2;
    u32 DDB_Reserved3;
} VxDDescBlock;

bool le_is_vxd(const LEFormat* le);
void le_load_vxd(const LEFormat* le, RDContext* ctx);
