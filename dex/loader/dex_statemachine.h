#pragma once

// https://source.android.com/devices/tech/dalvik/dex-format#debug-info-item

#include <unordered_map>
#include <redasm/redasm.h>
#include "dex_header.h"

using namespace REDasm;

enum class DEXStates: u8 {
    DbgEndSequence = 0, DbgAdvancePc, DbgAdvanceLine, DbgStartLocal,
    DbgStartLocalExtended, DbgEndLocal, DbgRestartLocal,
    DbgSetPrologueEnd, DbgSetEpilogueBegin, DbgSetFile,
    DbgFirstSpecial, DbgLastSpecial = 0xFF
};

class DEXStateMachine
{
    private:
        typedef std::function<void(u8**)> StateCallback;
        typedef std::unordered_map<u8, StateCallback> StatesMap;

    public:
        DEXStateMachine(address_t address, DexDebugInfo& debuginfo);
        void execute(u8* data);

    private:
        void execute0x00(u8** data);
        void execute0x01(u8** data);
        void execute0x02(u8** data);
        void execute0x03(u8** data);
        void execute0x04(u8** data);
        void execute0x05(u8** data);
        void execute0x06(u8** data);
        void execute0x07(u8** data);
        void execute0x08(u8** data);
        void execute0x09(u8** data);
        void executeSpecial(u8 opcode);

    private:
        void setDebugData(const DEXDebugData& debugdata);

    private:
        StatesMap m_statesmap;
        DexDebugInfo& m_debuginfo;
        address_t m_address;
        u16 m_line;
        bool m_atend;
};
