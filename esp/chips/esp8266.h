#pragma once

#include <unordered_map>
#include "esp_common.h"

class ESP8266: public ESPCommon
{
    public:
        bool load(RDContext* ctx, rd_offset offset = 0) override;
        static void initImports();

    private:
        static std::unordered_map<rd_address, const char*> m_imports;
};
