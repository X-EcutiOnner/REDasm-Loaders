#pragma once

#include <rdapi/rdapi.h>
#include "../esp_header.h"
#include "../esp_constants.h"

enum ESPImageType {
    ESPImage_Unknown,
    ESPImage_8266,
};

class ESPCommon
{
    public:
        ESPCommon() = default;
        virtual bool load(RDContext* ctx, rd_offset offset = RD_NVAL);

    public:
        static const char* test(const RDLoaderRequest* request);

    protected:
        bool load(RDContext* ctx, ESP8266RomHeader1* header, rd_offset offset = 0);
        bool load(RDContext* ctx, ESP8266RomHeader2* header);
};
