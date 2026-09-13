#pragma once

#include <redasm/redasm.h>

#define DEX_STRING_ID_SIZE 4
#define DEX_TYPE_ID_SIZE 4
#define DEX_PROTO_ID_SIZE 12
#define DEX_FIELD_ID_SIZE 8
#define DEX_METHOD_ID_SIZE 8
#define DEX_CLASS_DEF_SIZE 32
#define DEX_CALL_SITE_ID_SIZE 4
#define DEX_METHOD_HANDLE_SIZE 8

typedef struct DEXHeader {
    u8 magic[8];
    u32 checksum;
    u8 signature[20];
    u32 file_size;
    u32 header_size;
    u32 endian_tag;
    u32 link_size;
    u32 link_off;
    u32 map_off;
    u32 string_ids_size;
    u32 string_ids_off;
    u32 type_ids_size;
    u32 type_ids_off;
    u32 proto_ids_size;
    u32 proto_ids_off;
    u32 field_ids_size;
    u32 field_ids_off;
    u32 method_ids_size;
    u32 method_ids_off;
    u32 class_defs_size;
    u32 class_defs_off;
    u32 data_size;
    u32 data_off;
} DEXHeader;

typedef struct DEXStringId {
    u32 string_data_off;
} DEXStringId;

typedef struct DEXTypeId {
    u32 descriptor_idx;
} DEXTypeId;

typedef struct DEXProtoId {
    u32 shorty_idx;
    u32 return_type_idx;
    u32 parameters_off;
} DEXProtoId;

typedef struct DEXFieldId {
    u16 class_idx;
    u16 type_idx;
    u32 name_idx;
} DEXFieldId;

typedef struct DEXMethodId {
    u16 class_idx;
    u16 proto_idx;
    u32 name_idx;
} DEXMethodId;

typedef struct DEXClassDef {
    u32 class_idx;
    u32 access_flags;
    u32 superclass_idx;
    u32 interfaces_off;
    u32 source_file_idx;
    u32 annotations_off;
    u32 class_data_off;
    u32 static_values_off;
} DEXClassDef;

typedef struct DEXFormat {
    u32 version;
    DEXHeader header;
    RDScratchBuffer* raw_buf;
    RDScratchBuffer* string_buf;
    RDScratchBuffer* name_buf;
} DEXFormat;

u32 dex_read_header(RDReader* r, DEXHeader* v);
bool dex_read_string_id(RDReader* r, DEXStringId* v);
bool dex_read_type_id(RDReader* r, DEXTypeId* v);
bool dex_read_proto_id(RDReader* r, DEXProtoId* v);
bool dex_read_field_id(RDReader* r, DEXFieldId* v);
bool dex_read_method_id(RDReader* r, DEXMethodId* v);
bool dex_read_class_def(RDReader* r, DEXClassDef* v);

bool dex_validate_header(const RDReader* r, const DEXFormat* dex);
bool dex_validate_checksum(RDReader* r, const DEXFormat* dex);
bool dex_validate_signature(RDReader* r, const DEXFormat* dex);
