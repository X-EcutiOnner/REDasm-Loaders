#include "format.h"

// clang-format off
static void _pe_vb_register_guid(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_GUID", ctx);
    rd_typedef_add_member(tdef, "u32", "data1", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "data2", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "data3", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u8", "data4", 8, RD_TYPE_NONE, ctx);
    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_lcid(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_LCID", ctx);
    rd_typedef_add_member(tdef, "u32", "__value", 0, RD_TYPE_NONE, ctx);
    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_header(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_VB_HEADER", ctx);

    rd_typedef_add_member(tdef, "char", "szVbMagic", PE_VB_SIGNATURE_SIZE, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "wRuntimeBuild", 0, RD_TYPE_NONE, ctx);                    
    rd_typedef_add_member(tdef, "char", "szLangDll", 14, RD_TYPE_NONE, ctx);                   
    rd_typedef_add_member(tdef, "char", "szSecLangDll", 14, RD_TYPE_NONE, ctx);                
    rd_typedef_add_member(tdef, "u16", "wRuntimeRevision", 0, RD_TYPE_NONE, ctx);                 
    rd_typedef_add_member(tdef, "u32", "dwLCID", 0, RD_TYPE_NONE, ctx);                           
    rd_typedef_add_member(tdef, "u32", "dwSecLCID", 0, RD_TYPE_NONE, ctx);                        
    rd_typedef_add_member(tdef, "u32", "lpSubMain", 0, RD_TYPE_NONE, ctx);                        
    rd_typedef_add_member(tdef, "u32", "lpProjectData", 0, RD_TYPE_NONE, ctx);                    
    rd_typedef_add_member(tdef, "u32", "fMdlIntCtls", 0, RD_TYPE_NONE, ctx);                      
    rd_typedef_add_member(tdef, "u32", "fMdlIntCtls2", 0, RD_TYPE_NONE, ctx);                     
    rd_typedef_add_member(tdef, "u32", "dwThreadFlags", 0, RD_TYPE_NONE, ctx);                    
    rd_typedef_add_member(tdef, "u32", "dwThreadCount", 0, RD_TYPE_NONE, ctx);                    
    rd_typedef_add_member(tdef, "u16", "wFormCount", 0, RD_TYPE_NONE, ctx);                       
    rd_typedef_add_member(tdef, "u16", "wExternalCount", 0, RD_TYPE_NONE, ctx);                   
    rd_typedef_add_member(tdef, "u32", "dwThunkCount", 0, RD_TYPE_NONE, ctx);                     
    rd_typedef_add_member(tdef, "u32", "lpGuiTable", 0, RD_TYPE_NONE, ctx);                       
    rd_typedef_add_member(tdef, "u32", "lpExternalCompTable", 0, RD_TYPE_NONE, ctx);              
    rd_typedef_add_member(tdef, "u32", "lpComRegisterData", 0, RD_TYPE_NONE, ctx);                
    rd_typedef_add_member(tdef, "u32", "bszProjectDescription", 0, RD_TYPE_NONE, ctx); 
    rd_typedef_add_member(tdef, "u32", "bszProjectExeName", 0, RD_TYPE_NONE, ctx);    
    rd_typedef_add_member(tdef, "u32", "bszProjectHelpFile", 0, RD_TYPE_NONE, ctx);  
    rd_typedef_add_member(tdef, "u32", "bszProjectName", 0, RD_TYPE_NONE, ctx);     

    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_project_info(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_VB_PROJECT_INFO", ctx);

    rd_typedef_add_member(tdef, "u32", "dwVersion", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpObjectTable", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwNull", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpCodeStart", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpCodeEnd", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwDataSize", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpThreadSpace", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpVbaSeh", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpNativeCode", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "char16", "szPathInformation", 264, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpExternalTable", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwExternalCount", 0, RD_TYPE_NONE, ctx);

    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_gui_table(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_VB_GUI_TABLE", ctx);

    rd_typedef_add_member(tdef, "u32", "lpSectionHeader", 0, RD_TYPE_NONE, ctx); 
    rd_typedef_add_member(tdef, "u8", "dwReserved", 59, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwFormSize", 0, RD_TYPE_NONE, ctx);     
    rd_typedef_add_member(tdef, "u32", "dwReserved1", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpFormData", 0, RD_TYPE_NONE, ctx); 
    rd_typedef_add_member(tdef, "u32", "dwReserved2", 0, RD_TYPE_NONE, ctx);

    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_object_table(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_VB_OBJECT_TABLE", ctx);

    rd_typedef_add_member(tdef, "u32", "lpHeapLink", 0, RD_TYPE_NONE, ctx); 
    rd_typedef_add_member(tdef, "u32", "lpExecProj", 0, RD_TYPE_NONE, ctx); 
    rd_typedef_add_member(tdef, "u32", "lpObjectTreeInfo", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwReserved", 0, RD_TYPE_NONE, ctx);       
    rd_typedef_add_member(tdef, "u32", "dwNull", 0, RD_TYPE_NONE, ctx);           
    rd_typedef_add_member(tdef, "u32", "lpProjectObject", 0, RD_TYPE_NONE, ctx);  
    rd_typedef_add_member(tdef, "PE_GUID", "uuidObject", 0, RD_TYPE_NONE, ctx);    
    rd_typedef_add_member(tdef, "u16", "fCompileState", 0, RD_TYPE_NONE, ctx);    
    rd_typedef_add_member(tdef, "u16", "wTotalObjects", 0, RD_TYPE_NONE, ctx);    
    rd_typedef_add_member(tdef, "u16", "wCompiledObjects", 0, RD_TYPE_NONE, ctx); 
    rd_typedef_add_member(tdef, "u16", "wObjectsInUse", 0, RD_TYPE_NONE, ctx);    
    rd_typedef_add_member(tdef, "u32", "lpPubObjArray", 0, RD_TYPE_NONE, ctx);    
    rd_typedef_add_member(tdef, "u32", "fIdeFlag", 0, RD_TYPE_NONE, ctx);         
    rd_typedef_add_member(tdef, "u32", "lpIdeData", 0, RD_TYPE_NONE, ctx);        
    rd_typedef_add_member(tdef, "u32", "lpIdeData2", 0, RD_TYPE_NONE, ctx);       
    rd_typedef_add_member(tdef, "u32", "lpszProjectName", 0, RD_TYPE_NONE, ctx);  
    rd_typedef_add_member(tdef, "PE_LCID", "dwLcid", 0, RD_TYPE_NONE, ctx);        
    rd_typedef_add_member(tdef, "PE_LCID", "dwLcid2", 0, RD_TYPE_NONE, ctx);       
    rd_typedef_add_member(tdef, "u32", "lpIdeData3", 0, RD_TYPE_NONE, ctx);       
    rd_typedef_add_member(tdef, "u32", "dwIdentifier", 0, RD_TYPE_NONE, ctx);

    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_object_tree(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_VB_OBJECT_TREE", ctx);

    rd_typedef_add_member(tdef, "u32", "lpHeapLink", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpObjectTable", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwReserved", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwUnused", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpFormList", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwUnused2", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "szProjectDescription", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "szProjectHelpFile", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwReserved2", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwHelpContextId", 0, RD_TYPE_NONE, ctx);

    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_public_object_descriptor(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_VB_PUBLIC_OBJECT_DESCRIPTOR", ctx);

    rd_typedef_add_member(tdef, "u32", "lpObjectInfo", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwReserved", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpPublicBytes", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpStaticBytes", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpModulePublic", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpModuleStatic", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpszObjectName", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwMethodCount", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpMethodNames", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "bStaticVars", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "fObjectType", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwNull", 0, RD_TYPE_NONE, ctx);

    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_object_info(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_VB_OBJECT_INFO", ctx);

    rd_typedef_add_member(tdef, "u16", "wRefCount", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "wObjectIndex", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpObjectTable", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpIdeData", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpPrivateObject", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwReserved", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwNull", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpObject", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpProjectData", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "wMethodCount", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "wMethodCount2", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpMethods", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "wConstants", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "wMaxConstants", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpIdeData2", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpIdeData3", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpConstants", 0, RD_TYPE_NONE, ctx);

    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_object_info_optional(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_VB_OBJECT_INFO_OPTIONAL", ctx);

    rd_typedef_add_member(tdef, "PE_VB_OBJECT_INFO", "base", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwObjectGuids", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpObjectGuid", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwNull", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpuuidObjectTypes", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwObjectTypeGuids", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpControls2", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwNull2", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpObjectGuid2", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwControlCount", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpControls", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "wEventCount", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "wPCodeCount", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "bWInitializeEvent", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "bWTerminateEvent", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpEvents", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpBasicClassObject", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwNull3", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpIdeData", 0, RD_TYPE_NONE, ctx);

    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_control_info(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_VB_CONTROL_INFO", ctx);

    rd_typedef_add_member(tdef, "u32", "fControlType", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "wEventCount", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u16", "bWEventsOffset", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpGuid", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwIndex", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwNull", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwNull2", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpEventInfo", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpIdeData", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpszName", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "dwIndexCopy", 0, RD_TYPE_NONE, ctx);

    rd_typedef_register(tdef, ctx);
}

static void _pe_vb_register_event_info(RDContext* ctx) {
    RDTypeDef* tdef = rd_typedef_create_struct("PE_VB_EVENT_INFO", ctx);

    rd_typedef_add_member(tdef, "u32", "dwNull", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpControlsList", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpFormDescriptor", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpEVENT_SINK_QueryInterface", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpEVENT_SINK_AddRef", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(tdef, "u32", "lpEVENT_SINK_Release", 0, RD_TYPE_NONE, ctx);

    rd_typedef_register(tdef, ctx);
}
// clang-format on

void pe_vb_register_types(RDContext* ctx) {
    _pe_vb_register_guid(ctx);
    _pe_vb_register_lcid(ctx);
    _pe_vb_register_header(ctx);
    _pe_vb_register_project_info(ctx);
    _pe_vb_register_gui_table(ctx);
    _pe_vb_register_object_table(ctx);
    _pe_vb_register_object_tree(ctx);
    _pe_vb_register_public_object_descriptor(ctx);
    _pe_vb_register_object_info(ctx);
    _pe_vb_register_object_info_optional(ctx);
    _pe_vb_register_control_info(ctx);
    _pe_vb_register_event_info(ctx);
}

static bool _pe_vb_read_lcid(RDReader* r, PELCID* v) {
    rd_reader_read_le32(r, v);
    return !rd_reader_has_error(r);
}

bool pe_vb_read_guid(RDReader* r, PEGUID* v) {
    rd_reader_read_le32(r, &v->data1);
    rd_reader_read_le16(r, &v->data2);
    rd_reader_read_le16(r, &v->data3);
    rd_reader_read(r, v->data4, sizeof(v->data4));

    return !rd_reader_has_error(r);
}

bool pe_vb_read_header(RDReader* r, PEVBHeader* v) {
    rd_reader_read(r, v->szVbMagic, sizeof(v->szVbMagic));
    rd_reader_read_le16(r, &v->wRuntimeBuild);
    rd_reader_read(r, v->szLangDll, sizeof(v->szLangDll));
    rd_reader_read(r, v->szSecLangDll, sizeof(v->szSecLangDll));
    rd_reader_read_le16(r, &v->wRuntimeRevision);
    rd_reader_read_le32(r, &v->dwLCID);
    rd_reader_read_le32(r, &v->dwSecLCID);
    rd_reader_read_le32(r, &v->lpSubMain);
    rd_reader_read_le32(r, &v->lpProjectData);
    rd_reader_read_le32(r, &v->fMdlIntCtls);
    rd_reader_read_le32(r, &v->fMdlIntCtls2);
    rd_reader_read_le32(r, &v->dwThreadFlags);
    rd_reader_read_le32(r, &v->dwThreadCount);
    rd_reader_read_le16(r, &v->wFormCount);
    rd_reader_read_le16(r, &v->wExternalCount);
    rd_reader_read_le32(r, &v->dwThunkCount);
    rd_reader_read_le32(r, &v->lpGuiTable);
    rd_reader_read_le32(r, &v->lpExternalCompTable);
    rd_reader_read_le32(r, &v->lpComRegisterData);
    rd_reader_read_le32(r, &v->bszProjectDescription);
    rd_reader_read_le32(r, &v->bszProjectExeName);
    rd_reader_read_le32(r, &v->bszProjectHelpFile);
    rd_reader_read_le32(r, &v->bszProjectName);

    return !rd_reader_has_error(r);
}

bool pe_vb_read_project_info(RDReader* r, PEVBProjectInfo* v) {
    rd_reader_read_le32(r, &v->dwVersion);
    rd_reader_read_le32(r, &v->lpObjectTable);
    rd_reader_read_le32(r, &v->dwNull);
    rd_reader_read_le32(r, &v->lpCodeStart);
    rd_reader_read_le32(r, &v->lpCodeEnd);
    rd_reader_read_le32(r, &v->dwDataSize);
    rd_reader_read_le32(r, &v->lpThreadSpace);
    rd_reader_read_le32(r, &v->lpVbaSeh);
    rd_reader_read_le32(r, &v->lpNativeCode);
    rd_reader_read(r, &v->szPathInformation, sizeof(v->szPathInformation));
    rd_reader_read_le32(r, &v->lpExternalTable);
    rd_reader_read_le32(r, &v->dwExternalCount);

    return !rd_reader_has_error(r);
}

bool pe_vb_read_gui_table(RDReader* r, PEVBGuiTable* v) {
    rd_reader_read_le32(r, &v->lpSectionHeader);
    rd_reader_read(r, &v->dwReserved, sizeof(v->dwReserved));
    rd_reader_read_le32(r, &v->dwFormSize);
    rd_reader_read_le32(r, &v->dwReserved1);
    rd_reader_read_le32(r, &v->lpFormData);
    rd_reader_read_le32(r, &v->dwReserved2);

    return !rd_reader_has_error(r);
}

bool pe_vb_read_object_table(RDReader* r, PEVBObjectTable* v) {
    rd_reader_read_le32(r, &v->lpHeapLink);
    rd_reader_read_le32(r, &v->lpExecProj);
    rd_reader_read_le32(r, &v->lpObjectTreeInfo);
    rd_reader_read_le32(r, &v->dwReserved);
    rd_reader_read_le32(r, &v->dwNull);
    rd_reader_read_le32(r, &v->lpProjectObject);
    pe_vb_read_guid(r, &v->uuidObject);
    rd_reader_read_le16(r, &v->fCompileState);
    rd_reader_read_le16(r, &v->wTotalObjects);
    rd_reader_read_le16(r, &v->wCompiledObjects);
    rd_reader_read_le16(r, &v->wObjectsInUse);
    rd_reader_read_le32(r, &v->lpPubObjArray);
    rd_reader_read_le32(r, &v->fIdeFlag);
    rd_reader_read_le32(r, &v->lpIdeData);
    rd_reader_read_le32(r, &v->lpIdeData2);
    rd_reader_read_le32(r, &v->lpszProjectName);
    _pe_vb_read_lcid(r, &v->dwLcid);
    _pe_vb_read_lcid(r, &v->dwLcid2);
    rd_reader_read_le32(r, &v->lpIdeData3);
    rd_reader_read_le32(r, &v->dwIdentifier);

    return !rd_reader_has_error(r);
}

bool pe_vb_read_object_tree(RDReader* r, PEVBObjectTree* v) {
    rd_reader_read_le32(r, &v->lpHeapLink);
    rd_reader_read_le32(r, &v->lpObjectTable);
    rd_reader_read_le32(r, &v->dwReserved);
    rd_reader_read_le32(r, &v->dwUnused);
    rd_reader_read_le32(r, &v->lpFormList);
    rd_reader_read_le32(r, &v->dwUnused2);
    rd_reader_read_le32(r, &v->szProjectDescription);
    rd_reader_read_le32(r, &v->szProjectHelpFile);
    rd_reader_read_le32(r, &v->dwReserved2);
    rd_reader_read_le32(r, &v->dwHelpContextId);

    return !rd_reader_has_error(r);
}

bool pe_vb_read_public_object_descriptor(RDReader* r,
                                         PEVBPublicObjectDescriptor* v) {
    rd_reader_read_le32(r, &v->lpObjectInfo);
    rd_reader_read_le32(r, &v->dwReserved);
    rd_reader_read_le32(r, &v->lpPublicBytes);
    rd_reader_read_le32(r, &v->lpStaticBytes);
    rd_reader_read_le32(r, &v->lpModulePublic);
    rd_reader_read_le32(r, &v->lpModuleStatic);
    rd_reader_read_le32(r, &v->lpszObjectName);
    rd_reader_read_le32(r, &v->dwMethodCount);
    rd_reader_read_le32(r, &v->lpMethodNames);
    rd_reader_read_le32(r, &v->bStaticVars);
    rd_reader_read_le32(r, &v->fObjectType);
    rd_reader_read_le32(r, &v->dwNull);

    return !rd_reader_has_error(r);
}

bool pe_vb_read_object_info(RDReader* r, PEVBObjectInfo* v) {
    rd_reader_read_le16(r, &v->wRefCount);
    rd_reader_read_le16(r, &v->wObjectIndex);
    rd_reader_read_le32(r, &v->lpObjectTable);
    rd_reader_read_le32(r, &v->lpIdeData);
    rd_reader_read_le32(r, &v->lpPrivateObject);
    rd_reader_read_le32(r, &v->dwReserved);
    rd_reader_read_le32(r, &v->dwNull);
    rd_reader_read_le32(r, &v->lpObject);
    rd_reader_read_le32(r, &v->lpProjectData);
    rd_reader_read_le16(r, &v->wMethodCount);
    rd_reader_read_le16(r, &v->wMethodCount2);
    rd_reader_read_le32(r, &v->lpMethods);
    rd_reader_read_le16(r, &v->wConstants);
    rd_reader_read_le16(r, &v->wMaxConstants);
    rd_reader_read_le32(r, &v->lpIdeData2);
    rd_reader_read_le32(r, &v->lpIdeData3);
    rd_reader_read_le32(r, &v->lpConstants);

    return !rd_reader_has_error(r);
}

bool pe_vb_read_object_info_optional(RDReader* r, PEVBObjectInfoOptional* v) {
    pe_vb_read_object_info(r, &v->base);
    rd_reader_read_le32(r, &v->dwObjectGuids);
    rd_reader_read_le32(r, &v->lpObjectGuid);
    rd_reader_read_le32(r, &v->dwNull);
    rd_reader_read_le32(r, &v->lpuuidObjectTypes);
    rd_reader_read_le32(r, &v->dwObjectTypeGuids);
    rd_reader_read_le32(r, &v->lpControls2);
    rd_reader_read_le32(r, &v->dwNull2);
    rd_reader_read_le32(r, &v->lpObjectGuid2);
    rd_reader_read_le32(r, &v->dwControlCount);
    rd_reader_read_le32(r, &v->lpControls);
    rd_reader_read_le16(r, &v->wEventCount);
    rd_reader_read_le16(r, &v->wPCodeCount);
    rd_reader_read_le16(r, &v->bWInitializeEvent);
    rd_reader_read_le16(r, &v->bWTerminateEvent);
    rd_reader_read_le32(r, &v->lpEvents);
    rd_reader_read_le32(r, &v->lpBasicClassObject);
    rd_reader_read_le32(r, &v->dwNull3);
    rd_reader_read_le32(r, &v->lpIdeData);

    return !rd_reader_has_error(r);
}

bool pe_vb_read_control_info(RDReader* r, PEVBControlInfo* v) {
    rd_reader_read_le32(r, &v->fControlType);
    rd_reader_read_le16(r, &v->wEventCount);
    rd_reader_read_le16(r, &v->bWEventsOffset);
    rd_reader_read_le32(r, &v->lpGuid);
    rd_reader_read_le32(r, &v->dwIndex);
    rd_reader_read_le32(r, &v->dwNull);
    rd_reader_read_le32(r, &v->dwNull2);
    rd_reader_read_le32(r, &v->lpEventInfo);
    rd_reader_read_le32(r, &v->lpIdeData);
    rd_reader_read_le32(r, &v->lpszName);
    rd_reader_read_le32(r, &v->dwIndexCopy);

    return !rd_reader_has_error(r);
}

bool pe_vb_read_event_info(RDReader* r, PEVBEventInfo* v) {
    rd_reader_read_le32(r, &v->dwNull);
    rd_reader_read_le32(r, &v->lpControlsList);
    rd_reader_read_le32(r, &v->lpFormDescriptor);
    rd_reader_read_le32(r, &v->lpEVENT_SINK_QueryInterface);
    rd_reader_read_le32(r, &v->lpEVENT_SINK_AddRef);
    rd_reader_read_le32(r, &v->lpEVENT_SINK_Release);

    return !rd_reader_has_error(r);
}
