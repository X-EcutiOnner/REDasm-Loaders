#include "components.h"
#include <stdio.h>
#include <string.h>

#define PE_VB_COMPONENT(n, id, e) {.name = n, .guid_str = id, .events = e}

// clang-format off
static const char* const OLE_EVENTS[] = {
    "Click", "DblClick", "DragDrop", "DragOver","GotFocus", "KeyDown",
    "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp",
    "Resize", "Updated", "ObjectMove", "Validate",
    NULL,
};

static const char* const DATA_EVENTS[] = {
    "Error", "Reposition", "Validate", "DragDrop",
    "DragOver", "MouseDown", "MouseMove", "MouseUp",
    "Resize", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
    "OLEStartDrag", "OLESetData", "OLECompleteDrag",
    NULL,
};

static const char* const TIMER_EVENTS[] = {"Timer", NULL};
static const char* const MENU_EVENTS[] = {"Click", NULL};

static const char* const FRAME_EVENTS[] = {
    "DragDrop", "DragOver", "MouseDown", "MouseMove", "MouseUp", "Click",
    "DlbClick", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
    "OLEStartDrag", "OLESetData", "OLECompleteDrag",
    NULL,
};

static const char* const COMMAND_BUTTON_EVENTS[] = {
    "Click", "DragDrop", "DragOver", "GotFocus", "KeyDown", "KeyPress",
    "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp", "OLEDragOver",
    "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag",
    "OLESetData", "OLECompleteDrag",
    NULL,
};

static const char* const OPTION_BUTTON_EVENTS[] = {
    "Click", "DblClick", "DragDrop", "DragOver", "GotFocus", "KeyDown",
    "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp",
    "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
    "OLEStartDrag", "OLESetData", "OLECompleteDrag",
    NULL,
};

static const char* const TEXT_BOX_EVENTS[] = {
    "Change", "DragDrop", "DragOver", "GotFocus",
    "KeyDown", "KeyPress", "KeyUp", "LinkClose",
    "LinkError", "LinkOpen", "LostFocus", "LinkNotify",
    "MouseDown", "MouseMove", "MouseUp", "Click",
    "DblClick", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
    "OLEStartDrag", "OLESetData", "OLECompleteDrag", "Validate",
    NULL,
};

static const char* const CHECK_BOX_EVENTS[] = {
    "Click", "DragDrop", "DragOver", "GotFocus", "KeyDown", "KeyPress",
    "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp", "OLEDragOver",
    "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag",
    "OLESetData", "OLECompleteDrag", 
    NULL,
};

static const char* const COMBO_BOX_EVENTS[] = {
    "Change", "Click", "DblClick", "DragDrop",
    "DragOver", "DropDown", "GotFocus", "KeyDown",
    "KeyPress", "KeyUp", "LostFocus", "OLEDragOver",
    "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag", "OLESetData",
    "OLECompleteDrag", "Scroll", "Validate", 
    NULL,
};

static const char* const LABEL_EVENTS[] = {
    "Change", "Click", "DblClick",
    "DragDrop", "DragOver", "LinkClose",
    "LinkError", "LinkOpen", "MouseDown",
    "MouseMove", "MouseUp", "LinkNotify",
    "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
    "OLEStartDrag", "OLESetData", "OLECompleteDrag",
    NULL,
};

static const char* const FORM_EVENTS[] = {
    "DragDrop", "DragOver", "LinkClose", "LinkError",
    "LinkExecute", "LinkOpen", "Load", "Resize", "Unload",
    "QueryUnload", "Activate", "Deactivate",
    "Click", "DblClick", "GotFocus", "KeyDown",
    "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove",
    "MouseUp", "Paint", "Initialize", "Terminate", "OLEDragOver",
    "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag", "OLESetData",
    "OLECompleteDrag",
    NULL,
};

static const char* const IMAGE_EVENTS[] = {
    "Click", "DlbClick", "DragDrop", "DragOver", "MouseDown", "MouseMove",
    "MouseUp", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback", 
    "OLEStartDrag", "OLESetData", "OLECompleteDrag",
    NULL,
};

static const char* const PICTURE_EVENTS[] = {
    "Change", "Click", "DblClick", "DragDrop", "DragOver", "GotFocus",
    "KeyDown", "KeyPress", "KeyUp", "LinkClose", "LinkError", "LinkOpen",
    "LostFocus", "MouseDown", "MouseMove", "MouseUp", "Paint", "LinkNotify",
    "Resize", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag",
    "OLESetData", "OLECompleteDrag", "Validate",
    NULL,
};

static const char* const LISTBOX_EVENTS[] = {
    "Click", "DblClick", "DragDrop", "DragOver", "GotFocus", "KeyDown",
    "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp",
    "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag", "OLESetData",
    "OLECompleteDrag", "Scroll", "ItemCheck", "Validate",
    NULL,
};

static const char* const DRIVE_LISTBOX_EVENTS[] = {
    "Change", "DragDrop", "DragOver", "GotFocus", "KeyDown", "KeyPress",
    "KeyUp", "LostFocus", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
    "OLEStartDrag", "OLESetDrive", "OLECompleteDrag", "Scroll", "Validate",
    NULL,
};

static const char* const DIR_LISTBOX_EVENTS[] = {
    "Change", "Click", "DragDrop", "DragOver", "GotFocus", "KeyDown",
    "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp",
    "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag",
    "OLESetData", "OLECompleteDrag", "Scroll", "Validate",
    NULL,
};

static const char* const FILE_LISTBOX_EVENTS[] = {
    "Click", "DblClick", "DragDrop", "DragOver", "GotFocus", "KeyDown",
    "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp",
    "PathChange", "PatternChange" , "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
    "OLEStartDrag", "OLESetData", "OLECompleteDrag", "Scroll", "Validate",
    NULL,
};

static const char* const VSCROLLBAR_EVENTS[] = {
    "Change", "DragDrop", "DragOver", "GotFocus", "KeyDown",
    "KeyPress", "KeyUp", "LostFocus", "Scroll", "Validate",
    NULL,
};

static const char* const HSCROLLBAR_EVENTS[] = {
    "Change", "DragDrop", "DragOver", "GotFocus", "KeyDown",
    "KeyPress", "KeyUp", "LostFocus", "Scroll", "Validate",
    NULL,
};

static const PEVBComponent PE_VB_COMPONENTS[] = {
    PE_VB_COMPONENT("OLE", "33AD5002-6699-11CF-B70C-00AA0060D393", OLE_EVENTS),
    PE_VB_COMPONENT("Data", "33AD4FFA-6699-11CF-B70C-00AA0060D393", DATA_EVENTS),
    PE_VB_COMPONENT("Timer", "33AD4F2A-6699-11CF-B70C-00AA0060D393", TIMER_EVENTS),
    PE_VB_COMPONENT("Menu", "33AD4F6A-6699-11CF-B70C-00AA0060D393", MENU_EVENTS),
    PE_VB_COMPONENT("Frame", "33AD4EEA-6699-11CF-B70C-00AA0060D393", FRAME_EVENTS),
    PE_VB_COMPONENT("CommandButton", "33AD4EF2-6699-11CF-B70C-00AA0060D393", COMMAND_BUTTON_EVENTS),
    PE_VB_COMPONENT("OptionButton", "33AD4F02-6699-11CF-B70C-00AA0060D393", OPTION_BUTTON_EVENTS),
    PE_VB_COMPONENT("TextBox", "33AD4EE2-6699-11CF-B70C-00AA0060D393", TEXT_BOX_EVENTS),
    PE_VB_COMPONENT("CheckBox", "33AD4EFA-6699-11CF-B70C-00AA0060D393", CHECK_BOX_EVENTS),
    PE_VB_COMPONENT("ComboBox", "33AD4F0A-6699-11CF-B70C-00AA0060D393", COMBO_BOX_EVENTS),
    PE_VB_COMPONENT("Label", "33AD4EDA-6699-11CF-B70C-00AA0060D393", LABEL_EVENTS),
    PE_VB_COMPONENT("Form", "33AD4F3A-6699-11CF-B70C-00AA0060D393", FORM_EVENTS),
    PE_VB_COMPONENT("Image", "33AD4F92-6699-11CF-B70C-00AA0060D393", IMAGE_EVENTS),
    PE_VB_COMPONENT("Picture", "33AD4ED2-6699-11CF-B70C-00AA0060D393", PICTURE_EVENTS),
    PE_VB_COMPONENT("Listbox", "33AD4F12-6699-11CF-B70C-00AA0060D393", LISTBOX_EVENTS),
    PE_VB_COMPONENT("DriveListBox", "33AD4F52-6699-11CF-B70C-00AA0060D393", DRIVE_LISTBOX_EVENTS),
    PE_VB_COMPONENT("DirListBox", "33AD4F5A-6699-11CF-B70C-00AA0060D393", DIR_LISTBOX_EVENTS),
    PE_VB_COMPONENT("FileListBox", "33AD4F62-6699-11CF-B70C-00AA0060D393", FILE_LISTBOX_EVENTS),
    PE_VB_COMPONENT("VScrollBar", "33AD4F22-6699-11CF-B70C-00AA0060D393", VSCROLLBAR_EVENTS),
    PE_VB_COMPONENT("HScrollBar", "33AD4F1A-6699-11CF-B70C-00AA0060D393", HSCROLLBAR_EVENTS),
};
// clang-format on

static const char* _pe_cv_guid_to_string(const PEGUID* guid) {
    static char buffer[37]; // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" + NUL

    snprintf(buffer, sizeof(buffer),
             "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", guid->data1,
             guid->data2, guid->data3, guid->data4[0], guid->data4[1],
             guid->data4[2], guid->data4[3], guid->data4[4], guid->data4[5],
             guid->data4[6], guid->data4[7]);

    return buffer;
}

const PEVBComponent* pe_vb_components_find(const PEGUID* guid) {
    if(!guid) return NULL;

    const char* guid_str = _pe_cv_guid_to_string(guid);

    for(int i = 0; i < rd_count_of(PE_VB_COMPONENTS); i++) {
        const PEVBComponent* c = &PE_VB_COMPONENTS[i];
        if(!strcmp(guid_str, c->guid_str)) return c;
    }

    return NULL;
}
