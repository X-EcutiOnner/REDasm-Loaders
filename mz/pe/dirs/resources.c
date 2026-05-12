#include "resources.h"

#define PE_RESOURCE_NAME_IS_STRING 0x80000000
#define PE_RESOURCE_DATA_IS_DIRECTORY 0x80000000

static bool _pe_resource_read_dir(RDReader* r, PEResourceDirectory* dir) {
    rd_reader_read_le32(r, &dir->Characteristics);
    rd_reader_read_le32(r, &dir->TimeDateStamp);
    rd_reader_read_le16(r, &dir->MajorVersion);
    rd_reader_read_le16(r, &dir->MinorVersion);
    rd_reader_read_le16(r, &dir->NumberOfNamedEntries);
    rd_reader_read_le16(r, &dir->NumberOfIdEntries);
    return !rd_reader_has_error(r);
}

static bool _pe_resource_read_dir_entry(RDReader* r,
                                        PEResourceDirectoryEntry* entry) {
    rd_reader_read_le32(r, &entry->NameOffset);
    rd_reader_read_le32(r, &entry->OffsetToData);
    return !rd_reader_has_error(r);
}

static bool _pe_resource_read_data_entry(RDReader* r,
                                         PEResourceDataEntry* dataentry) {
    rd_reader_read_le32(r, &dataentry->OffsetToData);
    rd_reader_read_le32(r, &dataentry->Size);
    rd_reader_read_le32(r, &dataentry->CodePage);
    rd_reader_read_le32(r, &dataentry->Reserved);
    return !rd_reader_has_error(r);
}

static void _pe_resource_read_dirs(RDContext* ctx, PEFormat* pe, RDReader* r,
                                   RDAddress base, RDAddress va, int depth) {
    if(depth > 3) return; // max 3 levels deep in PE resources

    PEResourceDirectory resdir;
    rd_reader_seek(r, va);
    if(!_pe_resource_read_dir(r, &resdir)) return;

    rd_library_type(ctx, va, "PE_RESOURCE_DIRECTORY", 0, RD_TYPE_NONE);

    u16 total = resdir.NumberOfNamedEntries + resdir.NumberOfIdEntries;
    RDAddress entry_va = va + rd_size_of(ctx, "PE_RESOURCE_DIRECTORY", 0);

    for(u16 i = 0; i < total; i++) {
        PEResourceDirectoryEntry entry;
        rd_reader_seek(r, entry_va);
        if(!_pe_resource_read_dir_entry(r, &entry)) break;

        rd_library_type(ctx, entry_va, "PE_RESOURCE_DIRECTORY_ENTRY", 0,
                        RD_TYPE_NONE);

        if(entry.OffsetToData & PE_RESOURCE_DATA_IS_DIRECTORY) {
            RDAddress subdir_va =
                base + (entry.OffsetToData & ~PE_RESOURCE_DATA_IS_DIRECTORY);
            _pe_resource_read_dirs(ctx, pe, r, base, subdir_va, depth + 1);
        }
        else {
            RDAddress dataentry_va = base + entry.OffsetToData;
            rd_library_type(ctx, dataentry_va, "PE_RESOURCE_DATA_ENTRY", 0,
                            RD_TYPE_NONE);

            PEResourceDataEntry dataentry;
            rd_reader_seek(r, dataentry_va);
            if(!_pe_resource_read_data_entry(r, &dataentry)) break;

            RDAddress data_va;

            if(pe_from_rva(pe, dataentry.OffsetToData, &data_va) &&
               dataentry.Size) {
                rd_library_name(ctx, data_va,
                                rd_format("rsrc_data_%x", data_va));
            }
        }

        entry_va += rd_size_of(ctx, "PE_RESOURCE_DIRECTORY_ENTRY", 0);
    }
}

void pe_resources_register_types(RDContext* ctx) {
    // clang-format off
    RDTypeDef* resdir = rd_typedef_create_struct("PE_RESOURCE_DIRECTORY", ctx);
    rd_typedef_add_member(resdir, "u32", "Characteristics", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(resdir, "u32", "TimeDateStamp", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(resdir, "u16", "MajorVersion", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(resdir, "u16", "MinorVersion", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(resdir, "u16", "NumberOfNamedEntries", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(resdir, "u16", "NumberOfIdEntries", 0, RD_TYPE_NONE, ctx);
    rd_typedef_register(resdir, ctx);

    RDTypeDef* entry = rd_typedef_create_struct("PE_RESOURCE_DIRECTORY_ENTRY", ctx);
    rd_typedef_add_member(entry, "u32", "NameOffset", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(entry, "u32", "OffsetToData", 0, RD_TYPE_NONE, ctx);
    rd_typedef_register(entry, ctx);

    RDTypeDef* dataentry = rd_typedef_create_struct("PE_RESOURCE_DATA_ENTRY", ctx);
    rd_typedef_add_member(dataentry, "u32", "OffsetToData", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(dataentry, "u32", "Size", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(dataentry, "u32", "CodePage", 0, RD_TYPE_NONE, ctx);
    rd_typedef_add_member(dataentry, "u32", "Reserved", 0, RD_TYPE_NONE, ctx);
    rd_typedef_register(dataentry, ctx);
    // clang-format on
}

bool pe_resources_read(RDContext* ctx, PEFormat* pe) {
    PEDataDirectory d = pe->datadir[PE_DIRECTORY_ENTRY_RESOURCE];

    RDAddress va;
    if(!pe_from_rva(pe, d.VirtualAddress, &va)) return false;

    rd_library_type(ctx, va, "PE_RESOURCE_DIRECTORY", 0, RD_TYPE_NONE);

    RDReader* r = rd_get_reader(ctx);
    _pe_resource_read_dirs(ctx, pe, r, va, va, 0);
    return true;
}
