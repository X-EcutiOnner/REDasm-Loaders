#include "modules.h"

NEModuleSlice ne_moduleslice_create(NEFormat* ne, RDContext* ctx) {
    const NEHeader* hdr = &ne->header;

    NEModuleSlice modules = {
        .names = (char**)rd_alloc(hdr->ModRefs * sizeof(char*)),
        .imports = (NEImport*)rd_alloc(hdr->ModRefs * sizeof(NEImport)),
        .length = hdr->ModRefs,
    };

    RDReader* r = rd_get_input_reader(ctx);
    u32 mrt_off = ne->base + hdr->ModRefTableOffset;
    u32 int_base = ne->base + hdr->ImportNamesTableOffset;

    for(u16 i = 0; i < hdr->ModRefs; i++) {
        rd_reader_seek(r, mrt_off + (i * sizeof(u16)));

        u16 name_off;
        rd_reader_read_le16(r, &name_off);
        if(rd_reader_has_error(r)) break;

        rd_reader_seek(r, int_base + name_off);

        u8 len;
        rd_reader_read_u8(r, &len);
        if(rd_reader_has_error(r) || !len) continue;

        char* name = rd_alloc(len + 1);
        if(!name) continue;

        rd_reader_read(r, name, len);
        name[len] = '\0';

        if(rd_reader_has_error(r)) {
            rd_free(name);
            continue;
        }

        modules.names[i] = name;
    }

    return modules;
}

void ne_moduleslice_destroy(NEModuleSlice* self) {
    for(usize i = 0; i < self->length; i++)
        rd_free(self->names[i]);

    rd_free((void*)self->imports);
    rd_free((void*)self->names);
    self->length = 0;
}

void ne_moduleslice_build_imports(NEModuleSlice* self, NEFormat* ne,
                                  RDContext* ctx) {
    for(usize i = 0; i < self->length; i++) {
        // Slot index: NE segments occupy slots 1..SegCount,
        // import segments follow at SegCount+1, SegCount+2, ...
        u16 slot = ne->header.SegCount + 1 + i;
        RDAddress base = (RDAddress)slot * NE_SEG_SLOT;

        self->imports[i].base = base;
        self->imports[i].next_off = 0;

        rd_map_segment_n(ctx, self->names[i], base, NE_SEG_SLOT, RD_SP_RW);
    }
}

// Look up or allocate a flat address for an imported symbol.
// mod_idx is 1-based (as in the NE relocation record).
// Returns 0 if the module index is out of range.
//
// On first reference, the symbol name is registered via rd_library_function
// and the address is returned for patching into the call site.
// On subsequent references to the same offset the caller just re-patches.
RDAddress ne_moduleslice_resolve_import(NEModuleSlice* self, RDContext* ctx,
                                        u16 mod_idx, const char* sym_name) {
    if(mod_idx >= self->length) return 0;

    // Already registered from a previous reloc: reuse the same address
    RDAddress address;
    if(rd_get_address(ctx, sym_name, &address)) return address;

    // First time seeing this symbol: allocate a slot in the import segment
    NEImport* mod = &self->imports[mod_idx];

    // Allocate the next sizeof(u16) slot in the import segment.
    // Each symbol gets a unique address regardless of whether
    // it was seen before.
    u16 off = mod->next_off;
    if((u32)off + sizeof(u16) > NE_SEG_SLOT)
        return 0; // segment full (unlikely)

    RDAddress addr = mod->base + off;
    mod->next_off += sizeof(u16);

    // Register as an imported function in the label space
    rd_library_function(ctx, addr, sym_name);
    rd_set_imported(ctx, addr, NULL, sym_name);
    return addr;
}
