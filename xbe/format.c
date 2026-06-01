#include "format.h"

// Entry-point XOR keys
#define XBE_EP_RETAIL_KEY 0xa8fc57abU
#define XBE_EP_DEBUG_KEY 0x94859d4bU

// Kernel thunk XOR keys
#define XBE_KT_RETAIL_KEY 0x5b6d40b6U
#define XBE_KT_DEBUG_KEY 0xefb1f152U

bool xbe_read_header(RDReader* r, XBEImageHeader* v) {
    rd_reader_read_le32(r, &v->Magic);
    rd_reader_read(r, &v->Signature, sizeof(v->Signature));
    rd_reader_read_le32(r, &v->ImageBase);
    rd_reader_read_le32(r, &v->SizeOfHeaders);
    rd_reader_read_le32(r, &v->SizeOfImage);
    rd_reader_read_le32(r, &v->SizeOfImageHeader);
    rd_reader_read_le32(r, &v->Timestamp);
    rd_reader_read_le32(r, &v->CertificateAddress);
    rd_reader_read_le32(r, &v->NumberOfSections);
    rd_reader_read_le32(r, &v->SectionHeadersAddress);
    rd_reader_read_le32(r, &v->InitFlags);
    rd_reader_read_le32(r, &v->EntryPoint);
    rd_reader_read_le32(r, &v->TlsAddress);
    rd_reader_read_le32(r, &v->StackSize);
    rd_reader_read_le32(r, &v->PeHeapReserve);
    rd_reader_read_le32(r, &v->PeHeapCommit);
    rd_reader_read_le32(r, &v->PeBaseAddress);
    rd_reader_read_le32(r, &v->PeSizeOfImage);
    rd_reader_read_le32(r, &v->PeChecksum);
    rd_reader_read_le32(r, &v->PeTimestamp);
    rd_reader_read_le32(r, &v->DebugPathAddress);
    rd_reader_read_le32(r, &v->DebugFileNameAddress);
    rd_reader_read_le32(r, &v->DebugUnicodeFileNameAddress);
    rd_reader_read_le32(r, &v->KernelThunkAddress);
    rd_reader_read_le32(r, &v->NonKernelImportAddress);
    rd_reader_read_le32(r, &v->NumberOfLibraryVersions);
    rd_reader_read_le32(r, &v->LibraryVersionsAddress);
    rd_reader_read_le32(r, &v->KernelLibraryVersionAddress);
    rd_reader_read_le32(r, &v->XapiLibraryVersionAddress);
    rd_reader_read_le32(r, &v->LogoBitmapAddress);
    rd_reader_read_le32(r, &v->LogoBitmapSize);

    return !rd_reader_has_error(r);
}

bool xbe_read_section(RDReader* r, XBESectionHeader* v) {
    rd_reader_read_le32(r, &v->Flags);
    rd_reader_read_le32(r, &v->VirtualAddress);
    rd_reader_read_le32(r, &v->VirtualSize);
    rd_reader_read_le32(r, &v->RawOffset);
    rd_reader_read_le32(r, &v->RawSize);
    rd_reader_read_le32(r, &v->SectionNameAddress);
    rd_reader_read_le32(r, &v->SectionReferenceCount);
    rd_reader_read_le32(r, &v->HeadSharedPageReferenceCountAddress);
    rd_reader_read_le32(r, &v->TailSharedPageReferenceCountAddress);
    rd_reader_read(r, &v->SectionDigest, sizeof(v->SectionDigest));

    return !rd_reader_has_error(r);
}

bool xbe_read_certificate(RDReader* r, XBECertificate* v) {
    rd_reader_read_le32(r, &v->Size);
    rd_reader_read_le32(r, &v->Timestamp);
    rd_reader_read_le32(r, &v->TitleId);
    rd_reader_read(r, &v->TitleName, sizeof(v->TitleName));
    rd_reader_read(r, &v->AlternateTitleIds, sizeof(v->AlternateTitleIds));
    rd_reader_read_le32(r, &v->MediaTypes);
    rd_reader_read_le32(r, &v->GameRegion);
    rd_reader_read_le32(r, &v->GameRating);
    rd_reader_read_le32(r, &v->DiskNumber);
    rd_reader_read_le32(r, &v->Version);
    rd_reader_read(r, &v->LanKey, sizeof(v->LanKey));
    rd_reader_read(r, &v->SignatureKey, sizeof(v->SignatureKey));

    if(v->Version > 1) {
        rd_reader_read(r, &v->AlternateSignatureKeys,
                       sizeof(v->AlternateSignatureKeys));
    }

    return !rd_reader_has_error(r);
}

const char* xbe_read_section_name(RDReader* r, const XBEFormat* xbe,
                                  const XBESectionHeader* shdr) {
    if(!shdr->SectionNameAddress) return NULL;

    u32 off = xbe_va_to_off(xbe, shdr->SectionNameAddress);
    if(!off) return NULL;

    rd_reader_seek(r, off);
    return rd_reader_read_str(r, NULL);
}

RDSegmentPerm xbe_segment_perm(const XBESectionHeader* shdr) {
    RDSegmentPerm p = RD_SP_R;
    if(shdr->Flags & XBE_SF_WRITABLE) p |= RD_SP_W;
    if(shdr->Flags & XBE_SF_EXECUTABLE) p |= RD_SP_X;
    return p;
}

u32 xbe_va_to_off(const XBEFormat* xbe, u32 va) {
    if(va < xbe->header.ImageBase) return 0;
    return va - xbe->header.ImageBase;
}

u32 xbe_decode_ep(const XBEFormat* xbe, bool* out_debug) {
    u32 image_end = xbe->header.ImageBase + xbe->header.SizeOfImage;
    u32 retail = xbe->header.EntryPoint ^ XBE_EP_RETAIL_KEY;
    u32 debug = xbe->header.EntryPoint ^ XBE_EP_DEBUG_KEY;

    if(retail >= xbe->header.ImageBase && retail < image_end) {
        *out_debug = false;
        return retail;
    }

    if(debug >= xbe->header.ImageBase && debug < image_end) {
        *out_debug = true;
        return debug;
    }

    // Corrupt / unusual XBE: return retail decode as best-effort
    *out_debug = false;
    return retail;
}

u32 xbe_decode_kt(const XBEFormat* xbe) {
    return xbe->header.KernelThunkAddress ^
           (xbe->is_debug ? XBE_KT_DEBUG_KEY : XBE_KT_RETAIL_KEY);
}
