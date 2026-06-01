#pragma once

// Reference: xboxdevwiki.net/Xbe

#include <redasm/redasm.h>

#define XBE_MAGIC 0x48454258U // "XBEH" little-endian
#define XBE_MAGIC_STR "XBEH"
#define XBE_MAGIC_SIZE 4

// Section flag bits
#define XBE_SF_WRITABLE (1u << 0)
#define XBE_SF_PRELOAD (1u << 1)
#define XBE_SF_EXECUTABLE (1u << 2)
#define XBE_SF_INSERTED_FILE (1u << 3)

// Section flag bits
#define XBE_SF_WRITABLE (1u << 0)
#define XBE_SF_PRELOAD (1u << 1)
#define XBE_SF_EXECUTABLE (1u << 2)
#define XBE_SF_INSERTED_FILE (1u << 3)
#define XBE_SF_HEAD_PAGE_RO (1u << 4)
#define XBE_SF_TAIL_PAGE_RO (1u << 5)

#define XBE_MAX_SECTIONS 256

typedef struct XBEImageHeader {
    u32 Magic;
    u8 Signature[256];
    u32 ImageBase;
    u32 SizeOfHeaders;
    u32 SizeOfImage;
    u32 SizeOfImageHeader;
    u32 Timestamp;
    u32 CertificateAddress;
    u32 NumberOfSections;
    u32 SectionHeadersAddress;
    u32 InitFlags;
    u32 EntryPoint;
    u32 TlsAddress;
    u32 StackSize;
    u32 PeHeapReserve;
    u32 PeHeapCommit;
    u32 PeBaseAddress;
    u32 PeSizeOfImage;
    u32 PeChecksum;
    u32 PeTimestamp;
    u32 DebugPathAddress;
    u32 DebugFileNameAddress;
    u32 DebugUnicodeFileNameAddress;
    u32 KernelThunkAddress;
    u32 NonKernelImportAddress;
    u32 NumberOfLibraryVersions;
    u32 LibraryVersionsAddress;
    u32 KernelLibraryVersionAddress;
    u32 XapiLibraryVersionAddress;
    u32 LogoBitmapAddress;
    u32 LogoBitmapSize;
} XBEImageHeader;

typedef struct XBESectionHeader {
    u32 Flags;
    u32 VirtualAddress;
    u32 VirtualSize;
    u32 RawOffset;
    u32 RawSize;
    u32 SectionNameAddress;
    u32 SectionReferenceCount;
    u32 HeadSharedPageReferenceCountAddress;
    u32 TailSharedPageReferenceCountAddress;
    u8 SectionDigest[20];
} XBESectionHeader;

typedef struct XBECertificate {
    u32 Size;
    u32 Timestamp;
    u32 TitleId;
    u16 TitleName[40];
    u32 AlternateTitleIds[16];
    u32 MediaTypes;
    u32 GameRegion;
    u32 GameRating;
    u32 DiskNumber;
    u32 Version;
    u8 LanKey[16];
    u8 SignatureKey[16];
    u8 AlternateSignatureKeys[16][16]; // v2+
} XBECertificate;

typedef struct XBEFormat {
    XBEImageHeader header;
    XBECertificate certificate;
    bool is_debug;
    u32 entry_point;
    u32 kernel_thunk;
} XBEFormat;

bool xbe_read_header(RDReader* r, XBEImageHeader* v);
bool xbe_read_section(RDReader* r, XBESectionHeader* v);
bool xbe_read_certificate(RDReader* r, XBECertificate* v);
const char* xbe_read_section_name(RDReader* r, const XBEFormat* xbe,
                                  const XBESectionHeader* shdr);
RDSegmentPerm xbe_segment_perm(const XBESectionHeader* shdr);
u32 xbe_va_to_off(const XBEFormat* xbe, u32 va);
u32 xbe_decode_ep(const XBEFormat* xbe, bool* out_debug);
u32 xbe_decode_kt(const XBEFormat* xbe);
