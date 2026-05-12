#pragma once

#include "constants.h"
#include <redasm/redasm.h>

#define PE_FIRST_SECTION(nt)                                                   \
    (PESectionHeader*)((char*)(nt) + nt->FileHeader.SizeOfOptionalHeader + 0x18)

typedef struct PEFileHeader {
    u16 Machine, NumberOfSections;
    u32 TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    u16 SizeOfOptionalHeader, Characteristics;
} PEFileHeader;

typedef struct PEDataDirectory {
    u32 VirtualAddress, Size;
} PEDataDirectory;

typedef struct PEOptionalHeader32 {
    u16 Magic;
    u8 MajorLinkerVersion, MinorLinkerVersion;
    u32 SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    u32 AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase;
    u32 SectionAlignment, FileAlignment;
    u16 MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    u16 MajorImageVersion, MinorImageVersion;
    u16 MajorSubsystemVersion, MinorSubsystemVersion;
    u32 Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    u16 Subsystem, DllCharacteristics;
    u32 SizeOfStackReserve, SizeOfStackCommit;
    u32 SizeOfHeapReserve, SizeOfHeapCommit;
    u32 LoaderFlags, NumberOfRvaAndSizes;
    // PEDataDirectory DataDirectory[PE_NUMBER_OF_DIRECTORY_ENTRIES];
} PEOptionalHeader32;

typedef struct PEOptionalHeader64 {
    u16 Magic;
    u8 MajorLinkerVersion, MinorLinkerVersion;
    u32 SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    u32 AddressOfEntryPoint, BaseOfCode;
    u64 ImageBase;
    u32 SectionAlignment, FileAlignment;
    u16 MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    u16 MajorImageVersion, MinorImageVersion;
    u16 MajorSubsystemVersion, MinorSubsystemVersion;
    u32 Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    u16 Subsystem, DllCharacteristics;
    u64 SizeOfStackReserve, SizeOfStackCommit;
    u64 SizeOfHeapReserve, SizeOfHeapCommit;
    u32 LoaderFlags, NumberOfRvaAndSizes;
    // PEDataDirectory DataDirectory[PE_NUMBER_OF_DIRECTORY_ENTRIES];
} PEOptionalHeader64;

// typedef struct PENtHeaders {
//     u32 Signature;
//     PEFileHeader FileHeader;
// } PENtHeaders;

typedef struct PESectionHeader {
    char Name[PE_SIZE_OF_SHORT_NAME];
    u32 VirtualSize, VirtualAddress;
    u32 SizeOfRawData, PointerToRawData;
    u32 PointerToRelocations, PointerToLinenumbers;
    u16 NumberOfRelocations, NumberOfLinenumbers;
    u32 Characteristics;
} PESectionHeader;
