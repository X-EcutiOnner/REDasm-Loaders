#pragma once

#include "common.h"

typedef struct Elf64Ehdr {
    ELFIdent e_ident;
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u64 e_entry;
    u64 e_phoff;
    u64 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
} Elf64Ehdr;

typedef struct Elf64Phdr {
    u32 p_type;
    u32 p_flags; // before p_offset, different from Elf32Phdr */
    u64 p_offset;
    u64 p_vaddr;
    u64 p_paddr;
    u64 p_filesz;
    u64 p_memsz;
    u64 p_align;
} Elf64Phdr;

typedef struct Elf64Shdr {
    u32 sh_name;
    u32 sh_type;
    u64 sh_flags;
    u64 sh_addr;
    u64 sh_offset;
    u64 sh_size;
    u32 sh_link;
    u32 sh_info;
    u64 sh_addralign;
    u64 sh_entsize;
} Elf64Shdr;

typedef struct Elf64Sym {
    u32 st_name;
    u8 st_info; // before st_value, different from Elf32Sym
    u8 st_other;
    u16 st_shndx;
    u64 st_value;
    u64 st_size;
} Elf64Sym;

typedef struct Elf64Rel {
    u64 r_offset;
    u64 r_info;
} Elf64Rel;

typedef struct Elf64Rela {
    u64 r_offset;
    u64 r_info;
    i64 r_addend;
} Elf64Rela;
