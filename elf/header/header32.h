#pragma once

#include "common.h"

typedef struct Elf32Ehdr {
    ELFIdent e_ident;
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u32 e_entry;
    u32 e_phoff;
    u32 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
} Elf32Ehdr;

typedef struct Elf32Phdr {
    u32 p_type;
    u32 p_offset;
    u32 p_vaddr;
    u32 p_paddr;
    u32 p_filesz;
    u32 p_memsz;
    u32 p_flags;
    u32 p_align;
} Elf32Phdr;

typedef struct Elf32Shdr {
    u32 sh_name;
    u32 sh_type;
    u32 sh_flags;
    u32 sh_addr;
    u32 sh_offset;
    u32 sh_size;
    u32 sh_link;
    u32 sh_info;
    u32 sh_addralign;
    u32 sh_entsize;
} Elf32Shdr;

typedef struct Elf32Sym {
    u32 st_name;
    u32 st_value;
    u32 st_size;
    u8 st_info;
    u8 st_other;
    u16 st_shndx;
} Elf32Sym;

typedef struct Elf32Rel {
    u32 r_offset;
    u32 r_info;
} Elf32Rel;

typedef struct Elf32Rela {
    u32 r_offset;
    u32 r_info;
    i32 r_addend;
} Elf32Rela;
