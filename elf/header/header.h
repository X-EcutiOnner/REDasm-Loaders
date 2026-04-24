#pragma once

#include <redasm/redasm.h>

typedef struct ELFEhdr {
    u16 e_type;
    u16 e_machine;
    u32 e_flags;
    u64 e_entry;
    u64 e_phoff;
    u64 e_shoff;
    u16 e_phnum;
    u16 e_shnum;
    u16 e_shstrndx;
    u16 e_phentsize; // needed by elf_read_phdr offset arithmetic
    u16 e_shentsize; // needed by elf_read_shdr offset arithmetic
} ELFEhdr;

typedef struct ELFPhdr {
    u32 p_type;
    u32 p_flags;
    u64 p_offset;
    u64 p_vaddr;
    u64 p_paddr;
    u64 p_filesz;
    u64 p_memsz;
    u64 p_align;
} ELFPhdr;

typedef struct ELFShdr {
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
} ELFShdr;

typedef struct ELFSym {
    u32 st_name;
    u8 st_info;
    u8 st_other;
    u16 st_shndx;
    u64 st_value;
    u64 st_size;
} ELFSym;

typedef struct ELFRel {
    u64 r_offset; // GOT slot / target address
    u64 r_info;   // symbol index + reloc type
} ELFRel;

typedef struct ELFRela {
    u64 r_offset;
    u64 r_info;
    i64 r_addend; // explicit addend (ELF64 norm)
} ELFRela;
