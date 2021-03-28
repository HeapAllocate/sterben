#ifndef __ELF_H
#define __ELF_H

#include <cdefs.h>

typedef uint16_t ELF_HALF;
typedef uint32_t ELF_WORD;
typedef uint32_t ELF32_OFF;
typedef uint64_t ELF64_OFF;
typedef uint32_t ELF32_WORD;
typedef uint32_t ELF64_WORD;
typedef uint64_t ELF64_XWORD;
typedef uint16_t ELF32_SECT;
typedef uint16_t ELF64_SECT;
typedef uint32_t ELF32_ADDR;
typedef uint64_t ELF64_ADDR;

#if WORDSIZE == 64
#define ELF_SHDR ELF64_SHDR
#define ELF_PHDR ELF64_PHDR
#define ELF_ADDR ELF64_ADDR
#define ELF_AUXV ELF64_AUXV
#define ELF_SYM  ELF64_SYM
#define ELF_OFF  ELF64_OFF
#else
#define ELF_SHDR ELF32_SHDR
#define ELF_PHDR ELF32_PHDR
#define ELF_ADDR ELF32_ADDR
#define ELF_AUXV ELF32_AUXV
#define ELF_SYM  ELF32_SYM
#define ELF_OFF  ELF32_OFF
#endif

#define SHT_PROGBITS   1
#define SHT_SYMTAB     2
#define SHT_STRTAB     3
#define SHT_DYNSYM    11

#define PT_LOAD        1

#define AT_NULL        0
#define AT_ENTRY       9

#define EI_NIDENT     16

#define ELF_ENTRY(p) ((ELF_EHDR *)p)->e_entry
#define ELF_BASE(p)  ((ELF_PHDR *)(p+sizeof(ELF_EHDR)+(sizeof(ELF_PHDR))*2))->p_vaddr

typedef struct  {
  unsigned char e_ident[EI_NIDENT];
  ELF_HALF      e_type;
  ELF_HALF      e_machine;
  ELF_WORD      e_version;
  ELF_ADDR      e_entry;
  ELF_OFF       e_phoff;
  ELF_OFF       e_shoff;
  ELF_WORD      e_flags;
  ELF_HALF      e_ehsize;
  ELF_HALF      e_phentsize;
  ELF_HALF      e_phnum;
  ELF_HALF      e_shentsize;
  ELF_HALF      e_shnum;
  ELF_HALF      e_shstrndx;
} ELF_EHDR;


typedef struct
{
  ELF32_WORD    sh_name;
  ELF32_WORD    sh_type;
  ELF32_WORD    sh_flags;
  ELF32_ADDR    sh_addr;
  ELF32_OFF     sh_offset;
  ELF32_WORD    sh_size;
  ELF32_WORD    sh_link;
  ELF32_WORD    sh_info;
  ELF32_WORD    sh_addralign;
  ELF32_WORD    sh_entsize;
} ELF32_SHDR;

typedef struct
{
  ELF64_WORD    sh_name;
  ELF64_WORD    sh_type;
  ELF64_XWORD   sh_flags;
  ELF64_ADDR    sh_addr;
  ELF64_OFF     sh_offset;
  ELF64_XWORD   sh_size;
  ELF64_WORD    sh_link;
  ELF64_WORD    sh_info;
  ELF64_XWORD   sh_addralign;
  ELF64_XWORD   sh_entsize;
} ELF64_SHDR;

typedef struct
{
  ELF32_WORD    p_type;
  ELF32_OFF     p_offset;
  ELF32_ADDR    p_vaddr;
  ELF32_ADDR    p_paddr;
  ELF32_WORD    p_filesz;
  ELF32_WORD    p_memsz;
  ELF32_WORD    p_flags;
  ELF32_WORD    p_align;
} ELF32_PHDR;

typedef struct
{
  ELF64_WORD    p_type;
  ELF64_WORD    p_flags;
  ELF64_OFF     p_offset;
  ELF64_ADDR    p_vaddr;
  ELF64_ADDR    p_paddr;
  ELF64_XWORD   p_filesz;
  ELF64_XWORD   p_memsz;
  ELF64_XWORD   p_align;
} ELF64_PHDR;

typedef struct
{
  ELF32_WORD    st_name;
  ELF32_ADDR    st_value;
  ELF32_WORD    st_size;
  unsigned char st_info;
  unsigned char st_other;
  ELF32_SECT    st_shndx;
} ELF32_SYM;


typedef struct
{
  ELF64_WORD    st_name;
  unsigned char st_info;
  unsigned char st_other;
  ELF64_SECT    st_shndx;
  ELF64_ADDR    st_value;
  ELF64_XWORD   st_size;
} ELF64_SYM;

typedef struct
{
  uint32_t a_type;
  uint32_t a_val;
} ELF32_AUXV;

typedef struct
{
  uint64_t a_type;
  uint64_t a_val;
} ELF64_AUXV;

#endif
