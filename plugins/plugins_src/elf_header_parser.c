#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "pe_header_parser.h"
#include "api_monitor.h"
#include "plugins/plugin.h"

//#define DEBUG_DLL

typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef int32_t  Elf32_Sword;
typedef uint32_t Elf32_Word;

typedef struct Elf32_Sym{
  Elf32_Word    st_name;
  Elf32_Addr    st_value;
  Elf32_Word    st_size;
  unsigned char st_info;
  unsigned char st_other;
  Elf32_Half    st_shndx;
} QEMU_PACKED Elf32_Sym;

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4
#define STT_COMMON  5
#define STT_TLS     6

#define ELF_ST_BIND(x)      ((x) >> 4)
#define ELF_ST_TYPE(x)      (((unsigned int) x) & 0xf)

#define EI_NIDENT   16

typedef struct Elf32_Ehdr{
  unsigned char e_ident[EI_NIDENT];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;  /* Entry point */
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
} QEMU_PACKED Elf32_Ehdr;

/* sh_type */
#define SHT_NULL    0
#define SHT_PROGBITS    1
#define SHT_SYMTAB  2
#define SHT_STRTAB  3
#define SHT_RELA    4
#define SHT_HASH    5
#define SHT_DYNAMIC 6
#define SHT_NOTE    7
#define SHT_NOBITS  8
#define SHT_REL     9
#define SHT_SHLIB   10
#define SHT_DYNSYM  11
#define SHT_NUM     12
#define SHT_LOPROC  0x70000000
#define SHT_HIPROC  0x7fffffff
#define SHT_LOUSER  0x80000000
#define SHT_HIUSER  0xffffffff

/* This is the info that is needed to parse the dynamic section of the file */
#define DT_NULL     0
#define DT_NEEDED   1
#define DT_PLTRELSZ 2
#define DT_PLTGOT   3
#define DT_HASH     4
#define DT_STRTAB   5
#define DT_SYMTAB   6
#define DT_RELA     7
#define DT_RELASZ   8
#define DT_RELAENT  9
#define DT_STRSZ    10
#define DT_SYMENT   11
#define DT_INIT     12
#define DT_FINI     13
#define DT_SONAME   14
#define DT_RPATH    15
#define DT_SYMBOLIC 16
#define DT_REL          17
#define DT_RELSZ    18
#define DT_RELENT   19
#define DT_PLTREL   20
#define DT_DEBUG    21
#define DT_TEXTREL  22
#define DT_JMPREL   23
#define DT_ENCODING 32
#define OLD_DT_LOOS 0x60000000
#define DT_LOOS     0x6000000d
#define DT_HIOS     0x6ffff000
#define DT_VALRNGLO 0x6ffffd00
#define DT_VALRNGHI 0x6ffffdff
#define DT_ADDRRNGLO    0x6ffffe00
#define DT_ADDRRNGHI    0x6ffffeff
#define DT_VERSYM   0x6ffffff0
#define DT_RELACOUNT    0x6ffffff9
#define DT_RELCOUNT 0x6ffffffa
#define DT_FLAGS_1  0x6ffffffb
#define DT_VERDEF   0x6ffffffc
#define DT_VERDEFNUM    0x6ffffffd
#define DT_VERNEED  0x6ffffffe
#define DT_VERNEEDNUM   0x6fffffff
#define OLD_DT_HIOS     0x6fffffff
#define DT_LOPROC   0x70000000
#define DT_HIPROC   0x7fffffff

/* These constants are for the segment types stored in the image headers */
#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6
#define PT_TLS     7               /* Thread local storage segment */
#define PT_LOOS    0x60000000      /* OS-specific */
#define PT_HIOS    0x6fffffff      /* OS-specific */
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7fffffff
#define PT_GNU_EH_FRAME     0x6474e550

typedef struct elf32_phdr{
  Elf32_Word    p_type;
  Elf32_Off p_offset;
  Elf32_Addr    p_vaddr;
  Elf32_Addr    p_paddr;
  Elf32_Word    p_filesz;
  Elf32_Word    p_memsz;
  Elf32_Word    p_flags;
  Elf32_Word    p_align;
} QEMU_PACKED Elf32_Phdr;

typedef struct Elf32_Shdr {
  Elf32_Word    sh_name;
  Elf32_Word    sh_type;
  Elf32_Word    sh_flags;
  Elf32_Addr    sh_addr;
  Elf32_Off sh_offset;
  Elf32_Word    sh_size;
  Elf32_Word    sh_link;
  Elf32_Word    sh_info;
  Elf32_Word    sh_addralign;
  Elf32_Word    sh_entsize;
} QEMU_PACKED Elf32_Shdr;

typedef struct dynamic{
  Elf32_Sword d_tag;
  union{
    Elf32_Sword d_val;
    Elf32_Addr  d_ptr;
  } d_un;
} QEMU_PACKED Elf32_Dyn;

#define elfhdr Elf32_Ehdr
#define elf_sym Elf32_Sym
#define elf_phdr Elf32_Phdr
#define elf_shdr Elf32_Shdr
#define elf_dyn Elf32_Dyn

#define EI_MAG0     0       /* e_ident[] indexes */
#define EI_MAG1     1
#define EI_MAG2     2
#define EI_MAG3     3
#define EI_CLASS    4
#define EI_DATA     5
#define EI_VERSION  6
#define EI_OSABI    7
#define EI_PAD      8

#define ELFMAG0     0x7f        /* EI_MAG */
#define ELFMAG1     'E'
#define ELFMAG2     'L'
#define ELFMAG3     'F'
#define ELFMAG      "\177ELF"
#define SELFMAG     4

#define ELFCLASSNONE    0       /* EI_CLASS */
#define ELFCLASS32  1
#define ELFCLASS64  2
#define ELFCLASSNUM 3

#define ELFDATANONE 0       /* e_ident[EI_DATA] */
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

#define EV_NONE     0       /* e_version, EI_VERSION */
#define EV_CURRENT  1
#define EV_NUM      2

#define ELF_CLASS ELFCLASS32
#define ELF_DATA ELFDATA2LSB

static bool elf_check_ident(struct elfhdr *ehdr)
{
    return (ehdr->e_ident[EI_MAG0] == ELFMAG0
            && ehdr->e_ident[EI_MAG1] == ELFMAG1
            && ehdr->e_ident[EI_MAG2] == ELFMAG2
            && ehdr->e_ident[EI_MAG3] == ELFMAG3
            && ehdr->e_ident[EI_CLASS] == ELF_CLASS
            && ehdr->e_ident[EI_DATA] == ELF_DATA
            && ehdr->e_ident[EI_VERSION] == EV_CURRENT);
}

static bool read_page(uint8_t *data, uint32_t page, bool *pages, int countPages, uint32_t imageBaseAddr)
{
    if (page >= countPages) {
        return false;
    }
    if (pages[page]) {
        return true;
    }
    if (!cpu_memory_rw_debug(first_cpu, imageBaseAddr + page * TARGET_PAGE_SIZE, &data[page * TARGET_PAGE_SIZE], TARGET_PAGE_SIZE, 0)) {
        pages[page] = true;
        return true;
    }
    return false;
}

static bool read8(uint8_t *var, uint32_t pos, uint8_t *data, bool *pages, int countPages, uint32_t imageBase)
{
    uint32_t page = pos / TARGET_PAGE_SIZE;
    if (pages[page]
        || read_page(data, page, pages, countPages, imageBase)) {
        *var = data[pos];
        return true;
    }
    return false;
}

static bool read16(uint16_t *var, uint32_t pos, uint8_t *data, bool *pages, int countPages, uint32_t imageBase)
{
    uint32_t page = pos / TARGET_PAGE_SIZE;
    uint32_t page2 = (pos + 1) / TARGET_PAGE_SIZE;
    if (read_page(data, page, pages, countPages, imageBase)
        && read_page(data, page2, pages, countPages, imageBase)) {
        *var = lduw_p(&data[pos]);
        return true;
    }
    return false;
}

static bool read32(uint32_t *var, uint32_t pos, uint8_t *data, bool *pages, int countPages, uint32_t imageBase)
{
    uint32_t page = pos / TARGET_PAGE_SIZE;
    uint32_t page2 = (pos + 3) / TARGET_PAGE_SIZE;
    if (read_page(data, page, pages, countPages, imageBase)
        && read_page(data, page2, pages, countPages, imageBase)) {
        *var = ldl_p(&data[pos]);
        return true;
    }
    return false;
}

static uint8_t *data;
static uint64_t data_size;
static bool *pages;

ParseHeaderRet parse_header(void *params)
{
#define LD8(var, p) do { if (!read8(&var, p, data, pages, countPages, imageBaseAddr)) return PE_ERROR; } while (0)
#define LD16(var, p) do { if (!read16(&var, p, data, pages, countPages, imageBaseAddr)) return PE_ERROR; } while (0)
#define LD32(var, p) do { if (!read32(&var, p, data, pages, countPages, imageBaseAddr)) return PE_ERROR; } while (0)
#define PAGE(addr) do { if (!read_page(data, (addr) / TARGET_PAGE_SIZE, pages, countPages, imageBaseAddr)) return PE_ERROR; } while(0)

    uint32_t imageBaseAddr = 0;
    int i;
    
    map_params *param = (map_params *) params;
    imageBaseAddr = param->imageBase;

    if (param->section->headerCompleted) {
        return PE_OK;
    }
#ifdef DEBUG_DLL
    printf("elf_name: %s addr=0x%"PRIx64" size=0x%"PRIx64"\n", param->section->dll_name, param->imageBase, param->viewSize);
#endif
    uint64_t viewSize = param->viewSize;
    uint64_t countPages = (viewSize + TARGET_PAGE_SIZE - 1) / TARGET_PAGE_SIZE;
    if (!data) {
        data = g_malloc(viewSize);
        pages = g_new(bool, countPages);
        data_size = viewSize;
    } else if (data_size < viewSize) {
        g_free(data);
        g_free(pages);
        data = g_malloc(viewSize);
        pages = g_new(bool, countPages);
        data_size = viewSize;
    }

    memset(pages, 0, sizeof(pages[0]) * countPages);

    struct elfhdr *ehdr = (struct elfhdr *)data;

    // Fetch the header
    PAGE(0);

    // First of all, some simple consistency checks
    if (!elf_check_ident(ehdr)) {
        return PE_UNKNOWN_FORMAT;
    }
    // skip other checks

    // read program header
    uint16_t phnum, phentsize;
    uint32_t phoff;
    LD16(phnum, offsetof(elfhdr, e_phnum));
    LD16(phentsize, offsetof(elfhdr, e_phentsize));
    LD32(phoff, offsetof(elfhdr, e_phoff));
#ifdef DEBUG_DLL
    printf("program header off=0x%x entsize=0x%x num=0x%x\n", phoff, phentsize, phnum);
#endif

    uint32_t dynoff = -1, dynvaddr = -1, dynsz = 1;
    for (i = 0 ; i < phnum ; ++i) {
        uint32_t off = phoff + i * phentsize;
        uint32_t type, offset, vaddr, filesz, memsz;
        LD32(type, off + offsetof(elf_phdr, p_type));
        LD32(offset, off + offsetof(elf_phdr, p_offset));
        LD32(vaddr, off + offsetof(elf_phdr, p_vaddr));
        LD32(filesz, off + offsetof(elf_phdr, p_filesz));
        LD32(memsz, off + offsetof(elf_phdr, p_memsz));
        if (type == PT_DYNAMIC) {
            dynoff = offset;
            dynvaddr = vaddr;
            dynsz = filesz;
        }
#ifdef DEBUG_DLL
        printf("\tentry type=0x%x off=0x%x vaddr=0x%x filesz=0x%x memsz=0x%x\n", type, offset, vaddr, filesz, memsz);
#endif
    }

    if (dynoff == -1 || dynvaddr == -1) {
        return PE_UNKNOWN_FORMAT;
    }

    // read dynamic section
#ifdef DEBUG_DLL
    printf("dynamic section entries\n");
#endif
    uint32_t strtab = 0, symtab = 0, strsz = 0, syment = 0;
    for (i = 0 ; i < dynsz ; i += sizeof(elf_dyn)) {
        uint32_t tag, val;
        LD32(tag, dynvaddr + i + offsetof(elf_dyn, d_tag));
        LD32(val, dynvaddr + i + offsetof(elf_dyn, d_un));
#ifdef DEBUG_DLL
        printf("\tentry tag=0x%x val=0x%x\n", tag, val);
#endif
        if (tag == DT_STRTAB) {
            // already converted to vaddr by loader
            strtab = val - imageBaseAddr;
        } else if (tag == DT_SYMTAB) {
            // already converted to vaddr by loader
            symtab = val - imageBaseAddr;
        } else if (tag == DT_STRSZ) {
            strsz = val;
        } else if (tag == DT_SYMENT) {
            syment = val;
        }
    }
    if (!strtab || !symtab || !strsz || !syment) {
        return PE_UNKNOWN_FORMAT;
    }
    // read symbol table
#ifdef DEBUG_DLL
    printf("symbol table entries from 0x%x to 0x%x\n", symtab, strtab);
#endif
    uint32_t s;
    // count functions
    int func_count = 0;
    if (!param->section->functions) {
        for (s = symtab ; s < strtab ; s += syment) {
            uint8_t info;
            LD8(info, s + offsetof(elf_sym, st_info));
            if (ELF_ST_TYPE(info) == STT_FUNC) {
                ++func_count;
            }
        }
        // allocate memory for functions
        param->section->functions = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
        param->section->addresses = g_new0(uint64_t, func_count);
        param->section->funcCount = func_count;
    }
    func_count = 0;
    for (s = symtab ; s < strtab ; s += syment) {
        uint32_t name, value;
        uint8_t info;
        LD32(name, s + offsetof(elf_sym, st_name));
        LD32(value, s + offsetof(elf_sym, st_value));
        LD8(info, s + offsetof(elf_sym, st_info));
        if (ELF_ST_TYPE(info) == STT_FUNC) {
            // found a function
            param->section->addresses[func_count] = value;
            if (!g_hash_table_lookup(param->section->functions,
                                    &param->section->addresses[func_count])) {
                char str[128];
                int k;
                uint32_t pos = strtab + name;
                for (k = 0; k < 127; k++) {
                    uint8_t symbol;
                    LD8(symbol, pos);
                    str[k] = symbol;
                    if (!str[k]) {
                        break;
                    }
                    ++pos;
                }
                str[k] = 0;

                g_hash_table_insert(param->section->functions,
                    &param->section->addresses[func_count], g_strdup(str));
#ifdef DEBUG_DLL
                printf("  entry 0x%x name=%s value=0x%x info=0x%x\n",
                    s, str, value, info);
#endif
            }
            ++func_count;
        }
    }

#ifdef DEBUG_DLL
    printf("parsing is finished\n");
#endif    
    param->section->headerCompleted = true;
    return PE_OK;
}
