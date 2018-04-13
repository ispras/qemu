#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "pe_header_parser.h"
#include "api_monitor.h"
#include "elf.h"

//#define DEBUG_DLL

#define elfhdr Elf32_Ehdr
#define elf_sym Elf32_Sym
#define elf_phdr Elf32_Phdr
#define elf_shdr Elf32_Shdr
#define elf_dyn Elf32_Dyn

#define ELF_CLASS ELFCLASS32
#define ELF_DATA ELFDATA2LSB

static bool elf_check_ident(elfhdr *ehdr)
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
    if (!cpu_memory_rw_debug(first_cpu,
            imageBaseAddr + page * TARGET_PAGE_SIZE,
            &data[page * TARGET_PAGE_SIZE], TARGET_PAGE_SIZE, 0)) {
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
#define LD8(var, p) do { if ((p) >= viewSize) return PE_ERROR; if (!read8(&var, p, data, pages, countPages, imageBaseAddr)) return PE_ERROR; } while (0)
#define LD16(var, p) do { if ((p) >= viewSize) return PE_ERROR; if (!read16(&var, p, data, pages, countPages, imageBaseAddr)) return PE_ERROR; } while (0)
#define LD32(var, p) do { if ((p) >= viewSize) return PE_ERROR; if (!read32(&var, p, data, pages, countPages, imageBaseAddr)) return PE_ERROR; } while (0)
#define PAGE(addr) do { if ((addr) >= viewSize) return PE_ERROR; if (!read_page(data, (addr) / TARGET_PAGE_SIZE, pages, countPages, imageBaseAddr)) return PE_ERROR; } while(0)

    uint32_t imageBaseAddr = 0;
    int i;
    
    map_params *param = (map_params *) params;
    imageBaseAddr = param->imageBase;

    if (param->section->headerCompleted) {
        return PE_OK;
    }
#ifdef DEBUG_DLL
    static FILE *log_file;
//#define DUMP_FILES
#ifdef DUMP_FILES
    static int n = 0;
    {
        char fn[128];
        sprintf(fn, "%04dt.bin", n);
        if (log_file && log_file != stdout) {
            fclose(log_file);
        }
        log_file = fopen(fn, "w");
    }
#endif
    if (!log_file) {
        log_file = stdout;
    }

    fprintf(log_file, "context: %"PRIx64"\n", plugins_get_current_context());
    fprintf(log_file, "elf_name: %s addr=0x%"PRIx64" size=0x%"PRIx64"\n", param->section->dll_name, param->imageBase, param->viewSize);
#endif
    uint64_t viewSize = param->viewSize;
    uint64_t countPages = (viewSize + TARGET_PAGE_SIZE - 1) / TARGET_PAGE_SIZE;
    uint64_t arrSize = countPages * TARGET_PAGE_SIZE;
    if (!data) {
        data = g_malloc0(arrSize);
        pages = g_new(bool, countPages);
        data_size = arrSize;
    } else if (data_size < arrSize) {
        g_free(data);
        g_free(pages);
        data = g_malloc0(arrSize);
        pages = g_new(bool, countPages);
        data_size = arrSize;
    }

#ifdef DEBUG_DLL
#ifdef DUMP_FILES
    {
        cpu_memory_rw_debug(first_cpu, 
            imageBaseAddr, data, viewSize, 0);
        char fn[128];
        sprintf(fn, "%04d.bin", n++);
        FILE *f = fopen(fn, "wb");
        fwrite(data, viewSize, 1, f);
        fclose(f);
    }
#endif
#endif

    memset(pages, 0, sizeof(pages[0]) * countPages);

    elfhdr *ehdr = (elfhdr*)data;

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
    fprintf(log_file, "program header off=0x%x entsize=0x%x num=0x%x\n", phoff, phentsize, phnum);
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
        fprintf(log_file, "\tentry type=0x%x off=0x%x vaddr=0x%x filesz=0x%x memsz=0x%x\n", type, offset, vaddr, filesz, memsz);
#endif
    }

    if (dynoff == -1 || dynvaddr == -1) {
        return PE_UNKNOWN_FORMAT;
    }

    // read dynamic section
#ifdef DEBUG_DLL
    fprintf(log_file, "dynamic section entries\n");
#endif
    uint32_t strtab = 0, symtab = 0, strsz = 0, syment = 0;
    for (i = 0 ; i < dynsz ; i += sizeof(elf_dyn)) {
        uint32_t tag, val;
        LD32(tag, dynvaddr + i + offsetof(elf_dyn, d_tag));
        LD32(val, dynvaddr + i + offsetof(elf_dyn, d_un));
#ifdef DEBUG_DLL
        fprintf(log_file, "\tentry tag=0x%x val=0x%x\n", tag, val);
#endif
        if (tag == DT_STRTAB) {
            // already converted to vaddr by loader
            if (val >= imageBaseAddr) {
                strtab = val - imageBaseAddr;
            } else {
                strtab = val;
            }
        } else if (tag == DT_SYMTAB) {
            // already converted to vaddr by loader
            if (val >= imageBaseAddr) {
                symtab = val - imageBaseAddr;
            } else {
                symtab = val;
            }
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
    fprintf(log_file, "symbol table entries from 0x%x to 0x%x\n", symtab, strtab);
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
                fprintf(log_file, "  entry 0x%x name=%s value=0x%x info=0x%x\n",
                    s, str, value, info);
#endif
            }
            ++func_count;
        }
    }

#ifdef DEBUG_DLL
    fprintf(log_file, "parsing is finished\n");
    if (log_file != stdout) {
        fclose(log_file);
        log_file = stdout;
    }
#endif    
    param->section->headerCompleted = true;
    return PE_OK;
}

