#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "pe_header_parser.h"
#include "api_monitor.h"

//#define DEBUG_DLL
typedef struct _TCG_IMAGE_DOS_HEADER {
     uint16_t e_magic;
     uint16_t e_cblp;
     uint16_t e_cp;
     uint16_t e_crlc;
     uint16_t e_cparhdr;
     uint16_t e_minalloc;
     uint16_t e_maxalloc;
     uint16_t e_ss;
     uint16_t e_sp;
     uint16_t e_csum;
     uint16_t e_ip;
     uint16_t e_cs;
     uint16_t e_lfarlc;
     uint16_t e_ovno;
     uint16_t e_res[4];
     uint16_t e_oemid;
     uint16_t e_oeminfo;
     uint16_t e_res2[10];
     uint32_t e_lfanew;
} QEMU_PACKED TCG_IMAGE_DOS_HEADER;

typedef struct PEHeader {
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
} QEMU_PACKED PEHeader;
PEHeader pe_header;

typedef struct IMAGE_DATA_DIRECTORY_ {
    uint32_t virtualAddress;
    uint32_t size;
} QEMU_PACKED IMAGE_DATA_DIRECTORY_;
IMAGE_DATA_DIRECTORY_ data_dir[16];

typedef struct IMAGE_SECTION_HEADER_ {
    uint8_t Name[8];
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} QEMU_PACKED IMAGE_SECTION_HEADER_;


// will not be used here
// compiler complains about this
#define fread(A, B, C, D)

static bool read_page(uint8_t *data, uint32_t page, bool *pages, int countPages, uint32_t imageBaseAddr)
{
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

    uint32_t imageBaseAddr = 0;
    int curpos = 0;    
    
    map_params *param = (map_params *) params;
    imageBaseAddr = param->imageBase;

    if (param->section->headerCompleted) {
        return PE_OK;
    }

#ifdef DEBUG_DLL
    printf("dll_name: %s\n", param->section->dll_name);
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
    
    // check DOS header
    uint16_t magic;
    LD16(magic, offsetof(TCG_IMAGE_DOS_HEADER, e_magic));
    if (magic != 0x5a4d) {
        return PE_UNKNOWN_FORMAT;
    }
    uint32_t base;
    LD32(base, offsetof(TCG_IMAGE_DOS_HEADER, e_lfanew));
    curpos = base;
    // check PE header
    uint8_t s1, s2;
    LD8(s1, curpos);
    LD8(s2, curpos + 1);
    if (s1 != 'P' || s2 != 'E') {
        return PE_UNKNOWN_FORMAT;
    }
#ifdef DEBUG_DLL
    printf("signature: %c%c\n", data[0], data[1]);
    printf("header is read, offset = %i\n", curpos);
#endif
    
    /* now we can read header */
    curpos += 4;
#ifdef DEBUG_DLL
    printf( "header\n");
    // machine
    LD16(pe_header.machine, curpos);
#endif
    curpos += 2;
#ifdef DEBUG_DLL
    printf("machine: 0x%x\n", pe_header.machine);
#endif
    // number of sections
    LD16(pe_header.numberOfSections, curpos); // important 
#ifdef DEBUG_DLL    
    printf("number of sections: 0x%x\n", pe_header.numberOfSections);
#endif    
    curpos += 2;
    // time date stamp
#ifdef DEBUG_DLL    
    LD32(pe_header.timeDateStamp, curpos);
    printf("time date stamp: 0x%x\n", pe_header.timeDateStamp);
#endif
    curpos += 4;
    // pointer to symbol table
#ifdef DEBUG_DLL
    LD32(pe_header.pointerToSymbolTable, curpos);
    printf("pointer to symbol table: 0x%x\n", pe_header.pointerToSymbolTable);
#endif
    curpos += 4;
    // number of symbols
#ifdef DEBUG_DLL
    LD32(pe_header.numberOfSymbols, curpos);
    printf("number of symbols: 0x%x\n", pe_header.numberOfSymbols);
#endif
    curpos += 4;
    // size of optional header
    LD16(pe_header.sizeOfOptionalHeader, curpos);
#ifdef DEBUG_DLL    
    printf("size of optional header: 0x%x\n", pe_header.sizeOfOptionalHeader);
#endif    
    curpos += 2;
    // characteristics
#ifdef DEBUG_DLL
    LD16(pe_header.characteristics, curpos);
    printf("characteristics: 0x%x\n", pe_header.characteristics);
#endif
    curpos += 2;
    //printf("curpos = %i\n", curpos);
    
    curpos += 28;
    uint32_t imageBase;
    LD32(imageBase, curpos); // in 64-bit is is 8 bytes
#ifdef DEBUG_DLL
    printf("ImageBase: 0x%x\n", imageBase);
#endif
    curpos += 4;
#ifdef DEBUG_DLL
    uint32_t sectionAlign;
    LD32(sectionAlign, curpos);
    printf("SectionAligment: 0x%x\n", sectionAlign);
#endif
    curpos += 4;
    uint32_t fileAligment;
    LD32(fileAligment, curpos);
#ifdef DEBUG_DLL
    printf("FileAligment: 0x%x\n", fileAligment);
#endif
    curpos += 4;
    
    curpos += 56;

    uint32_t exp_addr = 0;
    uint32_t exp_size __attribute__ ((unused)) = 0;
    int i;
    for (i = 0; i < 16; i++)
    {
        uint32_t var;
        LD32(var, curpos);
#ifdef DEBUG_DLL
        printf("addr = 0x%x  ", var);
#endif
        if (i == 0) LD32(exp_addr, curpos);
        curpos += 4;

        LD32(var, curpos);
#ifdef DEBUG_DLL
        printf("size = 0x%x\n", var);
#endif
        if (i == 0) LD32(exp_size, curpos);
        curpos += 4;
    }
    IMAGE_SECTION_HEADER_ section_header[pe_header.numberOfSections];
    int k;
    for (k = 0; k < pe_header.numberOfSections; k++)
    {
        int i = 0;
        for (i = 0; i < 8; i++)
        {
#ifdef DEBUG_DLL
            printf("%c", data[curpos]);
#endif
            section_header[k].Name[i] = data[curpos];
            curpos++;
        }
#ifdef DEBUG_DLL        
        printf("\n");
#endif        

        LD32(section_header[k].VirtualSize, curpos);
#ifdef DEBUG_DLL        
        printf("VirtualSize 0x%x\n", section_header[k].VirtualSize);
#endif        
        curpos += 4;

        LD32(section_header[k].VirtualAddress, curpos);
#ifdef DEBUG_DLL        
        printf("VirtualAddress 0x%x\n", section_header[k].VirtualAddress); // section RVA
#endif
        curpos += 4;

        LD32(section_header[k].SizeOfRawData, curpos);
#ifdef DEBUG_DLL        
        printf("SizeOfRawData 0x%x\n", section_header[k].SizeOfRawData);
#endif        
        curpos += 4;

#ifdef DEBUG_DLL
        LD32(section_header[k].PointerToRawData, curpos);
        printf("PointerToRawData 0x%x\n", section_header[k].PointerToRawData);
#endif
        curpos += 4;
#ifdef DEBUG_DLL
        LD32(section_header[k].PointerToRelocations, curpos);
        printf("PointerToRelocations 0x%x\n", section_header[k].PointerToRelocations);
#endif
        curpos += 4;
#ifdef DEBUG_DLL
        LD32(section_header[k].PointerToLinenumbers, curpos);
        printf("PointerToLinenumbers 0x%x\n", section_header[k].PointerToLinenumbers);
#endif
        curpos += 4;
#ifdef DEBUG_DLL
        LD16(section_header[k].NumberOfRelocations, curpos);
        printf("NumberOfRelocations 0x%x\n", section_header[k].NumberOfRelocations);
#endif
        curpos += 2;
#ifdef DEBUG_DLL
        LD16(section_header[k].NumberOfLinenumbers, curpos);
        printf("NumberOfLinenumbers 0x%x\n", section_header[k].NumberOfLinenumbers);
#endif
        curpos += 2;
#ifdef DEBUG_DLL
        LD32(section_header[k].Characteristics, curpos);
        printf("Characteristics 0x%x\n", section_header[k].Characteristics);
#endif
        curpos += 4;
    }
    
    uint32_t exportRAWaddr = exp_addr;
#ifdef DEBUG_DLL    
    printf("RAW addr = 0x%x\n", exportRAWaddr);
#endif
    
    curpos = exportRAWaddr;
    uint32_t tmp;
    //uint16_t tmp2;
#ifdef DEBUG_DLL
    LD32(tmp, curpos);
    printf("export: characteristics 0x%x\n", tmp);
#endif
    curpos += 4;
#ifdef DEBUG_DLL
    LD32(tmp, curpos);
    printf("export: timeDateStamp 0x%x\n", tmp);
#endif
    curpos += 4;
#ifdef DEBUG_DLL    
    LD16(tmp2, curpos);
    printf("export: majorVersion 0x%x\n", tmp2);
#endif
    curpos += 2;
#ifdef DEBUG_DLL
    LD16(tmp2, curpos);
    printf("export: minorVersion 0x%x\n", tmp2);
#endif
    curpos += 2;

    uint32_t nameDLL;
    LD32(nameDLL, curpos);
#ifdef DEBUG_DLL    
    printf("export: name 0x%x\n", nameDLL);
#endif    
    curpos += 4;
    
    LD32(tmp, curpos);
#ifdef DEBUG_DLL
    printf("export: base 0x%x\n", tmp);
#endif
    curpos += 4;

    uint32_t numOfFunc;
    LD32(numOfFunc, curpos);
    if (!numOfFunc) {
        return PE_UNKNOWN_FORMAT;
    }
#ifdef DEBUG_DLL
    printf("export: numberOfFunctions 0x%x\n", numOfFunc);
#endif
    curpos += 4;

    uint32_t numOfNames;
    LD32(numOfNames, curpos);
#ifdef DEBUG_DLL    
    printf("export: numberOfNames 0x%x\n", numOfNames);
#endif    
    curpos += 4;

    uint32_t addrOfFunc;
    LD32(addrOfFunc, curpos);
#ifdef DEBUG_DLL    
    printf("export: addressOfFunctions 0x%x\n", addrOfFunc);
#endif
    curpos += 4;

    uint32_t addrOfNames;
    LD32(addrOfNames, curpos);
#ifdef DEBUG_DLL
    printf("export: addressOfNames 0x%x\n", addrOfNames);
#endif
    curpos += 4;

    uint32_t addrOfNameOrd;
    LD32(addrOfNameOrd, curpos);
#ifdef DEBUG_DLL    
    printf("export: addressOfNameOrdinals 0x%x\n", addrOfNameOrd);
#endif
    curpos += 4;

    if (!addrOfFunc || !addrOfNameOrd || !addrOfNames) {
        return PE_UNKNOWN_FORMAT;
    }
    
    if (!param->section->functions) {
        param->section->functions = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
        param->section->addresses = g_new0(uint64_t, numOfNames);
        param->section->funcCount = numOfNames;
    }

    /* read names of functions */
    for (i = 0; i < numOfNames; i++) {
        if (!g_hash_table_lookup(param->section->functions,
                                &param->section->addresses[i])) {
            // get function ordinal
            uint16_t ord;
            LD16(ord, addrOfNameOrd + i * 2);
            // get function address
            uint32_t addr;
            LD32(addr, addrOfFunc + ord * 4);
            param->section->addresses[i] = addr;
            // get name address
            LD32(addr, addrOfNames + i * 4);
            char name[128];
            int k;
            for (k = 0; k < 127; k++)
            {
                uint8_t symbol;
                LD8(symbol, addr + k);
                name[k] = symbol;
                if (symbol == 0) {
                    break;
                }
            }
            name[k] = 0;
            g_hash_table_insert(param->section->functions, &param->section->addresses[i], g_strdup(name));
        }
    }
#ifdef DEBUG_DLL
    printf("parsing is finished\n");
#endif    
    param->section->headerCompleted = true;
    return PE_OK;
}
