#ifndef API_MONITOR_H
#define API_MONITOR_H

enum APINumbers {API_CREATE_PROCESS, API_CREATE_PROCESS_AS_USER, API_EXIT_PROCESS, API_GET_CUR_PROC_ID,
                     API_COUNT};

typedef struct ModuleInfo {
    char *name; // file or section
    char *dll_name;
    
    uint32_t funcCount;
    GHashTable *functions;
    uint64_t *addresses;

    bool headerCompleted;
    QTAILQ_ENTRY(ModuleInfo) entry;
} ModuleInfo;

typedef struct openSection_params {
    ModuleInfo *section;
} openSection_params;

typedef struct map_params { // zasunut v opaque module map
    //base;
    uint64_t viewSize;
    uint64_t imageBase;

    ModuleInfo *section;
} map_params;

typedef struct createProcessW_params {
    uint32_t pInfo;
    wchar_t *name;
    wchar_t *cmdline;
    int len;
} createProcessW_params;

typedef struct func_params {
    char *name;
    char *dll_name;
    target_ulong pc;
    void *param;
} func_params;

typedef struct paramsGetCurPID {
    uint32_t pid;
} paramsGetCurPID;


#endif