#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "tcg/tcg-op.h"
#include "sysemu/sysemu.h"
#include "plugins/plugin.h"
#include "syscalls.h"
#include "api_monitor.h" 
#include "handle_map.h"
#include "module_map.h"
#include "pe_header_parser.h"
#include "guest_string.h"
#include "file_monitor.h"

static SignalInfo *cb;

static FILE *api_log;
static HandleMap *hm_file = NULL;
static HandleMap *hm_open_section = NULL;
static ModuleMap *mm = NULL;

static HandleMap *hm = NULL; /* for API functions*/


const struct pi_info init_info = 
{
    .signals_list = (const char *[]){"api", NULL},
    .dependencies = (const char *[]){"contexts", "files", "syscall", NULL},
#ifdef GUEST_OS_WINDOWS
    .os_ver = (const char *[]){"Win7", "WinXP", "Win8", "Win8.1", NULL}
#elif defined(GUEST_OS_LINUX)
    .os_ver = (const char *[]){"Linux", NULL}
#else
#error Cannot build api_monitor for this guest OS
#endif
};

static QTAILQ_HEAD(apiSyscallInfo, ModuleInfo) apiSyscallInfo = QTAILQ_HEAD_INITIALIZER(apiSyscallInfo);

static void api_monitor_printf_modules(void *monitor, uint64_t address, uint64_t context, void *opaque)
{
    Monitor *mon = (Monitor *) monitor;
    map_params *params = (map_params *) opaque;

    monitor_printf(mon, "\taddress: 0x%"PRIx64"; viewSize: 0x%"PRIx64"; name: %s\n",
                    params->imageBase, params->viewSize, 
                    params->section->name ? params->section->name : params->section->dll_name);
}

static void show_dll_list(Monitor *mon, const QDict *qdict)
{
    mm_iterate(mm, api_monitor_printf_modules, mon);
}

static void api_monitor_init(void)
{
    api_log = fopen("API_log.txt", "w");
    hm_open_section = hm_new();
    mm = mm_new();
    hm = hm_new();
}

int stricmp_(char *str1, char *str2);
int stricmp_(char *str1, char *str2)
{
    int len1 = strlen(str1);
    int len2 = strlen(str2);
    if (len1 != len2)
        return 1;
    
    int i;
    for (i = 0; i < len1; i++) {
        if (toupper(str1[i]) != toupper(str2[i])) {
            return 1;
        } 
    }

    return 0;
}

static map_params *get_address_dll(uint64_t address)
{
    return mm_find(mm, address, get_current_context());
}

#ifdef GUEST_OS_WINDOWS
static bool strstrmy(char *name)
{
    if (!name) {
        return false;
    }
    int len = strlen(name);
    if (name[len - 4] == '.' 
        && tolower(name[len - 3]) == 'd'
        && tolower(name[len - 2]) == 'l'
        && tolower(name[len - 1]) == 'l') {
        return true;
    }

    return false;
}

static void api_monitor_add_create_section_cb(void *msg, CPUArchState *env)
{
    Parameters_cs *api_params = (Parameters_cs *) msg;
    Parameters_oc *params = NULL;
    params = hm_find(hm_file, api_params->fHandle, get_current_context());
    if (params && strstrmy(params->name)) {
        fprintf(api_log, "CREATE SECTION. Add new data to exist record. fileHandle: 0x%x\tsectionHandle: 0x%x\tsectionName: %s  cntx: 0x%x  filename: %s\n", 
                (int) api_params->fHandle, (int) api_params->pHandle, api_params->name, (int) get_current_context(), params->name);
        ModuleInfo *section = g_malloc0(sizeof(ModuleInfo));
        section->name = g_strdup(api_params->name);
        section->dll_name = g_strdup(params->name);
        section->headerCompleted = false;
        QTAILQ_INSERT_TAIL(&apiSyscallInfo, section, entry);
        
        openSection_params *params = g_malloc0(sizeof(openSection_params));
        params->section = section;
        hm_insert(hm_open_section, api_params->pHandle, get_current_context(), params);
    }
}

//void printf_log(const char *format, ...);
static void api_monitor_add_open_section_cb(void *msg, CPUArchState *env)
{
    Parameters_os *api_params = (Parameters_os *) msg;
    
    ModuleInfo *api_info;

    fprintf(api_log, "trying to OPEN SECTION. handle: 0x%x  name: %s  cntx: 0x%x\n", 
                (int) api_params->pHandle, api_params->name, (int) get_current_context());
    if (!api_params->pHandle) {
        return;
    }
    QTAILQ_FOREACH(api_info, &apiSyscallInfo, entry) {
        if (api_params->name && api_info->name) {
            if (!stricmp_(api_params->name, api_info->name)) {
                fprintf(api_log, "OPEN SECTION success %p\n", api_info);
                    
                openSection_params *params = g_malloc0(sizeof(openSection_params));
                params->section = api_info;
                hm_insert(hm_open_section, api_params->pHandle, get_current_context(), params);    
            }
        }
    }
}

static void api_monitor_map_cb(void *msg, CPUArchState *env)
{
    Parameters_map *api_params = (Parameters_map *) msg;
    openSection_params *params_ = NULL;
    params_ = hm_find(hm_open_section, api_params->sHandle, get_current_context());
    fprintf(api_log, "MAP. Trying to map handle 0x%x to %p\n", (int)api_params->sHandle, params_);
    if (params_) {
        map_params *params = g_malloc0(sizeof(map_params));
        params->imageBase = api_params->pBaseAddress;
        params->viewSize = api_params->viewSize;
        params->section = params_->section;
        mm_insert(mm, api_params->pBaseAddress, api_params->viewSize, get_current_context(), params);
        fprintf(api_log, "MAP. Add new record. handle: 0x%x  name: %s\tbaseAddress: 0x%x\tviewSize: 0x%x cntx: 0x%x  dll_name: %s\n", 
            (int) api_params->sHandle, (params_->section->name)? params_->section->name : "none", (int) api_params->pBaseAddress, (int) api_params->viewSize, (int) get_current_context(),
            params_->section->dll_name);
    }
}

static void api_monitor_unmap_cb(void *msg, CPUArchState *env)
{
    Parameters_unmap *api_params = msg;
    while (mm_erase(mm, api_params->baseAddress, get_current_context())) {
        fprintf(api_log, "UNMAP. baseAddress: 0x%"PRIx64"\n", api_params->baseAddress);
    }
}

static void api_monitor_close_handle_cb(void *msg, CPUArchState *env)
{
    uint64_t handle = ((Parameters_c *)msg)->handle;
    openSection_params *params2 = NULL;
    params2 = hm_find(hm_open_section, handle, get_current_context());
    if (params2) {
        fprintf(api_log, "CLOSE handle. file_handle: 0x%"PRIx64"  name: %s\tcntx: 0x%x\n", 
                handle, (params2->section->name) ? params2->section->name : "", (int) get_current_context());
        hm_erase(hm_open_section, handle, get_current_context());
    }
}

static void api_monitor_duplicate_cb(void *msg, CPUArchState *env)
{
    uint64_t handle = ((Parameters_do *)msg)->sourceHandle;
    uint64_t handleCopy = ((Parameters_do *)msg)->pTargetHandle;
    openSection_params *params2 = NULL;
    params2 = hm_find(hm_open_section, handle, get_current_context());
    if (params2) {
        fprintf(api_log, "DUPLICATE handle. section_handle: 0x%"PRIx64" new: 0x%"PRIx64" name: %s\tcntx: 0x%"PRIx64"\n", 
                handle, handleCopy, params2->section->name, get_current_context());
        openSection_params *newParams2 = g_malloc0(sizeof(openSection_params));
        newParams2->section = params2->section;
        hm_insert(hm_open_section, handleCopy, get_current_context(), newParams2);
    }
}
#endif

#ifdef GUEST_OS_LINUX
static void api_monitor_mmap2_cb(void *msg, CPUArchState *env)
{
    Parameters_mmap *mmap_params = msg;
    uint64_t address = mmap_params->address;
    uint64_t length = mmap_params->length;
    if (address != -1UL && address != -1ULL
        && mmap_params->handle != -1UL) {
        fprintf(api_log, "MAP. Trying to map handle 0x%"PRIx64" to address 0x%"PRIx64" len=0x%"PRIx64" offset=0x%"PRIx64" ctx=0x%"PRIx64"\n",
            mmap_params->handle, mmap_params->address, mmap_params->length, mmap_params->offset, get_current_context());
        /* Find file */
        Parameters_oc *file = hm_find(hm_file, mmap_params->handle, get_current_context());
        if (file) {
            /* Check whether this is the other part of the same file */
            map_params *prev = get_address_dll(address);
            if (prev && !strcmp(file->name, prev->section->dll_name)) {
                if (prev->imageBase + prev->viewSize < address + length) {
                    length += address - prev->imageBase;
                    address = prev->imageBase;
                    fprintf(api_log, "UPDATE. base=0x%"PRIx64" new size=0x%"PRIx64"\n",
                        prev->imageBase, length);
                } else {
                    fprintf(api_log, "NO UPDATE for existing base=0x%"PRIx64"\n", prev->imageBase);
                    return;
                }
            } else {
                map_params *prev1 = get_address_dll(address - mmap_params->offset);
                /* Map additional section to higher addresses */
                if (prev1 && !strcmp(file->name, prev1->section->dll_name)
                    && prev1->imageBase == address - mmap_params->offset) {
                    /* Update the mapping of the same file */
                    prev = prev1;
                    length += address - prev->imageBase;
                    address = prev->imageBase;
                    fprintf(api_log, "ADD SECTION FOR base=0x%"PRIx64" new size=0x%"PRIx64"\n",
                        prev->imageBase, length);
                } else {
                    /* Should delete 'prev' mapping of different file */
                }
            }

            if (prev) {
                g_free(prev->section->name);
                g_free(prev->section->dll_name);
                g_free(prev->section);
                int ret = mm_erase_range(mm, address, length, get_current_context());
                fprintf(api_log, "ERASE %d previous entries for base=0x%"PRIx64" length=0x%"PRIx64"\n",
                    ret, address, length);
                assert(ret);
                //fprintf(api_log, "ERASE. previous entry for base=0x%"PRIx64"\n", address);
                //if (!mm_erase_map(mm, prev->imageBase, get_current_context(), prev)) {
                //    assert(false);
                //}
            }
            /* Create fake section */
            ModuleInfo *section = g_new0(ModuleInfo, 1);
            assert(file->name);
            section->name = g_strdup(file->name);
            section->dll_name = g_strdup(file->name);
            /* Fill mapping params */
            map_params *params = g_new0(map_params, 1);
            params->imageBase = address;
            params->viewSize = length;
            params->section = section;
            /* Save mapping */
            mm_insert(mm, address, length, get_current_context(), params);
            fprintf(api_log, "MAP. Mapped file 0x%s to address 0x%"PRIx64" params=%p\n",
                file->name, address, params);
        } else {
            fprintf(api_log, "MAP. File handle 0x%"PRIx64" not found\n", mmap_params->handle);
            int ret = mm_erase_range(mm, address, length, get_current_context());
            if (ret) {
                fprintf(api_log, "ERASE %d previous entries for base=0x%"PRIx64" length=0x%"PRIx64"\n",
                    ret, address, length);
            }
        }
    }
}
#endif

static void api_monitor_remove_mapping(map_params *map, CPUArchState *env)
{
    ModuleInfo *module = map->section;
    fprintf(api_log, "ERASE. baseAddress: 0x%"PRIx64" %s(%s) ctx=0x%"PRIx64"\n",
        map->imageBase, module->name, module->dll_name, get_current_context());
    if (!mm_erase_map(mm, map->imageBase, get_current_context(), map)) {
        fprintf(api_log, "ERASE failed\n");
        return;
    }
#ifdef GUEST_OS_LINUX
    g_free(module->name);
    g_free(module->dll_name);
    /* these fields are empty in modules that were not parsed */
    //g_free(module->addresses);
    //g_hash_table_destroy(module->functions);
    g_free(module);
#endif
}

static FILE *api_func_log;

#ifdef GUEST_OS_WINDOWS
static createProcessW_params *get_func_params(CPUArchState *env, uint32_t offset, uint32_t offset2)
{
    target_ulong nameAddr = guest_read_tl(env, env->regs[R_ESP] + offset);
    createProcessW_params *params = g_malloc0(sizeof(createProcessW_params));
    if (nameAddr) {
        target_ulong len = 0;
        wchar_t *s = guest_strdupw(env, nameAddr, &len);
        params->name = s;
        params->len = len;
    }
    target_ulong cmdAddr = guest_read_tl(env, env->regs[R_ESP] + (offset + 4));
    if (cmdAddr) {
        target_ulong len = 0;
        wchar_t *s = guest_strdupw(env, cmdAddr, &len);
        params->cmdline = s;
    }
    fprintf(api_func_log, "\tname = %ls, cmdline = %ls\n", params->name, params->cmdline);
    params->pInfo = guest_read_tl(env, env->regs[R_ESP] + offset2);
    return params;
}
#endif

static void dll_call(uint64_t pc, char *name, ModuleInfo *section, CPUArchState *env)
{
    fprintf(api_func_log, "name = %s:%s, addr = 0x%x, context = 0x%x  esp = 0x%x\n", section->dll_name, name, (int)pc, (int)get_current_context(), (int)env->regs[R_ESP]);

    //danger! it's a govnokod!
    
    func_params *p = g_malloc0(sizeof(func_params));
    p->pc = pc;
    p->name = g_strdup(name);
    p->dll_name = g_strdup(section->dll_name);
#ifdef GUEST_OS_WINDOWS
    if (name && !strcmp(name, "CreateProcessW")) {
        p->param = get_func_params(env, 4, 40);
    } else if (name && !strcmp(name, "CreateProcessAsUserW")) {
        p->param = get_func_params(env, 8, 44);
    }
    if (name && !strcmp(name, "GetCurrentProcessId")) {
        paramsGetCurPID *params = g_malloc0(sizeof(paramsGetCurPID));
        params->pid = -1;
        p->param = params;
    }
    if (name && !strcmp(name, "ExitProcess")) {
        plugin_gen_signal(cb, "API_EXIT_PROCESS", p->param, env);
    }
#endif

    hm_insert(hm, env->regs[R_ESP], get_current_context(), p);
}

static void dll_callback(target_ulong pc, map_params *params, CPUArchState *env)
{
    uint64_t pc64 = pc - params->imageBase;
    char *name = g_hash_table_lookup(params->section->functions, &pc64);
    if (name) {
        TCGv_i64 t_pc = tcg_const_i64((uint64_t)pc);
        TCGv_ptr t_name = tcg_const_ptr(name);
        TCGv_ptr t_params = tcg_const_ptr(params->section);
        TCGv_ptr t_env = tcg_const_ptr(env);
        TCGArg args[4];
        args[0] = GET_TCGV_I64(t_pc);
        args[1] = GET_TCGV_PTR(t_name);
        args[2] = GET_TCGV_PTR(t_params);
        args[3] = GET_TCGV_PTR(t_env);

        tcg_gen_callN(&tcg_ctx, dll_call, dh_retvar(void), 4, args);
        tcg_temp_free_i64(t_pc);
        tcg_temp_free_ptr(t_name);
        tcg_temp_free_ptr(t_params);
        tcg_temp_free_ptr(t_env);
    }
}

static void before_tb_cb(void *data, CPUArchState *env)
{
    TranslationBlock *tb = ((struct PluginParamsInstrTranslate*)data)->tb;
    target_ulong g_pc = tb->pc;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    // Do not take CS into account
    // E.g. g_pc=AF843E2C and CS:EIP=0073:4F843E2C
    g_pc -= env->segs[R_CS].base;
#endif
    do {
        map_params *params = get_address_dll(g_pc);
        if (params) {
            switch (parse_header(params)) {
            case PE_OK:
                dll_callback(g_pc, params, env);
                break;
            case PE_ERROR:
                break;
            case PE_UNKNOWN_FORMAT:
                api_monitor_remove_mapping(params, env);
                /* Maybe there are multiple mappings of a file
                   to intersecting areas */
                continue;
            }
        }
        break;
    } while (true);
}

#define USE_TLB
#ifdef GUEST_OS_LINUX
#ifdef USE_TLB
static void api_monitor_tlb_add_page(void *data, CPUArchState *env)
{
    struct PluginParamsTlbAddPage *params = data;
    //write_tlb_log_block(params->paddr, params->vaddr, false);
    map_params *map = get_address_dll(params->vaddr);
    if (map && map->imageBase != -1 && !map->section->headerCompleted) {
        parse_header(map);
    }
}
#endif
#endif

static void exit_func_call(uint64_t pc, CPUArchState *env)
{
    func_params *p = hm_find(hm, env->regs[R_ESP], get_current_context());
    if (p) {
        if (p->pc == 0x7c81caa2)
            printf("ExitProcess\n");
        fprintf(api_func_log, "function %s:%s with context = 0x%x finished esp = 0x%x\n", p->dll_name, p->name, (int)get_current_context(), (int)env->regs[R_ESP]);
        
#ifdef GUEST_OS_WINDOWS
        if (p->name && !strcmp(p->name, "CreateProcessW"))
            plugin_gen_signal(cb, "API_CREATE_PROCESS", p->param, env);
        else if (p->name && !strcmp(p->name, "CreateProcessAsUserW"))
            plugin_gen_signal(cb, "API_CREATE_PROCESS_AS_USER", p->param, env);
        else if (p->name && !strcmp(p->name, "GetCurrentProcessId"))
        {
            paramsGetCurPID *p2 = (paramsGetCurPID *) p->param;
            p2->pid = env->regs[R_EAX];
            plugin_gen_signal(cb, "API_GET_CUR_PROC_ID", p->param, env);
        }
        else if (p->name && !strcmp(p->name, "ExitProcess")) 
            plugin_gen_signal(cb, "API_EXIT_PROCESS", p->param, env);
#endif
        
        hm_erase(hm, env->regs[R_ESP], get_current_context());
    }
}

static void decode_instr(void *data, CPUArchState *env)
{
    target_ulong g_pc = ((struct PluginParamsInstrTranslate*)data)->pc;

    int code = cpu_ldub_code(env, g_pc);
    if (code == 0xc3 || code == 0xcb || code == 0xc2 || code == 0xca) {
        TCGv_i64 t_pc = tcg_const_i64((uint64_t) g_pc);
        TCGv_ptr t_env = tcg_const_ptr(env);
        TCGArg args[2];
        args[0] = GET_TCGV_I64(t_pc);
        args[1] = GET_TCGV_PTR(t_env);
        tcg_gen_callN(&tcg_ctx, exit_func_call, dh_retvar(void), 2, args);
        tcg_temp_free_i64(t_pc);
        tcg_temp_free_ptr(t_env);
    }
}

static void close_file(void)
{
    if (api_func_log) {
        fclose(api_func_log);
    }
}

void pi_start(PluginInterface *pi)
{
    
    static mon_cmd_t mon_cmds[] = {
        {
            .name       = "show_dll_list",
            .args_type  = "",
            .params     = "",
            .help       = "show list of loading modules",
            .cmd = show_dll_list,
        },
        {
            .name       = NULL,
        },
    };
    pi->cmd_table = mon_cmds;
    api_monitor_init();

    const struct fileMonFuncs *fileMon = plugin_get_functions_list("file_monitor");
    hm_file = fileMon->f1();
    cb = plugin_reg_signal("api");
    plugin_subscribe(decode_instr, "qemu", "PLUGIN_QEMU_INSTR_TRANSLATE");
    plugin_subscribe(before_tb_cb, "qemu", "PLUGIN_QEMU_BEFORE_GEN_TB");
    
#ifdef GUEST_OS_WINDOWS
    plugin_subscribe(api_monitor_add_create_section_cb, "syscall", "VMI_SC_CREATE_SECTION");
    plugin_subscribe(api_monitor_add_open_section_cb, "syscall", "VMI_SC_OPEN_SECTION");
    plugin_subscribe(api_monitor_map_cb, "syscall", "VMI_SC_MAP_VIEW_OF_SECTION");
    plugin_subscribe(api_monitor_unmap_cb, "syscall", "VMI_SC_UNMAP_VIEW_OF_SECTION");
    plugin_subscribe(api_monitor_close_handle_cb, "syscall", "VMI_SC_CLOSE");
    plugin_subscribe(api_monitor_duplicate_cb, "syscall", "VMI_SC_DUPLICATE_OBJ");
#elif defined(GUEST_OS_LINUX)
    plugin_subscribe(api_monitor_mmap2_cb, "syscall", "VMI_SC_MMAP");
#ifdef USE_TLB
    plugin_subscribe(api_monitor_tlb_add_page, "qemu", "PLUGIN_QEMU_TLB_SET_PAGE");
#endif
#endif
    tcg_context_register_helper(
        &tcg_ctx,
        dll_call,
        "dll_call",
        0,
        dh_sizemask(void, 0) | dh_sizemask(i64, 1) | dh_sizemask(ptr, 2) | dh_sizemask(ptr, 3) | dh_sizemask(ptr, 4));
        
    tcg_context_register_helper(
        &tcg_ctx,
        exit_func_call,
        "exit_func_call",
        0,
        dh_sizemask(void, 0) | dh_sizemask(ptr, 1) | dh_sizemask(i32, 2));        
        
    api_func_log = fopen("API_func_log.txt", "w");
    atexit(close_file);
}