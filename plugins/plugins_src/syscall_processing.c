#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "plugins/plugin.h"

#include "syscalls.h"
#if defined(GUEST_OS_WINDOWS)
#include "func_numbers_arch_windows.h"
#else
#include "func_numbers_arch_linux.h"
#endif

typedef struct SCKey {
    uint64_t esp;
    uint64_t ctx;
} SCKey;

typedef struct SCData {
    uint32_t num;
    void *param;
} SCData;

static GHashTable *syscalls;

static guint sc_key_hash(gconstpointer k)
{
    const SCKey *key = k;
    uint64_t v = key->esp ^ key->ctx;
    return (guint)(v ^ (v >> 32));
}

static gboolean sc_key_equal(gconstpointer a, gconstpointer b)
{
    const SCKey *k1 = a;
    const SCKey *k2 = b;
    return k1->esp == k2->esp && k1->ctx == k2->ctx;
}

static void sc_value_destroy(gpointer data)
{
    SCData *val = data;
    syscall_free_memory(val->param, val->num);
}

static void sc_init(void)
{
    if (syscalls) {
        return;
    }
    syscalls = g_hash_table_new_full(sc_key_hash, sc_key_equal,
        g_free, sc_value_destroy);
}

static SCData *sc_find(uint64_t ctx, uint64_t esp)
{
    sc_init();

    SCKey k = { .ctx = ctx, .esp = esp };
    return g_hash_table_lookup(syscalls, &k);
}

static void sc_erase(uint64_t ctx, uint64_t esp)
{
    sc_init();

    SCKey k = { .ctx = ctx, .esp = esp };
    g_hash_table_remove(syscalls, &k);
}

static void sc_insert(uint64_t ctx, uint64_t esp, uint32_t num, void *param)
{
    sc_init();

    SCKey *k = g_new(SCKey, 1);
    SCData *v = g_new(SCData, 1);
    k->ctx = ctx;
    k->esp = esp;
    v->num = num;
    v->param = param;

    if (!g_hash_table_insert(syscalls, k, v)) {
        //qemu_log_mask(LOG_PLUGINS, "overwriting old syscall with new %d\n", num);
    }
}

void start_system_call(CPUArchState *env)
{
    static struct FuncInfo { const char *name; } func_info[1024] = {
#include "func_info.inc"
    };
    bool terminate_syscall = false;
    uint64_t ctx = get_current_context();
    uint32_t num = env->regs[R_EAX];
    uint64_t esp = env->regs[R_ESP];
    void *param = NULL;
    if (num < 1024) {
        syscall_printf_all_calls(num);
        if (func_info[num].name != NULL) {
            switch (num) {
                /*** file syscalls ***/
                case VMI_SYS_CREATE: 
                    param = syscall_create_os(env); 
                    break;
                case VMI_SYS_OPEN: 
                    param = syscall_open_os(env); 
                    break;
                case VMI_SYS_READ: 
                    param = syscall_read_os(env); 
                    break;
                case VMI_SYS_WRITE: 
                    param = syscall_write_os(env);  
                    break;
                case VMI_SYS_CLOSE: 
                    param = syscall_close_os(env);
                    break;
#if defined(GUEST_OS_WINDOWS)
                case VMI_SYS_CREATE_SECTION: 
                    param = syscall_create_section_os(env);
                    break;
                case VMI_SYS_MAP_VIEW_OF_SECTION: 
                    param = syscall_map_view_of_section_os(env); 
                    break;
                case VMI_SYS_UNMAP_VIEW_OF_SECTION: 
                    param = syscall_unmap_view_of_section_os(env); 
                    break;
                case VMI_SYS_OPEN_SECTION:
                    param = syscall_open_section_os(env);
                    break;
                case VMI_SYS_DUPLICATE_OBJ:
                    param = syscall_duplicate_object_os(env);
                    break;
             
                /*** process syscalls ***/
                case VMI_SYS_CREATE_PROCESS:
                    param = syscall_create_process_os(env);
                    break;
                case VMI_SYS_CREATE_PROCESS_EX:
                    param = syscall_create_process_ex_os(env);
                    break;  
                case VMI_SYS_OPEN_PROCESS:
                    param = syscall_open_process_os(env);
                    break;                      
                case VMI_SYS_TERMINATE_PROCESS:
                    param = syscall_terminate_process_os(env);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_TERMINATE", param, env);
                    g_free(param);
                    terminate_syscall = true;
                    break;
                case VMI_SYS_OPEN_PROCESS_TOKEN:
                    param = syscall_open_process_token_os(env);
                    break;
                case VMI_SYS_RESUME_PROCESS:
                    param = syscall_resume_process_os(env);
                    break;
                case VMI_SYS_SUSPEND_PROCESS:
                    param = syscall_suspend_process_os(env);
                    break;
                case VMI_SYS_CREATE_THREAD:
                    param = syscall_create_thread_os(env);
                    break;
                case VMI_SYS_OPEN_THREAD:
                    param = syscall_open_thread_os(env);
                    break;
                case VMI_SYS_OPEN_THREAD_TOKEN:
                    param = syscall_open_thread_token_os(env);
                    break;
                case VMI_SYS_RESUME_THREAD:
                    param = syscall_resume_thread_os(env);
                    break;
                case VMI_SYS_SUSPEND_THREAD:
                    param = syscall_suspend_thread_os(env);
                    break;
                case VMI_SYS_TERMINATE_THREAD:
                    param = syscall_terminate_thread_os(env);
                    break;
                case VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES:
                    syscall_allocate_user_physical_pages_os(env);
                    break;
                case VMI_SYS_ALLOCATE_VIRTUAL_MEMORY:
                    param = syscall_allocate_virtual_memory_os(env);
                    break;
                case VMI_SYS_QUERY_INFO_PROCESS:
                    param = syscall_query_information_process_os(env);
                    break;
#elif defined (GUEST_OS_LINUX)
#ifndef TARGET_X86_64
                case VMI_SYS_CLONE:
                    param = syscall_clone_os(env);
                    break;
                case VMI_SYS_FORK:
                    //printf("fork\n");
                    param = syscall_fork_os(env);
                    break;
                case VMI_SYS_EXECVE:
                    param = syscall_execve_os(env);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_EXECVE", param, env);
                    break;
                case VMI_SYS_MOUNT:
                    param = syscall_mount_os(env);
                    break;
                case VMI_SYS_UMOUNT:
                    param = syscall_umount_os(env);
                    break;
                case VMI_SYS_EXIT_GROUP:
                    syscall_exit_group_os(env);
                    terminate_syscall = true;
                    break;
                case VMI_SYS_MMAP:
                    param = syscall_mmap_os(env);
                    break;
                case VMI_SYS_MMAP2:
                    param = syscall_mmap2_os(env);
                    break;
                case VMI_SYS_GETPID:
                    param = 0;
                    break;
                case VMI_SYS_GETPPID:
                    param = 0;
                    break;
#endif
                case VMI_SYS_OPENAT: 
                    param = syscall_openat_os(env); 
                    break;
#endif
                default: 
                    break;
            }
            if (!terminate_syscall) {
                sc_insert(ctx, esp, num, param);
            }
        }
    }
    if (terminate_syscall) {
        // Clean all entries with the current
        // TODO
        /*
        int i;
        for (i = 0 ; i < count ; ) {
            if (infoRet[i].ctx == ctx) {
                --count;
                if (count) {
                    infoRet[i] = infoRet[count];
                }
            } else {
                ++i;
            }
        }
        */
    }
}

void exit_system_call(CPUArchState *env, uint64_t stack)
{
    uint64_t ctx = get_current_context();

    SCData *data = sc_find(ctx, stack);
    if (data) {
        switch (data->num) {
            case VMI_SYS_CREATE: 
#if defined (GUEST_OS_WINDOWS)              
                syscall_ret_handle_os(data->param, env, VMI_SYS_CREATE);
#else                    
                syscall_ret_oc_os(data->param, env);
#endif
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_CREATE", data->param, env);
                break;
            case VMI_SYS_OPEN: 
#if defined (GUEST_OS_WINDOWS)                
                syscall_ret_handle_os(data->param, env, VMI_SYS_OPEN);
#else                    
                syscall_ret_oc_os(data->param, env);
#endif
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_OPEN", data->param, env); 
                break;
            case VMI_SYS_READ:
#if defined (GUEST_OS_WINDOWS)               
                syscall_ret_handle_os(data->param, env, VMI_SYS_READ);
#else                    
                syscall_ret_read_os(data->param, env);
#endif
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_READ", data->param, env); 
                break;
            case VMI_SYS_WRITE: 
#if defined (GUEST_OS_WINDOWS)             
                syscall_ret_handle_os(data->param, env, VMI_SYS_WRITE);
#else                    
                syscall_ret_write_os(data->param, env);
#endif
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_WRITE", data->param, env); 
                break;
            case VMI_SYS_CLOSE: 
#if defined (GUEST_OS_WINDOWS)             
                syscall_ret_handle_os(data->param, env, VMI_SYS_CLOSE);
#else                    
                syscall_ret_close_os(data->param, env);
#endif
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_CLOSE", data->param, env); 
                break;
#if defined (GUEST_OS_WINDOWS)

            case VMI_SYS_CREATE_SECTION: 
                syscall_ret_handle_os(data->param, env, VMI_SYS_CREATE_SECTION);
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_CREATE_SECTION", data->param, env); 
                break;
            case VMI_SYS_MAP_VIEW_OF_SECTION: 
                syscall_ret_handle_os(data->param, env, VMI_SYS_MAP_VIEW_OF_SECTION);
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_MAP_VIEW_OF_SECTION", data->param, env); 
                break;
            case VMI_SYS_UNMAP_VIEW_OF_SECTION: 
                syscall_ret_handle_os(data->param, env, VMI_SYS_UNMAP_VIEW_OF_SECTION);
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_UNMAP_VIEW_OF_SECTION", data->param, env); 
                break;
            case VMI_SYS_OPEN_SECTION:
                syscall_ret_handle_os(data->param, env, VMI_SYS_OPEN_SECTION);
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_OPEN_SECTION", data->param, env);
                break;
            case VMI_SYS_DUPLICATE_OBJ:
                syscall_ret_handle_os(data->param, env, VMI_SYS_DUPLICATE_OBJ);
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_DUPLICATE_OBJ", data->param, env);
                break;
            /*** process syscalls ***/
            case VMI_SYS_CREATE_PROCESS:
                syscall_ret_handle_os(data->param, env, VMI_SYS_CREATE_PROCESS);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_CREATE", data->param, env);
                break;
            case VMI_SYS_CREATE_PROCESS_EX:
                syscall_ret_handle_os(data->param, env, VMI_SYS_CREATE_PROCESS_EX);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_CREATE_EX", data->param, env);
                break;  
            case VMI_SYS_OPEN_PROCESS:
                //syscall_ret_oc_os(data->param, env);
                //printf("open_process \n");
                syscall_ret_handle_os(data->param, env, VMI_SYS_OPEN_PROCESS);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_OPEN", data->param, env);
                break;                      
            case VMI_SYS_OPEN_PROCESS_TOKEN: 
                //printf("open_process_token \n");
                syscall_ret_handle_os(data->param, env, VMI_SYS_OPEN_PROCESS_TOKEN);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_OPEN_TOKEN", data->param, env);
                break;
            case VMI_SYS_RESUME_PROCESS:
                //printf("resume_process \n");
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_RESUME", data->param, env);
                break;
            case VMI_SYS_SUSPEND_PROCESS:
                //printf("suspend_process \n");
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_SUSPEND", data->param, env);
                break;
            case VMI_SYS_TERMINATE_PROCESS:
                //printf("terminate_process \n");
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_TERMINATE", data->param, env);
                break; 
            
            case VMI_SYS_CREATE_THREAD:
                //printf("create_thread \n");
                syscall_ret_handle_os(data->param, env, VMI_SYS_CREATE_THREAD);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCT_CREATE", data->param, env);
                break;
            case VMI_SYS_OPEN_THREAD:
                //printf("open_thread \n");
                //syscall_ret_oc_os(data->param, env);
                syscall_ret_handle_os(data->param, env, VMI_SYS_OPEN_THREAD);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCT_OPEN", data->param, env);
                break;
            case VMI_SYS_OPEN_THREAD_TOKEN: 
                //printf("open_thread_token \n");
                syscall_ret_handle_os(data->param, env, VMI_SYS_OPEN_THREAD_TOKEN);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCT_OPEN_TOKEN", data->param, env);
                break;
            case VMI_SYS_RESUME_THREAD:
                //printf("resume_thread \n");
                plugin_gen_signal(syscall_get_cb(), "VMI_SCT_RESUME", data->param, env);
                break;
            case VMI_SYS_SUSPEND_THREAD:
                //printf("suspend_thread \n");
                plugin_gen_signal(syscall_get_cb(), "VMI_SCT_SUSPEND", data->param, env);
                break;                    
            case VMI_SYS_TERMINATE_THREAD:
                //printf("terminate_thread \n");
                plugin_gen_signal(syscall_get_cb(), "VMI_SCT_TERMINATE", data->param, env);
                break;
            case VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES:
                break;
            case VMI_SYS_ALLOCATE_VIRTUAL_MEMORY:
                syscall_ret_handle_os(data->param, env, VMI_SYS_ALLOCATE_VIRTUAL_MEMORY);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_ALLOCATE_VIRTUAL_MEMORY", data->param, env);
                break;
            case VMI_SYS_QUERY_INFO_PROCESS:
                syscall_ret_handle_os(data->param, env, VMI_SYS_QUERY_INFO_PROCESS);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_QUERY_INFO_PROCESS", data->param, env);
#elif defined (GUEST_OS_LINUX)
#ifndef TARGET_X86_64
            case VMI_SYS_CLONE:
                syscall_ret_clone_os(data->param, env);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_CLONE", data->param, env);
                break;
            case VMI_SYS_FORK:
                //printf("foooooork\n");
                syscall_ret_f_os(data->param, env);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_FORK", data->param, env);
                break;
            case VMI_SYS_EXECVE:
                syscall_ret_execve_os(data->param, env);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_EXECVE_END", data->param, env);
                break;
            case VMI_SYS_MOUNT:
                syscall_ret_mount_os(data->param, env);
                break;
            case VMI_SYS_UMOUNT:
                syscall_ret_umount_os(data->param, env);
                break;
            case VMI_SYS_EXIT_GROUP:
                break;
            case VMI_SYS_MMAP:
            case VMI_SYS_MMAP2:
                syscall_mmap_return(data->param, env);
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_MMAP", data->param, env);
                break;
            case VMI_SYS_GETPID:
                syscall_ret_values_os(data->param, env, VMI_SYS_GETPID);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_GETPID", data->param, env);
                break;
            case VMI_SYS_GETPPID:
                syscall_ret_values_os(data->param, env, VMI_SYS_GETPPID);
                plugin_gen_signal(syscall_get_cb(), "VMI_SCP_GETPPID", data->param, env);
                break;
#endif
            case VMI_SYS_OPENAT: 
                syscall_ret_oc_os(data->param, env);
                plugin_gen_signal(syscall_get_cb(), "VMI_SC_OPEN", data->param, env); 
                break;
#endif
            default: break;                
        }
        sc_erase(ctx, stack);
    }
}