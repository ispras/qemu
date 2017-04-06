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

typedef struct InfoRet {
    uint64_t num;
    uint64_t esp;
    uint64_t ctx;
    void *param;
} InfoRet;

InfoRet infoRet[1024];
static int count = 0;

void start_system_call(CPUArchState *env)
{
    static struct FuncInfo { const char *name; } func_info[1024] = {
#include "func_info.inc"
    };
    uint32_t num = env->regs[R_EAX];
    if (num < 1024) {
        if (func_info[num].name != NULL) {
            if (count >= 1024) {
                printf("syscall buffer overflow\n");
                return;
            }
            infoRet[count].num = num;
            infoRet[count].esp = env->regs[R_ESP]; //esp
            infoRet[count].ctx = get_current_context();
            infoRet[count].param = NULL;
            switch (num) {
                /*** file syscalls ***/
                case VMI_SYS_CREATE: 
                    infoRet[count].param = syscall_create_os(env); 
                    break;
                case VMI_SYS_OPEN: 
                    infoRet[count].param = syscall_open_os(env); 
                    break;
                case VMI_SYS_READ: 
                    infoRet[count].param = syscall_read_os(env); 
                    break;
                case VMI_SYS_WRITE: 
                    infoRet[count].param = syscall_write_os(env);  
                    break;
                case VMI_SYS_CLOSE: 
                    infoRet[count].param = syscall_close_os(env);
                    break;
#ifdef GUEST_OS_WINDOWS
                case VMI_SYS_CREATE_SECTION: 
                    infoRet[count].param = syscall_create_section_os(env);
                    break;
                case VMI_SYS_MAP_VIEW_OF_SECTION: 
                    infoRet[count].param = syscall_map_view_of_section_os(env); 
                    break;
                case VMI_SYS_UNMAP_VIEW_OF_SECTION: 
                    infoRet[count].param = syscall_unmap_view_of_section_os(env); 
                    break;
                case VMI_SYS_OPEN_SECTION:
                    infoRet[count].param = syscall_open_section_os(env);
                    break;
                case VMI_SYS_DUPLICATE_OBJ:
                    infoRet[count].param = syscall_duplicate_object_os(env);
                    break;
             
                /*** process syscalls ***/
                case VMI_SYS_CREATE_PROCESS:
                    infoRet[count].param = syscall_create_process_os(env);
                    break;
                case VMI_SYS_CREATE_PROCESS_EX:
                    infoRet[count].param = syscall_create_process_ex_os(env);
                    break;  
                case VMI_SYS_OPEN_PROCESS:
                    infoRet[count].param = syscall_open_process_os(env);
                    break;                      
                case VMI_SYS_TERMINATE_PROCESS:
                    infoRet[count].param = syscall_terminate_process_os(env);
                    break;
                case VMI_SYS_OPEN_PROCESS_TOKEN:
                    infoRet[count].param = syscall_open_process_token_os(env);
                    break;
                case VMI_SYS_RESUME_PROCESS:
                    infoRet[count].param = syscall_resume_process_os(env);
                    break;
                case VMI_SYS_SUSPEND_PROCESS:
                    infoRet[count].param = syscall_suspend_process_os(env);
                    break;
                case VMI_SYS_CREATE_THREAD:
                    infoRet[count].param = syscall_create_thread_os(env);
                    break;
                case VMI_SYS_OPEN_THREAD:
                    infoRet[count].param = syscall_open_thread_os(env);
                    break;
                case VMI_SYS_OPEN_THREAD_TOKEN:
                    infoRet[count].param = syscall_open_thread_token_os(env);
                    break;
                case VMI_SYS_RESUME_THREAD:
                    infoRet[count].param = syscall_resume_thread_os(env);
                    break;
                case VMI_SYS_SUSPEND_THREAD:
                    infoRet[count].param = syscall_suspend_thread_os(env);
                    break;
                case VMI_SYS_TERMINATE_THREAD:
                    infoRet[count].param = syscall_terminate_thread_os(env);
                    break;
                case VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES:
                    syscall_allocate_user_physical_pages_os(env);
                    break;
                case VMI_SYS_ALLOCATE_VIRTUAL_MEMORY:
                    infoRet[count].param = syscall_allocate_virtual_memory_os(env);
                    break;
                case VMI_SYS_QUERY_INFO_PROCESS:
                    infoRet[count].param = syscall_query_information_process_os(env);
                    break;
#else /* Linux */
                case VMI_SYS_CLONE:
                    syscall_clone_os(env);
                    break;
                case VMI_SYS_FORK:
                    //printf("fork\n");
                    infoRet[count].param = syscall_fork_os(env);
                    break;
                case VMI_SYS_EXECVE:
                    infoRet[count].param = syscall_execve_os(env);
                    break;
                case VMI_SYS_MOUNT:
                    infoRet[count].param = syscall_mount_os(env);
                    break;
                case VMI_SYS_UMOUNT:
                    infoRet[count].param = syscall_umount_os(env);
                    break;
                case VMI_SYS_EXIT_GROUP:
                    syscall_exit_group_os(env);
                    break;
                case VMI_SYS_MMAP:
                    infoRet[count].param = syscall_mmap_os(env);
                    break;
                case VMI_SYS_MMAP2:
                    infoRet[count].param = syscall_mmap2_os(env);
                    break;
                case VMI_SYS_GETPID:
                    printf("getpid\n");
                    syscall_getpid_os(env);
                    break;
                case VMI_SYS_GETPPID:
                    printf("getppid\n");
                    syscall_getppid_os(env);
                    break;
#endif                    
                default: 
                    syscall_printf_all_calls((int) env->regs[R_EAX]);
                    break;
            }
            ++count;
        } else {
            syscall_printf_all_calls((int) env->regs[R_EAX]);
        }
    }
}

void exit_system_call(CPUArchState *env, uint32_t reg)
{
    int i;
    int isOk = 0;

    if (count) {
        for (i = 0; i < count; i++) {
            if (infoRet[i].esp == env->regs[reg]
                && infoRet[i].ctx == get_current_context()) { //regs = windows ? ecx : esp
                isOk = 1;
                break;
            }
        }
        if (isOk) {
            switch (infoRet[i].num) {
                case VMI_SYS_CREATE: 
#ifdef GUEST_OS_WINDOWS                
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_CREATE);
#else                    
                    syscall_ret_oc_os(infoRet[i].param, env);
#endif
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_CREATE", infoRet[i].param, env);
                    syscall_free_memory(infoRet[i].param, VMI_SYS_CREATE);
                    break;
                case VMI_SYS_OPEN: 
#ifdef GUEST_OS_WINDOWS                
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_OPEN);
#else                    
                    syscall_ret_oc_os(infoRet[i].param, env);
#endif
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_OPEN", infoRet[i].param, env); 
                    syscall_free_memory(infoRet[i].param, VMI_SYS_OPEN);
                    break;
                case VMI_SYS_READ:
#ifdef GUEST_OS_WINDOWS                
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_READ);
#else                    
                    syscall_ret_read_os(infoRet[i].param, env);
#endif
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_READ", infoRet[i].param, env); 
                    syscall_free_memory(infoRet[i].param, VMI_SYS_READ);
                    break;
                case VMI_SYS_WRITE: 
#ifdef GUEST_OS_WINDOWS                
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_WRITE);
#else                    
                    syscall_ret_write_os(infoRet[i].param, env);
#endif
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_WRITE", infoRet[i].param, env); 
                    syscall_free_memory(infoRet[i].param, VMI_SYS_WRITE);
                    break;
                case VMI_SYS_CLOSE: 
#ifdef GUEST_OS_WINDOWS                
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_CLOSE);
#else                    
                    syscall_ret_close_os(infoRet[i].param, env);
#endif
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_CLOSE", infoRet[i].param, env); 
                    syscall_free_memory(infoRet[i].param, VMI_SYS_CLOSE);
                    break;
#ifdef GUEST_OS_WINDOWS 
                case VMI_SYS_CREATE_SECTION: 
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_CREATE_SECTION);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_CREATE_SECTION", infoRet[i].param, env); 
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_MAP_VIEW_OF_SECTION: 
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_MAP_VIEW_OF_SECTION);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_MAP_VIEW_OF_SECTION", infoRet[i].param, env); 
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_UNMAP_VIEW_OF_SECTION: 
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_UNMAP_VIEW_OF_SECTION);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_UNMAP_VIEW_OF_SECTION", infoRet[i].param, env); 
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_OPEN_SECTION:
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_OPEN_SECTION);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_OPEN_SECTION", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_DUPLICATE_OBJ:
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_DUPLICATE_OBJ);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_DUPLICATE_OBJ", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                /*** process syscalls ***/
                case VMI_SYS_CREATE_PROCESS:
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_CREATE_PROCESS);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_CREATE", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_CREATE_PROCESS_EX:
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_CREATE_PROCESS_EX);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_CREATE_EX", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;  
                case VMI_SYS_OPEN_PROCESS:
                    //syscall_ret_oc_os(infoRet[i].param, env);
                    //printf("open_process \n");
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_OPEN_PROCESS);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_OPEN", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;                      
                case VMI_SYS_OPEN_PROCESS_TOKEN: 
                    //printf("open_process_token \n");
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_OPEN_PROCESS_TOKEN);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_OPEN_TOKEN", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_RESUME_PROCESS:
                    //printf("resume_process \n");
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_RESUME", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_SUSPEND_PROCESS:
                    //printf("suspend_process \n");
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_SUSPEND", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_TERMINATE_PROCESS:
                    //printf("terminate_process \n");
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_TERMINATE", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break; 
                
                case VMI_SYS_CREATE_THREAD:
                    //printf("create_thread \n");
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_CREATE_THREAD);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCT_CREATE", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_OPEN_THREAD:
                    //printf("open_thread \n");
                    //syscall_ret_oc_os(infoRet[i].param, env);
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_OPEN_THREAD);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCT_OPEN", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_OPEN_THREAD_TOKEN: 
                    //printf("open_thread_token \n");
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_OPEN_THREAD_TOKEN);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCT_OPEN_TOKEN", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_RESUME_THREAD:
                    //printf("resume_thread \n");
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCT_RESUME", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_SUSPEND_THREAD:
                    //printf("suspend_thread \n");
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCT_SUSPEND", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;                    
                case VMI_SYS_TERMINATE_THREAD:
                    //printf("terminate_thread \n");
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCT_TERMINATE", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES:
                    break;
                case VMI_SYS_ALLOCATE_VIRTUAL_MEMORY:
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_ALLOCATE_VIRTUAL_MEMORY);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_ALLOCATE_VIRTUAL_MEMORY", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_QUERY_INFO_PROCESS:
                    syscall_ret_handle_os(infoRet[i].param, env, VMI_SYS_QUERY_INFO_PROCESS);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_QUERY_INFO_PROCESS", infoRet[i].param, env);
                    g_free(infoRet[i].param);
#else
                case VMI_SYS_CLONE:
                    syscall_ret_values_os(infoRet[i].param, env, VMI_SYS_CLONE);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_CLONE", infoRet[i].param, env);
                    break;
                case VMI_SYS_FORK:
                    //printf("foooooork\n");
                    syscall_ret_f_os(infoRet[i].param, env);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_FORK", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_EXECVE:
                    syscall_printf_end();
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_EXECVE", infoRet[i].param, env);
                    g_free(infoRet[i].param);
                    break;
                case VMI_SYS_MOUNT:
                    syscall_ret_mount_os(infoRet[i].param, env);
                    syscall_free_memory(infoRet[i].param, VMI_SYS_MOUNT);
                    break;
                case VMI_SYS_UMOUNT:
                    syscall_ret_umount_os(infoRet[i].param, env);
                    syscall_free_memory(infoRet[i].param, VMI_SYS_UMOUNT);
                    break;
                case VMI_SYS_EXIT_GROUP:
                    break;
                case VMI_SYS_MMAP:
                case VMI_SYS_MMAP2:
                    syscall_mmap_return(infoRet[i].param, env);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SC_MMAP", infoRet[i].param, env);
                    syscall_free_memory(infoRet[i].param, VMI_SYS_MMAP);
                    break;
                case VMI_SYS_GETPID:
                    syscall_ret_values_os(infoRet[i].param, env, VMI_SYS_GETPID);
                    plugin_gen_signal(syscall_get_cb(), "VMI_SCP_GETPID", infoRet[i].param, env);
                    break;
                case VMI_SYS_GETPPID:
                    syscall_ret_values_os(infoRet[i].param, env, VMI_SYS_GETPPID);
                    break;
#endif                
                default: break;                
            }
            --count;
            if (count)
                infoRet[i] = infoRet[count];
        }
        else {
            //fprintf(log, "ne povezlo\n");
        }
    }
}