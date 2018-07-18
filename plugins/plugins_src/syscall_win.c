#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"

#include "plugins/plugin.h"
#include "exec/cpu_ldst.h"

#include "func_numbers_arch_windows.h"
#include "syscalls.h"

static FILE *syscallfile;
//static FILE *log;

uint32_t handle_addr;
uint32_t buffer_addr;
uint64_t buf_len;

uint64_t count_line = 0;

Parameters_map *mapParams = NULL;

void printf_log(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    if (syscallfile) {
        vfprintf(syscallfile, format, ap);
    }
    va_end(ap);
}

void syscall_printf_all_calls(int syscallnum)
{
    printf_log("syscall number = 0x%x\n", syscallnum);
}

void syscall_printf_get_current_proc_id(void)
{
    printf_log("getCurrentProcessId function\n");
}

void write_prolog(CPUArchState *env, uint8_t *data, int size);

void write_prolog(CPUArchState *env, uint8_t *data, int size)
{
    //printf("line = %" PRId64 "\n", count_line++);
    printf_log("line = %" PRId64 "\n", count_line++);
    printf_log("system call   code_of_sys_call = 0x%x context = 0x%"PRIx64"\n",
            (int) env->regs[R_EAX], get_current_context());

    int i = 0;
    cpu_memory_rw_debug(first_cpu, (int) env->regs[R_EDX] + 8, data, size, 0);
    printf_log("\tparameters: ");
    for (; i < size; i++)
    {
        printf_log("%02x ", data[i]);
    }    
    printf_log("\n");

    buffer_addr = -1;
    buf_len = -1;
    handle_addr = -1;
}

/* syscall functions */

static uint32_t ld_handle(uint8_t *p)
{
    return ldl_p(p) & ~OBJ_HANDLE_TAGBITS;
}

static char *printf_unicode_string(uint32_t addr)
{
    //addr = ldl_p(&data_struct[8]);
    uint8_t data_oname[8];
    cpu_memory_rw_debug(first_cpu, addr, data_oname, sizeof(data_oname), 0);
    printf_log("\t\t\t\tLength 0x%x\n", lduw_p(data_oname));
    printf_log("\t\t\t\tMaximumLength 0x%x\n", lduw_p(&data_oname[2]));
    printf_log("\t\t\t\tpBuffer 0x%x\n", ldl_p(&data_oname[4]));
    {
        uint32_t addr = ldl_p(&data_oname[4]);
        if (addr)
        {
            uint16_t len = lduw_p(data_oname);
            uint16_t buf[len / 2];
            cpu_memory_rw_debug(first_cpu, addr, (uint8_t*)buf, sizeof(buf), 0);
            printf_log("name: ");
            char name[len / 2 + 1];
            int i, j = 0;
            for (i = 0; i < len / 2; i++)
            {
                printf_log("%lc", buf[i]);
                //if (buf[i] == '\\')
                //    j = 0;
                //else
                    name[j++] = buf[i];
            }
            name[j] = 0;
            printf_log("\n\t\t\t\t\tname = %s\n", name);
            if (name[0] != '\0') {
                return g_strdup(name);
            }
        }
    }
    return NULL;
}

Parameters_oc *syscall_open_os(CPUArchState *env)
{
    Parameters_oc *params = g_malloc0(sizeof(Parameters_oc));

    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtOpenFile addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tpFileHandle 0x%x\n", ldl_p(data));

    handle_addr = ldl_p(data);
    params->handle = handle_addr;
    
    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));

    params->access = 0;// TODO: ldl_p(&data[4]);

    printf_log("\t\tpObjectAttributes 0x%x\n", ldl_p(&data[8]));
    {
        uint8_t data_struct[24];
        uint32_t addr = ldl_p(&data[8]);
        cpu_memory_rw_debug(first_cpu, addr, data_struct, sizeof(data_struct), 0);
        printf_log("\t\t\tstructure: ");
        int i = 0;
        for (; i < sizeof(data_struct); i++)
        {
            printf_log("%02x ", data_struct[i]);
        }
        printf_log("\n");
        printf_log("\t\t\tLength 0x%x\n", ldl_p(data_struct));
        printf_log("\t\t\tRootDirectory 0x%x\n", ldl_p(&data_struct[4]));
        printf_log("\t\t\tObjectName 0x%x\n", ldl_p(&data_struct[8]));
        {
            addr = ldl_p(&data_struct[8]);

            if (addr)
                params->name = printf_unicode_string(addr);
        }
        printf_log("\t\t\tAttributes 0x%x\n", ldl_p(&data_struct[12]));
        printf_log("\t\t\tSecurityDescriptor 0x%x\n", ldl_p(&data_struct[16]));
        printf_log("\t\t\tSecurityQualityOfService 0x%x\n", ldl_p(&data_struct[20]));
    }
    printf_log("\t\tIoStatusBlock 0x%x\n", ldl_p(&data[12]));
    printf_log("\t\tShareAccess 0x%x\n", ldl_p(&data[16]));
    printf_log("\t\tOpenOptions 0x%x\n", ldl_p(&data[20]));
    
   
    return params;
}

Parameters_oc *syscall_create_os(CPUArchState *env)
{
    Parameters_oc *params = g_malloc0(sizeof(Parameters_oc));
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtCreateFile addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tpFileHandle 0x%x\n", ldl_p(data));

    handle_addr = ldl_p(data);
    params->handle = handle_addr;

    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));
    
    params->access = 0; // TODO: ldl_p(&data[4]);
    
    printf_log("\t\tpObjectAttributes 0x%x\n", ldl_p(&data[8]));
    {
        uint8_t data_struct[24];
        uint32_t addr = ldl_p(&data[8]);
        cpu_memory_rw_debug(first_cpu, addr, data_struct, sizeof(data_struct), 0);
        printf_log("\t\t\tstructure: ");
        int i = 0;
        for (; i < sizeof(data_struct); i++)
        {
            printf_log("%02x ", data_struct[i]);
        }
        printf_log("\n");
        printf_log("\t\t\tLength 0x%x\n", ldl_p(data_struct));
        printf_log("\t\t\tRootDirectory 0x%x\n", ldl_p(&data_struct[4]));
        printf_log("\t\t\tObjectName 0x%x\n", ldl_p(&data_struct[8]));
        {
            addr = ldl_p(&data_struct[8]);
            
            if (addr)
                params->name = printf_unicode_string(addr);
        }
        printf_log("\t\t\tAttributes 0x%x\n", ldl_p(&data_struct[12]));
        printf_log("\t\t\tSecurityDescriptor 0x%x\n", ldl_p(&data_struct[16]));
        printf_log("\t\t\tSecurityQualityOfService 0x%x\n", ldl_p(&data_struct[20]));
    }
    printf_log("\t\tIoStatusBlock 0x%x\n", ldl_p(&data[12]));
    printf_log("\t\tAllocationSize 0x%x\n", ldl_p(&data[16]));
    printf_log("\t\tFileAttributes 0x%x\n", ldl_p(&data[20]));
    printf_log("\t\tShareAccess 0x%x\n", ldl_p(&data[24]));
    printf_log("\t\tCreateDisposition 0x%x\n", ldl_p(&data[28]));
    printf_log("\t\tCreateOptions 0x%x\n", ldl_p(&data[32]));
    printf_log("\t\tEaBuffer 0x%x\n", ldl_p(&data[36]));
    printf_log("\t\tEaLength 0x%x\n", ldl_p(&data[40]));
    
    return params;
}

Parameters_rw *syscall_read_os(CPUArchState *env)
{
    Parameters_rw *params = g_malloc0(sizeof(Parameters_rw));
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtReadFile addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tFileHandle 0x%x\n", ldl_p(data));
    
    params->handle = ld_handle(data);

    printf_log("\t\tEvent 0x%x\n", ldl_p(&data[4]));
    printf_log("\t\tApcRoutine 0x%x\n", ldl_p(&data[8]));
    printf_log("\t\tApcContext 0x%x\n", ldl_p(&data[12]));
    printf_log("\t\tAIoStatusBlock 0x%x\n", ldl_p(&data[16]));
    printf_log("\t\tpBuffer 0x%x\n", ldl_p(&data[20]));
    printf_log("\t\tLength 0x%x\n", ldl_p(&data[24]));
    
    buffer_addr = ldl_p(&data[20]);
    buf_len = ldl_p(&data[24]);
    params->pBuffer = buffer_addr;
    params->length = buf_len;
    
    printf_log("\t\tByteOffset 0x%x\n", ldl_p(&data[28]));
    printf_log("\t\tKey 0x%x\n", ldl_p(&data[32]));
    
    return params;
}

Parameters_rw *syscall_write_os(CPUArchState *env)
{
    Parameters_rw *params = g_malloc0(sizeof(Parameters_rw));
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtWriteFile addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tFileHandle 0x%x\n", ldl_p(data));
    
    params->handle = ld_handle(data);
    printf_log("\t\tEvent 0x%x\n", ldl_p(&data[4]));
    printf_log("\t\tApcRoutine 0x%x\n", ldl_p(&data[8]));
    printf_log("\t\tApcContext 0x%x\n", ldl_p(&data[12]));
    printf_log("\t\tAIoStatusBlock 0x%x\n", ldl_p(&data[16]));
    printf_log("\t\tpBuffer 0x%x\n", ldl_p(&data[20]));
    {
        uint32_t addr = ldl_p(&data[20]);
        uint32_t len = ldl_p(&data[24]);
        params->pBuffer = addr;
        params->length = len;
        
        uint8_t buf[len];
        cpu_memory_rw_debug(first_cpu, addr, buf, len, 0);
        printf_log("\t\t\tbuffer: ");
        int i = 0;
        for (; i < len; i++)
        {
            printf_log("%02x ", buf[i]);
        }
        printf_log("\n");
    }
    printf_log("\t\tLength 0x%x\n", ldl_p(&data[24]));
    printf_log("\t\tByteOffset 0x%x\n", ldl_p(&data[28]));
    printf_log("\t\tKey 0x%x\n", ldl_p(&data[32]));
    
    return params;
}

Parameters_c *syscall_close_os(CPUArchState *env)
{
    Parameters_c *params = g_malloc0(sizeof(Parameters_c));
    uint8_t data[4];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtClose addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tHandle 0x%x\n", ldl_p(data));
    params->handle = ld_handle(data);
    
    return params;
}

Parameters_cs *syscall_create_section_os(CPUArchState *env)
{
    Parameters_cs *params = g_malloc0(sizeof(Parameters_cs));
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtCreateSection addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tpSectionHandle 0x%x\n", ldl_p(data));

    params->pHandle = ldl_p(data);

    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));
    printf_log("\t\tpObjectAttributes 0x%x\n", ldl_p(&data[8]));
    if (ldl_p(&data[8]))
    {
        uint8_t data_struct[24];
        uint32_t addr = ldl_p(&data[8]);
        cpu_memory_rw_debug(first_cpu, addr, data_struct, sizeof(data_struct), 0);
        printf_log("\t\t\tstructure: ");
        int i = 0;
        for (; i < sizeof(data_struct); i++)
        {
            printf_log("%02x ", data_struct[i]);
        }
        printf_log("\n");
        printf_log("\t\t\tLength 0x%x\n", ldl_p(data_struct));
        printf_log("\t\t\tRootDirectory 0x%x\n", ldl_p(&data_struct[4]));
        printf_log("\t\t\tObjectName 0x%x\n", ldl_p(&data_struct[8]));
        {
            addr = ldl_p(&data_struct[8]);
            
            if (addr)
                params->name = printf_unicode_string(addr);
        }
        printf_log("\t\t\tAttributes 0x%x\n", ldl_p(&data_struct[12]));
        printf_log("\t\t\tSecurityDescriptor 0x%x\n", ldl_p(&data_struct[16]));
        printf_log("\t\t\tSecurityQualityOfService 0x%x\n", ldl_p(&data_struct[20]));
    }
    printf_log("\t\tpMaximumSize 0x%x\n", ldl_p(&data[12]));
    printf_log("\t\tSectionPageProtection 0x%x\n", ldl_p(&data[16]));
    printf_log("\t\tAllocationAttributes 0x%x\n", ldl_p(&data[20]));
    printf_log("\t\tFileHandle 0x%x\n", ldl_p(&data[24]));
    params->fHandle = ld_handle(&data[24]);
    
    return params;
}

Parameters_map *syscall_map_view_of_section_os(CPUArchState *env)
{
    Parameters_map *params = g_malloc0(sizeof(Parameters_map));
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtMapViewOfSection addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tSectionHandle 0x%x\n", ldl_p(data));
    params->sHandle = ld_handle(data);
    printf_log("\t\tProcessHandle 0x%x\n", ldl_p(&data[4]));
    printf_log("\t\t*BaseAddress 0x%x\n", ldl_p(&data[8]));
    params->pBaseAddress = ldl_p(&data[8]);

    printf_log("\t\tZeroBits 0x%x\n", ldl_p(&data[12]));
    printf_log("\t\tCommitSize 0x%x\n", ldl_p(&data[16]));
    printf_log("\t\tpSectionOffset 0x%x\n", ldl_p(&data[20]));
    params->sectionOffset = ldl_p(&data[20]);
    printf_log("\t\tViewSize 0x%x\n", ldl_p(&data[24]));
    params->viewSize = ldl_p(&data[24]);
    if (params->viewSize) {
        uint8_t data[4];
        cpu_memory_rw_debug(first_cpu, params->viewSize, data, 4, 0);
        uint32_t viewSize = ldl_p(data);
        printf_log("!!view size: 0x%x\n", viewSize);
    }
    printf_log("\t\tInheritDisposition 0x%x\n", ldl_p(&data[28]));
    printf_log("\t\tAllocationType 0x%x\n", ldl_p(&data[32]));
    printf_log("\t\tWin32Protect 0x%x\n", ldl_p(&data[36]));
    
    printf_log("\t CR3 = %0x\n", (int) env->cr[3]);
    
    return params;
}

Parameters_unmap *syscall_unmap_view_of_section_os(CPUArchState *env)
{
    Parameters_unmap *params = g_new0(Parameters_unmap, 1);
    
    uint8_t data[8];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtUnmapViewOfSection addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    params->processHandle = ld_handle(data);
    printf_log("\t\tProcessHandle 0x%"PRIx64"\n", params->processHandle);
    params->baseAddress = ldl_p(&data[4]);
    printf_log("\t\t*BaseAddress 0x%"PRIx64"\n", params->baseAddress);
    printf_log("\t CR3 = %0x\n", (int) env->cr[3]);
    
    return params;
}

Parameters_os *syscall_open_section_os(CPUArchState *env)
{
    // _Out_ PHANDLE            SectionHandle,
    // _In_  ACCESS_MASK        DesiredAccess,
    // _In_  POBJECT_ATTRIBUTES ObjectAttributes
    Parameters_os *params = g_malloc0(sizeof(Parameters_os));
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtOpenSection addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tSectionHandle 0x%x\n", ldl_p(data));
    params->pHandle = ldl_p(data);
    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));
    printf_log("\t\tObjectAttributes 0x%x\n", ldl_p(&data[8]));
    
    if (ldl_p(&data[8]))
    {
        uint8_t data_struct[24];
        uint32_t addr = ldl_p(&data[8]);
        cpu_memory_rw_debug(first_cpu, addr, data_struct, sizeof(data_struct), 0);
        printf_log("\t\t\tstructure: ");
        int i = 0;
        for (; i < sizeof(data_struct); i++)
        {
            printf_log("%02x ", data_struct[i]);
        }
        printf_log("\n");
        printf_log("\t\t\tLength 0x%x\n", ldl_p(data_struct));
        printf_log("\t\t\tRootDirectory 0x%x\n", ldl_p(&data_struct[4]));
        printf_log("\t\t\tObjectName 0x%x\n", ldl_p(&data_struct[8]));
        {
            addr = ldl_p(&data_struct[8]);
            if (addr)
                params->name = printf_unicode_string(addr);
        }
        printf_log("\t\t\tAttributes 0x%x\n", ldl_p(&data_struct[12]));
        printf_log("\t\t\tSecurityDescriptor 0x%x\n", ldl_p(&data_struct[16]));
        printf_log("\t\t\tSecurityQualityOfService 0x%x\n", ldl_p(&data_struct[20]));
    }
    printf_log("context: 0x%x\n", (int) get_current_context());
    
    return params;
}

Parameters_do *syscall_duplicate_object_os(CPUArchState *env)
{
    // _In_      HANDLE      SourceProcessHandle,
    // _In_      HANDLE      SourceHandle,
    // _In_opt_  HANDLE      TargetProcessHandle,
    // _Out_opt_ PHANDLE     TargetHandle,
    // _In_      ACCESS_MASK DesiredAccess,
    // _In_      ULONG       HandleAttributes,
    // _In_      ULONG       Options
    
    Parameters_do *params = g_malloc0(sizeof(Parameters_do));
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtDuplicateObject addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    
    printf_log("\t\tSourceProcessHandle 0x%x\n", ldl_p(data));
    printf_log("\t\tSourceHandle 0x%x\n", ldl_p(&data[4]));
    params->sourceHandle = ld_handle(&data[4]);
    printf_log("\t\tTargetProcessHandle 0x%x\n", ldl_p(&data[8]));
    printf_log("\t\tTargetHandle 0x%x\n", ldl_p(&data[12]));
    params->pTargetHandle = ldl_p(&data[12]);
    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[16]));
    
    printf_log("\t\tHandleAttributes 0x%x\n", ldl_p(&data[20]));
    
    if (ldl_p(&data[20]))
    {
        uint8_t data_struct[24];
        uint32_t addr = ldl_p(&data[20]);
        cpu_memory_rw_debug(first_cpu, addr, data_struct, sizeof(data_struct), 0);
        printf_log("\t\t\tstructure: ");
        int i = 0;
        for (; i < sizeof(data_struct); i++)
        {
            printf_log("%02x ", data_struct[i]);
        }
        printf_log("\n");
        printf_log("\t\t\tLength 0x%x\n", ldl_p(data_struct));
        printf_log("\t\t\tRootDirectory 0x%x\n", ldl_p(&data_struct[4]));
        printf_log("\t\t\tObjectName 0x%x\n", ldl_p(&data_struct[8]));
        {
            addr = ldl_p(&data_struct[8]);
            printf_log("\t\t\t\t");
            g_free(printf_unicode_string(addr));
        }
        printf_log("\t\t\tAttributes 0x%x\n", ldl_p(&data_struct[12]));
        printf_log("\t\t\tSecurityDescriptor 0x%x\n", ldl_p(&data_struct[16]));
        printf_log("\t\t\tSecurityQualityOfService 0x%x\n", ldl_p(&data_struct[20]));
    }
    printf_log("\t\tOptions 0x%x\n", ldl_p(&data[24]));
    
    return params;
}

int syscall_init_log(void)
{
    const char *fname = "syscall.log";
    syscallfile = fopen(fname, "w");
    if (!syscallfile) {
        printf("Can\'t read file %s\n", fname);
        return 0;
    } else return 1;
}

int syscall_close_log(void)
{
    if (syscallfile) {
        fclose(syscallfile);
        return 1;
    } else return 0;
}

/*** return value ***/

void syscall_ret_oc_os(void *param, CPUArchState *env)
{
    Parameters_oc *params = (Parameters_oc *) param;
    uint8_t data_handle[4];
    cpu_memory_rw_debug(first_cpu, params->handle, data_handle, 4, 0);
    params->handle = ld_handle(data_handle);
    params->ret = (int) env->regs[R_EAX];
    printf_log("handle = 0x%x\n", params->handle);
}

void syscall_free_memory(void *param, int event)
{
    switch (event)
    {
        case VMI_SYS_CREATE:
        {
            Parameters_oc *params = (Parameters_oc *) param;        
            if (params->name)
            {
                g_free(params->name);
                params->name = NULL;
            }
            break;
        }
        case VMI_SYS_OPEN: 
        {
            Parameters_oc *params = (Parameters_oc *) param;
            if (params->name)
            {
                g_free(params->name);
                params->name = NULL;
            }
            break;
        }
        case VMI_SYS_READ: 
        {
            Parameters_rw *params = (Parameters_rw *) param;
            if (params->buffer)
            {
                g_free(params->buffer); 
                params->buffer = NULL;
            }
            break;
        }
        case VMI_SYS_WRITE: 
        {
            Parameters_rw *params = (Parameters_rw *) param;
            if (params->buffer)
            {
                g_free(params->buffer);
                params->buffer = NULL;
            }
            break;
        }
        case VMI_SYS_CLOSE: 
            break;
        //case VMI_SYS_CREATE_SECTION: 
        //    break;
        //case VMI_SYS_MAP_VIEW_OF_SECTION: 
        //    break;
        default: break;  
    }
    
    g_free(param);
}


/*** process syscalls ***/
ParametersProcCreate *syscall_create_process_os(CPUArchState *env)
{
    /*
    __out PHANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in HANDLE ParentProcess,
    __in BOOLEAN InheritObjectTable,
    __in_opt HANDLE SectionHandle,
    __in_opt HANDLE DebugPort,
    __in_opt HANDLE ExceptionPort    
    */
    ParametersProcCreate *params = g_malloc0(sizeof(ParametersProcCreate));
    printf_log("create process\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtCreateProcess addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tpHandle 0x%x\n", ldl_p(data));
    params->pProcHandle = ldl_p(data);
    
    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));
    params->desiredAccess = ldl_p(&data[4]);
    
    printf_log("\t\tObjectAttributes 0x%x\n", ldl_p(&data[8])); //optional
    if (ldl_p(&data[8])) {
        uint8_t data_struct[24];
        uint32_t addr = ldl_p(&data[8]);
        cpu_memory_rw_debug(first_cpu, addr, data_struct, sizeof(data_struct), 0);
        printf_log("\t\t\tstructure: ");
        int i = 0;
        for (; i < sizeof(data_struct); i++)
        {
            printf_log("%02x ", data_struct[i]);
        }
        printf_log("\n");
        printf_log("\t\t\tLength 0x%x\n", ldl_p(data_struct));
        printf_log("\t\t\tRootDirectory 0x%x\n", ldl_p(&data_struct[4]));
        printf_log("\t\t\tObjectName 0x%x\n", ldl_p(&data_struct[8]));
        {
            addr = ldl_p(&data_struct[8]);
            if (addr) {
                printf_log("\t\t\t\t\t");
                g_free(printf_unicode_string(addr));
            }
        }
    }
    
    printf_log("\t\tParentProcess 0x%x\n", ldl_p(&data[12]));
    params->parentProc = ldl_p(&data[12]);
    
    printf_log("\t\tInheritObjectHandle 0x%x\n", ldl_p(&data[16])); //boolean
    printf_log("\t\tSectionHandle 0x%x\n", ldl_p(&data[20])); //optional
    printf_log("\t\tDebugPort 0x%x\n", ldl_p(&data[24])); //optional
    printf_log("\t\tExceptionPort 0x%x\n", ldl_p(&data[28])); //optional
    printf_log("\t\tCR3 register 0x%x\n", (int) env->cr[3]);
    
    //printf("cr3 = %x\n", (int) env->cr[3]);
    printf_log("\t\tContext: 0x%x\n", (int) get_current_context());
    
    return params;
}

ParametersProcCreate *syscall_create_process_ex_os(CPUArchState *env)
{
    /*
    __out PHANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in HANDLE ParentProcess,
    __in ULONG Flags,
    __in_opt HANDLE SectionHandle,
    __in_opt HANDLE DebugPort,
    __in_opt HANDLE ExceptionPort,
    __in ULONG JobMemberLevel   
    */
    ParametersProcCreate *params = g_malloc0(sizeof(ParametersProcCreate));
    printf_log("create process ex\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtCreateProcessEx addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tpHandle 0x%x\n", ldl_p(data));
    
    params->pProcHandle = ldl_p(data);
    
    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));
    printf_log("\t\tObjectAttributes 0x%x\n", ldl_p(&data[8])); //optional
    if (ldl_p(&data[8])) {
        uint8_t data_struct[24];
        uint32_t addr = ldl_p(&data[8]);
        cpu_memory_rw_debug(first_cpu, addr, data_struct, sizeof(data_struct), 0);
        printf_log("\t\t\tstructure: ");
        int i = 0;
        for (; i < sizeof(data_struct); i++)
        {
            printf_log("%02x ", data_struct[i]);
        }
        printf_log("\n");
        printf_log("\t\t\tLength 0x%x\n", ldl_p(data_struct));
        printf_log("\t\t\tRootDirectory 0x%x\n", ldl_p(&data_struct[4]));
        printf_log("\t\t\tObjectName 0x%x\n", ldl_p(&data_struct[8]));
        {
            addr = ldl_p(&data_struct[8]);
            if (addr) {
                printf_log("\t\t\t\t\t");
                g_free(printf_unicode_string(addr));
            }
        }
    }
    printf_log("\t\tParentProcess 0x%x\n", ldl_p(&data[12]));
    printf_log("\t\tFlags 0x%x\n", ldl_p(&data[16])); //boolean
    printf_log("\t\tSectionHandle 0x%x\n", ldl_p(&data[20])); //optional
    printf_log("\t\tDebugPort 0x%x\n", ldl_p(&data[24])); //optional
    printf_log("\t\tExceptionPort 0x%x\n", ldl_p(&data[28])); //optional
    printf_log("\t\tJobMemberLevel 0x%x\n", ldl_p(&data[32])); 
    printf_log("\t\tCR3 register 0x%x\n", (int) env->cr[3]);
    
    return params;
}

void syscall_create_user_process_os(CPUArchState *env)
{
    /*
    __out PHANDLE ProcessHandle,
    __out PHANDLE ThreadHandle,
    __in ACCESS_MASK ProcessDesiredAccess,
    __in ACCESS_MASK ThreadDesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ProcessObjectAttributes,
    __in_opt POBJECT_ATTRIBUTES ThreadObjectAttributes,
    __in ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
    __in ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
    __in_opt PVOID ProcessParameters,
    __inout PPS_CREATE_INFO CreateInfo,
    __in_opt PPS_ATTRIBUTE_LIST AttributeList
    */
}

ParametersProcOpen *syscall_open_process_os(CPUArchState *env)
{
    /*
    __out PHANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId 
    */
    ParametersProcOpen *params = g_malloc0(sizeof(ParametersProcOpen));
    printf_log("open process\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtOpenProcess addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tpHandle 0x%x\n", ldl_p(data));
    params->pProcHandle = ldl_p(data);
    
    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));
    params->desiredAccess = ldl_p(&data[4]);
    
    printf_log("\t\tObjectAttributes 0x%x\n", ldl_p(&data[8]));
    params->objectAttr = ldl_p(&data[8]);
    printf_log("\t\tpObjectAttributes 0x%x\n", ldl_p(&data[8]));
    {
        uint8_t data_struct[24];
        uint32_t addr = ldl_p(&data[8]);
        cpu_memory_rw_debug(first_cpu, addr, data_struct, sizeof(data_struct), 0);
        printf_log("\t\t\tstructure: ");
        int i = 0;
        for (; i < sizeof(data_struct); i++)
        {
            printf_log("%02x ", data_struct[i]);
        }
        printf_log("\n");
        printf_log("\t\t\tLength 0x%x\n", ldl_p(data_struct));
        printf_log("\t\t\tRootDirectory 0x%x\n", ldl_p(&data_struct[4]));
        printf_log("\t\t\tObjectName 0x%x\n", ldl_p(&data_struct[8]));
        {
            addr = ldl_p(&data_struct[8]);
            /*
            uint8_t data_oname[8];
            cpu_memory_rw_debug(first_cpu, addr, data_oname, sizeof(data_oname), 0);
            printf_log("\t\t\t\tLength 0x%x\n", lduw_p(data_oname));
            printf_log("\t\t\t\tMaximumLength 0x%x\n", lduw_p(&data_oname[2]));
            printf_log("\t\t\t\tpBuffer 0x%x\n", ldl_p(&data_oname[4]));
            {
                uint32_t addr = ldl_p(&data_oname[4]);
                if (addr)
                {
                    uint16_t len = lduw_p(data_oname);
                    uint16_t buf[len / 2];
                    cpu_memory_rw_debug(first_cpu, addr, (uint8_t*)buf, sizeof(buf), 0);
                    printf_log("\t\t\t\t\tname: ");
                    char name[len / 2 + 1];
                    int j = 0;
                    for (i = 0; i < len / 2; i++)
                    {
                        printf_log("%lc", buf[i]);
                        if (buf[i] == '\\')
                            j = 0;
                        else
                            name[j++] = buf[i];
                    }
                    name[j] = 0;
                    printf_log("\n\t\t\t\t\tname = %s\n", name);
                }
            }
            */
            if (addr) {
                printf_log("\t\t\t\t\t");
                g_free(printf_unicode_string(addr));
            }
        }
        printf_log("\t\t\tAttributes 0x%x\n", ldl_p(&data_struct[12]));
        printf_log("\t\t\tSecurityDescriptor 0x%x\n", ldl_p(&data_struct[16]));
        printf_log("\t\t\tSecurityQualityOfService 0x%x\n", ldl_p(&data_struct[20]));
    }
    
    uint32_t addr = ldl_p(&data[12]);
    printf_log("\t\tClientID 0x%x\n", addr); //optional
    if (addr) {
        uint8_t data[8];
        cpu_memory_rw_debug(first_cpu, addr, data, sizeof(data), 0);
        printf_log("\t\t\tUniqueProcess 0x%x\n", ldl_p(data));
        printf_log("\t\t\tUniqueThread 0x%x\n", ldl_p(&data[4]));
        params->pid = ldl_p(data);
        params->tid = ldl_p(&data[4]);
    }
    
    return params;
}

ParametersProcOpenToken *syscall_open_process_token_os(CPUArchState *env)
{
    /*
    __in HANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __out PHANDLE TokenHandle
    */
    ParametersProcOpenToken *params = g_malloc0(sizeof(ParametersProcOpenToken));
    printf_log("open process token\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtOpenProcessToken addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tpProcessHandle 0x%x\n", ldl_p(data)); //in
    params->pTokenHandle = ldl_p(data);
    
    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));
    params->desiredAccess = ldl_p(&data[4]);
    
    printf_log("\t\tTokenHandle 0x%x\n", ldl_p(&data[8]));
    params->pTokenHandle = ld_handle(&data[8]);
    
    return params;
}

ParametersProcResSusp *syscall_resume_process_os(CPUArchState *env)
{
    /*
    __in HANDLE ProcessHandle
    */
    ParametersProcResSusp *params = g_malloc0(sizeof(ParametersProcResSusp));
    printf_log("resume process\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtResumeProcess addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tProcessHandle 0x%x\n", ldl_p(data));
    params->procHandle = ld_handle(data);
    
    return params;
}

ParametersProcResSusp *syscall_suspend_process_os(CPUArchState *env)
{
    /*
    __in HANDLE ProcessHandle
    */
    ParametersProcResSusp *params = g_malloc0(sizeof(ParametersProcResSusp));
    printf_log("suspend process\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtSuspendProcess addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tProcessHandle 0x%x\n", ldl_p(data));
    params->procHandle = ld_handle(data);
    
    return params;
}

ParametersProcTerm *syscall_terminate_process_os(CPUArchState *env)
{
    /*
    __in_opt HANDLE ProcessHandle,
    __in NTSTATUS ExitStatus
    */
    ParametersProcTerm *params = g_malloc0(sizeof(ParametersProcTerm));
    printf_log("terminate process\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtTerminateProcess addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tProcessHandle 0x%x\n", ldl_p(&data[4])); //optional
    if (ldl_p(&data[4]))
        params->procHandleOpt = ld_handle(&data[4]);
    
    printf_log("\t\tExitStatus 0x%x\n", ldl_p(&data[8]));
    params->exitStatus = ldl_p(&data[8]);
    
    return params;
}

ParametersThreadCreate *syscall_create_thread_os(CPUArchState *env)
{
    /*
    __out PHANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in HANDLE ProcessHandle,
    __out PCLIENT_ID ClientId,
    __in PCONTEXT ThreadContext,
    __in PINITIAL_TEB InitialTeb,
    __in BOOLEAN CreateSuspended
    */
    ParametersThreadCreate *params = g_malloc0(sizeof(ParametersThreadCreate));
    printf_log("create thread\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtCreateThread addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tpThreadHandle 0x%x\n", ldl_p(data));
    
    params->pThreadHandle = ldl_p(data);
    
    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));
    params->desiredAccess = ldl_p(&data[4]);
    
    printf_log("\t\tObjectAttributes 0x%x\n", ldl_p(&data[8])); //optional
    if (ldl_p(&data[8]))
        params->objectAttrOpt = ldl_p(&data[8]);
    
    printf_log("\t\tProcessHandle 0x%x\n", ldl_p(&data[12]));
    params->procHandle = ldl_p(&data[12]);
    
    printf_log("\t\tClientID 0x%x\n", ldl_p(&data[16])); //out
    params->pClientId = ldl_p(&data[16]);
    
    printf_log("\t\tThreadContext 0x%x\n", ldl_p(&data[20]));
    params->threadContext = ldl_p(&data[20]);
    
    printf_log("\t\tInitialTeb 0x%x\n", ldl_p(&data[24]));
    printf_log("\t\tCreateSuspended 0x%x\n", ldl_p(&data[28])); // BOOLEAN SIZE???? ldl_p lalalala
    
    return params;
}

ParametersThreadOpen *syscall_open_thread_os(CPUArchState *env)
{
    /*
    __out PHANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId
    */
    ParametersThreadOpen *params = g_malloc0(sizeof(ParametersThreadOpen));
    printf_log("open thread\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtOpenThread addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tpThreadHandle 0x%x\n", ldl_p(data));
    
    params->pThreadHandle = ldl_p(data);
    
    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));
    params->desiredAccess = ldl_p(&data[4]);
    
    printf_log("\t\tObjectAttributes 0x%x\n", ldl_p(&data[8]));
    params->objectAttr = ldl_p(&data[8]);
    
    printf_log("\t\tClientID 0x%x\n", ldl_p(&data[12])); //optional
    if (ldl_p(&data[12]))
        params->clientIdOpt = ldl_p(&data[12]);
    
    return params;
}

ParametersThreadOpenToken *syscall_open_thread_token_os(CPUArchState *env)
{
    /*
    __in HANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in BOOLEAN OpenAsSelf,
    __out PHANDLE TokenHandle
    */
    ParametersThreadOpenToken *params = g_malloc0(sizeof(ParametersThreadOpenToken));
    printf_log("open thread token\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtOpenThreadToken addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tThreadHandle 0x%x\n", ldl_p(data)); // IN
    params->threadHandle = ld_handle(data);
    
    printf_log("\t\tDesiredAccess 0x%x\n", ldl_p(&data[4]));
    params->desiredAccess = ldl_p(&data[4]);
    
    printf_log("\t\tOpenAsSelf 0x%x\n", ldl_p(&data[8])); // BOOLEAN
    printf_log("\t\tpTokenHandle 0x%x\n", ldl_p(&data[12])); // OUT
    params->pTokenHandle = ldl_p(&data[12]);
    
    return params;
}

ParametersThreadResSusp *syscall_resume_thread_os(CPUArchState *env)
{
    /*
    __in HANDLE ThreadHandle,
    __out_opt PULONG PreviousSuspendCount
    */
    ParametersThreadResSusp *params = g_malloc0(sizeof(ParametersThreadResSusp));
    printf_log("resume thread\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtResumeThread addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tThreadHandle 0x%x\n", ldl_p(data)); // IN
    params->threadHandle = ld_handle(data);
    
    printf_log("\t\tpPreviousSuspendCount 0x%x\n", ldl_p(&data[4])); // OUT optional
    
    return params;
}

ParametersThreadResSusp *syscall_suspend_thread_os(CPUArchState *env)
{
    /*
    __in HANDLE ThreadHandle,
    __out_opt PULONG PreviousSuspendCount
    */
    ParametersThreadResSusp *params = g_malloc0(sizeof(ParametersThreadResSusp));
    printf_log("suspend thread\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtSuspendThread addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tThreadHandle 0x%x\n", ldl_p(data)); // IN
    params->threadHandle = ld_handle(data);
    
    printf_log("\t\tpPreviousSuspendCount 0x%x\n", ldl_p(&data[4])); // OUT optional
    
    return params;
}

ParametersThreadTerm *syscall_terminate_thread_os(CPUArchState *env)
{
    /*
    __in_opt HANDLE ThreadHandle,
    __in NTSTATUS ExitStatus
    */
    ParametersThreadTerm *params = g_malloc0(sizeof(ParametersThreadTerm));
    printf_log("terminate thread\n");
    
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtTerminateThread addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tThreadHandle 0x%x\n", ldl_p(data)); // IN optional
    if (ldl_p(data))
        params->threadHandleOpt = ld_handle(data);
    
    printf_log("\t\tExitStatus 0x%x\n", ldl_p(&data[4]));
    params->exitStatus = ldl_p(&data[4]);
    
    return params;
}

void syscall_ret_handle_os(void *param, CPUArchState *env, int event)
{
    switch (event)
    {
        case VMI_SYS_OPEN:
        case VMI_SYS_CREATE:
        {
            Parameters_oc *params = (Parameters_oc *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->handle, data_handle, 4, 0);
            params->handle = ld_handle(data_handle);
            params->ret = (int) env->regs[R_EAX];
            printf_log("handle = 0x%x\n", params->handle);
        }
        break;
        case VMI_SYS_READ:
        case VMI_SYS_WRITE:
        {
            Parameters_rw *params = (Parameters_rw *) param;
            params->buffer = g_malloc0(params->length * sizeof(uint8_t));
            cpu_memory_rw_debug(first_cpu, params->pBuffer, params->buffer, params->length, 0);
            params->ret = (int) env->regs[R_EAX];
        }
        break;
        case VMI_SYS_OPEN_SECTION:
        {
            Parameters_os *params = (Parameters_os *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->pHandle, data_handle, 4, 0);
            params->pHandle = ld_handle(data_handle);
            printf_log("!!section handle: 0x%x  context: 0x%x\n", params->pHandle, (int) get_current_context());
        }
        break;
        case VMI_SYS_CREATE_SECTION:
        {
            Parameters_cs *params = (Parameters_cs *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->pHandle, data_handle, 4, 0);
            params->pHandle = ld_handle(data_handle);
            printf_log("!!section handle: 0x%x  name: %s\n", params->pHandle, params->name);
        }
        break;
        case VMI_SYS_DUPLICATE_OBJ:
        {
            Parameters_do *params = (Parameters_do *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->pTargetHandle, data_handle, 4, 0);
            params->pTargetHandle = ld_handle(data_handle);
            printf_log("!!target handle: 0x%x\n", params->pTargetHandle);
        }
        break;
        case VMI_SYS_MAP_VIEW_OF_SECTION:
        {
            Parameters_map *params = (Parameters_map *) param;
            uint8_t data[4];
            cpu_memory_rw_debug(first_cpu, params->pBaseAddress, data, 4, 0);
            params->pBaseAddress = ldl_p(data);
            printf_log("!!base address: 0x%x\n", params->pBaseAddress);

            cpu_memory_rw_debug(first_cpu, params->viewSize, data, 4, 0);
            params->viewSize = ldl_p(data);
            printf_log("!!view size: 0x%x\n", params->viewSize);
        }
        break;
        case VMI_SYS_UNMAP_VIEW_OF_SECTION:
        {
            Parameters_unmap *params = param;
            params->ret = (int)env->regs[R_EAX];
            break;
        }
        case VMI_SYS_CLOSE:
            break;
        case VMI_SYS_CREATE_PROCESS: 
        {
            ParametersProcCreate *params = (ParametersProcCreate *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->pProcHandle, data_handle, 4, 0);
            params->pProcHandle = ld_handle(data_handle);
            params->ret = (int) env->regs[R_EAX]; // x3 poka chto
            printf_log("!!process handle: 0x%x\n", params->pProcHandle);
        }
        break;
        case VMI_SYS_CREATE_PROCESS_EX: 
        {
            ParametersProcCreate *params = (ParametersProcCreate *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->pProcHandle, data_handle, 4, 0);
            params->pProcHandle = ld_handle(data_handle);
            //params->ret = (int) env->regs[R_EAX]; // x3 poka chto
        }
        break;
        case VMI_SYS_OPEN_PROCESS: 
        {
            ParametersProcOpen *params = (ParametersProcOpen *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->pProcHandle, data_handle, 4, 0);
            params->pProcHandle = ld_handle(data_handle);
            params->ret = (int) env->regs[R_EAX]; // x3 poka chto
            printf_log("!!process handle: 0x%x\n", params->pProcHandle);
        }
        break;
        case VMI_SYS_OPEN_PROCESS_TOKEN:
        {
            ParametersProcOpenToken *params = (ParametersProcOpenToken *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->pTokenHandle, data_handle, 4, 0);
            params->pTokenHandle = ld_handle(data_handle);
            params->ret = (int) env->regs[R_EAX]; // x3 poka chto
        }
        break;
        case VMI_SYS_CREATE_THREAD: 
        {
            ParametersThreadCreate *params = (ParametersThreadCreate *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->pThreadHandle, data_handle, 4, 0);
            params->pThreadHandle = ld_handle(data_handle);
            
            uint8_t client_id[8];
            cpu_memory_rw_debug(first_cpu, params->pClientId, (uint8_t*) client_id, sizeof(client_id), 0);
            printf_log("\t\t\tUnique process = 0x%x\n", ldl_p(client_id));
            printf_log("\t\t\tUnique thread = 0x%x\n", ldl_p(&client_id[4]));
            
            params->ret = (int) env->regs[R_EAX]; // x3 poka chto
        }
        break;
        case VMI_SYS_OPEN_THREAD: 
        {
            ParametersThreadOpen *params = (ParametersThreadOpen *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->pThreadHandle, data_handle, 4, 0);
            params->pThreadHandle = ld_handle(data_handle);
            params->ret = (int) env->regs[R_EAX]; // x3 poka chto
        }
        break;
        case VMI_SYS_OPEN_THREAD_TOKEN: 
        {
            ParametersThreadOpenToken *params = (ParametersThreadOpenToken *) param;
            uint8_t data_handle[4];
            cpu_memory_rw_debug(first_cpu, params->pTokenHandle, data_handle, 4, 0);
            params->pTokenHandle = ld_handle(data_handle);
            params->ret = (int) env->regs[R_EAX]; // x3 poka chto
        }
        break;
        case VMI_SYS_ALLOCATE_VIRTUAL_MEMORY:
        {
            ParametersAllocVirtMem *params = (ParametersAllocVirtMem *) param;
            uint8_t data[4];
            cpu_memory_rw_debug(first_cpu, params->pBaseAddress, data, 4, 0);
            params->pBaseAddress = ldl_p(data);
            cpu_memory_rw_debug(first_cpu, params->pRegionSize, data, 4, 0);
            params->pRegionSize = ldl_p(data);
            printf_log("\t\tRet base address = 0x%x\n", params->pBaseAddress);
            printf_log("\t\tRet region size = 0x%x\n", params->pRegionSize);
        }
        break;
        case VMI_SYS_QUERY_INFO_PROCESS:
        {
            Parameters_query_info_proc *params = (Parameters_query_info_proc *) param;
            if (params->infoClass == 0) {
                uint8_t data[24];
                cpu_memory_rw_debug(first_cpu, params->pProcInfo, data, sizeof(data), 0);
                params->reserved1 = ldl_p(data);
                params->pebBaseAddress = ldl_p(&data[4]);
                {
                    uint8_t data2[256];
                    cpu_memory_rw_debug(first_cpu, params->pebBaseAddress, data2, sizeof(data2), 0);
                    params->procParams = ldl_p(&data2[16]);
                    cpu_memory_rw_debug(first_cpu, params->procParams, data2, sizeof(data2), 0);
                    params->imagePathName = ldl_p(&data2[56]);
                    params->imageName = printf_unicode_string(params->imagePathName);
                    //printf("%s\n", info.str);
                    //uint32_t commandLine __attribute__((unused)) = ldl_p(&data2[56 + 8 + info.len]);
                }
                params->reserved2 = ldl_p(&data[8]);
                params->uniqueProcId = ldl_p(&data[16]);
                printf_log("\tprocessID: 0x%x\n", params->uniqueProcId);
                params->reserved3 = ldl_p(&data[20]);
            }
        }
        break;
        default: break;
    }
}

/*
void syscall_ret_rw_os(void *param, CPUArchState *env)
{
    Parameters_rw *params = (Parameters_rw *) param;
    params->buffer = g_malloc0(params->length * sizeof(uint8_t));
    cpu_memory_rw_debug(first_cpu, params->pBuffer, params->buffer, params->length, 0);
    params->ret = (int) env->regs[R_EAX];
}*/

void syscall_allocate_user_physical_pages_os(CPUArchState *env)
{
    printf_log("allocate_user_physical_page\n");
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
//    printf_log("\tNtAllocateUserPhysicalPage addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\tNtAllocateUserPhysicalPage addr_arg = 0x"TARGET_FMT_lx"\n", 1, env->regs[R_EDX] + 8);
    printf_log("\t\tProcessHandle 0x%x\n", ldl_p(data)); 
    printf_log("\t\tpNumberOfPages 0x%x\n", ldl_p(&data[4]));
    printf_log("\t\tpUserPfnArray 0x%x\n", ldl_p(&data[8]));
}

ParametersAllocVirtMem *syscall_allocate_virtual_memory_os(CPUArchState *env)
{
    ParametersAllocVirtMem *params = g_malloc0(sizeof(ParametersAllocVirtMem));
    
    printf_log("allocate_virtual_memory\n");
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtAllocateVirtualMemory addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tProcessHandle 0x%x\n", ldl_p(data)); 
    printf_log("\t\tpBaseAddress 0x%x\n", ldl_p(&data[4])); // out 
    params->pBaseAddress = ldl_p(&data[4]);
    uint8_t data2[4];
    cpu_memory_rw_debug(first_cpu, params->pBaseAddress, data2, 4, 0);
    printf_log("\t\t\tBaseAddress 0x%x\n", ldl_p(data2));
    printf_log("\t\tZeroBits 0x%x\n", ldl_p(&data[8]));
    printf_log("\t\tpRegionSize 0x%x\n", ldl_p(&data[12])); // out
    params->pRegionSize = ldl_p(&data[12]);
    cpu_memory_rw_debug(first_cpu, params->pRegionSize, data2, 4, 0);
    printf_log("\t\t\tRegionSize 0x%x\n", ldl_p(data2)); // out
    printf_log("\t\tAllocationType 0x%x\n", ldl_p(&data[16]));
    printf_log("\t\tProtect 0x%x\n", ldl_p(&data[20]));
    
    return params;
}

void syscall_exception(void *msg, CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);
    //trace_finish_step();
    if (
#if defined(TARGET_ARM)
        cpu->exception_index == EXCP_SWI
#elif defined(TARGET_I386) || defined(TARGET_X86_64)
        env->exception_is_int
#elif defined(TARGET_MIPS) || defined(TARGET_MIPS64)
        cpu->exception_index == EXCP_SYSCALL
#elif defined(TARGET_PPC) || defined(TARGET_PPC64) || defined(TARGET_PPCEMB)
        cpu->exception_index == POWERPC_EXCP_SYSCALL
#else
        0
#endif
    ) {
        //trace_write_event(TRACE_EVENT_INTERRUPT, TRACE_EVENT_B_SWI, cpu->exception_index, 0, 0);
    } else if (
#if defined(TARGET_ARM)
        cpu->exception_index == EXCP_IRQ || cpu->exception_index == EXCP_FIQ
#elif defined(TARGET_I386) || defined(TARGET_X86_64)
        0
#elif defined(TARGET_MIPS) || defined(TARGET_MIPS64)
        cpu->exception_index == EXCP_EXT_INTERRUPT
#elif defined(TARGET_PPC) || defined(TARGET_PPC64) || defined(TARGET_PPCEMB)
        cpu->exception_index == POWERPC_EXCP_EXTERNAL
#else
        0
#endif
    ) {
        //trace_write_event(TRACE_EVENT_INTERRUPT, TRACE_EVENT_B_HWI, cpu->exception_index, 0, 0);
    } else {
        //trace_write_event(TRACE_EVENT_INTERRUPT, TRACE_EVENT_B_EXC, cpu->exception_index, 0, 0);
        printf_log("\tEXC index = 0x%x   cr2 = 0x%x\n", cpu->exception_index, (int) env->cr[2]);
    }
}

//static int I = 0;
void syscall_tlb_add_page(void *msg, CPUArchState *env)
{
    //struct PluginParamsTlbAddPage *params = msg;
    //write_tlb_log_block(params->paddr, params->vaddr, false);
    //printf_log("\tpaddr = 0x%x   vaddr = 0x%x\n", (int) params->paddr, (int) params->vaddr);
    
    /*
     if (params->vaddr == 0x7c800000) {
        //if (mapParams) {
        //    printf("size = %x base_addr = %x \n", (int) params->size, (int) mapParams->pBaseAddress);
            uint8_t buf[params->size];
            //cpu_memory_rw_debug(first_cpu, /mapParams->pBaseAddress/ params->vaddr, buf, params->size, 0);
            //cpu_physical_memory_read(params->paddr, buf, params->size);
            
            char filename[128];
            sprintf(filename, "kernel32_%i.bin", I);
            I++;
            FILE *kernel = fopen(filename, "w");
            if (!kernel) printf ("File kernel is not open\n");
            
            fwrite(buf, 1, params->size, kernel);
            fclose(kernel);
        //    mapParams = NULL;
        //}
    }
    */
}

Parameters_query_info_proc *syscall_query_information_process_os(CPUArchState *env)
{
    Parameters_query_info_proc *params = g_malloc0(sizeof(Parameters_query_info_proc));
    
    printf_log("query_information_process\n");
    uint8_t data[44];
    write_prolog(env, data, sizeof(data));
    printf_log("\tNtQueryInformationProcess addr_arg = 0x"TARGET_FMT_lx"\n", env->regs[R_EDX] + 8);
    printf_log("\t\tProcessHandle 0x%x\n", ldl_p(data)); 
    printf_log("\t\tCR3 register 0x%x\n", (int) env->cr[3]);
    printf_log("\t\tProcessInformationClass 0x%x\n", ldl_p(&data[4]));
    printf_log("\t\tProcessInformation 0x%x\n", ldl_p(&data[8])); // out
    params->pProcInfo = ldl_p(&data[8]);
    params->infoClass = ldl_p(&data[4]);
    printf_log("\t\tProcessInformationLength 0x%x\n", ldl_p(&data[12]));
    //out opt return length 
    //printf("cr3 = 0x%x before queryinfo  procHandle = %x \n", (int) env->cr[3], ldl_p(data));
    
    return params;    
}

void syscall_printf_get_current_proc_id_ret(uint32_t ret)
{
    printf("pid = 0x%x\n", ret);
}