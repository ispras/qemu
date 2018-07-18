#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"

#include "plugins/plugin.h"
#include "exec/cpu_ldst.h"
#include "qemu/log.h"

#include "func_numbers_arch_linux.h"
#include "syscalls.h"
#include "guest_string.h"

static FILE *syscallfile;
static FILE *log;


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
    printf_log("syscall number = %d context=0x%"PRIx64"\n", syscallnum, get_current_context());
}

/* syscall functions */

static int get_oc_flags(int access)
{
    int res = 0;
    if (access & O_RDWR) {
        res |= OCF_READ | OCF_WRITE;
    } else if (access & O_WRONLY) {
        res |= OCF_WRITE;
    } else { // O_RDONLY is zero
        res |= OCF_READ;
    }
    if (access & O_CREAT) {
        res |= OCF_CREATE;
    }
    if (access & O_TRUNC) {
        res |= OCF_TRUNC;
    }
    if (access & O_APPEND) {
        res |= OCF_APPEND;
    }
    return res;
}

Parameters_oc *syscall_open_os(CPUArchState *env)
{
    Parameters_oc *params = g_malloc0(sizeof(Parameters_oc));
    // ebx[3] - const char*
    // ecx[1] - int
    // edx[2] - int 
    int access;
    uint64_t name_addr;
    uint8_t buf[128];
    uint64_t permission;

#if defined(TARGET_X86_64)
    access = env->regs[R_ESI];
    name_addr = env->regs[R_EDI];
    permission = env->regs[R_EDX];
#elif defined(TARGET_I386)
    access = env->regs[R_ECX];
    name_addr = env->regs[R_EBX];
    permission = env->regs[R_EDX];
#endif

    printf_log("\tsys_open\n");
    printf_log("\t\tpfilename 0x%x\n", (int) name_addr);
    cpu_memory_rw_debug(first_cpu, name_addr, buf, sizeof(buf), 0);
    printf_log("\t\t\tname: ");
    int i;
    for (i = 0; i < 128; i++)
    {
        if (buf[i] == '\0')
            break;
        printf_log("%c", buf[i]);
    }
    printf_log("\n");
    params->name = g_malloc((i + 1) * sizeof(char));
    memcpy(params->name, buf, i + 1);
    printf_log("\t\taccess 0x%x\n", access);
    printf_log("\t\tpermission 0x%x\n", (int) permission);
    params->access = get_oc_flags(access);

    return params;
}

Parameters_oc *syscall_openat_os(CPUArchState *env)
{
    Parameters_oc *params = g_malloc0(sizeof(Parameters_oc));
    // ebx - int dfd
    // ecx - const char* filename
    // edx - int flags
    // esi - int mode
    int access;
    uint64_t name_addr;
    uint64_t permission;

#if defined(TARGET_X86_64)
    access = env->regs[R_EDX];
    name_addr = env->regs[R_ESI];
    permission = env->regs[10];
#elif defined(TARGET_I386)
    access = env->regs[R_EDX];
    name_addr = env->regs[R_ECX];
    permission = env->regs[R_ESI];
#endif

    printf_log("\tsys_openat\n");
    printf_log("\t\tpfilename 0x%x\n", (int) name_addr);
    uint8_t buf[128];
    cpu_memory_rw_debug(first_cpu, name_addr, buf, sizeof(buf), 0);
    printf_log("\t\t\tname: ");
    int i;
    for (i = 0; i < 128; i++)
    {
        if (buf[i] == '\0')
            break;
        printf_log("%c", buf[i]);
    }
    printf_log("\n");
    params->name = g_malloc((i + 1) * sizeof(char));
    memcpy(params->name, buf, i + 1);
    printf_log("\t\taccess 0x%x\n", access);
    printf_log("\t\tpermission 0x%x\n", (int) permission);
    params->access = get_oc_flags(access);

    return params;
}

Parameters_oc *syscall_create_os(CPUArchState *env)
{
    Parameters_oc *params = g_malloc0(sizeof(Parameters_oc));
    int access;
    uint64_t name_addr;

#if defined(TARGET_X86_64)
    access = env->regs[R_ESI];
    name_addr = env->regs[R_EDI];
#elif defined(TARGET_I386)
    access = env->regs[R_ECX];
    name_addr = env->regs[R_EBX];
#endif

    printf_log("\tsys_creat\n");
    printf_log("\t\tpfilename 0x%x\n", (int) name_addr);
    uint8_t buf[128];
    cpu_memory_rw_debug(first_cpu, name_addr, buf, sizeof(buf), 0);
    printf_log("\t\t\tname: ");
    int i;
    for (i = 0; i < 128; i++)
    {
        if (buf[i] == '\0')
            break;
        printf_log("%c", buf[i]);
    }
    printf_log("\n");
    params->name = g_malloc((i + 1) * sizeof(char));
    memcpy(params->name, buf, i + 1);
    printf_log("\t\tmode 0x%x\n", access);
    params->access = get_oc_flags(access);
    
    return params;
}

Parameters_rw *syscall_read_os(CPUArchState *env)
{
    Parameters_rw *params = g_malloc0(sizeof(Parameters_rw));
    // ebx[3] - unsigned int
    // ecx[1] - char*
    // edx[2] - size_t 
    uint64_t handle;
    uint64_t buffer;
    uint64_t lenght;

#if defined(TARGET_X86_64)
    handle = env->regs[R_EDI];
    buffer = env->regs[R_ESI];
    lenght = env->regs[R_EDX];
#elif defined(TARGET_I386)
    handle = env->regs[R_EBX];
    buffer = env->regs[R_ECX];
    lenght = env->regs[R_EDX];
#endif

    printf_log("\tsys_read\n");
    printf_log("\t\thandle 0x%x\n", (int) handle);
    params->handle = handle;
    printf_log("\t\tpbuffer 0x%x\n", (int) buffer);
    params->pBuffer = buffer;
    printf_log("\t\tnbyte 0x%x\n", (int) lenght);
    params->length = lenght;
    
    return params;
}

Parameters_rw *syscall_write_os(CPUArchState *env)
{
    Parameters_rw *params = g_malloc0(sizeof(Parameters_rw));

    uint64_t handle;
    uint64_t buffer;
    uint64_t lenght;

#if defined(TARGET_X86_64)
    handle = env->regs[R_EDI];
    buffer = env->regs[R_ESI];
    lenght = env->regs[R_EDX];
#elif defined(TARGET_I386)
    handle = env->regs[R_EBX];
    buffer = env->regs[R_ECX];
    lenght = env->regs[R_EDX];
#endif

    printf_log("\tsys_write\n");
    printf_log("\t\thandle 0x%x\n", (int) handle);
    params->handle = handle;
    printf_log("\t\tpbuffer 0x%x\n", (int) buffer);
    params->pBuffer = buffer;
    printf_log("\t\tnbyte 0x%x\n", (int) lenght);
    params->length = lenght;
    
    if (params->length) {
        params->buffer = g_malloc(params->length * sizeof(uint8_t));
        cpu_memory_rw_debug(first_cpu, params->pBuffer, params->buffer, params->length, 0);
    } else { 
        params->buffer = NULL;
    }

    return params;
}

Parameters_c *syscall_close_os(CPUArchState *env)
{
    Parameters_c *params = g_malloc0(sizeof(Parameters_c));
    printf_log("\tsys_close\n");

    uint64_t handle;
#if defined(TARGET_X86_64)
    handle = env->regs[R_EDI];;
#elif defined(TARGET_I386)
    handle = env->regs[R_EBX];
#endif

    printf_log("\t\thandle 0x%x\n", (int) handle);
    params->handle = handle;
    
    return params;
}

int syscall_init_log(void)
{
    log = fopen("log_sys_ret.log", "w");
    if (!log)
        printf("Can\'t read file %s\n", "log_sys_ret.log");

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

void syscall_ret_oc_os(void *param, CPUArchState *env)
{
    Parameters_oc *params = (Parameters_oc *) param;
    params->handle = env->regs[R_EAX];
    if ((int)env->regs[R_EAX] > 0)
        params->ret = 0;
    else 
        params->ret = 1;
    printf_log("open ret handle = 0x%"PRIx64"\n", params->handle);
 }

void syscall_ret_read_os(void *param, CPUArchState *env)
{
    Parameters_rw *params = (Parameters_rw *) param;
    if (params->length) {
        params->buffer = g_malloc(params->length * sizeof(uint8_t));
        cpu_memory_rw_debug(first_cpu, params->pBuffer, params->buffer, params->length, 0);
    } else { 
        params->buffer = NULL;
    }
    if (env->regs[R_EAX] != -1) 
        params->ret = 0;
    else
        params->ret = 1;
}

void syscall_ret_write_os(void *param, CPUArchState *env)
{
    Parameters_rw *params = (Parameters_rw *) param;
    if (env->regs[R_EAX] != -1) 
        params->ret = 0;
    else
        params->ret = 1;
}

void syscall_ret_close_os(void *param, CPUArchState *env)
{
    Parameters_oc *params = (Parameters_oc *) param;
    if (env->regs[R_EAX] != -1) 
        params->ret = 0;
    else
        params->ret = 1;
}

void syscall_free_memory(void *param, int event)
{
    switch (event)
    {
        case VMI_SYS_CREATE:
        {
            Parameters_oc *params = (Parameters_oc *) param;        
            if (params->name)
                g_free(params->name);
            break;
        }
        case VMI_SYS_OPEN: 
        {
            Parameters_oc *params = (Parameters_oc *) param;
            if (params->name)
                g_free(params->name);
            break;
        }
        case VMI_SYS_READ: 
        {
            Parameters_rw *params = (Parameters_rw *) param;
            if (params->buffer)
                g_free(params->buffer); 
            break;
        }
        case VMI_SYS_WRITE: 
        {
            Parameters_rw *params = (Parameters_rw *) param;
            if (params->buffer)
                g_free(params->buffer);
            break;
        }
        case VMI_SYS_CLOSE: 
            break;
#ifndef TARGET_X86_64
        case VMI_SYS_MOUNT:
        {
            Parameters_mount *params = param;
            g_free(params->source);
            g_free(params->target);
            g_free(params->filesystemtype);
            break;
        }
        case VMI_SYS_UMOUNT:
        {
            Parameters_umount *params = param;
            g_free(params->target);
            break;
        }
        case VMI_SYS_EXECVE:
        {
            Parameters_execve *params = param;
            g_free(params->name);
            char **arg = params->argv;
            while (*arg) {
                g_free(*arg);
                ++arg;
            }
            g_free(params->argv);
            break;
        }
#endif
        //case VMI_SYS_CREATE_SECTION: 
        //    break;
        //case VMI_SYS_MAP_VIEW_OF_SECTION: 
        //    break;
        default: break;  
    }
    
    g_free(param);
}

void syscall_ret_f_os(void *param, CPUArchState *env)
{
    ParametersFork *params = (ParametersFork *) param;
    params->pid = env->regs[R_EAX];
    if (env->regs[R_EAX])
        params->ret = 0;
    else 
        params->ret = 1;
}

#if !defined(TARGET_X86_64)

Parameters_clone *syscall_clone_os(CPUArchState *env)
{
    Parameters_clone *params = g_new0(Parameters_clone, 1);
    params->flags = env->regs[R_EBX];
    // this will be another process memory
    //params->ctid = env->regs[R_EDI];
    //printf("CLONE\n");
    printf_log("\tsys_clone\n");
    printf_log("\t\tflags = 0x%x\n", (int) params->flags);
    printf_log("\t\tchild_stack = 0x%x\n", (int) env->regs[R_ECX]);
    printf_log("\t\tptid = 0x%x\n", (int) env->regs[R_EDX]);
    printf_log("\t\tnewtls = 0x%x\n", (int) env->regs[R_ESI]);
    printf_log("\t\tctid = 0x%x\n", (int) env->regs[R_EDI]);
    printf_log("\t\tcontext = 0x%x\n", (int) get_current_context());

    return params;
}

void syscall_ret_clone_os(void *param, CPUArchState *env)
{
    Parameters_clone *params = param;
    params->ret = env->regs[R_EAX];
    printf_log("\tclone ret = 0x%x\n", params->ret);
}

ParametersFork *syscall_fork_os(CPUArchState *env)
{
    ParametersFork *params = g_malloc0(sizeof(ParametersFork));
    printf_log("\tsys_fork\n");
    
    return params;
}

Parameters_mount *syscall_mount_os(CPUArchState *env)
{
    Parameters_mount *params = g_malloc0(sizeof(Parameters_mount));
    params->source = guest_strdup(env, env->regs[R_EBX]);
    params->target = guest_strdup(env, env->regs[R_ECX]);
    params->filesystemtype = guest_strdup(env, env->regs[R_EDX]);

    printf_log("\tsys_mount\n");
    printf_log("\t\tsource = %s\n", params->source);
    printf_log("\t\ttarget = %s\n", params->target);
    printf_log("\t\tfilesystemtype = %s\n", params->filesystemtype);
    return params;
}

void syscall_ret_mount_os(Parameters_mount *params, CPUArchState *env)
{
    params->ret = env->regs[R_EAX];
    printf("<syscall> mount ret=%d source=%s target=%s filesystemtype=%s\n",
        params->ret, params->source, params->target, params->filesystemtype);
}

Parameters_umount *syscall_umount_os(CPUArchState *env)
{
    Parameters_umount *params = g_malloc0(sizeof(Parameters_umount));
    params->target = guest_strdup(env, env->regs[R_EBX]);
    return params;
}

void syscall_ret_umount_os(Parameters_umount *params, CPUArchState *env)
{
    params->ret = env->regs[R_EAX];
    printf("<syscall> umount ret=%d target=%s\n",
        params->ret, params->target);
}


Parameters_execve *syscall_execve_os(CPUArchState *env)
{
    Parameters_execve *params = g_malloc0(sizeof(Parameters_execve));
    
    printf_log("START OF EXECVE\n");
    printf_log("\tsys_execve\n");
    
    printf_log("filename = 0x%x\nNAME: ", (int) env->regs[R_EBX]);
    params->name = guest_strdup(env, env->regs[R_EBX]);
    printf_log(params->name);
    
    uint8_t data[128];
    char **args = g_malloc0(sizeof(char*));
    int argc = 0;
    printf_log("\nargv = 0x%x\nARGS: ", (int) env->regs[R_ECX]);
    cpu_memory_rw_debug(first_cpu, env->regs[R_ECX], data, sizeof(data), 0);
    uint8_t data2[1024];
    int k;
    for (k = 0; k < 128; k += 4) {
        int i = 0;
        if (ldl_p(&data[k])) {
            cpu_memory_rw_debug(first_cpu, ldl_p(&data[k]), data2, sizeof(data2), 0);
            while (data2[i] != '\0') {
                printf_log("%c", data2[i]);
                i++;
            }
            printf_log(";  ");
            args = g_realloc(args, (++argc + 1) * sizeof(char*));
            args[argc - 1] = g_strdup((char*)data2);
            args[argc] = 0;
        } else break;
    }
    params->argv = args;

    printf_log("\nenpv = 0x%x\nKEYS: ", (int) env->regs[R_EDX]);
    cpu_memory_rw_debug(first_cpu, env->regs[R_EDX], data, sizeof(data), 0);
    for (k = 0; k < 128; k += 4) {
        int i = 0;
        if (&data[k]) {
            cpu_memory_rw_debug(first_cpu, ldl_p(&data[k]), data2, sizeof(data2), 0);
            while (data2[i] != '\0') {
                printf_log("%c", data2[i]);
                i++;
            }
            printf_log(";  ");
        } else break;
    }   
    
    printf_log("\n");
    
    return params;
}

/*
Parameters_map *syscall_map_view_of_section_os(CPUArchState *env)
{
    return NULL;
}
*/

void syscall_ret_execve_os(void *param, CPUArchState *env)
{
    Parameters_execve *params = param;
    params->ret = (int) env->regs[R_EAX];
    printf_log("END OF EXECVE return val = %i\n", params->ret);;
}

void syscall_exit_group_os(CPUArchState *env)
{
    printf_log("\tsys_exit_group\n");
    printf_log("\t\tstatus: 0x%x\n", (int) env->regs[R_EBX]);
}

Parameters_mmap *syscall_mmap_os(CPUArchState *env)
{
    Parameters_mmap *params = g_new0(Parameters_mmap, 1);
    printf_log("\tsys_old_mmap\n");
    
    uint8_t buf[24];
    cpu_memory_rw_debug(first_cpu, env->regs[R_EBX], buf, sizeof(buf), 0);

    params->address = ldl_p(&buf[0]);
    printf_log("\t\tstart = 0x%"PRIx64"\n", params->address);
    params->length = ldl_p(&buf[4]);
    printf_log("\t\tlength = 0x%"PRIx64"\n", params->length);
    printf_log("\t\tprot = 0x%x\n", (int)ldl_p(&buf[8]));
    printf_log("\t\tflags = 0x%x\n", (int)ldl_p(&buf[12]));
    params->handle = ldl_p(&buf[16]);;
    printf_log("\t\tfd = 0x%"PRIx64"\n", params->handle);
    params->offset = ldl_p(&buf[20]);;
    printf_log("\t\toffset = 0x%"PRIx64"\n", params->offset);

    return params;
}

Parameters_mmap *syscall_mmap2_os(CPUArchState *env)
{
    Parameters_mmap *params = g_new0(Parameters_mmap, 1);
    printf_log("\tsys_mmap2/sys_mmap_pgoff\n");
    
    params->address = env->regs[R_EBX];
    printf_log("\t\tstart = 0x%"PRIx64"\n", params->address);
    params->length = env->regs[R_ECX];
    printf_log("\t\tlength = 0x%"PRIx64"\n", params->length);
    printf_log("\t\tprot = 0x%x\n", (int) env->regs[R_EDX]);
    printf_log("\t\tflags = 0x%x\n", (int) env->regs[R_ESI]);
    params->handle = env->regs[R_EDI];
    printf_log("\t\tfd = 0x%"PRIx64"\n", params->handle);
    params->offset = env->regs[R_EBP] * TARGET_PAGE_SIZE;
    printf_log("\t\toffset = 0x%"PRIx64"\n", params->offset);

    return params;
}

void syscall_mmap_return(Parameters_mmap *params, CPUArchState *env)
{
    params->address = env->regs[R_EAX];
    printf_log("return value mmap/mmap2\n");
    printf_log("\t\taddress: 0x%"PRIx64"\n", params->address);
}

void syscall_ret_values_os(void *param, CPUArchState *env, int event)
{
    switch (event) {
        case VMI_SYS_OPEN:
            printf_log("return value open\n");
            printf_log("handle: 0x%x\n", (int) env->regs[R_EAX]);
            break;
        case VMI_SYS_CLONE:
            printf_log("end context: 0x%x\n", (int) get_current_context());
            break;
        case VMI_SYS_MMAP2:
            printf_log("return value mmap2\n");
            printf_log("address: 0x%x\n", (int) env->regs[R_EAX]);
            break;
        case VMI_SYS_GETPID:
            printf_log("return value getpid\n");
            printf_log("pid: 0x%x\n", (int) env->regs[R_EAX]);
            break;
        case VMI_SYS_GETPPID:
            printf_log("return value getppid\n");
            printf_log("ppid: 0x%x\n", (int) env->regs[R_EAX]);
            break;
        default: break;
    }
}
#endif