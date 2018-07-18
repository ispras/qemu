#ifndef SYSCALLS_H
#define SYSCALLS_H
#if 0
/***** os syscalls *****/
enum SyscallNumbers {
                    /* Common */
                     VMI_SC_CREATE, VMI_SC_OPEN, VMI_SC_READ, VMI_SC_WRITE, VMI_SC_CLOSE,
                     VMI_SC_DUPLICATE_OBJ,
                    /* Windows */
                     VMI_SC_CREATE_SECTION, VMI_SC_MAP_VIEW_OF_SECTION, VMI_SC_UNMAP_VIEW_OF_SECTION,
                     VMI_SC_OPEN_SECTION,
                    /* Linux */
                     VMI_SC_MMAP,
                    /* Unsorted */
                     VMI_SCP_CREATE, VMI_SCP_CREATE_EX, VMI_SCP_OPEN, VMI_SCP_OPEN_TOKEN, VMI_SCP_RESUME, VMI_SCP_SUSPEND, VMI_SCP_TERMINATE,
                     VMI_SCT_CREATE, VMI_SCT_OPEN, VMI_SCT_OPEN_TOKEN, VMI_SCT_RESUME, VMI_SCT_SUSPEND, VMI_SCT_TERMINATE,
                     VMI_SCP_CLONE, VMI_SCP_FORK, VMI_SCP_EXECVE, VMI_SCP_EXIT_GROUP, VMI_SCP_GETPID, VMI_SCP_GETPPID,
                     VMI_SCP_ALLOCATE_USER_PHYSICAL_PAGES, VMI_SCP_ALLOCATE_VIRTUAL_MEMORY, VMI_SCP_QUERY_INFO_PROCESS,
                     VMI_SC_COUNT};
/***** process syscalls *****/
#endif

SignalInfo *syscall_get_cb(void);
//{ ostaetsya
void start_system_call(CPUArchState *env);
void exit_system_call(CPUArchState *env, uint64_t stack);
//void check_dll_call(uint64_t pc);
//}

/* printf log_file */
void printf_log(const char *format, ...);

int syscall_init_log(void);
int syscall_close_log(void);

void syscall_printf_all_calls(int syscallnum);
void syscall_printf_get_current_proc_id(void);
void syscall_printf_get_current_proc_id_ret(uint32_t ret);

enum OCFlags {
    OCF_READ    = 1 << 0, // read access
    OCF_WRITE   = 1 << 1, // write access
    OCF_CREATE  = 1 << 2, // create new file
    OCF_TRUNC   = 1 << 3, // truncate old file
    OCF_APPEND  = 1 << 4, // append to old file
};

typedef struct Parameters_oc {
    char *name;
    int64_t handle;
    int access;
    int ret;
} Parameters_oc;
Parameters_oc *syscall_open_os(CPUArchState *env);
Parameters_oc *syscall_openat_os(CPUArchState *env);
Parameters_oc *syscall_create_os(CPUArchState *env);

typedef struct Parameters_rw {
    int64_t handle;
    int pBuffer;
    int length;
    uint8_t *buffer;
    int ret;
} Parameters_rw;
Parameters_rw *syscall_read_os(CPUArchState *env);
Parameters_rw *syscall_write_os(CPUArchState *env);

typedef struct Parameters_c {
    uint64_t handle;
    int ret;
} Parameters_c;
Parameters_c *syscall_close_os(CPUArchState *env);

typedef struct Parameters_do {
    uint64_t sourceHandle;
    uint64_t pTargetHandle;
} Parameters_do;
Parameters_do *syscall_duplicate_object_os(CPUArchState *env);

#ifdef GUEST_OS_LINUX

typedef struct ParametersFork {
    int pid;
    int ret;
} ParametersFork;
ParametersFork *syscall_fork_os(CPUArchState *env);

typedef struct Parameters_clone {
    uint32_t flags;
    //uint64_t ctid;
    int ret;
} Parameters_clone;
Parameters_clone *syscall_clone_os(CPUArchState *env);
void syscall_ret_clone_os(void *param, CPUArchState *env);

typedef struct Parameters_execve {
    char *name;
    char **argv;
    int ret;
} Parameters_execve;
Parameters_execve *syscall_execve_os(CPUArchState *env);
void syscall_ret_execve_os(void *param, CPUArchState *env);
/* process syscalls */
void syscall_exit_group_os(CPUArchState *env);

typedef struct Parameters_mmap {
    uint64_t address;
    uint64_t offset;
    uint64_t length;  
    uint64_t handle;
} Parameters_mmap;
Parameters_mmap *syscall_mmap_os(CPUArchState *env);
Parameters_mmap *syscall_mmap2_os(CPUArchState *env);

void syscall_getpid_os(CPUArchState *env);
void syscall_getppid_os(CPUArchState *env);

/* return value */
void syscall_ret_values_os(void *param, CPUArchState *env, int event);

void syscall_syscall_printf_end(CPUArchState *env);
void syscall_mmap_return(Parameters_mmap *params, CPUArchState *env);

typedef struct Parameters_mount {
    char *source;
    char *target;
    char *filesystemtype;
    int ret;
} Parameters_mount;
Parameters_mount *syscall_mount_os(CPUArchState *env);
void syscall_ret_mount_os(Parameters_mount *params, CPUArchState *env);

typedef struct Parameters_umount {
    char *target;
    int ret;
} Parameters_umount;
Parameters_umount *syscall_umount_os(CPUArchState *env);
void syscall_ret_umount_os(Parameters_umount *params, CPUArchState *env);

#endif

#ifdef GUEST_OS_WINDOWS

// Low order two bits of a handle are ignored by the system and available
// for use by application code as tag bits.  The remaining bits are opaque
// and used to store a serial number and table index.
#define OBJ_HANDLE_TAGBITS  0x00000003L

typedef struct Parameters_map {
    uint64_t pBaseAddress;
    uint64_t sectionOffset;
    uint64_t viewSize;  
    uint64_t sHandle;
} Parameters_map;
Parameters_map *syscall_map_view_of_section_os(CPUArchState *env);

typedef struct Parameters_unmap {
    uint64_t processHandle;
    uint64_t baseAddress;
    int ret;
} Parameters_unmap;
Parameters_unmap *syscall_unmap_view_of_section_os(CPUArchState *env);

typedef struct Parameters_os {
    int pHandle;
    char *name;
} Parameters_os;
Parameters_os *syscall_open_section_os(CPUArchState *env);

typedef struct Parameters_cs {
    target_ulong pHandle;
    target_ulong fHandle; 
    char *name;
} Parameters_cs;
Parameters_cs *syscall_create_section_os(CPUArchState *env);

typedef struct Parameters_query_info_proc {
    uint32_t pProcInfo;
    uint32_t infoClass;
    uint32_t reserved1;
    uint32_t pebBaseAddress;
    uint32_t reserved2;
    uint32_t uniqueProcId;
    uint32_t reserved3;
    uint32_t procParams;
    uint32_t imagePathName;
    char *imageName;
} Parameters_query_info_proc;
Parameters_query_info_proc *syscall_query_information_process_os(CPUArchState *env);

/* process */
typedef struct ParametersProcCreate {
    int pProcHandle;
    int desiredAccess;
    int objectAttrOpt;
    int parentProc;
    int ret;
} ParametersProcCreate;

typedef struct ParametersProcOpen {
    int pProcHandle;
    int desiredAccess;
    int objectAttr;
    int pid;
    int tid;
    int ret;
} ParametersProcOpen;

typedef struct ParametersProcOpenToken {
    int pTokenHandle;
    int procHandle;
    int desiredAccess;
    int ret;
} ParametersProcOpenToken;

typedef struct ParametersProcResSusp {
    int procHandle;
    int ret;
} ParametersProcResSusp;

typedef struct ParametersProcTerm {
    int exitStatus;
    int procHandleOpt;
    int ret;
} ParametersProcTerm;
/*
DWORD *typedef PVOID;
typedef struct initialTEB{
    PVOID PreviousStackBase;
    PVOID PreviousStackLimit;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID AllocatedStackBase;
} initialTEB;
*/
/* threads */
typedef struct ParametersThreadCreate {
    int pThreadHandle;
    int pClientId; // int?
    int desiredAccess;
    int objectAttrOpt;
    int procHandle;
    int threadContext;
    //initialTEB initTEB;
    int ret;
} ParametersThreadCreate;

typedef struct ParametersThreadOpen {
    int pThreadHandle;
    int desiredAccess;
    int objectAttr;
    int clientIdOpt;
    int ret;
} ParametersThreadOpen;

typedef struct ParametersThreadOpenToken {
    int pTokenHandle;
    int threadHandle;
    int desiredAccess;
    int ret;
} ParametersThreadOpenToken;

typedef struct ParametersThreadResSusp {
    int threadHandle;
    int ret;
} ParametersThreadResSusp;

typedef struct ParametersThreadTerm {
    int exitStatus;
    int threadHandleOpt;
    int ret;
} ParametersThreadTerm;

typedef struct ParametersAllocVirtMem {
    uint32_t pBaseAddress;
    uint32_t pRegionSize;
    uint32_t ret;
} ParametersAllocVirtMem;

/* process syscalls */
ParametersProcCreate *syscall_create_process_os(CPUArchState *env);
ParametersProcCreate *syscall_create_process_ex_os(CPUArchState *env);
void syscall_create_user_process_os(CPUArchState *env);
ParametersProcOpen *syscall_open_process_os(CPUArchState *env);
ParametersProcOpenToken *syscall_open_process_token_os(CPUArchState *env);
ParametersProcResSusp *syscall_resume_process_os(CPUArchState *env);
ParametersProcResSusp *syscall_suspend_process_os(CPUArchState *env);
ParametersProcTerm *syscall_terminate_process_os(CPUArchState *env);

ParametersThreadCreate *syscall_create_thread_os(CPUArchState *env);
ParametersThreadOpen *syscall_open_thread_os(CPUArchState *env);
ParametersThreadOpenToken *syscall_open_thread_token_os(CPUArchState *env);
ParametersThreadResSusp *syscall_resume_thread_os(CPUArchState *env);
ParametersThreadResSusp *syscall_suspend_thread_os(CPUArchState *env);
ParametersThreadTerm *syscall_terminate_thread_os(CPUArchState *env);

void syscall_allocate_user_physical_pages_os(CPUArchState *env);
ParametersAllocVirtMem *syscall_allocate_virtual_memory_os(CPUArchState *env);

void syscall_ret_handle_os(void *param, CPUArchState *env, int event);

#endif

/* return value */
void syscall_ret_oc_os(void *param, CPUArchState *env);
void syscall_ret_read_os(void *param, CPUArchState *env);
void syscall_ret_write_os(void *param, CPUArchState *env);
void syscall_ret_close_os(void *param, CPUArchState *env);
void syscall_free_memory(void *param, int event);
void syscall_ret_f_os(void *param, CPUArchState *env);
/* end of return value */

void syscall_tlb_add_page(void *msg, CPUArchState *env);
void syscall_exception(void *msg, CPUArchState *env);

#endif /* SYSCALLS_H */

