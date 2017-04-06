#if defined(TARGET_X86_64) || defined(TARGET_I386)

#define VMI_SYS_FORK        2
#define VMI_SYS_READ        3
#define VMI_SYS_WRITE       4
#define VMI_SYS_OPEN        5
#define VMI_SYS_CLOSE       6
#define VMI_SYS_CREATE      8
#define VMI_SYS_EXECVE      11
#define VMI_SYS_GETPID      20
#define VMI_SYS_MOUNT       21
#define VMI_SYS_UMOUNT      22
#define VMI_SYS_GETPPID     64
#define VMI_SYS_MMAP        90
#define VMI_SYS_CLONE       120
#define VMI_SYS_MMAP2       192
#define VMI_SYS_EXIT_GROUP  252

#endif
