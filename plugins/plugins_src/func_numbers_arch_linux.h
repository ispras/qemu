#if defined(TARGET_X86_64)

//#define VMI_SYS_FORK        57
#define VMI_SYS_READ        0
#define VMI_SYS_WRITE       1
#define VMI_SYS_OPEN        2
#define VMI_SYS_CLOSE       3
#define VMI_SYS_CREATE      85
//#define VMI_SYS_EXECVE      59
//#define VMI_SYS_GETPID      39
//#define VMI_SYS_MOUNT       165
//#define VMI_SYS_UMOUNT      166
//#define VMI_SYS_GETPPID     110
//#define VMI_SYS_MMAP        9
//#define VMI_SYS_CLONE       56
//#define VMI_SYS_EXIT_GROUP  231
#define VMI_SYS_OPENAT      257

#elif defined(TARGET_I386)

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
#define VMI_SYS_OPENAT      295

#endif
