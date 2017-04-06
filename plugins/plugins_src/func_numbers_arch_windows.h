/* windows XP */

#ifdef TARGET_X86_64

#ifdef GUEST_OS_WINXP

#define VMI_SYS_CREATE                  0x0052
#define VMI_SYS_OPEN                   0x0030
#define VMI_SYS_READ                    0x0003
#define VMI_SYS_WRITE                   0x0005
#define VMI_SYS_CLOSE                   0x000c
#define VMI_SYS_CREATE_SECTION          0x0047
#define VMI_SYS_MAP_VIEW_OF_SECTION     0x0025
#define VMI_SYS_UNMAP_VIEW_OF_SECTION   0x0027
#define VMI_SYS_OPEN_SECTION            0x0034
#define VMI_SYS_DUPLICATE_OBJ           0x0039

// process syscalls

#define VMI_SYS_CREATE_PROCESS          0x0082
#define VMI_SYS_CREATE_PROCESS_EX       0x004a
#define VMI_SYS_OPEN_PROCESS            0x0023
#define VMI_SYS_TERMINATE_PROCESS       0x0029

//#define VMI_SYS_CREATE_USER_PROCESS
#define VMI_SYS_OPEN_PROCESS_TOKEN      0x00be
#define VMI_SYS_RESUME_PROCESS          0x00ef
#define VMI_SYS_SUSPEND_PROCESS         0x0117
#define VMI_SYS_CREATE_THREAD           0x004b
#define VMI_SYS_OPEN_THREAD             0x00c1
#define VMI_SYS_OPEN_THREAD_TOKEN       0x0021
#define VMI_SYS_RESUME_THREAD           0x004f
#define VMI_SYS_SUSPEND_THREAD          0x0118
#define VMI_SYS_TERMINATE_THREAD        0x0050

#define VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES    0x0011
#define VMI_SYS_ALLOCATE_VIRTUAL_MEMORY         0x0013

#define VMI_SYS_QUERY_INFO_PROCESS      0x0016

#elif defined(GUEST_OS_WIN7)

#define VMI_SYS_CREATE                  0x0052
#define VMI_SYS_OPEN                    0x0030
#define VMI_SYS_READ                    0x0003
#define VMI_SYS_WRITE                   0x0005
#define VMI_SYS_CLOSE                   0x000c
#define VMI_SYS_CREATE_SECTION          0x0047
#define VMI_SYS_MAP_VIEW_OF_SECTION     0x0025
#define VMI_SYS_UNMAP_VIEW_OF_SECTION   0x0027
#define VMI_SYS_OPEN_SECTION            0x0034
#define VMI_SYS_DUPLICATE_OBJ           0x0039
// process syscalls
#define VMI_SYS_CREATE_PROCESS          0x009f
#define VMI_SYS_CREATE_PROCESS_EX       0x004a
#define VMI_SYS_OPEN_PROCESS            0x0023
#define VMI_SYS_TERMINATE_PROCESS       0x0029

//#define VMI_SYS_CREATE_USER_PROCESS
#define VMI_SYS_OPEN_PROCESS_TOKEN      0x00f9
#define VMI_SYS_RESUME_PROCESS          0x0144
#define VMI_SYS_SUSPEND_PROCESS         0x017a
#define VMI_SYS_CREATE_THREAD           0x004b
#define VMI_SYS_OPEN_THREAD             0x00fe
#define VMI_SYS_OPEN_THREAD_TOKEN       0x0021
#define VMI_SYS_RESUME_THREAD           0x004f
#define VMI_SYS_SUSPEND_THREAD          0x017b
#define VMI_SYS_TERMINATE_THREAD        0x0050

#define VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES    0x006d
#define VMI_SYS_ALLOCATE_VIRTUAL_MEMORY         0x0015

#define VMI_SYS_QUERY_INFO_PROCESS      0x0016

#else
#error Cannot build Windows syscall plugin for unknown Windows version.
#endif

#elif defined(TARGET_I386)

#ifdef GUEST_OS_WINXP

#define VMI_SYS_CREATE                  0x0025
#define VMI_SYS_OPEN                    0x0074
#define VMI_SYS_READ                    0x00b7
#define VMI_SYS_WRITE                   0x0112
#define VMI_SYS_CLOSE                   0x0019
#define VMI_SYS_CREATE_SECTION          0x0032
#define VMI_SYS_MAP_VIEW_OF_SECTION     0x006c
#define VMI_SYS_UNMAP_VIEW_OF_SECTION   0x010b
#define VMI_SYS_OPEN_SECTION            0x007d
#define VMI_SYS_DUPLICATE_OBJ           0x0044

// process syscalls

#define VMI_SYS_CREATE_PROCESS          0x002f
#define VMI_SYS_CREATE_PROCESS_EX       0x0030
#define VMI_SYS_OPEN_PROCESS            0x007a
#define VMI_SYS_TERMINATE_PROCESS       0x0101

//#define VMI_SYS_CREATE_USER_PROCESS XP dont support
#define VMI_SYS_OPEN_PROCESS_TOKEN      0x007b
#define VMI_SYS_RESUME_PROCESS          0x00cd
#define VMI_SYS_SUSPEND_PROCESS         0x00fd
#define VMI_SYS_CREATE_THREAD           0x0035
#define VMI_SYS_OPEN_THREAD             0x0080
#define VMI_SYS_OPEN_THREAD_TOKEN       0x0081
#define VMI_SYS_RESUME_THREAD           0x00ce
#define VMI_SYS_SUSPEND_THREAD          0x00fe
#define VMI_SYS_TERMINATE_THREAD        0x0102

#define VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES    0x000f
#define VMI_SYS_ALLOCATE_VIRTUAL_MEMORY         0x0011

#define VMI_SYS_QUERY_INFO_PROCESS      0x009a

#elif defined(GUEST_OS_WIN7)

#define VMI_SYS_CREATE                  0x0042
#define VMI_SYS_OPEN                    0x00b3
#define VMI_SYS_READ                    0x0111
#define VMI_SYS_WRITE                   0x018c
#define VMI_SYS_CLOSE                   0x0032
#define VMI_SYS_CREATE_SECTION          0x0054
#define VMI_SYS_MAP_VIEW_OF_SECTION     0x00a8
#define VMI_SYS_UNMAP_VIEW_OF_SECTION   0x0181
#define VMI_SYS_OPEN_SECTION            0x00c2
#define VMI_SYS_DUPLICATE_OBJ           0x006f
// process syscalls
#define VMI_SYS_CREATE_PROCESS          0x004f
#define VMI_SYS_CREATE_PROCESS_EX       0x0050
#define VMI_SYS_OPEN_PROCESS            0x00be
#define VMI_SYS_TERMINATE_PROCESS       0x0172

//#define VMI_SYS_CREATE_USER_PROCESS XP dont support
#define VMI_SYS_OPEN_PROCESS_TOKEN      0x00bf
#define VMI_SYS_RESUME_PROCESS          0x012f
#define VMI_SYS_SUSPEND_PROCESS         0x016e
#define VMI_SYS_CREATE_THREAD           0x0057
#define VMI_SYS_OPEN_THREAD             0x00c6
#define VMI_SYS_OPEN_THREAD_TOKEN       0x00c7
#define VMI_SYS_RESUME_THREAD           0x0130
#define VMI_SYS_SUSPEND_THREAD          0x016f
#define VMI_SYS_TERMINATE_THREAD        0x0173

#define VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES    0x0011
#define VMI_SYS_ALLOCATE_VIRTUAL_MEMORY         0x0013

#define VMI_SYS_QUERY_INFO_PROCESS      0x00ea

#elif defined(GUEST_OS_WIN8)
// IDs differ from the ones specified in http://j00ru.vexillium.org/ntapi/ table
#define VMI_SYS_CREATE                  0x0164 // 0x0163
#define VMI_SYS_OPEN                    0x00e9 // 0x00e8
#define VMI_SYS_READ                    0x0088 // 0x0087
#define VMI_SYS_WRITE                   0x0006 // 0x0005
#define VMI_SYS_CLOSE                   0x0175 // 0x0174
#define VMI_SYS_CREATE_SECTION          0x0151 // 0x0150
#define VMI_SYS_MAP_VIEW_OF_SECTION     0x00f4 // 0x00f3
#define VMI_SYS_UNMAP_VIEW_OF_SECTION   0x0014 // 0x0013
#define VMI_SYS_OPEN_SECTION            0x00da // 0x00d9
#define VMI_SYS_DUPLICATE_OBJ           0x0130 // 0x012f
// process syscalls
#define VMI_SYS_CREATE_PROCESS          0x0156 // 0x0155
#define VMI_SYS_CREATE_PROCESS_EX       0x0155 // 0x0154
#define VMI_SYS_OPEN_PROCESS            0x00de // 0x00dd
#define VMI_SYS_TERMINATE_PROCESS       0x0024 // 0x0023

//#define VMI_SYS_CREATE_USER_PROCESS XP dont support
#define VMI_SYS_OPEN_PROCESS_TOKEN      0x00dd // 0x00dc
#define VMI_SYS_RESUME_PROCESS          0x006a // 0x0069
#define VMI_SYS_SUSPEND_PROCESS         0x0028 // 0x0027
#define VMI_SYS_CREATE_THREAD           0x014e // 0x014d
#define VMI_SYS_OPEN_THREAD             0x00d6 // 0x00d5
#define VMI_SYS_OPEN_THREAD_TOKEN       0x00d5 // 0x00d4
#define VMI_SYS_RESUME_THREAD           0x0069 // 0x0068
#define VMI_SYS_SUSPEND_THREAD          0x0027 // 0x0026
#define VMI_SYS_TERMINATE_THREAD        0x0023 // 0x0022

#define VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES    0x0199 // 0x0198
#define VMI_SYS_ALLOCATE_VIRTUAL_MEMORY         0x0197 // 0x0196

#define VMI_SYS_QUERY_INFO_PROCESS      0x00b1 // 0x00b0

#elif defined(GUEST_OS_WIN81)

#define VMI_SYS_CREATE                  0x0168
#define VMI_SYS_OPEN                    0x00eb
#define VMI_SYS_READ                    0x008a
#define VMI_SYS_WRITE                   0x0006
#define VMI_SYS_CLOSE                   0x0179
#define VMI_SYS_CREATE_SECTION          0x0154
#define VMI_SYS_MAP_VIEW_OF_SECTION     0x00f6
#define VMI_SYS_UNMAP_VIEW_OF_SECTION   0x0013
#define VMI_SYS_OPEN_SECTION            0x00dc
#define VMI_SYS_DUPLICATE_OBJ           0x0133
// process syscalls
#define VMI_SYS_CREATE_PROCESS          0x0159
#define VMI_SYS_CREATE_PROCESS_EX       0x0158
#define VMI_SYS_OPEN_PROCESS            0x00e0
#define VMI_SYS_TERMINATE_PROCESS       0x0023

//#define VMI_SYS_CREATE_USER_PROCESS XP dont support
#define VMI_SYS_OPEN_PROCESS_TOKEN      0x00df
#define VMI_SYS_RESUME_PROCESS          0x006c
#define VMI_SYS_SUSPEND_PROCESS         0x0027
#define VMI_SYS_CREATE_THREAD           0x0151
#define VMI_SYS_OPEN_THREAD             0x00d8
#define VMI_SYS_OPEN_THREAD_TOKEN       0x00d7
#define VMI_SYS_RESUME_THREAD           0x006b
#define VMI_SYS_SUSPEND_THREAD          0x0026
#define VMI_SYS_TERMINATE_THREAD        0x0022

#define VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES    0x019d
#define VMI_SYS_ALLOCATE_VIRTUAL_MEMORY         0x019b

#define VMI_SYS_QUERY_INFO_PROCESS      0x00b3

#else
#error Cannot build Windows syscall plugin for unknown Windows version.
#endif

#else
#error Trying to build windows syscall plugin for non-x86 platform
#endif
