/**** file syscalls ****/
[VMI_SYS_CREATE] = {.name = "NtCreateFile"},
[VMI_SYS_OPEN] = {.name = "NtOpenFile"},
[VMI_SYS_READ] = {.name = "NtReadFile"},
[VMI_SYS_WRITE] = {.name = "NtWriteFile"},
[VMI_SYS_CLOSE] = {.name = "NtClose"},
#if defined(GUEST_OS_WINDOWS)
[VMI_SYS_CREATE_SECTION] = {.name = "NtCreateSection"},
[VMI_SYS_MAP_VIEW_OF_SECTION] = {.name = "NtMapViewOfSection"},
[VMI_SYS_UNMAP_VIEW_OF_SECTION] = {.name = "NtUnmapViewOfSection"},


/**** process syscalls ****/
[VMI_SYS_CREATE_PROCESS] = {.name = "NtCreateProcess"},
[VMI_SYS_CREATE_PROCESS_EX] = {.name = "NtCreateProcessEx"},
[VMI_SYS_OPEN_PROCESS] = {.name = "NtOpenProcess"},
[VMI_SYS_TERMINATE_PROCESS] = {.name = "NtTerminateProcess"},
[VMI_SYS_OPEN_PROCESS_TOKEN] = {.name = "NtOpenProcessToken"},
[VMI_SYS_RESUME_PROCESS] = {.name = "NtResumeProcess"},
[VMI_SYS_SUSPEND_PROCESS] = {.name = "NtSuspendProcess"},
[VMI_SYS_CREATE_THREAD] = {.name = "NtCreateThread"},
[VMI_SYS_OPEN_THREAD] = {.name = "NtOpenThread"},
[VMI_SYS_OPEN_THREAD_TOKEN] = {.name = "NtOpenThreadToken"},
[VMI_SYS_RESUME_THREAD] = {.name = "NtResumeThread"},
[VMI_SYS_SUSPEND_THREAD] = {.name = "NtSuspendThread"},
[VMI_SYS_TERMINATE_THREAD] = {.name = "NtTerminateThread"},
[VMI_SYS_ALLOCATE_USER_PHYSICAL_PAGES] = {.name = "NtAllocateUserPhysicalPages"},
[VMI_SYS_ALLOCATE_VIRTUAL_MEMORY] = {.name = "NtAllocateVirtualMemory"},
[VMI_SYS_QUERY_INFO_PROCESS] = {.name = "NtQueryInformationProcess"},
[VMI_SYS_OPEN_SECTION] = {.name = "NtOpenSection"},
[VMI_SYS_DUPLICATE_OBJ] = {.name = "NtDuplicateObject"}
#elif defined(GUEST_OS_LINUX)
#ifndef TARGET_X86_64
[VMI_SYS_CLONE] = {.name = "Clone"},
[VMI_SYS_FORK] = {.name = "Fork"},
[VMI_SYS_MOUNT] = {.name = "Mount"},
[VMI_SYS_UMOUNT] = {.name = "Umount"},
[VMI_SYS_EXECVE] = {.name = "Execve"},
[VMI_SYS_EXIT_GROUP] = {.name = "ExitGroup"},
[VMI_SYS_MMAP] = {.name = "Mmap"},
[VMI_SYS_MMAP2] = {.name = "Mmap2"},
[VMI_SYS_GETPID] = {.name = "Getpid"},
[VMI_SYS_GETPPID] = {.name = "Getppid"},
#endif
[VMI_SYS_OPENAT] = {.name = "openat"},
#endif