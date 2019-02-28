/*
 * windbgkd.h
 *
 * Copyright (c) 2010-2019 Institute for System Programming
 *                         of the Russian Academy of Sciences.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef WINDBGKD_H
#define WINDBGKD_H

/*
 * Packet Size and Control Stream Size
 */
#define PACKET_MAX_SIZE                     4096
#define DBGKD_MAXSTREAM                     16

/*
 * Magic Packet IDs
 */
#define INITIAL_PACKET_ID                   0x80800000
#define SYNC_PACKET_ID                      0x00000800
#define RESET_PACKET_ID                     0x0018359b

/*
 * Magic Packet bytes
 */
#define BREAKIN_PACKET                      0x62626262
#define BREAKIN_PACKET_BYTE                 0x62
#define PACKET_LEADER                       0x30303030
#define PACKET_LEADER_BYTE                  0x30
#define CONTROL_PACKET_LEADER               0x69696969
#define CONTROL_PACKET_LEADER_BYTE          0x69
#define PACKET_TRAILING_BYTE                0xaa

/*
 * Packet Types
 */
#define PACKET_TYPE_UNUSED                  0
#define PACKET_TYPE_KD_STATE_CHANGE32       1
#define PACKET_TYPE_KD_STATE_MANIPULATE     2
#define PACKET_TYPE_KD_DEBUG_IO             3
#define PACKET_TYPE_KD_ACKNOWLEDGE          4
#define PACKET_TYPE_KD_RESEND               5
#define PACKET_TYPE_KD_RESET                6
#define PACKET_TYPE_KD_STATE_CHANGE64       7
#define PACKET_TYPE_KD_POLL_BREAKIN         8
#define PACKET_TYPE_KD_TRACE_IO             9
#define PACKET_TYPE_KD_CONTROL_REQUEST      10
#define PACKET_TYPE_KD_FILE_IO              11
#define PACKET_TYPE_MAX                     12

/*
 * Wait State Change Types
 */
#define DbgKdMinimumStateChange             0x00003030
#define DbgKdExceptionStateChange           0x00003030
#define DbgKdLoadSymbolsStateChange         0x00003031
#define DbgKdCommandStringStateChange       0x00003032
#define DbgKdMaximumStateChange             0x00003033

/*
 * This is combined with the basic state change code
 * if the state is from an alternate source
 */
#define DbgKdAlternateStateChange           0x00010000

/*
 * Manipulate Types
 */
#define DbgKdMinimumManipulate              0x00003130
#define DbgKdReadVirtualMemoryApi           0x00003130
#define DbgKdWriteVirtualMemoryApi          0x00003131
#define DbgKdGetContextApi                  0x00003132
#define DbgKdSetContextApi                  0x00003133
#define DbgKdWriteBreakPointApi             0x00003134
#define DbgKdRestoreBreakPointApi           0x00003135
#define DbgKdContinueApi                    0x00003136
#define DbgKdReadControlSpaceApi            0x00003137
#define DbgKdWriteControlSpaceApi           0x00003138
#define DbgKdReadIoSpaceApi                 0x00003139
#define DbgKdWriteIoSpaceApi                0x0000313a
#define DbgKdRebootApi                      0x0000313b
#define DbgKdContinueApi2                   0x0000313c
#define DbgKdReadPhysicalMemoryApi          0x0000313d
#define DbgKdWritePhysicalMemoryApi         0x0000313e
#define DbgKdQuerySpecialCallsApi           0x0000313f
#define DbgKdSetSpecialCallApi              0x00003140
#define DbgKdClearSpecialCallsApi           0x00003141
#define DbgKdSetInternalBreakPointApi       0x00003142
#define DbgKdGetInternalBreakPointApi       0x00003143
#define DbgKdReadIoSpaceExtendedApi         0x00003144
#define DbgKdWriteIoSpaceExtendedApi        0x00003145
#define DbgKdGetVersionApi                  0x00003146
#define DbgKdWriteBreakPointExApi           0x00003147
#define DbgKdRestoreBreakPointExApi         0x00003148
#define DbgKdCauseBugCheckApi               0x00003149
#define DbgKdSwitchProcessor                0x00003150
#define DbgKdPageInApi                      0x00003151
#define DbgKdReadMachineSpecificRegister    0x00003152
#define DbgKdWriteMachineSpecificRegister   0x00003153
#define OldVlm1                             0x00003154
#define OldVlm2                             0x00003155
#define DbgKdSearchMemoryApi                0x00003156
#define DbgKdGetBusDataApi                  0x00003157
#define DbgKdSetBusDataApi                  0x00003158
#define DbgKdCheckLowMemoryApi              0x00003159
#define DbgKdClearAllInternalBreakpointsApi 0x0000315a
#define DbgKdFillMemoryApi                  0x0000315b
#define DbgKdQueryMemoryApi                 0x0000315c
#define DbgKdSwitchPartition                0x0000315d
#define DbgKdWriteCustomBreakpointApi       0x0000315e
#define DbgKdGetContextExApi                0x0000315f
#define DbgKdSetContextExApi                0x00003160
#define DbgKdMaximumManipulate              0x00003161

/*
 * Debug I/O Types
 */
#define DbgKdPrintStringApi                 0x00003230
#define DbgKdGetStringApi                   0x00003231

/*
 * Trace I/O Types
 */
#define DbgKdPrintTraceApi                  0x00003330

/*
 * Control Request Types
 */
#define DbgKdRequestHardwareBp              0x00004300
#define DbgKdReleaseHardwareBp              0x00004301

/*
 * File I/O Types
 */
#define DbgKdCreateFileApi                  0x00003430
#define DbgKdReadFileApi                    0x00003431
#define DbgKdWriteFileApi                   0x00003432
#define DbgKdCloseFileApi                   0x00003433

/*
 * Control Report Flags
 */
#define REPORT_INCLUDES_SEGS                0x0001
#define REPORT_STANDARD_CS                  0x0002

/*
 * Protocol Versions
 */
#define DBGKD_64BIT_PROTOCOL_VERSION1       5
#define DBGKD_64BIT_PROTOCOL_VERSION2       6

/*
 * Query Memory Address Spaces
 */
#define DBGKD_QUERY_MEMORY_VIRTUAL          0
#define DBGKD_QUERY_MEMORY_PROCESS          0
#define DBGKD_QUERY_MEMORY_SESSION          1
#define DBGKD_QUERY_MEMORY_KERNEL           2

/*
 * Query Memory Flags
 */
#define DBGKD_QUERY_MEMORY_READ             0x01
#define DBGKD_QUERY_MEMORY_WRITE            0x02
#define DBGKD_QUERY_MEMORY_EXECUTE          0x04
#define DBGKD_QUERY_MEMORY_FIXED            0x08

/*
 * Internal Breakpoint Flags
 */
#define DBGKD_INTERNAL_BP_FLAG_COUNTONLY    0x01
#define DBGKD_INTERNAL_BP_FLAG_INVALID      0x02
#define DBGKD_INTERNAL_BP_FLAG_SUSPENDED    0x04
#define DBGKD_INTERNAL_BP_FLAG_DYING        0x08

/*
 * Fill Memory Flags
 */
#define DBGKD_FILL_MEMORY_VIRTUAL           0x01
#define DBGKD_FILL_MEMORY_PHYSICAL          0x02

/*
 * Physical Memory Caching Flags
 */
#define DBGKD_CACHING_DEFAULT               0
#define DBGKD_CACHING_CACHED                1
#define DBGKD_CACHING_UNCACHED              2
#define DBGKD_CACHING_WRITE_COMBINED        3

/*
 * Partition Switch Flags
 */
#define DBGKD_PARTITION_DEFAULT             0x00
#define DBGKD_PARTITION_ALTERNATE           0x01

/*
 * AMD64 Control Space types
 */
#define AMD64_DEBUG_CONTROL_SPACE_KPCR      0
#define AMD64_DEBUG_CONTROL_SPACE_KPRCB     1
#define AMD64_DEBUG_CONTROL_SPACE_KSPECIAL  2
#define AMD64_DEBUG_CONTROL_SPACE_KTHREAD   3

/*
 * Version flags
 */
#define DBGKD_VERS_FLAG_MP                  0x0001
#define DBGKD_VERS_FLAG_DATA                0x0002
#define DBGKD_VERS_FLAG_PTR64               0x0004
#define DBGKD_VERS_FLAG_NOMM                0x0008
#define DBGKD_VERS_FLAG_HSS                 0x0010
#define DBGKD_VERS_FLAG_PARTITIONS          0x0020

/*
 * Image architectures
 */
#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64            0x8664
#endif
#ifndef IMAGE_FILE_MACHINE_ARM
#define IMAGE_FILE_MACHINE_ARM              0x1c0
#endif
#ifndef IMAGE_FILE_MACHINE_EBC
#define IMAGE_FILE_MACHINE_EBC              0xebc
#endif
#ifndef IMAGE_FILE_MACHINE_I386
#define IMAGE_FILE_MACHINE_I386             0x14c
#endif
#ifndef IMAGE_FILE_MACHINE_IA64
#define IMAGE_FILE_MACHINE_IA64             0x200
#endif

/*
 * DBGKD_GET_VERSION64.Simulation
 */
enum {
    DBGKD_SIMULATION_NONE,
    DBGKD_SIMULATION_EXDI
};

/*
 * Maximum supported number of breakpoints
 */
#define KD_BREAKPOINT_MAX 32

typedef uint8_t boolean_t;
typedef int32_t ntstatus_t;

/*
 * NTSTATUS
 */
#define NT_STATUS(status)  ((ntstatus_t) (status))
#define NT_SUCCESS(status) (NT_STATUS(status) >= 0)

#define NT_STATUS_SUCCESS                  NT_STATUS(0x00000000)
#define NT_STATUS_NO_MORE_ENTRIES          NT_STATUS(0x8000001A)
#define NT_STATUS_UNSUCCESSFUL             NT_STATUS(0xC0000001)
#define NT_STATUS_INVALID_PARAMETER        NT_STATUS(0xC000000D)
#define NT_STATUS_INTEGER_DIVIDE_BY_ZERO   NT_STATUS(0xC0000094)
#define NT_STATUS_BREAKPOINT               NT_STATUS(0x80000003)
#define NT_STATUS_STACK_OVERFLOW           NT_STATUS(0xC00000FD)
#define NT_STATUS_ARRAY_BOUNDS_EXCEEDED    NT_STATUS(0xC000008C)
#define NT_STATUS_ILLEGAL_INSTRUCTION      NT_STATUS(0xC000001D)

/*
 * KD Packet Structure
 */
typedef struct _KD_PACKET {
    uint32_t PacketLeader;
    uint16_t PacketType;
    uint16_t ByteCount;
    uint32_t PacketId;
    uint32_t Checksum;
} QEMU_PACKED KD_PACKET, *PKD_PACKET;

/*
 * KD Context
 */
typedef struct _KD_CONTEXT {
    uint32_t KdpDefaultRetries;
    boolean_t KdpControlCPending;
} KD_CONTEXT, *PKD_CONTEXT;

/*
 * Control Sets for Supported Architectures
 */
typedef struct _X86_DBGKD_CONTROL_SET {
    uint32_t TraceFlag;
    uint32_t Dr7;
    uint32_t CurrentSymbolStart;
    uint32_t CurrentSymbolEnd;
} X86_DBGKD_CONTROL_SET, *PX86_DBGKD_CONTROL_SET;

typedef struct _ALPHA_DBGKD_CONTROL_SET {
    uint32_t __padding;
} ALPHA_DBGKD_CONTROL_SET, *PALPHA_DBGKD_CONTROL_SET;

typedef struct _IA64_DBGKD_CONTROL_SET {
    uint32_t Continue;
    uint64_t CurrentSymbolStart;
    uint64_t CurrentSymbolEnd;
} IA64_DBGKD_CONTROL_SET, *PIA64_DBGKD_CONTROL_SET;

typedef struct _AMD64_DBGKD_CONTROL_SET {
    uint32_t TraceFlag;
    uint64_t Dr7;
    uint64_t CurrentSymbolStart;
    uint64_t CurrentSymbolEnd;
} AMD64_DBGKD_CONTROL_SET, *PAMD64_DBGKD_CONTROL_SET;

typedef struct _ARM_DBGKD_CONTROL_SET {
    uint32_t Continue;
    uint32_t CurrentSymbolStart;
    uint32_t CurrentSymbolEnd;
} ARM_DBGKD_CONTROL_SET, *PARM_DBGKD_CONTROL_SET;

typedef struct _DBGKD_ANY_CONTROL_SET {
    union {
        X86_DBGKD_CONTROL_SET X86ControlSet;
        ALPHA_DBGKD_CONTROL_SET AlphaControlSet;
        IA64_DBGKD_CONTROL_SET IA64ControlSet;
        AMD64_DBGKD_CONTROL_SET Amd64ControlSet;
        ARM_DBGKD_CONTROL_SET ARMControlSet;
    };
} DBGKD_ANY_CONTROL_SET, *PDBGKD_ANY_CONTROL_SET;

#if defined(TARGET_I386)
typedef X86_DBGKD_CONTROL_SET DBGKD_CONTROL_SET, *PDBGKD_CONTROL_SET;
#elif defined(TARGET_X86_64)
typedef AMD64_DBGKD_CONTROL_SET DBGKD_CONTROL_SET, *PDBGKD_CONTROL_SET;
#elif defined(TARGET_ARM)
typedef ARM_DBGKD_CONTROL_SET DBGKD_CONTROL_SET, *PDBGKD_CONTROL_SET;
#else
#error Unsupported Architecture
#endif

/*
 * EXCEPTION_RECORD Structures
 */
typedef struct _DBGKM_EXCEPTION_RECORD32 {
    int32_t ExceptionCode;
    uint32_t ExceptionFlags;
    uint32_t ExceptionRecord;
    uint32_t ExceptionAddress;
    uint32_t NumberParameters;
    uint32_t ExceptionInformation[15];
} DBGKM_EXCEPTION_RECORD32, *PDBGKM_EXCEPTION_RECORD32;

typedef struct _DBGKM_EXCEPTION_RECORD64 {
    int32_t ExceptionCode;
    uint32_t ExceptionFlags;
    uint64_t ExceptionRecord;
    uint64_t ExceptionAddress;
    uint32_t NumberParameters;
    uint32_t __unusedAligment;
    uint64_t ExceptionInformation[15];
} DBGKM_EXCEPTION_RECORD64, *PDBGKM_EXCEPTION_RECORD64;

/*
 * DBGKM Structure for Exceptions
 */
typedef struct _DBGKM_EXCEPTION32 {
    DBGKM_EXCEPTION_RECORD32 ExceptionRecord;
    uint32_t FirstChance;
} DBGKM_EXCEPTION32, *PDBGKM_EXCEPTION32;

typedef struct _DBGKM_EXCEPTION64 {
    DBGKM_EXCEPTION_RECORD64 ExceptionRecord;
    uint32_t FirstChance;
} DBGKM_EXCEPTION64, *PDBGKM_EXCEPTION64;

/*
 * DBGKD Structure for State Change
 */
typedef struct _X86_DBGKD_CONTROL_REPORT {
    uint32_t   Dr6;
    uint32_t   Dr7;
    uint16_t  InstructionCount;
    uint16_t  ReportFlags;
    uint8_t   InstructionStream[DBGKD_MAXSTREAM];
    uint16_t  SegCs;
    uint16_t  SegDs;
    uint16_t  SegEs;
    uint16_t  SegFs;
    uint32_t   EFlags;
} X86_DBGKD_CONTROL_REPORT, *PX86_DBGKD_CONTROL_REPORT;

typedef struct _ALPHA_DBGKD_CONTROL_REPORT {
    uint32_t InstructionCount;
    uint8_t InstructionStream[DBGKD_MAXSTREAM];
} ALPHA_DBGKD_CONTROL_REPORT, *PALPHA_DBGKD_CONTROL_REPORT;

typedef struct _IA64_DBGKD_CONTROL_REPORT {
    uint32_t InstructionCount;
    uint8_t InstructionStream[DBGKD_MAXSTREAM];
} IA64_DBGKD_CONTROL_REPORT, *PIA64_DBGKD_CONTROL_REPORT;

typedef struct _AMD64_DBGKD_CONTROL_REPORT {
    uint64_t Dr6;
    uint64_t Dr7;
    uint32_t EFlags;
    uint16_t InstructionCount;
    uint16_t ReportFlags;
    uint8_t InstructionStream[DBGKD_MAXSTREAM];
    uint16_t SegCs;
    uint16_t SegDs;
    uint16_t SegEs;
    uint16_t SegFs;
} AMD64_DBGKD_CONTROL_REPORT, *PAMD64_DBGKD_CONTROL_REPORT;

typedef struct _ARM_DBGKD_CONTROL_REPORT {
    uint32_t Cpsr;
    uint32_t InstructionCount;
    uint8_t InstructionStream[DBGKD_MAXSTREAM];
} ARM_DBGKD_CONTROL_REPORT, *PARM_DBGKD_CONTROL_REPORT;

typedef struct _DBGKD_ANY_CONTROL_REPORT {
    union {
        X86_DBGKD_CONTROL_REPORT X86ControlReport;
        ALPHA_DBGKD_CONTROL_REPORT AlphaControlReport;
        IA64_DBGKD_CONTROL_REPORT IA64ControlReport;
        AMD64_DBGKD_CONTROL_REPORT Amd64ControlReport;
        ARM_DBGKD_CONTROL_REPORT ARMControlReport;
    };
} DBGKD_ANY_CONTROL_REPORT, *PDBGKD_ANY_CONTROL_REPORT;

#if defined(TARGET_I386)
typedef X86_DBGKD_CONTROL_REPORT DBGKD_CONTROL_REPORT, *PDBGKD_CONTROL_REPORT;
#elif defined(TARGET_X86_64)
typedef AMD64_DBGKD_CONTROL_REPORT DBGKD_CONTROL_REPORT, *PDBGKD_CONTROL_REPORT;
#elif defined(TARGET_ARM)
typedef ARM_DBGKD_CONTROL_REPORT DBGKD_CONTROL_REPORT, *PDBGKD_CONTROL_REPORT;
#else
#error Unsupported Architecture
#endif

/*
 * DBGKD Structure for Debug I/O Type Print String
 */
typedef struct _DBGKD_PRINT_STRING {
    uint32_t LengthOfString;
} DBGKD_PRINT_STRING, *PDBGKD_PRINT_STRING;

/*
 * DBGKD Structure for Debug I/O Type Get String
 */
typedef struct _DBGKD_GET_STRING {
    uint32_t LengthOfPromptString;
    uint32_t LengthOfStringRead;
} DBGKD_GET_STRING, *PDBGKD_GET_STRING;

/*
 * DBGKD Structure for Debug I/O
 */
typedef struct _DBGKD_DEBUG_IO {
    uint32_t ApiNumber;
    uint16_t ProcessorLevel;
    uint16_t Processor;
    union {
        DBGKD_PRINT_STRING PrintString;
        DBGKD_GET_STRING GetString;
    } u;
} DBGKD_DEBUG_IO, *PDBGKD_DEBUG_IO;

/*
 * DBGkD Structure for Command String
 */
typedef struct _DBGKD_COMMAND_STRING {
    uint32_t Flags;
    uint32_t Reserved1;
    uint64_t Reserved2[7];
} DBGKD_COMMAND_STRING, *PDBGKD_COMMAND_STRING;

/*
 * DBGKD Structure for Load Symbols
 */
typedef struct _DBGKD_LOAD_SYMBOLS32 {
    uint32_t PathNameLength;
    uint32_t BaseOfDll;
    uint32_t ProcessId;
    uint32_t CheckSum;
    uint32_t SizeOfImage;
    boolean_t UnloadSymbols;
} DBGKD_LOAD_SYMBOLS32, *PDBGKD_LOAD_SYMBOLS32;

typedef struct _DBGKD_LOAD_SYMBOLS64 {
    uint32_t PathNameLength;
    uint64_t BaseOfDll;
    uint64_t ProcessId;
    uint32_t CheckSum;
    uint32_t SizeOfImage;
    boolean_t UnloadSymbols;
} DBGKD_LOAD_SYMBOLS64, *PDBGKD_LOAD_SYMBOLS64;

/*
 * DBGKD Structure for Wait State Change
 */
typedef struct _DBGKD_WAIT_STATE_CHANGE32 {
    uint32_t NewState;
    uint16_t ProcessorLevel;
    uint16_t Processor;
    uint32_t NumberProcessors;
    uint32_t Thread;
    uint32_t ProgramCounter;
    union {
        DBGKM_EXCEPTION32 Exception;
        DBGKD_LOAD_SYMBOLS32 LoadSymbols;
    } u;
} DBGKD_WAIT_STATE_CHANGE32, *PDBGKD_WAIT_STATE_CHANGE32;

typedef struct _DBGKD_WAIT_STATE_CHANGE64 {
    uint32_t NewState;
    uint16_t ProcessorLevel;
    uint16_t Processor;
    uint32_t NumberProcessors;
    uint64_t Thread;
    uint64_t ProgramCounter;
    union {
        DBGKM_EXCEPTION64 Exception;
        DBGKD_LOAD_SYMBOLS64 LoadSymbols;
    } u;
} DBGKD_WAIT_STATE_CHANGE64, *PDBGKD_WAIT_STATE_CHANGE64;

typedef struct _DBGKD_ANY_WAIT_STATE_CHANGE {
    uint32_t NewState;
    uint16_t ProcessorLevel;
    uint16_t Processor;
    uint32_t NumberProcessors;
    uint64_t Thread;
    uint64_t ProgramCounter;
    union {
        DBGKM_EXCEPTION64 Exception;
        DBGKD_LOAD_SYMBOLS64 LoadSymbols;
        DBGKD_COMMAND_STRING CommandString;
    } u;
    union {
        DBGKD_CONTROL_REPORT ControlReport;
        DBGKD_ANY_CONTROL_REPORT AnyControlReport;
    };
} DBGKD_ANY_WAIT_STATE_CHANGE, *PDBGKD_ANY_WAIT_STATE_CHANGE;

/*
 * DBGKD Manipulate Structures
 */
typedef struct _DBGKD_READ_MEMORY32 {
    uint32_t TargetBaseAddress;
    uint32_t TransferCount;
    uint32_t ActualBytesRead;
} DBGKD_READ_MEMORY32, *PDBGKD_READ_MEMORY32;

typedef struct _DBGKD_READ_MEMORY64 {
    uint64_t TargetBaseAddress;
    uint32_t TransferCount;
    uint32_t ActualBytesRead;
} DBGKD_READ_MEMORY64, *PDBGKD_READ_MEMORY64;

typedef struct _DBGKD_WRITE_MEMORY32 {
    uint32_t TargetBaseAddress;
    uint32_t TransferCount;
    uint32_t ActualBytesWritten;
} DBGKD_WRITE_MEMORY32, *PDBGKD_WRITE_MEMORY32;

typedef struct _DBGKD_WRITE_MEMORY64 {
    uint64_t TargetBaseAddress;
    uint32_t TransferCount;
    uint32_t ActualBytesWritten;
} DBGKD_WRITE_MEMORY64, *PDBGKD_WRITE_MEMORY64;

typedef struct _DBGKD_GET_CONTEXT {
    uint32_t Unused;
} DBGKD_GET_CONTEXT, *PDBGKD_GET_CONTEXT;

typedef struct _DBGKD_SET_CONTEXT {
    uint32_t ContextFlags;
} DBGKD_SET_CONTEXT, *PDBGKD_SET_CONTEXT;

typedef struct _DBGKD_WRITE_BREAKPOINT32 {
    uint32_t BreakPointAddress;
    uint32_t BreakPointHandle;
} DBGKD_WRITE_BREAKPOINT32, *PDBGKD_WRITE_BREAKPOINT32;

typedef struct _DBGKD_WRITE_BREAKPOINT64 {
    uint64_t BreakPointAddress;
    uint32_t BreakPointHandle;
} DBGKD_WRITE_BREAKPOINT64, *PDBGKD_WRITE_BREAKPOINT64;

typedef struct _DBGKD_RESTORE_BREAKPOINT {
    uint32_t BreakPointHandle;
} DBGKD_RESTORE_BREAKPOINT, *PDBGKD_RESTORE_BREAKPOINT;

typedef struct _DBGKD_CONTINUE {
    ntstatus_t ContinueStatus;
} DBGKD_CONTINUE, *PDBGKD_CONTINUE;

#pragma pack(push, 4)
typedef struct _DBGKD_CONTINUE2 {
    ntstatus_t ContinueStatus;
    union {
        DBGKD_CONTROL_SET ControlSet;
        DBGKD_ANY_CONTROL_SET AnyControlSet;
    };
} DBGKD_CONTINUE2, *PDBGKD_CONTINUE2;
#pragma pack(pop)

typedef struct _DBGKD_READ_WRITE_IO32 {
    uint32_t IoAddress;
    uint32_t DataSize;
    uint32_t DataValue;
} DBGKD_READ_WRITE_IO32, *PDBGKD_READ_WRITE_IO32;

typedef struct _DBGKD_READ_WRITE_IO64 {
    uint64_t IoAddress;
    uint32_t DataSize;
    uint32_t DataValue;
} DBGKD_READ_WRITE_IO64, *PDBGKD_READ_WRITE_IO64;

typedef struct _DBGKD_READ_WRITE_IO_EXTENDED32 {
    uint32_t DataSize;
    uint32_t InterfaceType;
    uint32_t BusNumber;
    uint32_t AddressSpace;
    uint32_t IoAddress;
    uint32_t DataValue;
} DBGKD_READ_WRITE_IO_EXTENDED32, *PDBGKD_READ_WRITE_IO_EXTENDED32;

typedef struct _DBGKD_READ_WRITE_IO_EXTENDED64 {
    uint32_t DataSize;
    uint32_t InterfaceType;
    uint32_t BusNumber;
    uint32_t AddressSpace;
    uint64_t IoAddress;
    uint32_t DataValue;
} DBGKD_READ_WRITE_IO_EXTENDED64, *PDBGKD_READ_WRITE_IO_EXTENDED64;

typedef struct _DBGKD_READ_WRITE_MSR {
    uint32_t Msr;
    uint32_t DataValueLow;
    uint32_t DataValueHigh;
} DBGKD_READ_WRITE_MSR, *PDBGKD_READ_WRITE_MSR;

typedef struct _DBGKD_QUERY_SPECIAL_CALLS {
    uint32_t NumberOfSpecialCalls;
} DBGKD_QUERY_SPECIAL_CALLS, *PDBGKD_QUERY_SPECIAL_CALLS;

typedef struct _DBGKD_SET_SPECIAL_CALL32 {
    uint32_t SpecialCall;
} DBGKD_SET_SPECIAL_CALL32, *PDBGKD_SET_SPECIAL_CALL32;

typedef struct _DBGKD_SET_SPECIAL_CALL64 {
    uint64_t SpecialCall;
} DBGKD_SET_SPECIAL_CALL64, *PDBGKD_SET_SPECIAL_CALL64;

typedef struct _DBGKD_SET_INTERNAL_BREAKPOINT32 {
    uint32_t BreakpointAddress;
    uint32_t Flags;
} DBGKD_SET_INTERNAL_BREAKPOINT32, *PDBGKD_SET_INTERNAL_BREAKPOINT32;

typedef struct _DBGKD_SET_INTERNAL_BREAKPOINT64 {
    uint64_t BreakpointAddress;
    uint32_t Flags;
} DBGKD_SET_INTERNAL_BREAKPOINT64, *PDBGKD_SET_INTERNAL_BREAKPOINT64;

typedef struct _DBGKD_GET_INTERNAL_BREAKPOINT32 {
    uint32_t BreakpointAddress;
    uint32_t Flags;
    uint32_t Calls;
    uint32_t MaxCallsPerPeriod;
    uint32_t MinInstructions;
    uint32_t MaxInstructions;
    uint32_t TotalInstructions;
} DBGKD_GET_INTERNAL_BREAKPOINT32, *PDBGKD_GET_INTERNAL_BREAKPOINT32;

typedef struct _DBGKD_GET_INTERNAL_BREAKPOINT64 {
    uint64_t BreakpointAddress;
    uint32_t Flags;
    uint32_t Calls;
    uint32_t MaxCallsPerPeriod;
    uint32_t MinInstructions;
    uint32_t MaxInstructions;
    uint32_t TotalInstructions;
} DBGKD_GET_INTERNAL_BREAKPOINT64, *PDBGKD_GET_INTERNAL_BREAKPOINT64;

typedef struct _DBGKD_GET_VERSION32 {
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t ProtocolVersion;
    uint16_t Flags;
    uint32_t KernBase;
    uint32_t PsLoadedModuleList;
    uint16_t MachineType;
    uint16_t ThCallbackStack;
    uint16_t NextCallback;
    uint16_t FramePointer;
    uint32_t KiCallUserMode;
    uint32_t KeUserCallbackDispatcher;
    uint32_t BreakpointWithStatus;
    uint32_t DebuggerDataList;
} DBGKD_GET_VERSION32, *PDBGKD_GET_VERSION32;

typedef struct _DBGKD_GET_VERSION64 {
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint8_t ProtocolVersion;
    uint8_t KdSecondaryVersion;
    uint16_t Flags;
    uint16_t MachineType;
    uint8_t MaxPacketType;
    uint8_t MaxStateChange;
    uint8_t MaxManipulate;
    uint8_t Simulation;
    uint16_t Unused[1];
    uint64_t KernBase;
    uint64_t PsLoadedModuleList;
    uint64_t DebuggerDataList;
} DBGKD_GET_VERSION64, *PDBGKD_GET_VERSION64;

typedef struct _DBGKD_BREAKPOINTEX {
    uint32_t BreakPointCount;
    ntstatus_t ContinueStatus;
} DBGKD_BREAKPOINTEX, *PDBGKD_BREAKPOINTEX;

typedef struct _DBGKD_SEARCH_MEMORY {
    union {
        uint64_t SearchAddress;
        uint64_t FoundAddress;
    };
    uint64_t SearchLength;
    uint32_t PatternLength;
} DBGKD_SEARCH_MEMORY, *PDBGKD_SEARCH_MEMORY;

typedef struct _DBGKD_GET_SET_BUS_DATA {
    uint32_t BusDataType;
    uint32_t BusNumber;
    uint32_t SlotNumber;
    uint32_t Offset;
    uint32_t Length;
} DBGKD_GET_SET_BUS_DATA, *PDBGKD_GET_SET_BUS_DATA;

typedef struct _DBGKD_FILL_MEMORY {
    uint64_t Address;
    uint32_t Length;
    uint16_t Flags;
    uint16_t PatternLength;
} DBGKD_FILL_MEMORY, *PDBGKD_FILL_MEMORY;

typedef struct _DBGKD_QUERY_MEMORY {
    uint64_t Address;
    uint64_t Reserved;
    uint32_t AddressSpace;
    uint32_t Flags;
} DBGKD_QUERY_MEMORY, *PDBGKD_QUERY_MEMORY;

typedef struct _DBGKD_SWITCH_PARTITION {
    uint32_t Partition;
} DBGKD_SWITCH_PARTITION;

typedef struct _DBGKD_CONTEXT_EX {
   uint32_t Offset;
   uint32_t ByteCount;
   uint32_t BytesCopied;
} DBGKD_CONTEXT_EX, *PDBGKD_CONTEXT_EX;

typedef struct _DBGKD_WRITE_CUSTOM_BREAKPOINT {
   uint64_t BreakPointAddress;
   uint64_t BreakPointInstruction;
   uint32_t BreakPointHandle;
   uint16_t BreakPointInstructionSize;
   uint16_t BreakPointInstructionAlignment;
} DBGKD_WRITE_CUSTOM_BREAKPOINT, *PDBGKD_WRITE_CUSTOM_BREAKPOINT;

/*
 * DBGKD Structure for Manipulate
 */
typedef struct _DBGKD_MANIPULATE_STATE32 {
    uint32_t ApiNumber;
    uint16_t ProcessorLevel;
    uint16_t Processor;
    ntstatus_t ReturnStatus;
    union {
        DBGKD_READ_MEMORY32 ReadMemory;
        DBGKD_WRITE_MEMORY32 WriteMemory;
        DBGKD_READ_MEMORY64 ReadMemory64;
        DBGKD_WRITE_MEMORY64 WriteMemory64;
        DBGKD_GET_CONTEXT GetContext;
        DBGKD_SET_CONTEXT SetContext;
        DBGKD_WRITE_BREAKPOINT32 WriteBreakPoint;
        DBGKD_RESTORE_BREAKPOINT RestoreBreakPoint;
        DBGKD_CONTINUE Continue;
        DBGKD_CONTINUE2 Continue2;
        DBGKD_READ_WRITE_IO32 ReadWriteIo;
        DBGKD_READ_WRITE_IO_EXTENDED32 ReadWriteIoExtended;
        DBGKD_QUERY_SPECIAL_CALLS QuerySpecialCalls;
        DBGKD_SET_SPECIAL_CALL32 SetSpecialCall;
        DBGKD_SET_INTERNAL_BREAKPOINT32 SetInternalBreakpoint;
        DBGKD_GET_INTERNAL_BREAKPOINT32 GetInternalBreakpoint;
        DBGKD_GET_VERSION32 GetVersion32;
        DBGKD_BREAKPOINTEX BreakPointEx;
        DBGKD_READ_WRITE_MSR ReadWriteMsr;
        DBGKD_SEARCH_MEMORY SearchMemory;
        DBGKD_GET_SET_BUS_DATA GetSetBusData;
        DBGKD_FILL_MEMORY FillMemory;
        DBGKD_QUERY_MEMORY QueryMemory;
        DBGKD_SWITCH_PARTITION SwitchPartition;
    } u;
} DBGKD_MANIPULATE_STATE32, *PDBGKD_MANIPULATE_STATE32;

typedef struct _DBGKD_MANIPULATE_STATE64 {
    uint32_t ApiNumber;
    uint16_t ProcessorLevel;
    uint16_t Processor;
    ntstatus_t ReturnStatus;
    union {
        DBGKD_READ_MEMORY64 ReadMemory;
        DBGKD_WRITE_MEMORY64 WriteMemory;
        DBGKD_GET_CONTEXT GetContext;
        DBGKD_SET_CONTEXT SetContext;
        DBGKD_WRITE_BREAKPOINT64 WriteBreakPoint;
        DBGKD_RESTORE_BREAKPOINT RestoreBreakPoint;
        DBGKD_CONTINUE Continue;
        DBGKD_CONTINUE2 Continue2;
        DBGKD_READ_WRITE_IO64 ReadWriteIo;
        DBGKD_READ_WRITE_IO_EXTENDED64 ReadWriteIoExtended;
        DBGKD_QUERY_SPECIAL_CALLS QuerySpecialCalls;
        DBGKD_SET_SPECIAL_CALL64 SetSpecialCall;
        DBGKD_SET_INTERNAL_BREAKPOINT64 SetInternalBreakpoint;
        DBGKD_GET_INTERNAL_BREAKPOINT64 GetInternalBreakpoint;
        DBGKD_GET_VERSION64 GetVersion64;
        DBGKD_BREAKPOINTEX BreakPointEx;
        DBGKD_READ_WRITE_MSR ReadWriteMsr;
        DBGKD_SEARCH_MEMORY SearchMemory;
        DBGKD_GET_SET_BUS_DATA GetSetBusData;
        DBGKD_FILL_MEMORY FillMemory;
        DBGKD_QUERY_MEMORY QueryMemory;
        DBGKD_SWITCH_PARTITION SwitchPartition;
        DBGKD_WRITE_CUSTOM_BREAKPOINT WriteCustomBreakpoint;
        DBGKD_CONTEXT_EX ContextEx;
    } u;
} DBGKD_MANIPULATE_STATE64, *PDBGKD_MANIPULATE_STATE64;

/*
 * File I/O Structure
 */
typedef struct _DBGKD_CREATE_FILE {
    uint32_t DesiredAccess;
    uint32_t FileAttributes;
    uint32_t ShareAccess;
    uint32_t CreateDisposition;
    uint32_t CreateOptions;
    uint64_t Handle;
    uint64_t Length;
} DBGKD_CREATE_FILE, *PDBGKD_CREATE_FILE;

typedef struct _DBGKD_READ_FILE {
    uint64_t Handle;
    uint64_t Offset;
    uint32_t Length;
} DBGKD_READ_FILE, *PDBGKD_READ_FILE;

typedef struct _DBGKD_WRITE_FILE {
    uint64_t Handle;
    uint64_t Offset;
    uint32_t Length;
} DBGKD_WRITE_FILE, *PDBGKD_WRITE_FILE;

typedef struct _DBGKD_CLOSE_FILE {
    uint64_t Handle;
} DBGKD_CLOSE_FILE, *PDBGKD_CLOSE_FILE;

typedef struct _DBGKD_FILE_IO {
    uint32_t ApiNumber;
    uint32_t Status;
    union {
        uint64_t ReserveSpace[7];
        DBGKD_CREATE_FILE CreateFile;
        DBGKD_READ_FILE ReadFile;
        DBGKD_WRITE_FILE WriteFile;
        DBGKD_CLOSE_FILE CloseFile;
    } u;
} DBGKD_FILE_IO, *PDBGKD_FILE_IO;

/*
 * Control Request Structure
 */
typedef struct _DBGKD_REQUEST_BREAKPOINT {
    uint32_t HardwareBreakPointNumber;
    uint32_t Available;
} DBGKD_REQUEST_BREAKPOINT, *PDBGKD_REQUEST_BREAKPOINT;

typedef struct _DBGKD_RELEASE_BREAKPOINT {
    uint32_t HardwareBreakPointNumber;
    uint32_t Released;
} DBGKD_RELEASE_BREAKPOINT, *PDBGKD_RELEASE_BREAKPOINT;

typedef struct _DBGKD_CONTROL_REQUEST {
    uint32_t ApiNumber;
    union {
        DBGKD_REQUEST_BREAKPOINT RequestBreakpoint;
        DBGKD_RELEASE_BREAKPOINT ReleaseBreakpoint;
    } u;
} DBGKD_CONTROL_REQUEST, *PDBGKD_CONTROL_REQUEST;

/*
 * Trace I/O Structure
 */
typedef struct _DBGKD_PRINT_TRACE {
    uint32_t LengthOfData;
} DBGKD_PRINT_TRACE, *PDBGKD_PRINT_TRACE;

typedef struct _DBGKD_TRACE_IO {
   uint32_t ApiNumber;
   uint16_t ProcessorLevel;
   uint16_t Processor;
   union {
       uint64_t ReserveSpace[7];
       DBGKD_PRINT_TRACE PrintTrace;
   } u;
} DBGKD_TRACE_IO, *PDBGKD_TRACE_IO;

#endif /* WINDBGKD_H */
