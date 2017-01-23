#ifndef WINDBGSTUB_UTILS_H
#define WINDBGSTUB_UTILS_H

#include "qemu/osdep.h"
#include "cpu.h"
#include "sysemu/sysemu.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "exec/exec-all.h"
#include "exec/address-spaces.h"
#include "exec/windbgkd.h"

// FOR DEBUG

#define COUT(...) printf("" __VA_ARGS__)
#define COUT_LN(fmt, ...) COUT(fmt "\n", ##__VA_ARGS__)
#define COUT_COMMON(fmt, var) COUT_LN(#var " = [" fmt "]", var)
#define COUT_DEC(var) COUT_COMMON("%d", (uint32_t) var)
#define COUT_HEX(var) COUT_COMMON("0x%x", (uint32_t) var)
#define COUT_STRING(var) COUT_COMMON("%s", var)
#define COUT_SIZEOF(var) COUT_COMMON("%lld", sizeof(var))

#define COUT_STRUCT(var) COUT_ARRAY(&var, 1)
#define COUT_PSTRUCT(var) COUT_ARRAY(var, 1)
#define COUT_ARRAY(var, count) _COUT_STRUCT(var, sizeof(*(var)), count)

#define _COUT_STRUCT(var, size, count) {                           \
    COUT(#var " ");                                                \
    COUT_LN("[size: %d, count: %d]", (int) (size), (int) (count)); \
    _COUT_BLOCK(var, size * count);                                \
}

#define _COUT_BLOCK(ptr, size) {     \
    uint8_t *_p = (uint8_t *) (ptr); \
    uint32_t _s = (size);            \
                                     \
    int _i = 0;                      \
    for (; _i < _s; ++_i) {          \
        if (!(_i % 16) && _i) {      \
            COUT_LN();               \
        }                            \
        COUT("%02x ", _p[_i]);       \
    }                                \
    COUT_LN();                       \
}

// FOR DEBUG END

#define FMT_ADDR "addr 0x" TARGET_FMT_lx
#define FMT_ERR  "Error %d"

#define WINDBG_DEBUG_ON true
#if (WINDBG_DEBUG_ON)
#define WINDBG_DEBUG(...) COUT_LN("Debug: " __VA_ARGS__)
#define WINDBG_ERROR(...) COUT_LN("Error: " __VA_ARGS__); \
                          error_report("WinDbg: " __VA_ARGS__)
#else
#define WINDBG_DEBUG(...)
#define WINDBG_ERROR(...) error_report("WinDbg: " __VA_ARGS__)
#endif

#define CAST_TO_PTR(type, var) ((type *) &(var))
#define PTR(var) CAST_TO_PTR(uint8_t, var)

#define UINT8(var, index) (CAST_TO_PTR(uint8_t, var)[index])
#define UINT32(var, index) (CAST_TO_PTR(uint32_t, var)[index])

#define M64_SIZE sizeof(DBGKD_MANIPULATE_STATE64)

//
// Structure for DbgKdExceptionStateChange
//
#pragma pack(push, 1)
typedef struct _EXCEPTION_STATE_CHANGE {
    DBGKD_ANY_WAIT_STATE_CHANGE StateChange;
    uint32_t value;
} EXCEPTION_STATE_CHANGE, *PEXCEPTION_STATE_CHANGE;
#pragma pack(pop)

typedef struct _CPU_CTRL_ADDRS {
    target_ulong KPCR;
    target_ulong KPRCB;
    target_ulong Version;
    target_ulong KernelBase;
} CPU_CTRL_ADDRS, *PCPU_CTRL_ADDRS;

#if defined(TARGET_I386)

#define SIZE_OF_X86_REG 80
#define MAX_SUP_EXT 512

typedef struct _CPU_DESCRIPTOR {
    uint16_t Pad;
    uint16_t Limit;
    uint32_t Base;
} CPU_DESCRIPTOR, *PCPU_DESCRIPTOR;

typedef struct _CPU_KSPECIAL_REGISTERS {
    uint32_t Cr0;
    uint32_t Cr2;
    uint32_t Cr3;
    uint32_t Cr4;
    uint32_t KernelDr0;
    uint32_t KernelDr1;
    uint32_t KernelDr2;
    uint32_t KernelDr3;
    uint32_t KernelDr6;
    uint32_t KernelDr7;
    CPU_DESCRIPTOR Gdtr;
    CPU_DESCRIPTOR Idtr;
    uint16_t Tr;
    uint16_t Ldtr;
    uint32_t Reserved[6];
} CPU_KSPECIAL_REGISTERS, *PCPU_KSPECIAL_REGISTERS;

typedef struct _CPU_FLOATING_SAVE_AREA {
    uint32_t ControlWord;
    uint32_t StatusWord;
    uint32_t TagWord;
    uint32_t ErrorOffset;
    uint32_t ErrorSelector;
    uint32_t DataOffset;
    uint32_t DataSelector;
    uint8_t RegisterArea[SIZE_OF_X86_REG];
    uint32_t Cr0NpxState;
} CPU_FLOATING_SAVE_AREA, *PCPU_FLOATING_SAVE_AREA;

#define CPU_CONTEXT_i386 0x10000

#define CPU_CONTEXT_CONTROL (CPU_CONTEXT_i386 | 0x1)
#define CPU_CONTEXT_INTEGER (CPU_CONTEXT_i386 | 0x2)
#define CPU_CONTEXT_SEGMENTS (CPU_CONTEXT_i386 | 0x4)
#define CPU_CONTEXT_FLOATING_POINT (CPU_CONTEXT_i386 | 0x8)
#define CPU_CONTEXT_DEBUG_REGISTERS (CPU_CONTEXT_i386 | 0x10)
#define CPU_CONTEXT_EXTENDED_REGISTERS (CPU_CONTEXT_i386 | 0x20)

#define CPU_CONTEXT_FULL \
    (CPU_CONTEXT_CONTROL | CPU_CONTEXT_INTEGER | CPU_CONTEXT_SEGMENTS)
#define CPU_CONTEXT_ALL \
    (CPU_CONTEXT_FULL | CPU_CONTEXT_FLOATING_POINT | \
    CPU_CONTEXT_DEBUG_REGISTERS | CPU_CONTEXT_EXTENDED_REGISTERS)

typedef struct _CPU_CONTEXT {
    uint32_t ContextFlags;
    uint32_t Dr0;
    uint32_t Dr1;
    uint32_t Dr2;
    uint32_t Dr3;
    uint32_t Dr6;
    uint32_t Dr7;
    CPU_FLOATING_SAVE_AREA FloatSave;
    uint32_t SegGs;
    uint32_t SegFs;
    uint32_t SegEs;
    uint32_t SegDs;

    uint32_t Edi;
    uint32_t Esi;
    uint32_t Ebx;
    uint32_t Edx;
    uint32_t Ecx;
    uint32_t Eax;
    uint32_t Ebp;
    uint32_t Eip;
    uint32_t SegCs;
    uint32_t EFlags;
    uint32_t Esp;
    uint32_t SegSs;
    uint8_t ExtendedRegisters[MAX_SUP_EXT];
} CPU_CONTEXT, *PCPU_CONTEXT;

#elif defined(TARGET_X86_64)

#pragma pack(push, 2)
typedef struct _CPU_M128A {
    uint64_t Low;
    int64_t High;
} CPU_M128A, *PCPU_M128A;
#pragma pack(pop)

typedef struct _CPU_XMM_SAVE_AREA32 {
    uint16_t ControlWord;
    uint16_t StatusWord;
    uint8_t TagWord;
    uint8_t Reserved1;
    uint16_t ErrorOpcode;
    uint32_t ErrorOffset;
    uint16_t ErrorSelector;
    uint16_t Reserved2;
    uint32_t DataOffset;
    uint16_t DataSelector;
    uint16_t Reserved3;
    uint32_t MxCsr;
    uint32_t MxCsr_Mask;
    CPU_M128A FloatRegisters[8];
    CPU_M128A XmmRegisters[16];
    uint8_t Reserved4[96];
} CPU_XMM_SAVE_AREA32, *PCPU_XMM_SAVE_AREA32;

#define CPU_CONTEXT_AMD64 0x100000

#define CPU_CONTEXT_CONTROL (CPU_CONTEXT_AMD64 | 0x1)
#define CPU_CONTEXT_INTEGER (CPU_CONTEXT_AMD64 | 0x2)
#define CPU_CONTEXT_SEGMENTS (CPU_CONTEXT_AMD64 | 0x4)
#define CPU_CONTEXT_FLOATING_POINT (CPU_CONTEXT_AMD64 | 0x8)
#define CPU_CONTEXT_DEBUG_REGISTERS (CPU_CONTEXT_AMD64 | 0x10)

#define CPU_CONTEXT_FULL \
    (CPU_CONTEXT_CONTROL | CPU_CONTEXT_INTEGER | CPU_CONTEXT_FLOATING_POINT)
#define CPU_CONTEXT_ALL \
    (CPU_CONTEXT_FULL | CPU_CONTEXT_SEGMENTS | CPU_CONTEXT_DEBUG_REGISTERS)

#pragma pack(push, 2)
typedef struct _CPU_CONTEXT {
    uint64_t P1Home;
    uint64_t P2Home;
    uint64_t P3Home;
    uint64_t P4Home;
    uint64_t P5Home;
    uint64_t P6Home;
    uint32_t ContextFlags;
    uint32_t MxCsr;
    uint16_t SegCs;
    uint16_t SegDs;
    uint16_t SegEs;
    uint16_t SegFs;
    uint16_t SegGs;
    uint16_t SegSs;
    uint32_t EFlags;
    uint64_t Dr0;
    uint64_t Dr1;
    uint64_t Dr2;
    uint64_t Dr3;
    uint64_t Dr6;
    uint64_t Dr7;
    uint64_t Rax;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rbx;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;
    uint64_t Rip;
    union {
        CPU_XMM_SAVE_AREA32 FltSave;
        CPU_XMM_SAVE_AREA32 FloatSave;
        struct {
            CPU_M128A Header[2];
            CPU_M128A Legacy[8];
            CPU_M128A Xmm0;
            CPU_M128A Xmm1;
            CPU_M128A Xmm2;
            CPU_M128A Xmm3;
            CPU_M128A Xmm4;
            CPU_M128A Xmm5;
            CPU_M128A Xmm6;
            CPU_M128A Xmm7;
            CPU_M128A Xmm8;
            CPU_M128A Xmm9;
            CPU_M128A Xmm10;
            CPU_M128A Xmm11;
            CPU_M128A Xmm12;
            CPU_M128A Xmm13;
            CPU_M128A Xmm14;
            CPU_M128A Xmm15;
        };
    };
    CPU_M128A VectorRegister[26];
    uint64_t VectorControl;
    uint64_t DebugControl;
    uint64_t LastBranchToRip;
    uint64_t LastBranchFromRip;
    uint64_t LastExceptionToRip;
    uint64_t LastExceptionFromRip;
} CPU_CONTEXT, *PCPU_CONTEXT;
#pragma pack(pop)

#else
#error Unsupported Architecture
#endif

typedef struct _CPU_KPROCESSOR_STATE {
    CPU_CONTEXT ContextFrame;
    CPU_KSPECIAL_REGISTERS SpecialRegisters;
} CPU_KPROCESSOR_STATE, *PCPU_KPROCESSOR_STATE;

typedef struct SizedBuf {
    uint8_t *data;
    size_t size;
} SizedBuf;

typedef struct InitedAddr {
    target_ulong addr;
    bool is_init;
} InitedAddr;

typedef struct PacketData {
    DBGKD_MANIPULATE_STATE64 *m64;
    uint8_t *extra;
    uint16_t extra_size;
} PacketData;

void kd_api_read_virtual_memory(CPUState *cpu, PacketData *pd);
void kd_api_write_virtual_memory(CPUState *cpu, PacketData *pd);
void kd_api_get_context(CPUState *cpu, PacketData *pd);
void kd_api_set_context(CPUState *cpu, PacketData *pd);
void kd_api_write_breakpoint(CPUState *cpu, PacketData *pd);
void kd_api_restore_breakpoint(CPUState *cpu, PacketData *pd);
void kd_api_continue(CPUState *cpu, PacketData *pd);
void kd_api_read_control_space(CPUState *cpu, PacketData *pd);
void kd_api_write_control_space(CPUState *cpu, PacketData *pd);
void kd_api_read_physical_memory(CPUState *cpu, PacketData *pd);
void kd_api_write_physical_memory(CPUState *cpu, PacketData *pd);
void kd_api_get_version(CPUState *cpu, PacketData *pd);
void kd_api_read_io_space(CPUState *cpu, PacketData *pd);
void kd_api_write_io_space(CPUState *cpu, PacketData *pd);
void kd_api_read_msr(CPUState *cpu, PacketData *pd);
void kd_api_write_msr(CPUState *cpu, PacketData *pd);
void kd_api_search_memory(CPUState *cpu, PacketData *pd);
void kd_api_query_memory(CPUState *cpu, PacketData *pd);
void kd_api_unsupported(CPUState *cpu, PacketData *pd);

CPU_CTRL_ADDRS         *kd_get_cpu_ctrl_addrs(CPUState *cpu);
EXCEPTION_STATE_CHANGE *kd_get_exception_sc(CPUState *cpu);
SizedBuf               *kd_get_load_symbols_sc(CPUState *cpu);

void windbg_dump(const char *fmt, ...);

void windbg_on_init(void);
void windbg_on_exit(void);

uint8_t get_cpu_amount(void);
uint32_t compute_checksum(uint8_t *data, uint16_t len);

#endif