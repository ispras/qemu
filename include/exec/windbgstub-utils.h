#ifndef WINDBGSTUB_UTILS_H
#define WINDBGSTUB_UTILS_H
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/windbgkd.h"

// FOR DEBUG

#define COUT(...) printf(__VA_ARGS__);
#define COUT_DEC(var) COUT_COMMON("%d", var)
#define COUT_HEX(var) COUT_COMMON("0x%x", var)
#define COUT_STRING(var) COUT_COMMON("%s", var)
#define COUT_SIZEOF(var) COUT_DEC(sizeof(var))
#define COUT_COMMON(fmt, var) COUT(#var ": " fmt "\n", var);

#define COUT_STRUCT(var) COUT_ARRAY(&var, 1)
#define COUT_PSTRUCT(var) COUT_ARRAY(var, 1)
#define COUT_ARRAY(var, count) _COUT_STRUCT(var, sizeof(*(var)), count)
#define _COUT_STRUCT(var, size, count) {          \
    COUT("%s: ", #var);                           \
    COUT("[size: %d, count: %d]\n", size, count); \
    int di;                                       \
    for (di = 0; di < size * count; ++di) {       \
        if (di % 16 == 0 && di != 0) {            \
            COUT("\n");                           \
        }                                         \
        COUT("%02x ", ((uint8_t *) (var))[di]);   \
    }                                             \
    COUT("\n");                                   \
}

// FOR DEBUG END

#define DUMP_VAR(var) windbg_dump("%c", var);
#define DUMP_STRUCT(var) DUMP_ARRAY(&var, 1)
#define DUMP_PSTRUCT(var) DUMP_ARRAY(var, 1)
#define DUMP_ARRAY(var, count) _DUMP_STRUCT(var, sizeof(*(var)), count)
#define _DUMP_STRUCT(var, size, count) {    \
    int di;                                 \
    for (di = 0; di < size * count; ++di) { \
       DUMP_VAR(((uint8_t *) (var))[di]);   \
    }                                       \
}

#define ROUND(value, max) value > max ? max : value

#define BYTE(var, index) (COMMON_PTR(uint8_t, var)[index])
#define LONG(var, index) (COMMON_PTR(uint32_t, var)[index])

#define COMMON_PTR(ptr, var) ((ptr *) &(var))
#define PTR(var) COMMON_PTR(uint8_t, var)

#define M64_OFFSET(data) data + sizeof(DBGKD_MANIPULATE_STATE64)

#define CPU_ARCH_STATE(cpu) (CPUArchState *) (cpu)->env_ptr

#define OFFSET_KPRCB            0x20
#define OFFSET_KPRCB_CURRTHREAD 0x4
#define OFFSET_VERSION          0x34
#define OFFSET_CONTEXT          0x18

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
    uint32_t KPCR;
    uint32_t KPRCB;
    uint32_t Version;
} CPU_CTRL_ADDRS, *PCPU_CTRL_ADDRS;

#if defined(TARGET_I386)

#define SIZE_OF_X86_REG 80
#define MAX_SUP_EXT 512

typedef struct _DESCRIPTOR
{
    uint16_t Pad;
    uint16_t Limit;
    uint32_t Base;
} DESCRIPTOR, *PDESCRIPTOR;

typedef struct _KSPECIAL_REGISTERS
{
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
    DESCRIPTOR Gdtr;
    DESCRIPTOR Idtr;
    uint16_t Tr;
    uint16_t Ldtr;
    uint32_t Reserved[6];
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

typedef struct _FLOATING_SAVE_AREA {
    uint32_t ControlWord;
    uint32_t StatusWord;
    uint32_t TagWord;
    uint32_t ErrorOffset;
    uint32_t ErrorSelector;
    uint32_t DataOffset;
    uint32_t DataSelector;
    uint8_t RegisterArea[SIZE_OF_X86_REG];
    uint32_t Cr0NpxState;
} FLOATING_SAVE_AREA, *PFLOATING_SAVE_AREA;

typedef struct _CPU_CONTEXT {
    uint32_t ContextFlags;
    uint32_t Dr0;
    uint32_t Dr1;
    uint32_t Dr2;
    uint32_t Dr3;
    uint32_t Dr6;
    uint32_t Dr7;
    FLOATING_SAVE_AREA FloatSave;
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
typedef struct _XMM_SAVE_AREA32 {
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
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    uint8_t Reserved4[96];
} XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

#define LEGACY_SAVE_AREA_LENGTH sizeof(XMM_SAVE_AREA32)

typedef struct DECLSPEC_ALIGN(16) _CPU_CONTEXT {
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
    __C89_NAMELESS union {
        XMM_SAVE_AREA32 FltSave;
        XMM_SAVE_AREA32 FloatSave;
        __C89_NAMELESS struct {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        };
    };
    M128A VectorRegister[26];
    uint64_t VectorControl;
    uint64_t DebugControl;
    uint64_t LastBranchToRip;
    uint64_t LastBranchFromRip;
    uint64_t LastExceptionToRip;
    uint64_t LastExceptionFromRip;
} CPU_CONTEXT, *PCPU_CONTEXT;
#endif

PCPU_CTRL_ADDRS         get_KPCRAddress(int index);
PEXCEPTION_STATE_CHANGE get_ExceptionStateChange(int index);
PCPU_CONTEXT            get_Context(int index);
PKSPECIAL_REGISTERS     get_KSpecialRegisters(int index);

void set_Context(uint8_t *data, int len, int index);
void set_KSpecialRegisters(uint8_t *data, int len, int offset, int index);

CPUState *find_cpu(int index);
uint8_t cpu_amount(void);
uint32_t data_checksum_compute(uint8_t *data, uint16_t length);

#endif