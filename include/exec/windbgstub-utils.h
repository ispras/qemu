#ifndef WINDBGSTUB_UTILS_H
#define WINDBGSTUB_UTILS_H
#include "qemu/osdep.h"
#include "exec/windbgkd.h"
#include "cpu.h"

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
    ULONG value;
} EXCEPTION_STATE_CHANGE, *PEXCEPTION_STATE_CHANGE;
#pragma pack(pop)

typedef struct _CPU_CTRL_ADDRS {
    uint32_t KPCR;
    uint32_t KPRCB;
    uint32_t Version;
} CPU_CTRL_ADDRS, *PCPU_CTRL_ADDRS;

typedef struct _DESCRIPTOR
{
    WORD Pad;
    WORD Limit;
    ULONG Base;
} DESCRIPTOR, *PDESCRIPTOR;

typedef struct _KSPECIAL_REGISTERS
{
    ULONG Cr0;
    ULONG Cr2;
    ULONG Cr3;
    ULONG Cr4;
    ULONG KernelDr0;
    ULONG KernelDr1;
    ULONG KernelDr2;
    ULONG KernelDr3;
    ULONG KernelDr6;
    ULONG KernelDr7;
    DESCRIPTOR Gdtr;
    DESCRIPTOR Idtr;
    WORD Tr;
    WORD Ldtr;
    ULONG Reserved[6];
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

PCPU_CTRL_ADDRS         get_KPCRAddress(int index);
PEXCEPTION_STATE_CHANGE get_ExceptionStateChange(int index);
PCONTEXT                get_Context(int index);
PKSPECIAL_REGISTERS     get_KSpecialRegisters(int index);

void set_Context(uint8_t *data, int len, int index);
void set_KSpecialRegisters(uint8_t *data, int len, int offset, int index);

CPUState *find_cpu(int index);
uint8_t cpu_amount(void);
uint32_t data_checksum_compute(uint8_t *data, uint16_t length);

#endif