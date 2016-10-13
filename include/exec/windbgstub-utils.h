#ifndef WINDBGSTUB_UTILS_H
#define WINDBGSTUB_UTILS_H
#include "qemu/osdep.h"
#include "exec/windbgkd.h"
#include "cpu.h"

#define ROUND(value, max) value > max ? max : value

#define BYTE(var, index) (COMMON_PTR(uint8_t, var)[index])
#define LONG(var, index) (COMMON_PTR(uint32_t, var)[index])

#define COMMON_PTR(ptr, var) ((ptr *) &(var))
#define PTR(var) COMMON_PTR(uint8_t, var)

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

void set_Context(uint8_t *data, int len, int index);

CPUState *find_cpu(int index);
uint8_t cpu_amount(void);
uint32_t data_checksum_compute(uint8_t *data, uint16_t length);

#endif