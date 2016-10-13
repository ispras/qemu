#ifndef WINDBGSTUB_UTILS_H
#define WINDBGSTUB_UTILS_H
#include "exec/windbgkd.h"

#define BYTE(var, index) (COMMON_PTR(uint8_t, var)[index])
#define LONG(var, index) (COMMON_PTR(uint32_t, var)[index])

#define COMMON_PTR(ptr, var) ((ptr *) &(var))
#define PTR(var) COMMON_PTR(uint8_t, var)

//
// Structure for DbgKdExceptionStateChange
//
#pragma pack(push, 1)
typedef struct _EXCEPTION_STATE_CHANGE {
    DBGKD_ANY_WAIT_STATE_CHANGE StateChange;
    ULONG value;
} EXCEPTION_STATE_CHANGE, *PEXCEPTION_STATE_CHANGE;
#pragma pack(pop)

PEXCEPTION_STATE_CHANGE get_ExceptionStateChange(int index);

CPUState *find_cpu(int index);
uint8_t cpu_amount(void);
uint32_t data_checksum_compute(uint8_t *data, uint16_t length);

#endif