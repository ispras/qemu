#ifndef WINDBGSTUB_UTILS_H
#define WINDBGSTUB_UTILS_H
#include "exec/windbgkd.h"

#define BYTE(var, index) (COMMON_PTR(uint8_t, var)[index])
#define LONG(var, index) (COMMON_PTR(uint32_t, var)[index])

#define COMMON_PTR(ptr, var) ((ptr *) &(var))
#define PTR(var) COMMON_PTR(uint8_t, var)

CPUState *find_cpu(int index);
uint32_t data_checksum_compute(uint8_t *data, uint16_t length);

#endif