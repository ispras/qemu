#ifndef WINDBGSTUB_UTILS_H
#define WINDBGSTUB_UTILS_H
#include "exec/windbgkd.h"

uint32_t data_checksum_compute(uint8_t *data, uint16_t length);

#endif