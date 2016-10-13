#include "qemu-common.h"
#include "exec/windbgstub-utils.h"

uint32_t data_checksum_compute(uint8_t *data, uint16_t length)
{
    uint32_t checksum = 0;
    for(; length; --length) {
        checksum += (uint32_t)*data++;
    }
    return checksum;
}