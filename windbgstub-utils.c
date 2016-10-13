#include "exec/windbgstub-utils.h"

static CPUState *find_cpu(uint32_t thread_id)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu_index(cpu) == thread_id) {
            return cpu;
        }
    }

    return NULL;
}

uint32_t data_checksum_compute(uint8_t *data, uint16_t length)
{
    uint32_t checksum = 0;
    for(; length; --length) {
        checksum += (uint32_t)*data++;
    }
    return checksum;
}