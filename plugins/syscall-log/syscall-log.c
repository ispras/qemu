#include <stdint.h>
#include <stdio.h>
#include "plugins.h"

bool plugin_init(const char *args)
{
    return true;
}

bool plugin_needs_before_insn(uint64_t pc, void *cpu)
{
    uint8_t code = 0;
    if (!qemulib_read_memory(cpu, pc, &code, 1)
        && code == 0x0f) {
        if (qemulib_read_memory(cpu, pc + 1, &code, 1)) {
            return false;
        }
        if (code == 0x34) {
            /* sysenter */
            return true;
        }
        if (code == 0x35) {
            /* sysexit */
            return true;
        }
    }
    return false;
}

void plugin_before_insn(uint64_t pc, void *cpu)
{
    uint8_t code = 0;
    uint32_t reg;
    qemulib_read_memory(cpu, pc + 1, &code, 1);
    /* Read EAX. There should be a header with register ids
       or a function for reading the register by the name */
    qemulib_read_register(cpu, (uint8_t*)&reg, 0);
    /* log system calls */
    if (code == 0x34) {
        qemulib_log("sysenter %x\n", reg);
    } else if (code == 0x35) {
        qemulib_log("sysexit %x\n", reg);
    }
}
