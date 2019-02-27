#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "qemu/error-report.h"
#include "qemu/plugins.h"
#include "qemu/log.h"
#include "include/plugins.h"

void qemulib_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    qemu_log_vprintf(fmt, args);
    va_end(args);
}

int qemulib_read_memory(void *cpu, uint64_t addr, uint8_t *buf, int len)
{
    return cpu_memory_rw_debug(cpu, addr, buf, len, false);
}

int qemulib_read_register(void *cpu, uint8_t *mem_buf, int reg)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (reg < cc->gdb_num_core_regs) {
        return cc->gdb_read_register(cpu, mem_buf, reg);
    }

    return 0;
}
