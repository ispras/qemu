#ifndef PLUGINS_INTERFACE_H
#define PLUGINS_INTERFACE_H

#include <stdbool.h>

/* Plugin interface */

bool plugin_init(const char *args);
bool plugin_needs_before_insn(uint64_t pc, void *cpu);
void plugin_before_insn(uint64_t pc, void *cpu);
bool plugin_needs_before_tb(uint64_t pc, void *cpu);
void plugin_before_tb(uint64_t pc, void *cpu);

/* QEMU interface */

void qemulib_log(const char *fmt, ...) /*GCC_FMT_ATTR(1, 2)*/;
int qemulib_read_memory(void *cpu, uint64_t addr, uint8_t *buf, int len);
int qemulib_read_register(void *cpu, uint8_t *mem_buf, int reg);

#endif /* PLUGINS_INTERFACE_H */
