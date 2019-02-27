#ifndef PLUGINS_INTERFACE_H
#define PLUGINS_INTERFACE_H

#include <stdbool.h>

/* Plugin interface */

bool plugin_init(const char *args);
bool plugin_needs_before_insn(uint64_t pc, void *cpu);
void plugin_before_insn(uint64_t pc, void *cpu);

#endif /* PLUGINS_INTERFACE_H */
