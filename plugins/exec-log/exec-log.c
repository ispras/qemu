#include <stdint.h>
#include <stdio.h>
#include "plugins.h"

bool plugin_init(const char *args)
{
    return true;
}

bool plugin_needs_before_insn(uint64_t pc, void *cpu)
{
    return true;
}

void plugin_before_insn(uint64_t pc, void *cpu)
{
    qemulib_log("executing instruction at %lx\n", pc);
}
