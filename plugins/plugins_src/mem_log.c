#include "qemu/osdep.h"
#include "tcg/tcg.h"
#include "exec/exec-all.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>

#include "plugins/plugin.h"

const struct pi_info init_info = 
{
    .signals_list = (const char *[]){NULL},
    .dependencies = (const char *[]){NULL},
    .os_ver = NULL
};

static void log_memory(void *data, CPUArchState *env)
{
    struct PluginParamsMemOp *params = data;
    qemu_log_mask(LOG_PLUGINS, "TB%08"PRIx64": ",
#if defined(TARGET_I386) || defined(TARGET_x86_64)
        (uint64_t)(env->eip + env->segs[R_CS].base)
#elif defined(TARGET_MIPS) || defined(TARGET_MIPS64)
        (uint64_t)env->active_tc.gpr[31]
#else
        (uint64_t)0
#endif
    );
    if (params->isLoad) {
        qemu_log_mask(LOG_PLUGINS, "Load ");
    } else {
        qemu_log_mask(LOG_PLUGINS, "Store ");
    }
    uint64_t vaddr = params->vaddr;
    qemu_log_mask(LOG_PLUGINS, "0x%"PRIx64"@%"PRId64" ", params->value, params->size * 8);
    qemu_log_mask(LOG_PLUGINS, "virt:%"PRIx64" phys:%"PRIx64"\n", vaddr,
        (uint64_t)cpu_get_phys_page_debug(ENV_GET_CPU(env), vaddr));
}

static void cpus_paused(const PluginInterface *pi)
{
}

void pi_start(PluginInterface *pi)
{
    plugin_subscribe(log_memory, "qemu", "PLUGIN_QEMU_MEM_OP");

    pi->exit = cpus_paused;
}
