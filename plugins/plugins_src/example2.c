#include "qemu/osdep.h"
#include "qapi/error.h"
#include "plugins/plugin.h"

#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "exec/helper-proto.h"
#include <exec/helper-head.h>
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"

#include "example1.h"

const struct pi_info init_info = 
{
    .signals_list = (const char *[]){NULL},
    .dependencies = (const char *[]){NULL},
    .os_ver = NULL
};

static void test_f(void* data, CPUArchState *env)
{
    char *str = data;
    fprintf(stderr, "what is it? - %s ",
                str);
}

static void cpus_stopped(const PluginInterface *pi)
{
    fprintf(pi->output,"Example2 plugin has stopped\n");
}

static void unload_signal(void)
{
    plugin_del_subscriber(test_f, "test", "EVERY_10000");
    plugin_del_subscriber(test_f, "test", "HELPER");
}

void pi_start(PluginInterface *pi)
{
    plugin_subscribe(test_f, "test", "EVERY_10000");
    plugin_subscribe(test_f, "test", "HELPER");

    struct SSS *funcs= (struct SSS*)plugin_get_functions_list("example1");
    if(funcs != NULL)
    {
        funcs->f1();
        funcs->f2(1, 2);
    }

    pi->exit = cpus_stopped;
    pi->unload_signal = unload_signal;
}

