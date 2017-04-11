#include "qemu/osdep.h"
#include "qapi/error.h"
#include "plugins/plugin.h"

//there could be some unused includes, but im too lazy to check this atm
#include "exec/cpu_ldst.h"

#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "exec/helper-proto.h"
#include <exec/helper-head.h>
#include "exec/exec-all.h"

#include "example1.h"

static SignalInfo *cb;
static uint64_t scount;

const struct pi_info init_info = 
{
    .signals_list = (const char *[]){"test",NULL},
    .dependencies = (const char *[]){"contexts", NULL},
    .os_ver = NULL
};

static void after_exec_opc(void)
{
    //qemu_log_mask(LOG_GUEST_ERROR, "System call again \n");
    char data[] = "And I am a signal from helper. Isn't it great?\n";
    plugin_gen_signal(cb, "HELPER", data, NULL);
}

static void decode_instr(void *data, CPUArchState *env)
{
    scount++;
    if(!(scount % 10000))
    {
        char data[] = "10 000 instructions has passed. Impressive! \n";
        plugin_gen_signal(cb, "EVERY_10000", data, env);
        tcg_gen_callN(&tcg_ctx, after_exec_opc, dh_retvar(void), 0, NULL);
    }
}

static void cpus_paused(const PluginInterface *pi)
{
    fprintf(pi->output,"number of instructions = %" PRIu64 "\n",
                scount);
}

static void unload_signal(void)
{
    plugin_del_signal(cb);
    plugin_del_subscriber(decode_instr, "qemu", "PLUGIN_QEMU_INSTR_TRANSLATE");
}

static void test_print_function_wout_params(void)
{
    fprintf(stderr, "Test function wout paramenters successfuly executed \n");
}
static void test_print_function_w_params(int p1, int p2)
{
    fprintf(stderr, "Test function with parameters successfuly executed; param1 = %d & param2 =%d  \n", p1,p2);
}

void pi_start(PluginInterface *pi)
{
    scount = 0;
    cb = plugin_reg_signal("test");

    plugin_subscribe(decode_instr, "qemu", "PLUGIN_QEMU_INSTR_TRANSLATE");

    tcg_context_register_helper(
            &tcg_ctx,
            after_exec_opc,
            "after_exec_opc",
            0,
            dh_sizemask(void, 0)
            );

    static const struct SSS funcs = { .f1 = test_print_function_wout_params, .f2 = test_print_function_w_params};

    pi->exit = cpus_paused;
    pi->unload_signal = unload_signal;
    pi->funcs = &funcs;
}

