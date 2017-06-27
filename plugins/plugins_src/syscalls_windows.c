#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"

#include "tcg/tcg.h"
#include "plugins/plugin.h"
#include "exec/cpu_ldst.h"

#include "tcg/tcg-op.h"

#include "syscalls.h"
#include "func_numbers_arch_windows.h"

//#include "syscall_win.h"
static SignalInfo *cb;
static int logIsOn = 0;

const struct pi_info init_info = 
{
    .signals_list = (const char *[]){"syscall", NULL},
    .dependencies = (const char *[]){"contexts", NULL},
#if defined(GUEST_OS_WINXP)
    .os_ver = (const char *[]){"WinXP", NULL}
#elif defined(GUEST_OS_WIN7)
    .os_ver = (const char *[]){"Win7", NULL}
#elif defined(GUEST_OS_WIN8)
    .os_ver = (const char *[]){"Win8", NULL}
#elif defined(GUEST_OS_WIN81)
    .os_ver = (const char *[]){"Win8.1", NULL}
#else
#error Cannot build Windows syscall plugin for unknown Windows version.
#endif
};

static void cpus_exit(const PluginInterface *pi)
{
    fprintf(pi->output, "ok\n");
}

SignalInfo *syscall_get_cb(void)
{
    return cb;
}

static void exit_system_call_win(CPUArchState *env)
{
    exit_system_call(env, env->regs[R_ECX]);
}

static void decode_instr(void *data, CPUArchState *env)
{
    target_ulong g_pc = ((struct PluginParamsInstrTranslate*)data)->pc;
    int code1 = cpu_ldub_code(env, g_pc);
    if (code1 == 0x0f) {
        int code2 = cpu_ldub_code(env, g_pc + 1);
        if (code2 == 0x34) {
            TCGv_ptr t_env = tcg_const_ptr(env);
            TCGArg args[1];
            args[0] = GET_TCGV_PTR(t_env);
            tcg_gen_callN(&tcg_ctx, start_system_call, dh_retvar(void), 1, args);
            tcg_temp_free_ptr(t_env);
        }	
        if (code2 == 0x35) {
            TCGv_ptr t_env = tcg_const_ptr(env);
            TCGArg args[1];
            args[0] = GET_TCGV_PTR(t_env);
            tcg_gen_callN(&tcg_ctx, exit_system_call_win, dh_retvar(void), 1, args);
            tcg_temp_free_ptr(t_env);
        }
    }
}

static void enable_printf_log(Monitor *mon, const QDict *qdict)
{
    if (!logIsOn)
    {
        if (syscall_init_log()) {
            monitor_printf(mon, "Syscall log is enabled\n");
            logIsOn = 1;
        }
    } else monitor_printf(mon, "Syscall log is already enabled\n");
}

static void disable_printf_log(Monitor *mon, const QDict *qdict)
{
    if (syscall_close_log()) {
        monitor_printf(mon, "Syscall log is disabled\n");
        logIsOn = 0;
    } else monitor_printf(mon, "Log is not enabled\n");
}

void pi_start(PluginInterface *pi)
{
    static mon_cmd_t mon_cmds[] = {
        {
            .name       = "enable_syscall_log",
            .args_type  = "",
            .params     = "",
            .help       = "enable log of syscalls",
            .cmd        = enable_printf_log,
        },
        {
            .name       = "disable_syscall_log",
            .args_type  = "",
            .params     = "",
            .help       = "disable log of syscalls",
            .cmd        = disable_printf_log,
        },
        {
            .name       = NULL,
        },
    };
    pi->cmd_table = mon_cmds;

    pi->exit = cpus_exit;
    cb = plugin_reg_signal("syscall");
    plugin_subscribe(decode_instr, "qemu", "PLUGIN_QEMU_INSTR_TRANSLATE");
    plugin_subscribe(syscall_tlb_add_page, "qemu", "PLUGIN_QEMU_TLB_SET_PAGE");
    tcg_context_register_helper(
            &tcg_ctx,
            start_system_call,
            "start_system_call",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1));
    tcg_context_register_helper(
            &tcg_ctx,
            exit_system_call_win,
            "exit_system_call_win",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1));
}

