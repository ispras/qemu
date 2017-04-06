#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"

#include "plugins/plugin.h"
#include "exec/cpu_ldst.h"

#include "tcg/tcg.h"
#include "tcg/tcg-op.h"

#include "syscalls.h"
#include "func_numbers_arch_linux.h"

static SignalInfo *cb;
static int logIsOn = 0;
static bool isInt80;

SignalInfo *syscall_get_cb(void)
{
    return cb;
}

const struct pi_info init_info = 
{
    .signals_list = (const char *[]){"syscall", NULL},
    .dependencies = (const char *[]){"contexts", NULL},
    .os_ver = (const char *[]){"Linux", NULL}
};

static void cpus_stopped(const PluginInterface *pi)
{
    fprintf(pi->output, "ok\n");
}

static void before_exception(void *data, CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);
    isInt80 = env->exception_is_int && cpu->exception_index == 0x80;
}

static void after_exception(void *data, CPUArchState *env)
{
    if (isInt80) {
        start_system_call(env);
    }
    isInt80 = false;
}

static void decode_instr(void *data, CPUArchState *env)
{
    target_ulong g_pc = ((struct PluginParamsInstrTranslate*)data)->pc;
    int code1 = cpu_ldub_code(env, g_pc);
    int code2 = cpu_ldub_code(env, ++g_pc);
    // int 80h is processed by exception handlers
    if (code1 == 0xcf)
    {
        TCGv_ptr t_env = tcg_const_ptr(env);
        TCGv_i32 t_esp = tcg_const_i32(R_ESP);
        TCGArg args[2];
        args[0] = GET_TCGV_PTR(t_env);
        args[1] = GET_TCGV_I32(t_esp);
        tcg_gen_callN(&tcg_ctx, exit_system_call, dh_retvar(void), 2, args);
        tcg_temp_free_ptr(t_env);
        tcg_temp_free_i32(t_esp);
    }
    if (code1 == 0x0f && code2 == 0x34)
    {
        TCGv_ptr t_env = tcg_const_ptr(env);
        TCGArg args[1];
        args[0] = GET_TCGV_PTR(t_env);
        tcg_gen_callN(&tcg_ctx, start_system_call, dh_retvar(void), 1, args);
        tcg_temp_free_ptr(t_env);
    }	
    if (code1 == 0x0f && code2 == 0x35)
    {
        TCGv_ptr t_env = tcg_const_ptr(env);
        TCGv_i32 t_ecx = tcg_const_i32(R_ECX);
        TCGArg args[2];
        args[0] = GET_TCGV_PTR(t_env);
        args[1] = GET_TCGV_I32(t_ecx);
        tcg_gen_callN(&tcg_ctx, exit_system_call, dh_retvar(void), 2, args);
        tcg_temp_free_ptr(t_env);
        tcg_temp_free_i32(t_ecx);
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
    plugin_subscribe(cpus_stopped, "qemu", "PLUGIN_QEMU_CPUS_STOPPED");
    
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

    cb = plugin_reg_signal("syscall");
    
    plugin_subscribe(decode_instr, "qemu", "PLUGIN_QEMU_INSTR_TRANSLATE");
    plugin_subscribe(before_exception, "qemu", "PLUGIN_QEMU_EXCEPTION");
    plugin_subscribe(after_exception, "qemu", "PLUGIN_QEMU_EXCEPTION_HANDLER");

    tcg_context_register_helper(
            &tcg_ctx,
            start_system_call,
            "start_system_call",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1));
    tcg_context_register_helper(
            &tcg_ctx,
            exit_system_call,
            "exit_system_call",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1) | dh_sizemask(i32, 2));
}

