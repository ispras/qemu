#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"

#include "plugins/plugin.h"
#include "exec/cpu_ldst.h"

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

static uint32_t guest_read_dword(CPUArchState *env, uint64_t address)
{
    uint32_t val = 0;
    cpu_memory_rw_debug(ENV_GET_CPU(env), address, (uint8_t*)&val, sizeof(val), 0);
    // TODO: support big endian host
    return val;
}

#ifdef TARGET_X86_64
static uint64_t guest_read_qword(CPUArchState *env, uint64_t address)
{
    uint64_t val = 0;
    cpu_memory_rw_debug(ENV_GET_CPU(env), address, (uint8_t*)&val, sizeof(val), 0);
    // TODO: support big endian host
    return val;
}
#endif

static void iret_helper(CPUArchState *env)
{
    uint64_t esp = 0;
    if (env->eflags & NT_MASK) {
        uint32_t selector = guest_read_dword(env, env->tr.base + 0);
        SegmentCache *dt;
        int index;
        target_ulong ptr;

        if (selector & 0x4) {
            dt = &env->ldt;
        } else {
            dt = &env->gdt;
        }
        index = selector & ~7;
        if ((index + 7) > dt->limit) {
            return;
        }
        ptr = dt->base + index;

        uint32_t e1 = guest_read_dword(env, ptr);
        uint32_t e2 = guest_read_dword(env, ptr + 4);

        uint32_t tss_base = (e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000); // get_seg_base
        esp = guest_read_dword(env, tss_base + (0x28 + 4 * 4));

        exit_system_call(env, esp);
    } else {
        // try for int 80
        esp = env->regs[R_ESP];
        exit_system_call(env, esp);
        // get new ESP from the stack - try for sysenter-iret pair
#ifndef TARGET_X86_64
        esp = guest_read_dword(env, 12 + env->segs[R_SS].base + env->regs[R_ESP]);
#else
        esp = guest_read_qword(env, 24 + env->segs[R_SS].base + env->regs[R_ESP]);
#endif
        exit_system_call(env, esp);
    }
}

static void sysexit_helper(CPUArchState *env)
{
    exit_system_call(env, env->regs[R_ECX]);
}

static void sysret_helper(CPUArchState *env)
{
    exit_system_call(env, env->regs[R_ESP]);
}

static void decode_instr(void *data, CPUArchState *env)
{
    target_ulong g_pc = ((struct PluginParamsInstrTranslate*)data)->pc;
    int code1 = cpu_ldub_code(env, g_pc);
    // int 80h is processed by exception handlers
    if (code1 == 0xcf)
    {
        TCGv_ptr t_env = tcg_const_ptr(env);
        TCGArg args[1];
        args[0] = GET_TCGV_PTR(t_env);
        tcg_gen_callN(&tcg_ctx, iret_helper, dh_retvar(void), 1, args);
        tcg_temp_free_ptr(t_env);
    }
    if (code1 == 0x0f) {
        int code2 = cpu_ldub_code(env, ++g_pc);
        if (code2 == 0x34) {
            // sysenter
            TCGv_ptr t_env = tcg_const_ptr(env);
            TCGArg args[1];
            args[0] = GET_TCGV_PTR(t_env);
            tcg_gen_callN(&tcg_ctx, start_system_call, dh_retvar(void), 1, args);
            tcg_temp_free_ptr(t_env);
        }
        if (code2 == 0x05) {
            // syscall
            TCGv_ptr t_env = tcg_const_ptr((intptr_t)env);
            TCGArg args[1];
            args[0] = GET_TCGV_PTR(t_env);
            tcg_gen_callN(&tcg_ctx, start_system_call, dh_retvar(void), 1, args);
            tcg_temp_free_ptr(t_env);
        }
        if (code2 == 0x35) {
            // sysexit
            TCGv_ptr t_env = tcg_const_ptr(env);
            TCGArg args[1];
            args[0] = GET_TCGV_PTR(t_env);
            tcg_gen_callN(&tcg_ctx, sysexit_helper, dh_retvar(void), 1, args);
            tcg_temp_free_ptr(t_env);
        }
        if (code2 == 0x07) {
            // sysret
            TCGv_ptr t_env = tcg_const_ptr((intptr_t)env);
            TCGArg args[1];
            args[0] = GET_TCGV_PTR(t_env);
            tcg_gen_callN(&tcg_ctx, sysret_helper, dh_retvar(void), 1, args);
            tcg_temp_free_ptr(t_env);
        }
    } else if (code1 == 0x48) {
        int code2 = cpu_ldub_code(env, ++g_pc);
        if (code2 == 0x0f) {
            int code3 = cpu_ldub_code(env, ++g_pc);
            if (code3 == 0x07) {
                TCGv_ptr t_env = tcg_const_ptr((intptr_t)env);
                TCGArg args[1];
                args[0] = GET_TCGV_PTR(t_env);
                tcg_gen_callN(&tcg_ctx, sysret_helper, dh_retvar(void), 1, args);
                tcg_temp_free_ptr(t_env);
            }
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
            sysexit_helper,
            "sysexit_helper",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1) | dh_sizemask(i32, 2));
    tcg_context_register_helper(
            &tcg_ctx,
            sysret_helper,
            "sysret_helper",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1));
    tcg_context_register_helper(
            &tcg_ctx,
            iret_helper,
            "iret_helper",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1));
}

