/*
 * QEMU plugin support.
 *
 * Copyright (C) 2015 ISP RAS
 *
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "plugin.h"
#include "tcg-op.h"

static SignalInfo *signals;

static const uint32_t memop_size[] = { [MO_8] = 1, [MO_16] = 2, [MO_32] = 4, [MO_64] = 8 };

static void helper_ld32(CPUArchState *env, uint32_t memop, target_ulong addr,
                        target_ulong idx, uint32_t val)
{
    struct PluginParamsMemOp params;
    params.isLoad = true;
    params.vaddr = addr;
    params.size = memop_size[memop & MO_SIZE];
    params.value = val;

    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_MEM_OP", &params, env);
}

static void helper_st32(CPUArchState *env, uint32_t memop, target_ulong addr,
                        target_ulong idx, uint32_t val)
{
    struct PluginParamsMemOp params;
    params.isLoad = false;
    params.vaddr = addr;
    params.size = memop_size[memop & MO_SIZE];
    params.value = val;

    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_MEM_OP", &params, env);
}

static void helper_ld64(CPUArchState *env, uint32_t memop, target_ulong addr,
                         target_ulong idx, uint64_t val)
{
    struct PluginParamsMemOp params;
    params.isLoad = true;
    params.vaddr = addr;
    params.size = memop_size[memop & MO_SIZE];
    params.value = val;

    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_MEM_OP", &params, env);
}

static void helper_st64(CPUArchState *env, uint32_t memop, target_ulong addr,
                        target_ulong idx, uint64_t val)
{
    struct PluginParamsMemOp params;
    params.isLoad = false;
    params.vaddr = addr;
    params.size = memop_size[memop & MO_SIZE];
    params.value = val;

    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_MEM_OP", &params, env);
}

void plugins_init(void)
{
    signals = plugin_reg_signal("qemu");

    tcg_context_register_helper(
            &tcg_ctx,
            helper_ld32,
            "helper_ld32",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1) | dh_sizemask(i32, 2)
                | dh_sizemask(tl, 3) | dh_sizemask(tl, 4) | dh_sizemask(i32, 5));

    tcg_context_register_helper(
            &tcg_ctx,
            helper_st32,
            "helper_st32",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1) | dh_sizemask(i32, 2)
                | dh_sizemask(tl, 3) | dh_sizemask(tl, 4) | dh_sizemask(i32, 5));

    tcg_context_register_helper(
            &tcg_ctx,
            helper_ld64,
            "helper_ld64",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1) | dh_sizemask(i32, 2)
                | dh_sizemask(tl, 3) | dh_sizemask(tl, 4) | dh_sizemask(i64, 5));

    tcg_context_register_helper(
            &tcg_ctx,
            helper_st64,
            "helper_st64",
            0,
            dh_sizemask(void, 0) | dh_sizemask(ptr, 1) | dh_sizemask(i32, 2)
                | dh_sizemask(tl, 3) | dh_sizemask(tl, 4) | dh_sizemask(i64, 5));
}

void plugin_exception(CPUState *cpu)
{
    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_EXCEPTION", NULL, cpu->env_ptr);
}

void plugin_exception_handler(CPUState *cpu)
{
    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_EXCEPTION_HANDLER", NULL, cpu->env_ptr);
}

void plugin_interrupt(CPUState *cpu)
{
    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_INTERRUPT", NULL, cpu->env_ptr);
}

/* Hook called once CPU is paused.  */
void plugin_cpu_paused(CPUState *cpu)
{
    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_CPU_PAUSED", NULL, cpu->env_ptr);
}

/* Hook called before the Intermediate Code Generation (ICG).  */
void plugin_before_gen_tb(CPUState *cpu, TranslationBlock *tb)
{
    struct PluginParamsInstrTranslate params;
    params.pc = 0;
    params.tb = tb;
    
    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_BEFORE_GEN_TB", &params, cpu->env_ptr);
}

void plugin_instr_translate(target_ulong pc, CPUState *cpu, TranslationBlock *tb)
{
    struct PluginParamsInstrTranslate params;
    params.pc = pc;
    params.tb = tb;
    
    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_INSTR_TRANSLATE", &params, cpu->env_ptr);
}

void plugin_tlb_set_page(CPUState *cpu, target_ulong vaddr,
                             hwaddr paddr, int prot, int mmu_idx, target_ulong size)
{
    struct PluginParamsTlbAddPage params;
    params.vaddr = vaddr;
    params.paddr = paddr;
    params.prot = prot;
    params.mmu_idx = mmu_idx;
    params.size = size;
    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_TLB_SET_PAGE", &params, cpu->env_ptr);
}

void plugin_page_dir_update(CPUArchState *env, target_ulong context)
{
    target_ulong gotten_ctxt = context;
    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_PAGE_DIR_UPD", &gotten_ctxt, env);
}

void plugin_instruction_exception(CPUState *cpu)
{
    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_INSTRUCTION_EXCEPTION", NULL, cpu->env_ptr);
}

void plugin_cpus_stopped(void)
{
    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_CPUS_STOPPED", NULL, NULL);
}

void plugin_ld(CPUArchState *env, target_ulong vaddr, target_ulong size, uint64_t val)
{
    struct PluginParamsMemOp params = {
        .isLoad = true,
        .vaddr = vaddr,
        .size = size,
        .value = val
    };

    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_MEM_OP", &params, env);
}

void plugin_st(CPUArchState *env, target_ulong vaddr, target_ulong size, uint64_t val)
{
    struct PluginParamsMemOp params = {
        .isLoad = false,
        .vaddr = vaddr,
        .size = size,
        .value = val
    };

    PLUGIN_GEN_SIGNAL(signals, "PLUGIN_QEMU_MEM_OP", &params, env);
}

void plugin_gen_ld32(TCGContext *ctx, TCGMemOp memop, TCGv addr, TCGArg idx, TCGv_i32 val)
{
    TCGv_i32 t_memop = tcg_const_i32(memop);
    TCGArg args[5] = {GET_TCGV_PTR(ctx->tcg_env),
        GET_TCGV_I32(t_memop),
#if TARGET_LONG_BITS == 32
        GET_TCGV_I32(addr),
#else
        GET_TCGV_I64(addr),
#endif
        idx, GET_TCGV_I32(val)};
    tcg_gen_callN(ctx, helper_ld32, dh_retvar(void), 5, args);
    tcg_temp_free_i32(t_memop);
}

void plugin_gen_st32(TCGContext *ctx, TCGMemOp memop, TCGv addr, TCGArg idx, TCGv_i32 val)
{
    TCGv_i32 t_memop = tcg_const_i32(memop);
    TCGArg args[5] = {GET_TCGV_PTR(ctx->tcg_env),
        GET_TCGV_I32(t_memop),
#if TARGET_LONG_BITS == 32
        GET_TCGV_I32(addr),
#else
        GET_TCGV_I64(addr),
#endif
        idx, GET_TCGV_I32(val)};
    tcg_gen_callN(ctx, helper_st32, dh_retvar(void), 5, args);
    tcg_temp_free_i32(t_memop);
}

void plugin_gen_ld64(TCGContext *ctx, TCGMemOp memop, TCGv addr, TCGArg idx, TCGv_i64 val)
{
    TCGv_i32 t_memop = tcg_const_i32(memop);
    TCGArg args[5] = {GET_TCGV_PTR(ctx->tcg_env),
        GET_TCGV_I32(t_memop),
#if TARGET_LONG_BITS == 32
        GET_TCGV_I32(addr),
#else
        GET_TCGV_I64(addr),
#endif
        idx, GET_TCGV_I64(val)};
    tcg_gen_callN(ctx, helper_ld32, dh_retvar(void), 5, args);
    tcg_temp_free_i32(t_memop);
}

void plugin_gen_st64(TCGContext *ctx, TCGMemOp memop, TCGv addr, TCGArg idx, TCGv_i64 val)
{
    TCGv_i32 t_memop = tcg_const_i32(memop);
    TCGArg args[5] = {GET_TCGV_PTR(ctx->tcg_env),
        GET_TCGV_I32(t_memop),
#if TARGET_LONG_BITS == 32
        GET_TCGV_I32(addr),
#else
        GET_TCGV_I64(addr),
#endif
        idx, GET_TCGV_I64(val)};
    tcg_gen_callN(ctx, helper_st32, dh_retvar(void), 5, args);
    tcg_temp_free_i32(t_memop);
}