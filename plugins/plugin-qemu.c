/*
 * QEMU plugin support.
 *
 * Copyright (C) 2015 ISP RAS
 *
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "plugin.h"

static SignalInfo *signals;

void plugins_init(void)
{
    signals = plugin_reg_signal("qemu");
}

void plugin_exception(CPUState *cpu)
{
    plugin_gen_signal(signals, "PLUGIN_QEMU_EXCEPTION", NULL, cpu->env_ptr);
}

void plugin_exception_handler(CPUState *cpu)
{
    plugin_gen_signal(signals, "PLUGIN_QEMU_EXCEPTION_HANDLER", NULL, cpu->env_ptr);
}

void plugin_interrupt(CPUState *cpu)
{
    plugin_gen_signal(signals, "PLUGIN_QEMU_INTERRUPT", NULL, cpu->env_ptr);
}

/* Hook called once CPU is paused.  */
void plugin_cpu_paused(CPUState *cpu)
{
    plugin_gen_signal(signals, "PLUGIN_QEMU_CPU_PAUSED", NULL, cpu->env_ptr);
}

/* Hook called before the Intermediate Code Generation (ICG).  */
void plugin_before_gen_tb(CPUState *cpu, TranslationBlock *tb)
{
    struct PluginParamsInstrTranslate params;
    params.pc = 0;
    params.tb = tb;
    
    plugin_gen_signal(signals, "PLUGIN_QEMU_BEFORE_GEN_TB", &params, cpu->env_ptr);
}

void plugin_instr_translate(target_ulong pc, CPUState *cpu, TranslationBlock *tb)
{
    struct PluginParamsInstrTranslate params;
    params.pc = pc;
    params.tb = tb;
    
    plugin_gen_signal(signals, "PLUGIN_QEMU_INSTR_TRANSLATE", &params, cpu->env_ptr);
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
    plugin_gen_signal(signals, "PLUGIN_QEMU_TLB_SET_PAGE", &params, cpu->env_ptr);
}

void plugin_page_dir_update(CPUArchState *env, target_ulong context)
{
    target_ulong gotten_ctxt = context;
    plugin_gen_signal(signals, "PLUGIN_QEMU_PAGE_DIR_UPD", &gotten_ctxt, env);
}

void plugin_instruction_exception(CPUState *cpu)
{
    plugin_gen_signal(signals, "PLUGIN_QEMU_INSTRUCTION_EXCEPTION", NULL, cpu->env_ptr);
}

void plugin_cpus_stopped(void)
{
    plugin_gen_signal(signals, "PLUGIN_QEMU_CPUS_STOPPED", NULL, NULL);
}
