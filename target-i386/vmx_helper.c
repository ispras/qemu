/*
 *  x86 VMX helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "cpu.h"
#include "exec/cpu-all.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"

static uint32_t exit_reason;
static int nested_exception;
static uint32_t latest_int_reason;

#define MAX_EXIT_PARAM 10
static uint64_t exit_params[MAX_EXIT_PARAM];

//function doesn't work right, as load_vmcs (deleted now)
//guest works as long as hyper loads same vmcs, because data preserved
//in vmcs structure
static void flush_vmcs(CPUX86State *env, uint64_t addr)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));

    addr += 8;
    //guest state area
    stl_phys(cs->as, addr, env->curr_vmcs.launch_state); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.cr0); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.cr3); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.cr4); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.dr7); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.rsp); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.rip); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.rflags); addr += 8;
    stw_phys(cs->as, addr, env->curr_vmcs.guest_state.cs.selector); addr += 2;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.cs.base); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.cs.selector); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.cs.flags); addr += 4;
    stw_phys(cs->as, addr, env->curr_vmcs.guest_state.ss.selector); addr += 2;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.ss.base); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.ss.selector); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.ss.flags); addr += 4;
    stw_phys(cs->as, addr, env->curr_vmcs.guest_state.ds.selector); addr += 2;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.ds.base); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.ds.selector); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.ds.flags); addr += 4;
    stw_phys(cs->as, addr, env->curr_vmcs.guest_state.es.selector); addr += 2;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.es.base); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.es.selector); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.es.flags); addr += 4;
    stw_phys(cs->as, addr, env->curr_vmcs.guest_state.fs.selector); addr += 2;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.fs.base); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.fs.selector); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.fs.flags); addr += 4;
    stw_phys(cs->as, addr, env->curr_vmcs.guest_state.gs.selector); addr += 2;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.gs.base); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.gs.selector); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.gs.flags); addr += 4;
    stw_phys(cs->as, addr, env->curr_vmcs.guest_state.ldtr.selector); addr += 2;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.ldtr.base); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.ldtr.selector); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.ldtr.flags); addr += 4;
    stw_phys(cs->as, addr, env->curr_vmcs.guest_state.tr.selector); addr += 2;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.tr.base); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.tr.selector); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.tr.flags ); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.gdtr.base); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.idtr.base); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.gdtr.limit); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.idtr.limit); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.msr_debugctl); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.msr_sysenter_cs); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.msr_sysenter_esp); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.msr_sysenter_eip); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.smbase); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.activity_state); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.guest_state.interuptibility_state); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.pending_debug_exceptions); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.guest_state.vmcs_link_pointer); addr += 8;
    //host state area
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.cr0); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.cr3); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.cr4); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.rsp); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.rip); addr += 8;
    stw_phys(cs->as, addr, env->curr_vmcs.host_state.cs_selector); addr += 2;
    stw_phys(cs->as, addr, env->curr_vmcs.host_state.ss_selector); addr += 2;
    stw_phys(cs->as, addr, env->curr_vmcs.host_state.ds_selector); addr += 2;
    stw_phys(cs->as, addr, env->curr_vmcs.host_state.es_selector); addr += 2;
    stw_phys(cs->as, addr, env->curr_vmcs.host_state.fs_selector); addr += 2;
    stw_phys(cs->as, addr, env->curr_vmcs.host_state.gs_selector); addr += 2;
    stw_phys(cs->as, addr, env->curr_vmcs.host_state.tr_selector); addr += 2;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.fs_base); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.gs_base); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.tr_base); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.idtr_base); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.gdtr_base); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.host_state.msr_sysenter_cs); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.msr_sysenter_esp); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.host_state.msr_sysenter_eip); addr += 8;
    //vm execution control fields
    stl_phys(cs->as, addr, env->curr_vmcs.exec_control.pin_based_controls); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.exec_control.processor_based_controls); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.exec_control.exception_bitmap); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.exec_control.page_fault_error_code_mask); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.exec_control.page_fault_error_code_match); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.exec_control.io_bitmap_a); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exec_control.io_bitmap_b); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exec_control.tsc_offset); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exec_control.cr3_target_value[0]); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exec_control.cr3_target_value[1]); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exec_control.cr3_target_value[2]); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exec_control.cr3_target_value[3]); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.exec_control.cr3_target_count); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.exec_control.virtual_apic_page_address); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exec_control.executive_vmcs_pointer); addr += 8;
    //vm exit control fields
    stl_phys(cs->as, addr, env->curr_vmcs.exit_control.controls); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.exit_control.msr_store_count); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.exit_control.msr_store_address); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.exit_control.msr_load_count); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.exit_control.msr_load_address); addr += 8;
    //vm entry control fields
    stl_phys(cs->as, addr, env->curr_vmcs.entry_control.controls); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.entry_control.msr_load_count); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.entry_control.msr_load_address); addr += 8;
    stl_phys(cs->as, addr, env->curr_vmcs.entry_control.interruption_information); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.entry_control.instruction_length); addr += 4;
    //vm exit informations fields
    stl_phys(cs->as, addr, env->curr_vmcs.exit_info.exit_reason); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.exit_info.exit_qualification); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exit_info.guest_linear_address); addr += 8;    
    stl_phys(cs->as, addr, env->curr_vmcs.exit_info.interruption_information); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.exit_info.interruption_error_code); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.exit_info.idt_vectoring_information); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.exit_info.idt_vectoring_error_code); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.exit_info.instruction_length); addr += 4;
    stl_phys(cs->as, addr, env->curr_vmcs.exit_info.instruction_information); addr += 4;
    stq_phys(cs->as, addr, env->curr_vmcs.exit_info.io_rcx); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exit_info.io_rsi); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exit_info.io_rdi); addr += 8;
    stq_phys(cs->as, addr, env->curr_vmcs.exit_info.io_rip); addr += 8;
}

static void vm_succeed(CPUX86State *env)
{
    cpu_load_eflags(env, 0, ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C));
}

void helper_vm_succeed(CPUX86State *env)
{
    vm_succeed(env);
}

static void vm_fail_invalid(CPUX86State *env)
{
    cpu_load_eflags(env, 0 | CC_C, ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C));
}

static void vm_fail_valid(CPUX86State *env, uint32_t error_number)
{
    cpu_load_eflags(env, 0 | CC_Z, ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C));

    env->curr_vmcs.exit_info.vm_instruction_error = error_number;
}

static void vm_fail(CPUX86State *env, uint32_t error_number)
{
    if (env->curr_vmcs_ptr != VMX_VMCS_INVALID_PTR) {
        vm_fail_valid(env, error_number);
    } else {
        vm_fail_invalid(env);
    }
}

/*** LOADING GUEST MSRS ***/
/*** LOADING HOST MSRS ***/
int load_msrs(CPUX86State *env, uint64_t addr, int msr_count)
{
    if (msr_count) {
        error_report("WARNING: load_msrs have msrs to load (%i)\n", msr_count);
        exit(1);
    }
}

/*** SAVING GUEST MSRS ***/
void save_msrs(CPUX86State *env, uint64_t addr, int msr_count)
{
    if (msr_count) {
        error_report("WARNING: save_msrs have msrs to save (%i)\n", msr_count);
        exit(1);
    }
}

static inline void load_guest_state(CPUX86State *env)
{
    /*** LOADING GUEST STATE ***/

/*** Loading Guest Control Registers, Debug Registers, and MSRs ***/
    cpu_x86_update_cr0(env, (env->curr_vmcs.guest_state.cr0 & 0x8005002F) | (env->cr[0] & 0x7FFAFFD0));
    cpu_x86_update_cr3(env, env->curr_vmcs.guest_state.cr3);
    cpu_x86_update_cr4(env, env->curr_vmcs.guest_state.cr4);
    env->dr[7] = (env->curr_vmcs.guest_state.dr7 & 0xFFFFFFFFFFFF2FFFULL) | 0x400;
    env->sysenter_cs = env->curr_vmcs.guest_state.msr_sysenter_cs;
    env->sysenter_esp = env->curr_vmcs.guest_state.msr_sysenter_esp;
    env->sysenter_eip = env->curr_vmcs.guest_state.msr_sysenter_eip;
    //XXX: load gs, fs bases here if it is not loaded anywhere else
    env->efer = (env->efer & ~0x400) | ((IA32E_MODE_GUEST ? 1 : 0) << 10);
    env->efer = (env->efer & ~0x100) | ((IA32E_MODE_GUEST ? 1 : 0) << 8);
/** end **/

/*** Loading Guest Segment Registers and Descriptor-Table Registers ***/
    cpu_x86_load_seg_cache(env, R_CS, env->curr_vmcs.guest_state.cs.selector, env->curr_vmcs.guest_state.cs.base, env->curr_vmcs.guest_state.cs.limit, env->curr_vmcs.guest_state.cs.flags << 8);
    cpu_x86_load_seg_cache(env, R_SS, env->curr_vmcs.guest_state.ss.selector, env->curr_vmcs.guest_state.ss.base, env->curr_vmcs.guest_state.ss.limit, env->curr_vmcs.guest_state.ss.flags << 8);
    cpu_x86_load_seg_cache(env, R_DS, env->curr_vmcs.guest_state.ds.selector, env->curr_vmcs.guest_state.ds.base, env->curr_vmcs.guest_state.ds.limit, env->curr_vmcs.guest_state.ds.flags << 8);
    cpu_x86_load_seg_cache(env, R_ES, env->curr_vmcs.guest_state.es.selector, env->curr_vmcs.guest_state.es.base, env->curr_vmcs.guest_state.es.limit, env->curr_vmcs.guest_state.es.flags << 8);
    cpu_x86_load_seg_cache(env, R_FS, env->curr_vmcs.guest_state.fs.selector, env->curr_vmcs.guest_state.fs.base, env->curr_vmcs.guest_state.fs.limit, env->curr_vmcs.guest_state.fs.flags << 8);
    cpu_x86_load_seg_cache(env, R_GS, env->curr_vmcs.guest_state.gs.selector, env->curr_vmcs.guest_state.gs.base, env->curr_vmcs.guest_state.gs.limit, env->curr_vmcs.guest_state.gs.flags << 8);
    env->ldt.selector = env->curr_vmcs.guest_state.ldtr.selector;
    env->ldt.base = env->curr_vmcs.guest_state.ldtr.base;
    env->ldt.limit = env->curr_vmcs.guest_state.ldtr.limit;
    env->ldt.flags = env->curr_vmcs.guest_state.ldtr.flags << 8;
    env->tr.selector = env->curr_vmcs.guest_state.tr.selector;
    env->tr.base = env->curr_vmcs.guest_state.tr.base;
    env->tr.limit = env->curr_vmcs.guest_state.tr.limit;
    env->tr.flags = env->curr_vmcs.guest_state.tr.flags << 8;
    env->gdt.base = env->curr_vmcs.guest_state.gdtr.base;
    env->gdt.limit = env->curr_vmcs.guest_state.gdtr.limit;
    env->idt.base = env->curr_vmcs.guest_state.idtr.base;
    env->idt.limit = env->curr_vmcs.guest_state.idtr.limit;
/** end **/

/*** 26.3.2.3 Loading Guest RIP, RSP, and RFLAGS ***/
    env->eip = env->curr_vmcs.guest_state.rip;
    env->regs[R_ESP] = env->curr_vmcs.guest_state.rsp;
    cpu_load_eflags(env, env->curr_vmcs.guest_state.rflags, ~0);
/** end **/
}

static inline void save_guest_state(CPUX86State *env, uint32_t exit_reason)
{
/*** Saving Control Registers, Debug Registers, and MSRs ***/
    env->curr_vmcs.guest_state.cr0 = env->cr[0];
    env->curr_vmcs.guest_state.cr3 = env->cr[3];
    env->curr_vmcs.guest_state.cr4 = env->cr[4];
    env->curr_vmcs.guest_state.msr_sysenter_cs = env->sysenter_cs;
    env->curr_vmcs.guest_state.msr_sysenter_esp = env->sysenter_esp;
    env->curr_vmcs.guest_state.msr_sysenter_eip = env->sysenter_eip;
    if (SAVE_DEBUG_CONTROLS) {
        env->curr_vmcs.guest_state.dr7 = env->dr[7];
    }
    env->curr_vmcs.guest_state.smbase = env->smbase;

/*** Saving Segment Registers and Descriptor-Table Registers ***/
    env->curr_vmcs.guest_state.cs.selector = env->segs[R_CS].selector;
    env->curr_vmcs.guest_state.cs.base = env->segs[R_CS].base;
    env->curr_vmcs.guest_state.cs.limit = env->segs[R_CS].limit;
    env->curr_vmcs.guest_state.cs.flags = env->segs[R_CS].flags >> 8;
    env->curr_vmcs.guest_state.ss.selector = env->segs[R_SS].selector;
    env->curr_vmcs.guest_state.ss.base = env->segs[R_SS].base;
    env->curr_vmcs.guest_state.ss.limit = env->segs[R_SS].limit;
    env->curr_vmcs.guest_state.ss.flags = env->segs[R_SS].flags >> 8;
    env->curr_vmcs.guest_state.ds.selector = env->segs[R_DS].selector;
    env->curr_vmcs.guest_state.ds.base = env->segs[R_DS].base;
    env->curr_vmcs.guest_state.ds.limit = env->segs[R_DS].limit;
    env->curr_vmcs.guest_state.ds.flags = env->segs[R_DS].flags >> 8;
    env->curr_vmcs.guest_state.es.selector = env->segs[R_ES].selector;
    env->curr_vmcs.guest_state.es.base = env->segs[R_ES].base;
    env->curr_vmcs.guest_state.es.limit = env->segs[R_ES].limit;
    env->curr_vmcs.guest_state.es.flags = env->segs[R_ES].flags >> 8;
    env->curr_vmcs.guest_state.fs.selector = env->segs[R_FS].selector;
    env->curr_vmcs.guest_state.fs.base = env->segs[R_FS].base;
    env->curr_vmcs.guest_state.fs.limit = env->segs[R_FS].limit;
    env->curr_vmcs.guest_state.fs.flags = env->segs[R_FS].flags >> 8;
    env->curr_vmcs.guest_state.gs.selector = env->segs[R_GS].selector;
    env->curr_vmcs.guest_state.gs.base = env->segs[R_GS].base;
    env->curr_vmcs.guest_state.gs.limit = env->segs[R_GS].limit;
    env->curr_vmcs.guest_state.gs.flags = env->segs[R_GS].flags >> 8;
    env->curr_vmcs.guest_state.ldtr.selector = env->ldt.selector;
    env->curr_vmcs.guest_state.ldtr.base = env->ldt.base;
    env->curr_vmcs.guest_state.ldtr.limit = env->ldt.limit;
    env->curr_vmcs.guest_state.ldtr.flags = env->ldt.flags >> 8;
    env->curr_vmcs.guest_state.tr.selector = env->tr.selector;
    env->curr_vmcs.guest_state.tr.base = env->tr.base;
    env->curr_vmcs.guest_state.tr.limit = env->tr.limit;
    env->curr_vmcs.guest_state.tr.flags = env->tr.flags >> 8;
    env->curr_vmcs.guest_state.gdtr.base = env->gdt.base;
    env->curr_vmcs.guest_state.gdtr.limit = env->gdt.limit;
    env->curr_vmcs.guest_state.idtr.base = env->idt.base;
    env->curr_vmcs.guest_state.idtr.limit = env->idt.limit;

/*** Saving RIP, RSP, and RFLAGS ***/
    env->curr_vmcs.guest_state.rip = env->eip;
    env->curr_vmcs.guest_state.rsp = env->regs[R_ESP];
    env->curr_vmcs.guest_state.rflags = cpu_compute_eflags(env);
    //if exit due to instruction execution, that cause exit conditionaly
    //or not: clear bit 16

/*** Saving Non-Register State ***/
    env->curr_vmcs.guest_state.interuptibility_state = 0;
    if (env->hflags & HF_INHIBIT_IRQ_MASK) {
        if (env->hflags2 & HF2_STI_BLOCKING_MASK) {
            env->curr_vmcs.guest_state.interuptibility_state = 1;
        }
        if (env->hflags2 & HF2_MOV_SS_BLOCKING_MASK) {
            env->curr_vmcs.guest_state.interuptibility_state = 2;
        }
        env->hflags &= ~HF_INHIBIT_IRQ_MASK;
        env->hflags2 &= ~(HF2_STI_BLOCKING_MASK | HF2_MOV_SS_BLOCKING_MASK);
    }

    save_msrs(env, env->curr_vmcs.exit_control.msr_store_address, env->curr_vmcs.exit_control.msr_store_count);
}

static inline void load_host_state(CPUX86State *env)
{
/*** Loading Host Control Registers, Debug Registers, MSRs ***/
    cpu_x86_update_cr0(env, env->curr_vmcs.host_state.cr0 & 0xFFFFFFFF7FF8FFD0ULL | env->cr[0] & ~0xFFFFFFFF7FF8FFD0ULL); //FIXIT: do not modify bits fixed in VMX
    cpu_x86_update_cr3(env, env->curr_vmcs.host_state.cr3 & 0xFFFFFFFFFFULL | env->cr[3] & ~0xFFFFFFFFFFULL);
    cpu_x86_update_cr4(env, env->curr_vmcs.host_state.cr4); //FIXIT: do not modify bits fixed in VMX
    env->dr[7] = 0x400;
    env->sysenter_cs = env->curr_vmcs.host_state.msr_sysenter_cs;
    env->sysenter_esp = env->curr_vmcs.host_state.msr_sysenter_esp;
    env->sysenter_eip = env->curr_vmcs.host_state.msr_sysenter_eip;
    if (HOST_ADDRESS_SPACE_SIZE) {
        env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
    } else {
        env->efer &= ~(MSR_EFER_LMA | MSR_EFER_LME);
    }

/*** Loading Host Segment and Descriptor-Table Registers ***/
    cpu_x86_load_seg_cache(env, R_CS, env->curr_vmcs.host_state.cs_selector, 0, 0xffffffff, (11 << DESC_TYPE_SHIFT) | DESC_S_MASK | DESC_P_MASK | ((HOST_ADDRESS_SPACE_SIZE ? 1 : 0) << DESC_L_SHIFT) | ((HOST_ADDRESS_SPACE_SIZE ? 0 : 1) << DESC_B_SHIFT) | DESC_G_MASK);
    cpu_x86_load_seg_cache(env, R_SS, env->curr_vmcs.host_state.ss_selector, 0, 0xffffffff, (3 << DESC_TYPE_SHIFT) | DESC_S_MASK | DESC_P_MASK | DESC_B_MASK | DESC_G_MASK);
    cpu_x86_load_seg_cache(env, R_DS, env->curr_vmcs.host_state.ds_selector, 0, 0xffffffff, (3 << DESC_TYPE_SHIFT) | DESC_S_MASK | DESC_P_MASK | DESC_B_MASK | DESC_G_MASK);
    cpu_x86_load_seg_cache(env, R_ES, env->curr_vmcs.host_state.es_selector, 0, 0xffffffff, (3 << DESC_TYPE_SHIFT) | DESC_S_MASK | DESC_P_MASK | DESC_B_MASK | DESC_G_MASK);
    cpu_x86_load_seg_cache(env, R_FS, env->curr_vmcs.host_state.fs_selector, env->curr_vmcs.host_state.fs_base, 0xffffffff, (3 << DESC_TYPE_SHIFT) | DESC_S_MASK | DESC_P_MASK | DESC_B_MASK | DESC_G_MASK);
    cpu_x86_load_seg_cache(env, R_GS, env->curr_vmcs.host_state.gs_selector, env->curr_vmcs.host_state.gs_base, 0xffffffff, (3 << DESC_TYPE_SHIFT) | DESC_S_MASK | DESC_P_MASK | DESC_B_MASK | DESC_G_MASK);
    env->tr.selector = env->curr_vmcs.host_state.tr_selector;
    env->tr.base = env->curr_vmcs.host_state.tr_base;
    env->tr.limit = 0x67;
    env->tr.flags = (11 << DESC_TYPE_SHIFT) | DESC_P_MASK;
    env->ldt.selector = 0;
    env->ldt.base = 0; //make canonical addr (undef, but canonical)
    env->gdt.base = env->curr_vmcs.host_state.gdtr_base;
    env->gdt.limit = 0xFFFF;
    env->idt.base = env->curr_vmcs.host_state.idtr_base;
    env->idt.limit = 0xFFFF;

/*** Loading Host RIP, RSP, and RFLAGS ***/
    env->eip = env->curr_vmcs.host_state.rip;
    env->regs[R_ESP] = env->curr_vmcs.host_state.rsp;
    cpu_load_eflags(env, 0, 0xFFFFFFFF);

/*** Updating Non-Register State ***/
    env->hflags &= ~HF_INHIBIT_IRQ_MASK;
    env->hflags2 &= ~(HF2_STI_BLOCKING_MASK | HF2_MOV_SS_BLOCKING_MASK);

/*** LOADING MSRS ***/
    load_msrs(env, env->curr_vmcs.exit_control.msr_load_address, env->curr_vmcs.exit_control.msr_load_count);
}

void VMentry_failure(CPUX86State *env)
{
    //exit reason & qualification is set in appropriate places
    env->curr_vmcs.exit_info.exit_reason = env->curr_vmcs.exit_info.exit_reason | (1 << 31); // VMX_ENTRY_FAIL_INVALID_GUEST / VMX_ENTRY_FAIL_MSR_LOADING
    load_host_state(env);
    load_msrs(env, env->curr_vmcs.exit_control.msr_load_address, env->curr_vmcs.exit_control.msr_load_count);
    //may be it's needed to set flags about failure, but likely no
}

static int need_compute_instruction_length(CPUX86State *env)
{
    int int_info_type = (env->curr_vmcs.exit_info.interruption_information >> 8) & 7;
    int idt_info_type = (env->curr_vmcs.exit_info.idt_vectoring_information >> 8) & 7;
    int idt_info_valid = env->curr_vmcs.exit_info.idt_vectoring_information >> 31;
    int ts_source = (env->curr_vmcs.exit_info.exit_qualification >> 30) & 3;
    switch (env->curr_vmcs.exit_info.exit_reason) {
        case VMX_EXIT_CR_ACCESS:
        case VMX_EXIT_MOV_DR:
        case VMX_EXIT_VMCALL:
        case VMX_EXIT_VMCLEAR:
        case VMX_EXIT_VMLAUNCH:
        case VMX_EXIT_VMPTRLD:
        case VMX_EXIT_VMPTRST:
        case VMX_EXIT_VMREAD:
        case VMX_EXIT_VMRESUME:
        case VMX_EXIT_VMWRITE:
        case VMX_EXIT_VMXOFF:
        case VMX_EXIT_VMXON:
        case VMX_EXIT_RDMSR:
        case VMX_EXIT_WRMSR:
        case VMX_EXIT_CPUID:
        case VMX_EXIT_HLT:
        case VMX_EXIT_IO_INSTRUCTION:
        case VMX_EXIT_INVD:
        case VMX_EXIT_INVLPG:
        case VMX_EXIT_MONITOR:
        case VMX_EXIT_MWAIT:
        case VMX_EXIT_PAUSE:
        case VMX_EXIT_RDPMC:
        case VMX_EXIT_RDTSC:
        case VMX_EXIT_RSM:
            return 1;
        case VMX_EXIT_EXCEPTION_NMI:
            if (int_info_type == INT_TYPE_SOFT_EXCP) return 1;
            if (idt_info_valid && ((idt_info_type == INT_TYPE_SOFT_EXCP) || (idt_info_type == INT_TYPE_SOFT_INT)))
                return 1;
            break;
        case VMX_EXIT_TASK_SWITCH:
            if (ts_source != 3) return 1;
            if (idt_info_valid && ((idt_info_type == INT_TYPE_SOFT_EXCP) || (idt_info_type == INT_TYPE_SOFT_INT)))
                return 1;
            break;
        default:
            return 0;
    }
    return 0;
}

static void compute_instruction_length(CPUX86State *env)
{
    CPUState *cpu = CPU(x86_env_get_cpu(env));
    TranslationBlock *tb;
    int singlestep_tmp;
    if (need_compute_instruction_length(env)) {
        singlestep_tmp = cpu->singlestep_enabled;
        cpu->singlestep_enabled = 1;
        tb = tb_gen_code(cpu, env->eip + env->segs[R_CS].base, env->segs[R_CS].base, env->hflags |
        (cpu_compute_eflags(env) & (IOPL_MASK | TF_MASK | RF_MASK | VM_MASK | AC_MASK)), 0);
        cpu->singlestep_enabled = singlestep_tmp;
        env->curr_vmcs.exit_info.instruction_length = tb->size;
        tb_phys_invalidate(tb, -1);
        tb_free(tb);
    }
}

static void vm_exit(CPUX86State *env, uint32_t exit_reason)
{
    CPUState *cpu = CPU(x86_env_get_cpu(env));
    VMX_SET_ROOT;
    env->curr_vmcs.exit_info.exit_reason &= 0xFF;
    save_guest_state(env, exit_reason);
    compute_instruction_length(env);
    load_host_state(env);
    cpu_loop_exit_restore(cpu, GETPC());
}

void helper_vmclear(CPUX86State *env, target_ulong addr)
{
    if (VMX_NON_ROOT) {
        vm_exit(env, VMX_EXIT_VMCLEAR);
    } else if (env->hflags & HF_CPL_MASK) {
        raise_exception(env, EXCP0D_GPF);
    } else {
        if (addr & 0xFFFFFF0000000FFFULL) {
            vm_fail(env, 2);
        } else if (addr == env->vmxon_ptr) {
            vm_fail(env, 3);
        } else {
            if (env->curr_vmcs_ptr != VMX_VMCS_INVALID_PTR) {
                flush_vmcs(env, env->curr_vmcs_ptr);
            }
            env->curr_vmcs.launch_state = VMCS_CLEAR;
            flush_vmcs(env, addr);
            if (addr == env->curr_vmcs_ptr) {
                env->curr_vmcs_ptr = VMX_VMCS_INVALID_PTR;
            }
            vm_succeed(env);
        }
    }
}

void load_guest_crs_drs_msrs(CPUX86State *env)
{
    cpu_x86_update_cr0(env, (env->curr_vmcs.guest_state.cr0 & 0x8005002F) | (env->cr[0] & 0x7FFAFFD0));
    cpu_x86_update_cr3(env, env->curr_vmcs.guest_state.cr3);
    cpu_x86_update_cr4(env, env->curr_vmcs.guest_state.cr4);
    env->dr[7] = (env->curr_vmcs.guest_state.dr7 & 0xFFFFFFFFFFFF2FFFULL) | 0x400;
    env->sysenter_cs = env->curr_vmcs.guest_state.msr_sysenter_cs;
    env->sysenter_esp = env->curr_vmcs.guest_state.msr_sysenter_esp;
    env->sysenter_eip = env->curr_vmcs.guest_state.msr_sysenter_eip;
    //XXX: load gs, fs bases here if it is not loaded anywhere else
    env->efer = (env->efer & ~0x400) | ((IA32E_MODE_GUEST ? 1 : 0) << 10);
    env->efer = (env->efer & ~0x100) | ((IA32E_MODE_GUEST ? 1 : 0) << 8);
}

void load_guest_segments_and_dt_regs(CPUX86State *env)
{
    cpu_x86_load_seg_cache(env, R_CS, env->curr_vmcs.guest_state.cs.selector, env->curr_vmcs.guest_state.cs.base, env->curr_vmcs.guest_state.cs.limit, env->curr_vmcs.guest_state.cs.flags << 8);
    cpu_x86_load_seg_cache(env, R_SS, env->curr_vmcs.guest_state.ss.selector, env->curr_vmcs.guest_state.ss.base, env->curr_vmcs.guest_state.ss.limit, env->curr_vmcs.guest_state.ss.flags << 8);
    cpu_x86_load_seg_cache(env, R_DS, env->curr_vmcs.guest_state.ds.selector, env->curr_vmcs.guest_state.ds.base, env->curr_vmcs.guest_state.ds.limit, env->curr_vmcs.guest_state.ds.flags << 8);
    cpu_x86_load_seg_cache(env, R_ES, env->curr_vmcs.guest_state.es.selector, env->curr_vmcs.guest_state.es.base, env->curr_vmcs.guest_state.es.limit, env->curr_vmcs.guest_state.es.flags << 8);
    cpu_x86_load_seg_cache(env, R_FS, env->curr_vmcs.guest_state.fs.selector, env->curr_vmcs.guest_state.fs.base, env->curr_vmcs.guest_state.fs.limit, env->curr_vmcs.guest_state.fs.flags << 8);
    cpu_x86_load_seg_cache(env, R_GS, env->curr_vmcs.guest_state.gs.selector, env->curr_vmcs.guest_state.gs.base, env->curr_vmcs.guest_state.gs.limit, env->curr_vmcs.guest_state.gs.flags << 8);
    env->ldt.selector = env->curr_vmcs.guest_state.ldtr.selector;
    env->ldt.base = env->curr_vmcs.guest_state.ldtr.base;
    env->ldt.limit = env->curr_vmcs.guest_state.ldtr.limit;
    env->ldt.flags = env->curr_vmcs.guest_state.ldtr.flags << 8;
    env->tr.selector = env->curr_vmcs.guest_state.tr.selector;
    env->tr.base = env->curr_vmcs.guest_state.tr.base;
    env->tr.limit = env->curr_vmcs.guest_state.tr.limit;
    env->tr.flags = env->curr_vmcs.guest_state.tr.flags << 8;
    env->gdt.base = env->curr_vmcs.guest_state.gdtr.base;
    env->gdt.limit = env->curr_vmcs.guest_state.gdtr.limit;
    env->idt.base = env->curr_vmcs.guest_state.idtr.base;
    env->idt.limit = env->curr_vmcs.guest_state.idtr.limit;
}

void load_guest_rip_rsp_rflags(CPUX86State *env)
{
    env->eip = env->curr_vmcs.guest_state.rip;
    env->regs[R_ESP] = env->curr_vmcs.guest_state.rsp;
    cpu_load_eflags(env, env->curr_vmcs.guest_state.rflags, ~0);
}

int check_and_load_guest_state(CPUX86State *env)
{
    
    load_guest_crs_drs_msrs(env);
    load_guest_segments_and_dt_regs(env);
    load_guest_rip_rsp_rflags(env);
    if (env->curr_vmcs.guest_state.interuptibility_state) {
        env->hflags |= HF_INHIBIT_IRQ_MASK;
        if (env->curr_vmcs.guest_state.interuptibility_state == 1) {
            env->hflags2 |= HF2_STI_BLOCKING_SHIFT;
        } else if (env->curr_vmcs.guest_state.interuptibility_state == 2) {
            env->hflags2 |= HF2_MOV_SS_BLOCKING_SHIFT;
        } else {
            error_report("unimplemented interruptibility state\n");
            exit(1);
        }
    }
    
    return 0;
}

void event_injection(CPUX86State *env)
{
    int vector = env->curr_vmcs.entry_control.interruption_information & 0xFF;
    int interuption_type = env->curr_vmcs.entry_control.interruption_information & (7 << 8);
    int deliver_error_code = env->curr_vmcs.entry_control.interruption_information & (1 << 11);
    int valid = env->curr_vmcs.entry_control.interruption_information & (1 << 31);
    if (!valid) {
        if (env->curr_vmcs.guest_state.interuptibility_state & 3) {
            env->hflags |= HF_INHIBIT_IRQ_MASK;
            if (env->curr_vmcs.guest_state.interuptibility_state & 1) {
                env->hflags2 |= HF2_STI_BLOCKING_MASK;
            }
            else if (env->curr_vmcs.guest_state.interuptibility_state & 2) {
                env->hflags2 |= HF2_MOV_SS_BLOCKING_MASK;
            }
        }
        return;
    }

    error_report("WARNING: event injection, but it's not realized yet\n");
    exit(1);
}

void helper_vmlaunch_vmresume(CPUX86State *env, target_ulong vm_op)
{
    if (VMX_NON_ROOT) {
        vm_exit(env, (vm_op == 2) ? VMX_EXIT_VMLAUNCH : VMX_EXIT_VMRESUME);
    } else if (env->hflags & HF_CPL_MASK) {
        raise_exception(env, EXCP0D_GPF);
    } else if (env->curr_vmcs_ptr == VMX_VMCS_INVALID_PTR) {
        vm_fail_invalid(env);
    } else if (env->hflags2 & HF2_MOV_SS_BLOCKING_MASK) {
        vm_fail_valid(env, 26);
    } else if ((vm_op == 2) && (env->curr_vmcs.launch_state != VMCS_CLEAR)) {
        vm_fail_valid(env, 4);
    } else if ((vm_op == 3) && (env->curr_vmcs.launch_state != VMCS_LAUNCHED)) {
        vm_fail_valid(env, 5);
    } else {
        if (check_and_load_guest_state(env)) {
            env->curr_vmcs.exit_info.exit_reason = VMX_ENTRY_FAIL_INVALID_GUEST;
            env->curr_vmcs.exit_info.exit_qualification = 0;
            VMentry_failure(env);
        } else {
            if (load_msrs(env, env->curr_vmcs.entry_control.msr_load_address, env->curr_vmcs.entry_control.msr_load_count))
                VMentry_failure(env);
            else {
                if (vm_op == 2)
                    env->curr_vmcs.launch_state = VMCS_LAUNCHED;
                if ((env->hflags & HF_SMM_MASK) && !ENTRY_TO_SMM) {
                    error_report("WARNING: vmlaunch/resume in SMM, unrealized feature\n");
                    // complete it later
                }
                nested_exception = 0;
                env->curr_vmcs.exit_info.interruption_information = 0;
                env->vmx_int_icount = 0;
                event_injection(env); //(set interrupt params, let qemu do rest from cpu-exec)
                VMX_SET_GUEST;
            }
        }
    }
}

void helper_vmptrld(CPUX86State *env, target_ulong addr)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    uint32_t rev_id = 0;

    if (VMX_NON_ROOT) {
        vm_exit(env, 0);
    } else if (env->hflags & HF_CPL_MASK) {
        raise_exception(env, EXCP0D_GPF);
    } else {
        if (addr & 0xFFFFFF0000000FFFULL) {
            vm_fail(env, 9);
        } else if (addr == env->vmxon_ptr) {
            vm_fail(env, 10);
        } else {
            rev_id = ldl_phys(cs->as, addr);
            if (rev_id != VMX_MSR_VMX_BASIC_VMCS_REVISION_ID) {
                vm_fail(env, 11);
            } else {
                env->curr_vmcs_ptr = addr;
                vm_succeed(env);
            }
        }
    }
}

void helper_vmptrst(CPUX86State *env, target_ulong addr)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    uint32_t rev_id = 0;

    if (VMX_NON_ROOT) {
        vm_exit(env, 0);
    } else if (env->hflags & HF_CPL_MASK) {
        raise_exception(env, EXCP0D_GPF);
    } else {
        stq_phys(cs->as, addr, env->curr_vmcs_ptr);
        vm_succeed(env);
    }
}

target_ulong helper_vmread(CPUX86State *env, target_ulong encoding)
{
    uint64_t value = 0;
    if (VMX_NON_ROOT) {
        vm_exit(env, 0);
    } else if (env->hflags & HF_CPL_MASK) {
        raise_exception(env, EXCP0D_GPF);
    } else if (VMX_ROOT && (env->curr_vmcs_ptr == VMX_VMCS_INVALID_PTR)) {
        vm_fail_invalid(env);
    } else {
        switch (encoding) {
            //16-bit
            case GUEST_ES_SELECTOR:
                value = env->curr_vmcs.guest_state.es.selector;
                break;
            case GUEST_CS_SELECTOR:
                value = env->curr_vmcs.guest_state.cs.selector;
                break;
            case GUEST_SS_SELECTOR:
                value = env->curr_vmcs.guest_state.ss.selector;
                break;
            case GUEST_DS_SELECTOR:
                value = env->curr_vmcs.guest_state.ds.selector;
                break;
            case GUEST_FS_SELECTOR:
                value = env->curr_vmcs.guest_state.fs.selector;
                break;
            case GUEST_GS_SELECTOR:
                value = env->curr_vmcs.guest_state.gs.selector;
                break;
            case GUEST_LDTR_SELECTOR:
                value = env->curr_vmcs.guest_state.ldtr.selector;
                break;
            case GUEST_TR_SELECTOR:
                value = env->curr_vmcs.guest_state.tr.selector;
                break;
            case HOST_ES_SELECTOR:
                value = env->curr_vmcs.host_state.es_selector;
                break;
            case HOST_CS_SELECTOR:
                value = env->curr_vmcs.host_state.cs_selector;
                break;
            case HOST_SS_SELECTOR:
                value = env->curr_vmcs.host_state.ss_selector;
                break;
            case HOST_DS_SELECTOR:
                value = env->curr_vmcs.host_state.ds_selector;
                break;
            case HOST_FS_SELECTOR:
                value = env->curr_vmcs.host_state.fs_selector;
                break;
            case HOST_GS_SELECTOR:
                value = env->curr_vmcs.host_state.gs_selector;
                break;
            case HOST_TR_SELECTOR:
                value = env->curr_vmcs.host_state.tr_selector;
                break;
            //64-bit
            case ADDRESS_OF_IO_BITMAP_A_FULL:
                value = env->curr_vmcs.exec_control.io_bitmap_a;
                break;
            case ADDRESS_OF_IO_BITMAP_A_HIGH:
                value = env->curr_vmcs.exec_control.io_bitmap_a >> 32;
                break;
            case ADDRESS_OF_IO_BITMAP_B_FULL:
                value = env->curr_vmcs.exec_control.io_bitmap_b;
                break;
            case ADDRESS_OF_IO_BITMAP_B_HIGH:
                value = env->curr_vmcs.exec_control.io_bitmap_b >> 32;
                break;
            case ADDRESS_OF_MSR_BITMAPS_FULL:
                value = env->curr_vmcs.exec_control.msr_bitmap_address;
                break;
            case ADDRESS_OF_MSR_BITMAPS_HIGH:
                value = env->curr_vmcs.exec_control.msr_bitmap_address >> 32;
                break;
            case VM_EXIT_MSR_STORE_ADDRESS_FULL:
                value = env->curr_vmcs.exit_control.msr_store_address;
                break;
            case VM_EXIT_MSR_STORE_ADDRESS_HIGH:
                value = env->curr_vmcs.exit_control.msr_store_address >> 32;
                break;
            case VM_EXIT_MSR_LOAD_ADDRESS_FULL:
                value = env->curr_vmcs.exit_control.msr_load_address;
                break;
            case VM_EXIT_MSR_LOAD_ADDRESS_HIGH:
                value = env->curr_vmcs.exit_control.msr_load_address >> 32;
                break;
            case VM_ENTRY_MSR_LOAD_ADDRESS_FULL:
                value = env->curr_vmcs.entry_control.msr_load_address;
                break;
            case VM_ENTRY_MSR_LOAD_ADDRESS_HIGH:
                value = env->curr_vmcs.entry_control.msr_load_address >> 32;
                break;
            case EXECUTIVE_VMCS_POINTER_FULL:
                value = env->curr_vmcs.exec_control.executive_vmcs_pointer;
                break;
            case EXECUTIVE_VMCS_POINTER_HIGH:
                value = env->curr_vmcs.exec_control.executive_vmcs_pointer >> 32;
                break;
            case TSC_OFFSET_FULL:
                value = env->curr_vmcs.exec_control.tsc_offset;
                break;
            case TSC_OFFSET_HIGH:
                value = env->curr_vmcs.exec_control.tsc_offset >> 32;
                break;
            case VIRTUAL_APIC_ADDRESS_FULL:
                value = env->curr_vmcs.exec_control.virtual_apic_page_address;
                break;
            case VIRTUAL_APIC_ADDRESS_HIGH:
                value = env->curr_vmcs.exec_control.virtual_apic_page_address >> 32;
                break;
            case VMCS_LINK_POINTER_FULL:
                value = env->curr_vmcs.guest_state.vmcs_link_pointer;
                break;
            case VMCS_LINK_POINTER_HIGH:
                value = env->curr_vmcs.guest_state.vmcs_link_pointer >> 32;
                break;
            case GUEST_IA32_DEBUGCTL_FULL:
                value = env->curr_vmcs.guest_state.msr_debugctl;
                break;
            case GUEST_IA32_DEBUGCTL_HIGH:
                value = env->curr_vmcs.guest_state.msr_debugctl >> 32;
                break;      
            //32-bit
            case PIN_BASED_VM_EXECUTION_CONTROLS:
                value = env->curr_vmcs.exec_control.pin_based_controls;
                break;
            case PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS:
                value = env->curr_vmcs.exec_control.processor_based_controls;
                break;
            case EXCEPTION_BITMAP:
                value = env->curr_vmcs.exec_control.exception_bitmap;
                break;
            case PAGE_FAULT_ERROR_CODE_MASK:
                value = env->curr_vmcs.exec_control.page_fault_error_code_mask;
                break;
            case PAGE_FAULT_ERROR_CODE_MATCH:
                value = env->curr_vmcs.exec_control.page_fault_error_code_match;
                break;
            case CR3_TARGET_COUNT:
                value = env->curr_vmcs.exec_control.cr3_target_count;
                break;
            case VM_EXIT_CONTROLS:
                value = env->curr_vmcs.exit_control.controls;
                break;
            case VM_EXIT_MSR_STORE_COUNT:
                value = env->curr_vmcs.exit_control.msr_store_count;
                break;
            case VM_EXIT_MSR_LOAD_COUNT:
                value = env->curr_vmcs.exit_control.msr_load_count;
                break;
            case VM_ENTRY_CONTROLS:
                value = env->curr_vmcs.entry_control.controls;
                break;
            case VM_ENTRY_MSR_LOAD_COUNT:
                value = env->curr_vmcs.entry_control.msr_load_count;
                break;
            case VM_ENTRY_INTERRUPTION_INFORMATION:
                value = env->curr_vmcs.entry_control.interruption_information;
                break;
            case VM_ENTRY_EXCEPTION_ERROR_CODE:
                value = env->curr_vmcs.entry_control.exception_error_code;
                break;
            case VM_ENTRY_INSTRUCTION_LENGTH:
                value = env->curr_vmcs.entry_control.instruction_length;
                break;
            case TPR_THRESHOLD:
                value = env->curr_vmcs.exec_control.tpr_threshold;
                break;
            case VM_INSTRUCTION_ERROR:
                value = env->curr_vmcs.exit_info.vm_instruction_error;
                break;
            case EXIT_REASON:
                value = env->curr_vmcs.exit_info.exit_reason;
                break;
            case VM_EXIT_INTERRUPTION_INFORMATION:
                value = env->curr_vmcs.exit_info.interruption_information;
                break;
            case VM_EXIT_INTERRUPTION_ERROR_CODE:
                value = env->curr_vmcs.exit_info.interruption_error_code;
                break;
            case IDT_VECTORING_INFORMFTION_FIELD:
                value = env->curr_vmcs.exit_info.idt_vectoring_information;
                break;
            case IDT_VECTORING_ERROR_CODE:
                value = env->curr_vmcs.exit_info.idt_vectoring_error_code;
                break;
            case VM_EXIT_INSTRUCTION_LENGTH:
                value = env->curr_vmcs.exit_info.instruction_length;
                break;
            case VM_EXIT_INSTRUCTION_INFORMATION:
                value = env->curr_vmcs.exit_info.instruction_information;
                break;   
            case GUEST_ES_LIMIT:
                value = env->curr_vmcs.guest_state.es.limit;
                break;
            case GUEST_CS_LIMIT:
                value = env->curr_vmcs.guest_state.cs.limit;
                break;
            case GUEST_SS_LIMIT:
                value = env->curr_vmcs.guest_state.ss.limit;
                break;
            case GUEST_DS_LIMIT:
                value = env->curr_vmcs.guest_state.ds.limit;
                break;
            case GUEST_FS_LIMIT:
                value = env->curr_vmcs.guest_state.fs.limit;
                break;
            case GUEST_GS_LIMIT:
                value = env->curr_vmcs.guest_state.gs.limit;
                break;
            case GUEST_LDTR_LIMIT:
                value = env->curr_vmcs.guest_state.ldtr.limit;
                break;
            case GUEST_TR_LIMIT:
                value = env->curr_vmcs.guest_state.tr.limit;
                break;
            case GUEST_GDTR_LIMIT:
                value = env->curr_vmcs.guest_state.gdtr.limit;
                break;
            case GUEST_IDTR_LIMIT:
                value = env->curr_vmcs.guest_state.idtr.limit;
                break;
            case GUEST_ES_ACCESS_RIGHTS:
                value = env->curr_vmcs.guest_state.es.flags;
                break;
            case GUEST_CS_ACCESS_RIGHTS:
                value = env->curr_vmcs.guest_state.cs.flags;
                break;
            case GUEST_SS_ACCESS_RIGHTS:
                value = env->curr_vmcs.guest_state.ss.flags;
                break;
            case GUEST_DS_ACCESS_RIGHTS:
                value = env->curr_vmcs.guest_state.ds.flags;
                break;
            case GUEST_FS_ACCESS_RIGHTS:
                value = env->curr_vmcs.guest_state.fs.flags;
                break;
            case GUEST_GS_ACCESS_RIGHTS:
                value = env->curr_vmcs.guest_state.gs.flags;
                break;
            case GUEST_LDTR_ACCESS_RIGHTS:
                value = env->curr_vmcs.guest_state.ldtr.flags;
                break;
            case GUEST_TR_ACCESS_RIGHTS:
                value = env->curr_vmcs.guest_state.tr.flags;
                break;
            case GUEST_INTERRUPTIBILITY_STATE:
                value = env->curr_vmcs.guest_state.interuptibility_state;
                break;
            case GUEST_ACTIVITY_STATE:
                value = env->curr_vmcs.guest_state.activity_state;
                break;
            case GUEST_IA32_SYSENTER_CS:
                value = env->curr_vmcs.guest_state.msr_sysenter_cs;
                break;
            case HOST_IA32_SYSENTER_CS:
                value = env->curr_vmcs.host_state.msr_sysenter_cs;
                break;
            // natural-width fields
            case CR0_GUEST_HOST_MASK:
                value = env->curr_vmcs.exec_control.cr0_guest_host_mask;
                break;
            case CR4_GUEST_HOST_MASK:
                value = env->curr_vmcs.exec_control.cr4_guest_host_mask;
                break;
            case CR0_READ_SHADOW:
                value = env->curr_vmcs.exec_control.cr0_read_shadow;
                break;
            case CR4_READ_SHADOW:
                value = env->curr_vmcs.exec_control.cr4_read_shadow;
                break;
            case CR3_TARGET_VALUE_0:
                value = env->curr_vmcs.exec_control.cr3_target_value[0];
                break;
            case CR3_TARGET_VALUE_1:
                value = env->curr_vmcs.exec_control.cr3_target_value[1];
                break;
            case CR3_TARGET_VALUE_2:
                value = env->curr_vmcs.exec_control.cr3_target_value[2];
                break;
            case CR3_TARGET_VALUE_3:
                value = env->curr_vmcs.exec_control.cr3_target_value[3];
                break;
            case EXIT_QUALIFICATION:
                value = env->curr_vmcs.exit_info.exit_qualification;
                break;
            case IO_RCX:
                value = env->curr_vmcs.exit_info.io_rcx;
                break;
            case IO_RSI:
                value = env->curr_vmcs.exit_info.io_rsi;
                break;
            case IO_RDI:
                value = env->curr_vmcs.exit_info.io_rdi;
                break;
            case IO_RIP:
                value = env->curr_vmcs.exit_info.io_rip;
                break;
            case GUEST_LINEAR_ADDRESS:
                value = env->curr_vmcs.exit_info.guest_linear_address;
                break;
            case GUEST_CR0:
                value = env->curr_vmcs.guest_state.cr0;
                break;
            case GUEST_CR3:
                value = env->curr_vmcs.guest_state.cr3;
                break;
            case GUEST_CR4:
                value = env->curr_vmcs.guest_state.cr4;
                break;
            case GUEST_ES_BASE:
                value = env->curr_vmcs.guest_state.es.base;
                break;
            case GUEST_CS_BASE:
                value = env->curr_vmcs.guest_state.cs.base;
                break;
            case GUEST_SS_BASE:
                value = env->curr_vmcs.guest_state.ss.base;
                break;
            case GUEST_DS_BASE:
                value = env->curr_vmcs.guest_state.ds.base;
                break;
            case GUEST_FS_BASE:
                value = env->curr_vmcs.guest_state.fs.base;
                break;
            case GUEST_GS_BASE:
                value = env->curr_vmcs.guest_state.gs.base;
                break;
            case GUEST_LDTR_BASE:
                value = env->curr_vmcs.guest_state.ldtr.base;
                break;
            case GUEST_TR_BASE:
                value = env->curr_vmcs.guest_state.tr.base;
                break;
            case GUEST_GDTR_BASE:
                value = env->curr_vmcs.guest_state.gdtr.base;
                break;
            case GUEST_IDTR_BASE:
                value = env->curr_vmcs.guest_state.idtr.base;
                break;
            case GUEST_DR7:
                value = env->curr_vmcs.guest_state.dr7;
                break;
            case GUEST_RSP:
                value = env->curr_vmcs.guest_state.rsp;
                break;
            case GUEST_RIP:
                value = env->curr_vmcs.guest_state.rip;
                break;
            case GUEST_RFLAGS:
                value = env->curr_vmcs.guest_state.rflags;
                break;
            case GUEST_PENDING_DEBUG_EXCEPTIONS:
                value = env->curr_vmcs.guest_state.pending_debug_exceptions;
                break;
            case GUEST_IA32_SYSENTER_ESP:
                value = env->curr_vmcs.guest_state.msr_sysenter_esp;
                break;
            case GUEST_IA32_SYSENTER_EIP:
                value = env->curr_vmcs.guest_state.msr_sysenter_eip;
                break;
            case HOST_CR0:
                value = env->curr_vmcs.host_state.cr0;
                break;
            case HOST_CR3:
                value = env->curr_vmcs.host_state.cr3;
                break;
            case HOST_CR4:
                value = env->curr_vmcs.host_state.cr4;
                break;
            case HOST_FS_BASE:
                value = env->curr_vmcs.host_state.fs_base;
                break;
            case HOST_GS_BASE:
                value = env->curr_vmcs.host_state.gs_base;
                break;
            case HOST_TR_BASE:
                value = env->curr_vmcs.host_state.tr_base;
                break;
            case HOST_GDTR_BASE:
                value = env->curr_vmcs.host_state.gdtr_base;
                break;
            case HOST_IDTR_BASE:
                value = env->curr_vmcs.host_state.idtr_base;
                break;
            case HOST_IA32_SYSENTER_ESP:
                value = env->curr_vmcs.host_state.msr_sysenter_esp;
                break;
            case HOST_IA32_SYSENTER_EIP:
                value = env->curr_vmcs.host_state.msr_sysenter_eip;
                break;
            case HOST_RSP:
                value = env->curr_vmcs.host_state.rsp;
                break;
            case HOST_RIP:
                value = env->curr_vmcs.host_state.rip;
                break;
            default:
                vm_fail_valid(env, 12);
        }
    }
    return value;
}

void helper_vmwrite(CPUX86State *env, target_ulong encoding, target_ulong value)
{
    if (VMX_NON_ROOT) {
        vm_exit(env, 0);
    } else if (env->hflags & HF_CPL_MASK) {
        raise_exception(env, EXCP0D_GPF);
    } else if (VMX_ROOT && (env->curr_vmcs_ptr == VMX_VMCS_INVALID_PTR)) {
        vm_fail_invalid(env);
    } else {
        switch (encoding) {
            //16-bit
            case GUEST_ES_SELECTOR:
                env->curr_vmcs.guest_state.es.selector = (uint16_t) value;
                break;
            case GUEST_CS_SELECTOR:
                env->curr_vmcs.guest_state.cs.selector = (uint16_t) value;
                break;
            case GUEST_SS_SELECTOR:
                env->curr_vmcs.guest_state.ss.selector = (uint16_t) value;
                break;
            case GUEST_DS_SELECTOR:
                env->curr_vmcs.guest_state.ds.selector = (uint16_t) value;
                break;
            case GUEST_FS_SELECTOR:
                env->curr_vmcs.guest_state.fs.selector = (uint16_t) value;
                break;
            case GUEST_GS_SELECTOR:
                env->curr_vmcs.guest_state.gs.selector = (uint16_t) value;
                break;
            case GUEST_LDTR_SELECTOR:
                env->curr_vmcs.guest_state.ldtr.selector = (uint16_t) value;
                break;
            case GUEST_TR_SELECTOR:
                env->curr_vmcs.guest_state.tr.selector = (uint16_t) value;
                break;
            case HOST_ES_SELECTOR:
                env->curr_vmcs.host_state.es_selector = (uint16_t) value;
                break;
            case HOST_CS_SELECTOR:
                env->curr_vmcs.host_state.cs_selector = (uint16_t) value;
                break;
            case HOST_SS_SELECTOR:
                env->curr_vmcs.host_state.ss_selector = (uint16_t) value;
                break;
            case HOST_DS_SELECTOR:
                env->curr_vmcs.host_state.ds_selector = (uint16_t) value;
                break;
            case HOST_FS_SELECTOR:
                env->curr_vmcs.host_state.fs_selector = (uint16_t) value;
                break;
            case HOST_GS_SELECTOR:
                env->curr_vmcs.host_state.gs_selector = (uint16_t) value;
                break;
            case HOST_TR_SELECTOR:
                env->curr_vmcs.host_state.tr_selector = (uint16_t) value;
                break;
            //64-bit
            case ADDRESS_OF_IO_BITMAP_A_FULL:
                env->curr_vmcs.exec_control.io_bitmap_a = value;
                env->curr_vmcs.exec_control.io_bitmap_a &= 0xFFFFFFFF;
                break;
            case ADDRESS_OF_IO_BITMAP_A_HIGH:
                env->curr_vmcs.exec_control.io_bitmap_a &= 0xFFFFFFFF;
                env->curr_vmcs.exec_control.io_bitmap_a |= (value << 32);
                break;
            case ADDRESS_OF_IO_BITMAP_B_FULL:
                env->curr_vmcs.exec_control.io_bitmap_b = value;
                env->curr_vmcs.exec_control.io_bitmap_b &= 0xFFFFFFFF;
                break;
            case ADDRESS_OF_IO_BITMAP_B_HIGH:
                env->curr_vmcs.exec_control.io_bitmap_b &= 0xFFFFFFFF;
                env->curr_vmcs.exec_control.io_bitmap_b |= (value << 32);
                break;
            case ADDRESS_OF_MSR_BITMAPS_FULL:
                env->curr_vmcs.exec_control.msr_bitmap_address = value;
                env->curr_vmcs.exec_control.msr_bitmap_address &= 0xFFFFFFFF;
                break;
            case ADDRESS_OF_MSR_BITMAPS_HIGH:
                env->curr_vmcs.exec_control.msr_bitmap_address &= 0xFFFFFFFF;
                env->curr_vmcs.exec_control.msr_bitmap_address |= (value << 32);
                break;
            case VM_EXIT_MSR_STORE_ADDRESS_FULL:
                env->curr_vmcs.exit_control.msr_store_address = value;
                env->curr_vmcs.exit_control.msr_store_address &= 0xFFFFFFFF;
                break;
            case VM_EXIT_MSR_STORE_ADDRESS_HIGH:
                env->curr_vmcs.exit_control.msr_store_address &= 0xFFFFFFFF;
                env->curr_vmcs.exit_control.msr_store_address |= (value << 32);
                break;
            case VM_EXIT_MSR_LOAD_ADDRESS_FULL:
                env->curr_vmcs.exit_control.msr_load_address = value;
                env->curr_vmcs.exit_control.msr_load_address &= 0xFFFFFFFF;
                break;
            case VM_EXIT_MSR_LOAD_ADDRESS_HIGH:
                env->curr_vmcs.exit_control.msr_load_address &= 0xFFFFFFFF;
                env->curr_vmcs.exit_control.msr_load_address |= (value << 32);
                break;
            case VM_ENTRY_MSR_LOAD_ADDRESS_FULL:
                env->curr_vmcs.entry_control.msr_load_address = value;
                env->curr_vmcs.entry_control.msr_load_address &= 0xFFFFFFFF;
                break;
            case VM_ENTRY_MSR_LOAD_ADDRESS_HIGH:
                env->curr_vmcs.entry_control.msr_load_address &= 0xFFFFFFFF;
                env->curr_vmcs.entry_control.msr_load_address |= (value << 32);
                break;
            case EXECUTIVE_VMCS_POINTER_FULL:
                env->curr_vmcs.exec_control.executive_vmcs_pointer = value;
                env->curr_vmcs.exec_control.executive_vmcs_pointer = value;
                break;
            case EXECUTIVE_VMCS_POINTER_HIGH:
                env->curr_vmcs.exec_control.executive_vmcs_pointer &= 0xFFFFFFFF;
                env->curr_vmcs.exec_control.executive_vmcs_pointer |= (value << 32);
                break;
            case TSC_OFFSET_FULL:
                env->curr_vmcs.exec_control.tsc_offset = value;
                env->curr_vmcs.exec_control.tsc_offset &= 0xFFFFFFFF;
                break;
            case TSC_OFFSET_HIGH:
                env->curr_vmcs.exec_control.tsc_offset &= 0xFFFFFFFF;
                env->curr_vmcs.exec_control.tsc_offset |= (value << 32);
                break;
            case VIRTUAL_APIC_ADDRESS_FULL:
                env->curr_vmcs.exec_control.virtual_apic_page_address = value;
                env->curr_vmcs.exec_control.virtual_apic_page_address &= 0xFFFFFFFF;
                break;
            case VIRTUAL_APIC_ADDRESS_HIGH:
                env->curr_vmcs.exec_control.virtual_apic_page_address &= 0xFFFFFFFF;
                env->curr_vmcs.exec_control.virtual_apic_page_address |= (value << 32);
                break;
            case VMCS_LINK_POINTER_FULL:
                env->curr_vmcs.guest_state.vmcs_link_pointer = value;
                env->curr_vmcs.guest_state.vmcs_link_pointer &= 0xFFFFFFFF;
                break;
            case VMCS_LINK_POINTER_HIGH:
                env->curr_vmcs.guest_state.vmcs_link_pointer &= 0xFFFFFFFF;
                env->curr_vmcs.guest_state.vmcs_link_pointer |= (value << 32);
                break;
            case GUEST_IA32_DEBUGCTL_FULL:
                env->curr_vmcs.guest_state.msr_debugctl = value;
                env->curr_vmcs.guest_state.msr_debugctl &= 0xFFFFFFFF;
                break;
            case GUEST_IA32_DEBUGCTL_HIGH:
                env->curr_vmcs.guest_state.msr_debugctl &= 0xFFFFFFFF;
                env->curr_vmcs.guest_state.msr_debugctl |= (value << 32);
                break;      
            //32-bit
            case PIN_BASED_VM_EXECUTION_CONTROLS:
                env->curr_vmcs.exec_control.pin_based_controls = (uint32_t) value;
                break;
            case PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS:
                env->curr_vmcs.exec_control.processor_based_controls = (uint32_t) value;
                break;
            case EXCEPTION_BITMAP:
                env->curr_vmcs.exec_control.exception_bitmap = (uint32_t) value;
                break;
            case PAGE_FAULT_ERROR_CODE_MASK:
                env->curr_vmcs.exec_control.page_fault_error_code_mask = (uint32_t) value;
                break;
            case PAGE_FAULT_ERROR_CODE_MATCH:
                env->curr_vmcs.exec_control.page_fault_error_code_match = (uint32_t) value;
                break;
            case CR3_TARGET_COUNT:
                env->curr_vmcs.exec_control.cr3_target_count = (uint32_t) value;
                break;
            case VM_EXIT_CONTROLS:
                env->curr_vmcs.exit_control.controls = (uint32_t) value;
                break;
            case VM_EXIT_MSR_STORE_COUNT:
                env->curr_vmcs.exit_control.msr_store_count = (uint32_t) value;
                break;
            case VM_EXIT_MSR_LOAD_COUNT:
                env->curr_vmcs.exit_control.msr_load_count = (uint32_t) value;
                break;
            case VM_ENTRY_CONTROLS:
                env->curr_vmcs.entry_control.controls = (uint32_t) value;
                break;
            case VM_ENTRY_MSR_LOAD_COUNT:
                env->curr_vmcs.entry_control.msr_load_count = (uint32_t) value;
                break;
            case VM_ENTRY_INTERRUPTION_INFORMATION:
                env->curr_vmcs.entry_control.interruption_information = (uint32_t) value;
                break;
            case VM_ENTRY_EXCEPTION_ERROR_CODE:
                env->curr_vmcs.entry_control.exception_error_code = (uint32_t) value;
                break;
            case VM_ENTRY_INSTRUCTION_LENGTH:
                env->curr_vmcs.entry_control.instruction_length = (uint32_t) value;
                break;
            case TPR_THRESHOLD:
                env->curr_vmcs.exec_control.tpr_threshold = (uint32_t) value;
                break;
            case VM_INSTRUCTION_ERROR:
                env->curr_vmcs.exit_info.vm_instruction_error = (uint32_t) value;
                break;
            case EXIT_REASON:
                env->curr_vmcs.exit_info.exit_reason = (uint32_t) value;
                break;
            case VM_EXIT_INTERRUPTION_INFORMATION:
                env->curr_vmcs.exit_info.interruption_information = (uint32_t) value;
                break;
            case VM_EXIT_INTERRUPTION_ERROR_CODE:
                env->curr_vmcs.exit_info.interruption_error_code = (uint32_t) value;
                break;
            case IDT_VECTORING_INFORMFTION_FIELD:
                env->curr_vmcs.exit_info.idt_vectoring_information = (uint32_t) value;
                break;
            case IDT_VECTORING_ERROR_CODE:
                env->curr_vmcs.exit_info.idt_vectoring_error_code = (uint32_t) value;
                break;
            case VM_EXIT_INSTRUCTION_LENGTH:
                env->curr_vmcs.exit_info.instruction_length = (uint32_t) value;
                break;
            case VM_EXIT_INSTRUCTION_INFORMATION:
                env->curr_vmcs.exit_info.instruction_information = (uint32_t) value;
                break;   
            case GUEST_ES_LIMIT:
                env->curr_vmcs.guest_state.es.limit = (uint32_t) value;
                break;
            case GUEST_CS_LIMIT:
                env->curr_vmcs.guest_state.cs.limit = (uint32_t) value;
                break;
            case GUEST_SS_LIMIT:
                env->curr_vmcs.guest_state.ss.limit = (uint32_t) value;
                break;
            case GUEST_DS_LIMIT:
                env->curr_vmcs.guest_state.ds.limit = (uint32_t) value;
                break;
            case GUEST_FS_LIMIT:
                env->curr_vmcs.guest_state.fs.limit = (uint32_t) value;
                break;
            case GUEST_GS_LIMIT:
                env->curr_vmcs.guest_state.gs.limit = (uint32_t) value;
                break;
            case GUEST_LDTR_LIMIT:
                env->curr_vmcs.guest_state.ldtr.limit = (uint32_t) value;
                break;
            case GUEST_TR_LIMIT:
                env->curr_vmcs.guest_state.tr.limit = (uint32_t) value;
                break;
            case GUEST_GDTR_LIMIT:
                env->curr_vmcs.guest_state.gdtr.limit = (uint32_t) value;
                break;
            case GUEST_IDTR_LIMIT:
                env->curr_vmcs.guest_state.idtr.limit = (uint32_t) value;
                break;
            case GUEST_ES_ACCESS_RIGHTS:
                env->curr_vmcs.guest_state.es.flags = (uint32_t) value;
                break;
            case GUEST_CS_ACCESS_RIGHTS:
                env->curr_vmcs.guest_state.cs.flags = (uint32_t) value;
                break;
            case GUEST_SS_ACCESS_RIGHTS:
                env->curr_vmcs.guest_state.ss.flags = (uint32_t) value;
                break;
            case GUEST_DS_ACCESS_RIGHTS:
                env->curr_vmcs.guest_state.ds.flags = (uint32_t) value;
                break;
            case GUEST_FS_ACCESS_RIGHTS:
                env->curr_vmcs.guest_state.fs.flags = (uint32_t) value;
                break;
            case GUEST_GS_ACCESS_RIGHTS:
                env->curr_vmcs.guest_state.gs.flags = (uint32_t) value;
                break;
            case GUEST_LDTR_ACCESS_RIGHTS:
                env->curr_vmcs.guest_state.ldtr.flags = (uint32_t) value;
                break;
            case GUEST_TR_ACCESS_RIGHTS:
                env->curr_vmcs.guest_state.tr.flags = (uint32_t) value;
                break;
            case GUEST_INTERRUPTIBILITY_STATE:
                env->curr_vmcs.guest_state.interuptibility_state = (uint32_t) value;
                break;
            case GUEST_ACTIVITY_STATE:
                env->curr_vmcs.guest_state.activity_state = (uint32_t) value;
                break;
            case GUEST_IA32_SYSENTER_CS:
                env->curr_vmcs.guest_state.msr_sysenter_cs = (uint32_t) value;
                break;
            case HOST_IA32_SYSENTER_CS:
                env->curr_vmcs.host_state.msr_sysenter_cs = (uint32_t) value;
                break;
            // natural-width fields
            case CR0_GUEST_HOST_MASK:
                env->curr_vmcs.exec_control.cr0_guest_host_mask = value;
                break;
            case CR4_GUEST_HOST_MASK:
                env->curr_vmcs.exec_control.cr4_guest_host_mask = value;
                break;
            case CR0_READ_SHADOW:
                env->curr_vmcs.exec_control.cr0_read_shadow = value;
                break;
            case CR4_READ_SHADOW:
                env->curr_vmcs.exec_control.cr4_read_shadow = value;
                break;
            case CR3_TARGET_VALUE_0:
                env->curr_vmcs.exec_control.cr3_target_value[0] = value;
                break;
            case CR3_TARGET_VALUE_1:
                env->curr_vmcs.exec_control.cr3_target_value[1] = value;
                break;
            case CR3_TARGET_VALUE_2:
                env->curr_vmcs.exec_control.cr3_target_value[2] = value;
                break;
            case CR3_TARGET_VALUE_3:
                env->curr_vmcs.exec_control.cr3_target_value[3] = value;
                break;
            case EXIT_QUALIFICATION:
                env->curr_vmcs.exit_info.exit_qualification = value;
                break;
            case IO_RCX:
                env->curr_vmcs.exit_info.io_rcx = value;
                break;
            case IO_RSI:
                env->curr_vmcs.exit_info.io_rsi = value;
                break;
            case IO_RDI:
                env->curr_vmcs.exit_info.io_rdi = value;
                break;
            case IO_RIP:
                env->curr_vmcs.exit_info.io_rip = value;
                break;
            case GUEST_LINEAR_ADDRESS:
                env->curr_vmcs.exit_info.guest_linear_address = value;
                break;
            case GUEST_CR0:
                env->curr_vmcs.guest_state.cr0 = value;
                break;
            case GUEST_CR3:
                env->curr_vmcs.guest_state.cr3 = value;
                break;
            case GUEST_CR4:
                env->curr_vmcs.guest_state.cr4 = value;
                break;
            case GUEST_ES_BASE:
                env->curr_vmcs.guest_state.es.base = value;
                break;
            case GUEST_CS_BASE:
                env->curr_vmcs.guest_state.cs.base = value;
                break;
            case GUEST_SS_BASE:
                env->curr_vmcs.guest_state.ss.base = value;
                break;
            case GUEST_DS_BASE:
                env->curr_vmcs.guest_state.ds.base = value;
                break;
            case GUEST_FS_BASE:
                env->curr_vmcs.guest_state.fs.base = value;
                break;
            case GUEST_GS_BASE:
                env->curr_vmcs.guest_state.gs.base = value;
                break;
            case GUEST_LDTR_BASE:
                env->curr_vmcs.guest_state.ldtr.base = value;
                break;
            case GUEST_TR_BASE:
                env->curr_vmcs.guest_state.tr.base = value;
                break;
            case GUEST_GDTR_BASE:
                env->curr_vmcs.guest_state.gdtr.base = value;
                break;
            case GUEST_IDTR_BASE:
                env->curr_vmcs.guest_state.idtr.base = value;
                break;
            case GUEST_DR7:
                env->curr_vmcs.guest_state.dr7 = value;
                break;
            case GUEST_RSP:
                env->curr_vmcs.guest_state.rsp = value;
                break;
            case GUEST_RIP:
                env->curr_vmcs.guest_state.rip = value;
                break;
            case GUEST_RFLAGS:
                env->curr_vmcs.guest_state.rflags = value;
                break;
            case GUEST_PENDING_DEBUG_EXCEPTIONS:
                env->curr_vmcs.guest_state.pending_debug_exceptions = value;
                break;
            case GUEST_IA32_SYSENTER_ESP:
                env->curr_vmcs.guest_state.msr_sysenter_esp = value;
                break;
            case GUEST_IA32_SYSENTER_EIP:
                env->curr_vmcs.guest_state.msr_sysenter_eip = value;
                break;
            case HOST_CR0:
                env->curr_vmcs.host_state.cr0 = value;
                break;
            case HOST_CR3:
                env->curr_vmcs.host_state.cr3 = value;
                break;
            case HOST_CR4:
                env->curr_vmcs.host_state.cr4 = value;
                break;
            case HOST_FS_BASE:
                env->curr_vmcs.host_state.fs_base = value;
                break;
            case HOST_GS_BASE:
                env->curr_vmcs.host_state.gs_base = value;
                break;
            case HOST_TR_BASE:
                env->curr_vmcs.host_state.tr_base = value;
                break;
            case HOST_GDTR_BASE:
                env->curr_vmcs.host_state.gdtr_base = value;
                break;
            case HOST_IDTR_BASE:
                env->curr_vmcs.host_state.idtr_base = value;
                break;
            case HOST_IA32_SYSENTER_ESP:
                env->curr_vmcs.host_state.msr_sysenter_esp = value;
                break;
            case HOST_IA32_SYSENTER_EIP:
                env->curr_vmcs.host_state.msr_sysenter_eip = value;
                break;
            case HOST_RSP:
                env->curr_vmcs.host_state.rsp = value;
                break;
            case HOST_RIP:
                env->curr_vmcs.host_state.rip = value;
                break;
            default:
                vm_fail_valid(env, 12);
                return;
        }
        vm_succeed(env);
    }
}

void helper_vmxoff(CPUX86State *env)
{
    if (VMX_NON_ROOT) {
        vm_exit(env, 0);
    } else if (env->hflags & HF_CPL_MASK) {
        raise_exception(env, EXCP0D_GPF);
    } else if (0/*dual-monitor treatment of SMIs and SMM is active*/) {
        vm_fail(env, 23);
    } else {
        VMX_LEAVE;
        //XXX: unblock INIT; ???
        if (1/*A32_SMM_MONITOR_CTL[2] == 0*/) {
            env->hflags &= ~HF_SMM_MASK;
        }
        vm_succeed(env);
    }
}

void helper_vmxon(CPUX86State *env, target_ulong addr)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    uint32_t rev_id = 0;
    
    if (NOT_IN_VMX) {
        if ((env->hflags & HF_CPL_MASK)
        //|| (in A20M mode) 
        || ((env->cr[0] & ~(VMX_MSR_VMX_CR0_FIXED0 | VMX_MSR_VMX_CR0_FIXED1 | 0x60000000)) || (~env->cr[0] & (VMX_MSR_VMX_CR0_FIXED0 & VMX_MSR_VMX_CR0_FIXED1 & ~0x60000000)))
        || ((env->cr[4] & ~(VMX_MSR_VMX_CR4_FIXED0 | VMX_MSR_VMX_CR4_FIXED1)) || (~env->cr[4] & (VMX_MSR_VMX_CR4_FIXED0 & VMX_MSR_VMX_CR4_FIXED1)))
        //|| (bit 0 (lock bit) of IA32_FEATURE_CONTROL MSR is clear) 
        || 0/*(outside SMX operation and bit 2 of IA32_FEATURE_CONTROL MSR is clear)*/) {
            raise_exception(env, EXCP0D_GPF);
        } else {
            if (addr & 0xFFFFFF0000000FFFULL) {
                vm_fail_invalid(env);
            } else {
                rev_id = ldl_phys(cs->as, addr);
                if (rev_id != VMX_MSR_VMX_BASIC_VMCS_REVISION_ID) {
                    vm_fail_invalid(env);
                } else {
                    env->curr_vmcs_ptr = VMX_VMCS_INVALID_PTR;
                    VMX_SET_ROOT;
                    //XXX: block INIT signals; ???
                    //block and disable A20M; ???
                    env->vmxon_ptr = addr;
                    vm_succeed(env);
                }
            }
        }
    } else if (VMX_NON_ROOT) {
        vm_exit(env, 0);
    } else if (env->hflags & HF_CPL_MASK) {
        raise_exception(env, EXCP0D_GPF);
    } else {
        vm_fail(env, 15);
    }
}


static int exception_has_error_code(int intno)
{
    switch (intno) {
    case 8:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 17:
        return 1;
    }
    return 0;
}

// get_int_info do not set valid bit
uint32_t static get_int_info(CPUX86State *env, uint32_t type, int intno)
{
    uint32_t int_info = intno;
    switch (type) {
        case VMX_EXIT_EXCEPTION:
            if (intno == EXCP03_INT3 || intno == EXCP04_INTO) {
                int_info |= INT_TYPE_SOFT_EXCP << 8;
            } else {
                int_info |= INT_TYPE_HARD_EXCP << 8;
                if (exception_has_error_code(intno)) {
                    int_info |= 1 << 11;
                }
            }
            //possible to set bit 12
            break;
        case VMX_EXIT_NMI:
            int_info |= INT_TYPE_NMI << 8;
            break;
        case VMX_EXIT_EXTERNAL_INTERRUPT:
            break;
        default:
            error_report("vmx: get_int_info default reached!\n");
            exit(1);
    }

    return int_info;
}

void cpu_vmx_check_intercept_vectored(CPUX86State *env, uint32_t type, int intno, int error_code)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    
    if (likely(!(VMX_NON_ROOT)))
        return;

    switch (type) {
        case VMX_EXIT_EXCEPTION:
            if (!nested_exception) {
                //fill idt fields, but do not set valid bit
                env->curr_vmcs.exit_info.idt_vectoring_information = get_int_info(env, type, intno);
                env->curr_vmcs.exit_info.idt_vectoring_error_code = error_code;
                latest_int_reason = type;
            }

            if (!((env->curr_vmcs.exec_control.exception_bitmap >> intno) & 1) && (intno != EXCP0E_PAGE)) {
                return;
            }
            if ((intno == EXCP0E_PAGE) &&
                ((((error_code & env->curr_vmcs.exec_control.page_fault_error_code_mask) == env->curr_vmcs.exec_control.page_fault_error_code_match) && !((env->curr_vmcs.exec_control.exception_bitmap >> intno) & 1))
                || (((error_code & env->curr_vmcs.exec_control.page_fault_error_code_mask) != env->curr_vmcs.exec_control.page_fault_error_code_match) && ((env->curr_vmcs.exec_control.exception_bitmap >> intno) & 1)))
                ) {
                return;
            }
            env->curr_vmcs.exit_info.exit_reason = type;

            if (intno == EXCP01_DB) {
            } else if (intno == EXCP0E_PAGE) {
                env->curr_vmcs.exit_info.exit_qualification = exit_params[0];
                if (!(env->hflags & HF_LMA_SHIFT)) {
                    env->curr_vmcs.exit_info.exit_qualification &= 0xFFFFFFFF;
                }
            } else {
                env->curr_vmcs.exit_info.exit_qualification = 0;
            }

            env->curr_vmcs.exit_info.interruption_information = get_int_info(env, type, intno);
            env->curr_vmcs.exit_info.interruption_information |= 1 << 31;
            env->curr_vmcs.exit_info.interruption_error_code = error_code;

            if (nested_exception) {
                env->curr_vmcs.exit_info.idt_vectoring_information |= 1 << 31;
            }
            cs->exception_index = -1;
            env->old_exception = -1;
            break;
        case VMX_EXIT_NMI:
            env->curr_vmcs.exit_info.idt_vectoring_information = get_int_info(env, type, intno);
            if (NMI_EXITING) {
                env->curr_vmcs.exit_info.exit_reason = type;
                env->curr_vmcs.exit_info.exit_qualification = 0;
                env->curr_vmcs.exit_info.interruption_information = get_int_info(env, type, intno);
                env->curr_vmcs.exit_info.interruption_information |= 1 << 31;
            } else {
                return;
            }
            break;
        case VMX_EXIT_EXTERNAL_INTERRUPT:
            if (INTERRUPT_WINDOW_EXITING && (env->eflags & IF_MASK) && !(env->hflags & HF_INHIBIT_IRQ_MASK)) {
                env->curr_vmcs.exit_info.exit_reason = VMX_EXIT_INTERRUPT_WINDOW;
                env->curr_vmcs.exit_info.exit_qualification = 0;
                vm_exit(env, VMX_EXIT_INTERRUPT_WINDOW);
            }
            env->curr_vmcs.exit_info.idt_vectoring_information = get_int_info(env, type, intno);
            if (EXTERNAL_INTERRUPT_EXITING) {
                env->curr_vmcs.exit_info.exit_reason = type;
                env->curr_vmcs.exit_info.exit_qualification = 0;
                env->curr_vmcs.exit_info.interruption_information = get_int_info(env, type, intno);
                env->curr_vmcs.exit_info.interruption_information |= 1 << 31;
            } else {
                return;
            }
            break;
        case VMX_EXIT_TRIPLE_FAULT:
            env->curr_vmcs.exit_info.exit_reason = type;
            env->curr_vmcs.exit_info.exit_qualification = 0;
            env->curr_vmcs.exit_info.idt_vectoring_information = 8;
            env->curr_vmcs.exit_info.idt_vectoring_information |= 3 <<8;
            env->curr_vmcs.exit_info.idt_vectoring_information |= 1 << 31;
            cs->exception_index = -1;
            env->old_exception = -1;
            //prepare vmexit
            break;
        default:
            error_report("vectored_vmx_exit DEFAULT\n");
            exit(1);
    }
    vm_exit(env, type);
    return;
}

static void vmx_cr_access_exit(CPUX86State *env)
{
    env->curr_vmcs.exit_info.exit_reason = exit_reason & 0xFF;
    switch (exit_reason) {
        case VMX_EXIT_CLTS:
            env->curr_vmcs.exit_info.exit_qualification = 2 << 4;
            break;
        case VMX_EXIT_LMSW:
            env->curr_vmcs.exit_info.exit_qualification = 3 << 4;
            if (((exit_params[0] & 0xFF) >> 6) != 3) {
                env->curr_vmcs.exit_info.exit_qualification |= 1 << 6;
            }
            env->curr_vmcs.exit_info.exit_qualification |= exit_params[1] << 16;
            env->curr_vmcs.exit_info.guest_linear_address = exit_params[2];
            if (!(env->hflags & HF_CS64_MASK)) {
                env->curr_vmcs.exit_info.guest_linear_address &= 0xFFFFFFFF;
            }
            break;
        case VMX_EXIT_MOV_TO_CR0:
            env->curr_vmcs.exit_info.exit_qualification = exit_params[0] << 8;
            break;
        case VMX_EXIT_MOV_TO_CR3:
            env->curr_vmcs.exit_info.exit_qualification = exit_params[0] << 8;
            env->curr_vmcs.exit_info.exit_qualification |= 3;
            break;
        case VMX_EXIT_MOV_TO_CR4:
            env->curr_vmcs.exit_info.exit_qualification = exit_params[0] << 8;
            env->curr_vmcs.exit_info.exit_qualification |= 4;
            break;
        case VMX_EXIT_MOV_TO_CR8:
            env->curr_vmcs.exit_info.exit_qualification = exit_params[0] << 8;
            env->curr_vmcs.exit_info.exit_qualification |= 8;
            break;
        case VMX_EXIT_MOV_FROM_CR3:
            env->curr_vmcs.exit_info.exit_qualification = exit_params[0] << 8;
            env->curr_vmcs.exit_info.exit_qualification = 3;
            env->curr_vmcs.exit_info.exit_qualification |= 1 << 4;
            break;
        case VMX_EXIT_MOV_FROM_CR8:
            env->curr_vmcs.exit_info.exit_qualification = exit_params[0] << 8;
            env->curr_vmcs.exit_info.exit_qualification |= 8;
            env->curr_vmcs.exit_info.exit_qualification |= 1 << 4;
            break;
    }
    vm_exit(env, exit_reason);
}

uint32_t cpu_vmx_get_masked_new_cr(CPUX86State *env, uint32_t new_cr, int cr_number)
{
    uint32_t mask = 0;
    uint32_t shadow_cr = 0;
    uint32_t current_cr = 0;

    if (cr_number == 0) {
        mask = (uint32_t) env->curr_vmcs.exec_control.cr0_guest_host_mask;
        shadow_cr = (uint32_t) env->curr_vmcs.exec_control.cr0_read_shadow;
        current_cr = (uint32_t) env->cr[0];
    } else if (cr_number == 4) {
        mask = (uint32_t) env->curr_vmcs.exec_control.cr4_guest_host_mask;
        shadow_cr = (uint32_t) env->curr_vmcs.exec_control.cr4_read_shadow;
        current_cr = (uint32_t) env->cr[4];
    }
    if ((new_cr & mask) != (shadow_cr & mask)) {
        if ((cr_number == 0) && (exit_reason != VMX_EXIT_CLTS && exit_reason != VMX_EXIT_LMSW)) {
            exit_reason = VMX_EXIT_MOV_TO_CR0;
        } else if (cr_number == 4) {
            exit_reason = VMX_EXIT_MOV_TO_CR4;
        }
        vmx_cr_access_exit(env);
    }

    return ((new_cr & (~mask)) | (current_cr & mask));
}

target_ulong cpu_vmx_get_shadow_cr(CPUX86State *env, int cr_number)
{
    uint32_t mask = 0;
    uint32_t shadow_cr = 0;
    uint32_t current_cr = 0;

    if (cr_number == 0) {
        mask = (uint32_t) env->curr_vmcs.exec_control.cr0_guest_host_mask;
        shadow_cr = (uint32_t) env->curr_vmcs.exec_control.cr0_read_shadow;
        current_cr = (uint32_t) env->cr[0];
    } else if (cr_number == 4){
        mask = (uint32_t) env->curr_vmcs.exec_control.cr4_guest_host_mask;
        shadow_cr = (uint32_t) env->curr_vmcs.exec_control.cr4_read_shadow;
        current_cr = (uint32_t) env->cr[4];
    }
    return ((~mask & current_cr) | (mask & shadow_cr));
}

void helper_vmx_set_exit_reason(CPUX86State *env, uint32_t type)
{
    exit_reason = type;
}

void cpu_vmx_set_exit_reason(CPUX86State *env, uint32_t type)
{
    exit_reason = type;
}

void helper_vmx_set_param(int index, uint64_t val)
{
    exit_params[index] = val;
}

void cpu_vmx_set_param(int index, uint64_t val)
{
    exit_params[index] = val;
}

void cpu_vmx_need_exit(CPUX86State *env, uint32_t type)
{
    if (!VMX_NON_ROOT)
        return;
    env->curr_vmcs.exit_info.exit_qualification = 0;
    switch (type) {
        case VMX_EXIT_MOV_FROM_CR3:
            if (CR3_STORE_EXITING) {
                exit_reason = VMX_EXIT_MOV_FROM_CR3;
                vmx_cr_access_exit(env);
            }
            break;
        case VMX_EXIT_MOV_TO_CR3:
            if (CR3_LOAD_EXITING) {
                exit_reason = VMX_EXIT_MOV_TO_CR3;
                vmx_cr_access_exit(env);
            }
            break;
        case VMX_EXIT_MOV_FROM_CR8:
            if (CR8_STORE_EXITING) {
                exit_reason = VMX_EXIT_MOV_FROM_CR8;
                vmx_cr_access_exit(env);
            }
            break;
        case VMX_EXIT_MOV_TO_CR8:
            if (CR8_LOAD_EXITING) {
                exit_reason = VMX_EXIT_MOV_TO_CR8;
                vmx_cr_access_exit(env);
            }
            break;
        case VMX_EXIT_MOV_DR:
            if (VMX_EXIT_MOV_DR) {
                env->curr_vmcs.exit_info.exit_reason = VMX_EXIT_MOV_DR;
                env->curr_vmcs.exit_info.exit_qualification = exit_params[0];
                if (!exit_params[1]) {
                    env->curr_vmcs.exit_info.exit_qualification |= 1 << 4;
                }
                env->curr_vmcs.exit_info.exit_qualification |= exit_params[2] << 8;
                vm_exit(env, VMX_EXIT_MOV_DR);
            }
            break;
        case VMX_EXIT_RDMSR:
        case VMX_EXIT_WRMSR:
            vm_exit(env, type);
            break;
        case VMX_EXIT_CPUID:
            vm_exit(env, VMX_EXIT_CPUID);
            break;
        case VMX_EXIT_HLT:
            if (HLT_EXITING) {
                vm_exit(env, VMX_EXIT_HLT);
            }
            break;
        case VMX_EXIT_INVLPG:
            if (INVLPG_EXITING) {
                env->curr_vmcs.exit_info.exit_qualification = exit_params[0];
                if (!(env->hflags & HF_CS64_MASK)) {
                    env->curr_vmcs.exit_info.exit_qualification &= 0xFFFFFFFF;
                }
                vm_exit(env, VMX_EXIT_INVLPG);
            }
            break;
        case VMX_EXIT_MWAIT:
            if (MWAIT_EXITING) {
                env->curr_vmcs.exit_info.exit_qualification = 0;
                vm_exit(env, VMX_EXIT_MWAIT);
            }
            break;
        case VMX_EXIT_PAUSE:
            if (PAUSE_EXITING) {
                vm_exit(env, VMX_EXIT_PAUSE);
            }
            break;
        case VMX_EXIT_MONITOR:
            if (MONITOR_EXITING) {
                vm_exit(env, VMX_EXIT_MONITOR);
            }
            break;
        case VMX_EXIT_RDPMC:
            if (RDPMC_EXITING) {
                vm_exit(env, VMX_EXIT_RDPMC);
            }
            break;
        case VMX_EXIT_TASK_SWITCH:
            env->curr_vmcs.exit_info.exit_qualification = exit_params[2];
            if (exit_params[0]) {
                env->curr_vmcs.exit_info.exit_qualification |= 3 << 30;
            } else if (exit_params[1] == 0) {
                env->curr_vmcs.exit_info.exit_qualification |= 2 << 30;
            } else if (exit_params[1] == 1) {
                env->curr_vmcs.exit_info.exit_qualification |= 1 << 30;
            }
            env->curr_vmcs.exit_info.idt_vectoring_information |= 1 << 31;
            vm_exit(env, VMX_EXIT_TASK_SWITCH);
            break;
        default:
            return;
    }
}

void helper_vmx_need_exit(CPUX86State *env, uint32_t type)
{
    cpu_vmx_need_exit(env, type);
}

void cpu_vmx_set_nested_exception(CPUX86State *env, int val)
{
    if (val) {
        if (latest_int_reason == VMX_EXIT_EXCEPTION && env->old_exception == -1) {
            return;
        }
        nested_exception = 1;
    } else {
        nested_exception = 0;
    }
}

void helper_vmx_check_int_window_exiting(CPUX86State *env)
{
    if (INTERRUPT_WINDOW_EXITING && (env->eflags & IF_MASK) && !(env->hflags & HF_INHIBIT_IRQ_MASK)) {
        env->curr_vmcs.exit_info.exit_reason = VMX_EXIT_INTERRUPT_WINDOW;
        env->curr_vmcs.exit_info.exit_qualification = 0;
        vm_exit(env, VMX_EXIT_INTERRUPT_WINDOW);
    }
}