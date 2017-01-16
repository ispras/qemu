#include "exec/windbgstub-utils.h"

#define IS_LOCAL_BP_ENABLED(dr7, index) (((dr7) >> ((index) * 2)) & 1)

#define IS_GLOBAL_BP_ENABLED(dr7, index) (((dr7) >> ((index) * 2)) & 2)

#define IS_BP_ENABLED(dr7, index) \
    (IS_LOCAL_BP_ENABLED(dr7, index) || IS_GLOBAL_BP_ENABLED(dr7, index))

#define BP_TYPE(dr7, index) \
    ((int) ((dr7) >> (DR7_TYPE_SHIFT + ((index) * 4))) & 3)

#define BP_LEN(dr7, index) ({                                    \
    int _len = (((dr7) >> (DR7_LEN_SHIFT + ((index) * 4))) & 3); \
    (_len == 2) ? 8 : _len + 1;                                  \
})

typedef struct KDData {
    CPU_CTRL_ADDRS cca;
    SizedBuf lssc;
    EXCEPTION_STATE_CHANGE esc;
    CPU_CONTEXT cc;
    CPU_KSPECIAL_REGISTERS ckr;
} KDData;

static KDData kd;
static InitedAddr bps[KD_BREAKPOINT_MAX];
static InitedAddr dr[8];
static uint8_t cpu_amount;

static const char *kd_api_names[] = {
    "DbgKdReadVirtualMemoryApi",
    "DbgKdWriteVirtualMemoryApi",
    "DbgKdGetContextApi",
    "DbgKdSetContextApi",
    "DbgKdWriteBreakPointApi",
    "DbgKdRestoreBreakPointApi",
    "DbgKdContinueApi",
    "DbgKdReadControlSpaceApi",
    "DbgKdWriteControlSpaceApi",
    "DbgKdReadIoSpaceApi",
    "DbgKdWriteIoSpaceApi",
    "DbgKdRebootApi",
    "DbgKdContinueApi2",
    "DbgKdReadPhysicalMemoryApi",
    "DbgKdWritePhysicalMemoryApi",
    "DbgKdQuerySpecialCallsApi",
    "DbgKdSetSpecialCallApi",
    "DbgKdClearSpecialCallsApi",
    "DbgKdSetInternalBreakPointApi",
    "DbgKdGetInternalBreakPointApi",
    "DbgKdReadIoSpaceExtendedApi",
    "DbgKdWriteIoSpaceExtendedApi",
    "DbgKdGetVersionApi",
    "DbgKdWriteBreakPointExApi",
    "DbgKdRestoreBreakPointExApi",
    "DbgKdCauseBugCheckApi",
    "",
    "",
    "",
    "",
    "",
    "",
    "DbgKdSwitchProcessor",
    "DbgKdPageInApi",
    "DbgKdReadMachineSpecificRegister",
    "DbgKdWriteMachineSpecificRegister",
    "OldVlm1",
    "OldVlm2",
    "DbgKdSearchMemoryApi",
    "DbgKdGetBusDataApi",
    "DbgKdSetBusDataApi",
    "DbgKdCheckLowMemoryApi",
    "DbgKdClearAllInternalBreakpointsApi",
    "DbgKdFillMemoryApi",
    "DbgKdQueryMemoryApi",
    "DbgKdSwitchPartition",
    "DbgKdUnknownApi"
};

ntstatus_t windbg_write_breakpoint(CPUState *cpu, PacketData *pd)
{
    DBGKD_WRITE_BREAKPOINT64 *m64cu = &pd->m64->u.WriteBreakPoint;
    target_ulong addr = m64cu->BreakPointAddress - 1;
    int i = 0, err = 0;

    for (; i < KD_BREAKPOINT_MAX; ++i) {
        if (!bps[i].is_init) {
            err = cpu_breakpoint_insert(cpu, addr, BP_GDB, NULL);
            if (!err) {
                tb_flush(cpu);
                bps[i].addr = addr;
                bps[i].is_init = true;
                WINDBG_DEBUG("write_breakpoint: " FMT_ADDR, addr);
                break;
            }
            else {
                WINDBG_ERROR("write_breakpoint: " FMT_ADDR ", " FMT_ERR, addr, err);
                return STATUS_UNSUCCESSFUL;
            }
        }
        else if (addr == bps[i].addr) {
            break;
        }
    }

    if (!err) {
        m64cu->BreakPointHandle = i + 1;
        return STATUS_SUCCESS;
    }

    WINDBG_ERROR("write_breakpoint: All breakpoints occupied");
    return STATUS_UNSUCCESSFUL;
}

ntstatus_t windbg_restore_breakpoint(CPUState *cpu, PacketData *pd)
{
    DBGKD_RESTORE_BREAKPOINT *m64cu = &pd->m64->u.RestoreBreakPoint;
    uint8_t index = m64cu->BreakPointHandle - 1;
    int err = -1;

    if (bps[index].is_init) {
        err = cpu_breakpoint_remove(cpu, bps[index].addr, BP_GDB);
        if (!err) {
            WINDBG_DEBUG("restore_breakpoint: " FMT_ADDR ", index %d",
                         bps[index].addr, index);
        }
        else {
            WINDBG_ERROR("restore_breakpoint: " FMT_ADDR ", index %d, " FMT_ERR,
                         bps[index].addr, index, err);
        }
        bps[index].is_init = false;
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

ntstatus_t windbg_read_msr(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_WRITE_MSR *m64cu = &pd->m64->u.ReadWriteMsr;
    CPUArchState *env = cpu->env_ptr;
    uint64_t val;

    cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 0);

    switch (m64cu->Msr) {
    case MSR_IA32_SYSENTER_CS:
        val = env->sysenter_cs;
        break;
    case MSR_IA32_SYSENTER_ESP:
        val = env->sysenter_esp;
        break;
    case MSR_IA32_SYSENTER_EIP:
        val = env->sysenter_eip;
        break;
    case MSR_IA32_APICBASE:
        val = cpu_get_apic_base(x86_env_get_cpu(env)->apic_state);
        break;
    case MSR_EFER:
        val = env->efer;
        break;
    case MSR_STAR:
        val = env->star;
        break;
    case MSR_PAT:
        val = env->pat;
        break;
    case MSR_VM_HSAVE_PA:
        val = env->vm_hsave;
        break;
    case MSR_IA32_PERF_STATUS:
        /* tsc_increment_by_tick */
        val = 1000ULL;
        /* CPU multiplier */
        val |= (((uint64_t)4ULL) << 40);
        break;
  #ifdef TARGET_X86_64
    case MSR_LSTAR:
        val = env->lstar;
        break;
    case MSR_CSTAR:
        val = env->cstar;
        break;
    case MSR_FMASK:
        val = env->fmask;
        break;
    case MSR_FSBASE:
        val = env->segs[R_FS].base;
        break;
    case MSR_GSBASE:
        val = env->segs[R_GS].base;
        break;
    case MSR_KERNELGSBASE:
        val = env->kernelgsbase;
        break;
    case MSR_TSC_AUX:
        val = env->tsc_aux;
        break;
  #endif
    case MSR_MTRRphysBase(0):
    case MSR_MTRRphysBase(1):
    case MSR_MTRRphysBase(2):
    case MSR_MTRRphysBase(3):
    case MSR_MTRRphysBase(4):
    case MSR_MTRRphysBase(5):
    case MSR_MTRRphysBase(6):
    case MSR_MTRRphysBase(7):
        val = env->mtrr_var[((uint32_t)env->regs[R_ECX] -
                             MSR_MTRRphysBase(0)) / 2].base;
        break;
    case MSR_MTRRphysMask(0):
    case MSR_MTRRphysMask(1):
    case MSR_MTRRphysMask(2):
    case MSR_MTRRphysMask(3):
    case MSR_MTRRphysMask(4):
    case MSR_MTRRphysMask(5):
    case MSR_MTRRphysMask(6):
    case MSR_MTRRphysMask(7):
        val = env->mtrr_var[((uint32_t)env->regs[R_ECX] -
                             MSR_MTRRphysMask(0)) / 2].mask;
        break;
    case MSR_MTRRfix64K_00000:
        val = env->mtrr_fixed[0];
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        val = env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                              MSR_MTRRfix16K_80000 + 1];
        break;
    case MSR_MTRRfix4K_C0000:
    case MSR_MTRRfix4K_C8000:
    case MSR_MTRRfix4K_D0000:
    case MSR_MTRRfix4K_D8000:
    case MSR_MTRRfix4K_E0000:
    case MSR_MTRRfix4K_E8000:
    case MSR_MTRRfix4K_F0000:
    case MSR_MTRRfix4K_F8000:
        val = env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                              MSR_MTRRfix4K_C0000 + 3];
        break;
    case MSR_MTRRdefType:
        val = env->mtrr_deftype;
        break;
    case MSR_MTRRcap:
        if (env->features[FEAT_1_EDX] & CPUID_MTRR) {
            val = MSR_MTRRcap_VCNT | MSR_MTRRcap_FIXRANGE_SUPPORT |
                MSR_MTRRcap_WC_SUPPORTED;
        } else {
            /* XXX: exception? */
            val = 0;
        }
        break;
    case MSR_MCG_CAP:
        val = env->mcg_cap;
        break;
    case MSR_MCG_CTL:
        if (env->mcg_cap & MCG_CTL_P) {
            val = env->mcg_ctl;
        } else {
            val = 0;
        }
        break;
    case MSR_MCG_STATUS:
        val = env->mcg_status;
        break;
    case MSR_IA32_MISC_ENABLE:
        val = env->msr_ia32_misc_enable;
        break;
    case MSR_IA32_BNDCFGS:
        val = env->msr_bndcfgs;
        break;
    default:
        if ((uint32_t)env->regs[R_ECX] >= MSR_MC0_CTL
            && (uint32_t)env->regs[R_ECX] < MSR_MC0_CTL +
            (4 * env->mcg_cap & 0xff)) {
            uint32_t offset = (uint32_t)env->regs[R_ECX] - MSR_MC0_CTL;
            val = env->mce_banks[offset];
            break;
        }
        /* XXX: exception? */
        val = 0;
        break;
    }

    m64cu->DataValueLow  = UINT32(val, 0);
    m64cu->DataValueHigh = UINT32(val, 1);
    return STATUS_SUCCESS;
}

ntstatus_t windbg_write_msr(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_WRITE_MSR *m64cu = &pd->m64->u.ReadWriteMsr;
    CPUArchState *env = cpu->env_ptr;
    uint64_t val;

    cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 1);

    val = m64cu->DataValueLow | ((uint64_t) m64cu->DataValueHigh) << 32;

    switch (m64cu->Msr) {
    case MSR_IA32_SYSENTER_CS:
        env->sysenter_cs = val & 0xffff;
        break;
    case MSR_IA32_SYSENTER_ESP:
        env->sysenter_esp = val;
        break;
    case MSR_IA32_SYSENTER_EIP:
        env->sysenter_eip = val;
        break;
    case MSR_IA32_APICBASE:
        cpu_set_apic_base(x86_env_get_cpu(env)->apic_state, val);
        break;
    case MSR_EFER:
        {
            uint64_t update_mask;

            update_mask = 0;
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_SYSCALL) {
                update_mask |= MSR_EFER_SCE;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
                update_mask |= MSR_EFER_LME;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR) {
                update_mask |= MSR_EFER_FFXSR;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_NX) {
                update_mask |= MSR_EFER_NXE;
            }
            if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
                update_mask |= MSR_EFER_SVME;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR) {
                update_mask |= MSR_EFER_FFXSR;
            }
            cpu_load_efer(env, (env->efer & ~update_mask) |
                          (val & update_mask));
        }
        break;
    case MSR_STAR:
        env->star = val;
        break;
    case MSR_PAT:
        env->pat = val;
        break;
    case MSR_VM_HSAVE_PA:
        env->vm_hsave = val;
        break;
  #ifdef TARGET_X86_64
    case MSR_LSTAR:
        env->lstar = val;
        break;
    case MSR_CSTAR:
        env->cstar = val;
        break;
    case MSR_FMASK:
        env->fmask = val;
        break;
    case MSR_FSBASE:
        env->segs[R_FS].base = val;
        break;
    case MSR_GSBASE:
        env->segs[R_GS].base = val;
        break;
    case MSR_KERNELGSBASE:
        env->kernelgsbase = val;
        break;
  #endif
    case MSR_MTRRphysBase(0):
    case MSR_MTRRphysBase(1):
    case MSR_MTRRphysBase(2):
    case MSR_MTRRphysBase(3):
    case MSR_MTRRphysBase(4):
    case MSR_MTRRphysBase(5):
    case MSR_MTRRphysBase(6):
    case MSR_MTRRphysBase(7):
        env->mtrr_var[((uint32_t)env->regs[R_ECX] -
                       MSR_MTRRphysBase(0)) / 2].base = val;
        break;
    case MSR_MTRRphysMask(0):
    case MSR_MTRRphysMask(1):
    case MSR_MTRRphysMask(2):
    case MSR_MTRRphysMask(3):
    case MSR_MTRRphysMask(4):
    case MSR_MTRRphysMask(5):
    case MSR_MTRRphysMask(6):
    case MSR_MTRRphysMask(7):
        env->mtrr_var[((uint32_t)env->regs[R_ECX] -
                       MSR_MTRRphysMask(0)) / 2].mask = val;
        break;
    case MSR_MTRRfix64K_00000:
        env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                        MSR_MTRRfix64K_00000] = val;
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                        MSR_MTRRfix16K_80000 + 1] = val;
        break;
    case MSR_MTRRfix4K_C0000:
    case MSR_MTRRfix4K_C8000:
    case MSR_MTRRfix4K_D0000:
    case MSR_MTRRfix4K_D8000:
    case MSR_MTRRfix4K_E0000:
    case MSR_MTRRfix4K_E8000:
    case MSR_MTRRfix4K_F0000:
    case MSR_MTRRfix4K_F8000:
        env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                        MSR_MTRRfix4K_C0000 + 3] = val;
        break;
    case MSR_MTRRdefType:
        env->mtrr_deftype = val;
        break;
    case MSR_MCG_STATUS:
        env->mcg_status = val;
        break;
    case MSR_MCG_CTL:
        if ((env->mcg_cap & MCG_CTL_P)
            && (val == 0 || val == ~(uint64_t)0)) {
            env->mcg_ctl = val;
        }
        break;
    case MSR_TSC_AUX:
        env->tsc_aux = val;
        break;
    case MSR_IA32_MISC_ENABLE:
        env->msr_ia32_misc_enable = val;
        break;
    case MSR_IA32_BNDCFGS:
        /* FIXME: #GP if reserved bits are set.  */
        /* FIXME: Extend highest implemented bit of linear address.  */
        env->msr_bndcfgs = val;
        cpu_sync_bndcs_hflags(env);
        break;
    default:
        if ((uint32_t)env->regs[R_ECX] >= MSR_MC0_CTL
            && (uint32_t)env->regs[R_ECX] < MSR_MC0_CTL +
            (4 * env->mcg_cap & 0xff)) {
            uint32_t offset = (uint32_t)env->regs[R_ECX] - MSR_MC0_CTL;
            if ((offset & 0x3) != 0
                || (val == 0 || val == ~(uint64_t)0)) {
                env->mce_banks[offset] = val;
            }
            break;
        }
        /* XXX: exception? */
        break;
    }
    return STATUS_SUCCESS;
}

ntstatus_t windbg_search_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_SEARCH_MEMORY *m64cu = &pd->m64->u.SearchMemory;
    int s_len = MAX(1, m64cu->SearchLength);
    int p_len = MIN(m64cu->PatternLength, pd->extra_size);

    SizedBuf mem;
    mem.size = s_len - 1 + p_len;
    mem.data = g_malloc0(mem.size);

    ntstatus_t err;
    err = cpu_memory_rw_debug(cpu, m64cu->SearchAddress, mem.data, mem.size, 0);
    if (!err) {
        int i;
        err = STATUS_NO_MORE_ENTRIES;
        for (i = 0; i < s_len; ++i) {
            if (memcmp(mem.data + i, pd->extra, p_len) == 0) {
                m64cu->FoundAddress = m64cu->SearchAddress + i;
                err = STATUS_SUCCESS;
                break;
            }
        }
    }
    else {
        // tmp checking
        WINDBG_DEBUG("search_memory: No physical page mapped: " FMT_ADDR,
                     (target_ulong) m64cu->SearchAddress);
        err = STATUS_UNSUCCESSFUL;
    }

    g_free(mem.data);
    return err;
}

static void windbg_breakpoint_remove_range(CPUState *cpu, target_ulong base, target_ulong limit)
{
    int i = 0, err = 0;
    for (; i < KD_BREAKPOINT_MAX; ++i) {
        if (bps[i].is_init && bps[i].addr >= base && bps[i].addr < limit) {
            err = cpu_breakpoint_remove(cpu, bps[i].addr, BP_GDB);
            if (!err) {
                WINDBG_DEBUG("breakpoint_remove_range: " FMT_ADDR ", index %d",
                            bps[i].addr, i);
            }
            else {
                WINDBG_ERROR("breakpoint_remove_range: " FMT_ADDR ", index %d, " FMT_ERR,
                            bps[i].addr, i, err);
            }
            bps[i].is_init = false;
        }
    }
}

static void windbg_watchpoint_insert(CPUState *cpu, target_ulong addr, int len, int type)
{
    int err = 0;
    switch (type) {
    case DR7_TYPE_DATA_WR:
        err = cpu_watchpoint_insert(cpu, addr, len, BP_MEM_WRITE | BP_GDB, NULL);
        break;
    case DR7_TYPE_DATA_RW:
        err = cpu_watchpoint_insert(cpu, addr, len, BP_MEM_ACCESS | BP_GDB, NULL);
        break;
    case DR7_TYPE_BP_INST:
        err = cpu_breakpoint_insert(cpu, addr, BP_GDB, NULL);
        break;
    default:
        WINDBG_ERROR("watchpoint_insert: Unknown wp type 0x%x", type);
        break;
    }

    if (!err) {
        WINDBG_DEBUG("watchpoint_insert: " FMT_ADDR ", len %d, type 0x%x",
                     addr, len, type);
    }
    else {
        WINDBG_ERROR("watchpoint_insert: " FMT_ADDR ", len %d, type 0x%x, " FMT_ERR,
                     addr, len, type, err);
    }
}

static void windbg_watchpoint_remove(CPUState *cpu, target_ulong addr, int len, int type)
{
    int err = 0;
    switch (type) {
    case DR7_TYPE_DATA_WR:
        err = cpu_watchpoint_remove(cpu, addr, len, BP_MEM_WRITE | BP_GDB);
        break;
    case DR7_TYPE_DATA_RW:
        err = cpu_watchpoint_remove(cpu, addr, len, BP_MEM_ACCESS | BP_GDB);
        break;
    case DR7_TYPE_BP_INST:
        err = cpu_breakpoint_remove(cpu, addr, BP_GDB);
        break;
    default:
        WINDBG_ERROR("wp_remove: Unknown wp type 0x%x", type);
        break;
    }

    if (!err) {
        WINDBG_DEBUG("wp_remove: " FMT_ADDR ", len %d, type 0x%x",
                     addr, len, type);
    }
    else {
        WINDBG_ERROR("wp_remove: " FMT_ADDR ", len %d, type 0x%x, " FMT_ERR,
                     addr, len, type, err);
    }
}

static void windbg_update_dr(CPUState *cpu, target_ulong *new_dr)
{
    int i;

    for (i = 0; i < DR7_MAX_BP; ++i) {
        bool is_enabled = IS_BP_ENABLED(new_dr[7], i);
        if (!is_enabled) {
            if (dr[i].is_init) {
                windbg_watchpoint_remove(cpu, dr[i].addr, BP_LEN(dr[7].addr, i),
                                         BP_TYPE(dr[7].addr, i));
                dr[i].is_init = false;
            }
        }
        else if (is_enabled && (new_dr[i] != dr[i].addr)) {
            if (dr[i].is_init) {
                windbg_watchpoint_remove(cpu, dr[i].addr, BP_LEN(dr[7].addr, i),
                                         BP_TYPE(dr[7].addr, i));
                dr[i].is_init = false;
            }

            dr[i].addr = new_dr[i];
            dr[i].is_init = true;

            windbg_watchpoint_insert(cpu, dr[i].addr, BP_LEN(new_dr[7], i),
                                     BP_TYPE(new_dr[7], i));
        }
    }

    if (!dr[7].is_init || dr[7].addr != new_dr[7]) {
        dr[7].addr = new_dr[7];
        dr[7].is_init = false;
        for (i = 0; i < DR7_MAX_BP; ++i) {
            if (dr[i].is_init) {
                dr[7].is_init = true;
                break;
            }
        }
    }
}

const char *kd_api_name(int api_number)
{
    if (api_number >= DbgKdMinimumManipulate && api_number < DbgKdMaximumManipulate) {
        return kd_api_names[api_number - DbgKdMinimumManipulate];
    }
    return kd_api_names[DbgKdMaximumManipulate];
}

CPU_CTRL_ADDRS *kd_get_cpu_ctrl_addrs(CPUState *cpu)
{
    CPUArchState *env = cpu->env_ptr;

    kd.cca.KPCR = env->segs[R_FS].base;

    cpu_memory_rw_debug(cpu, kd.cca.KPCR + OFFSET_KPRCB, PTR(kd.cca.KPRCB),
                        sizeof(kd.cca.KPRCB), 0);

    cpu_memory_rw_debug(cpu, kd.cca.KPCR + OFFSET_VERSION, PTR(kd.cca.Version),
                        sizeof(kd.cca.Version), 0);

    cpu_memory_rw_debug(cpu, kd.cca.Version + OFFSET_KRNL_BASE, PTR(kd.cca.KernelBase),
                        sizeof(kd.cca.KernelBase), 0);

    WINDBG_DEBUG("control_addr: KPCR " FMT_ADDR, kd.cca.KPCR);
    WINDBG_DEBUG("control_addr: KPRCB " FMT_ADDR, kd.cca.KPRCB);
    WINDBG_DEBUG("control_addr: KernelBase " FMT_ADDR, kd.cca.KernelBase);

    return &kd.cca;
}

static void kd_init_common_sc(CPUState *cpu, DBGKD_ANY_WAIT_STATE_CHANGE *sc)
{
    CPUArchState *env = cpu->env_ptr;
    int err = 0;

    // HEADER

    sc->NewState = DbgKdExceptionStateChange;
    sc->ProcessorLevel = 0x6;
    sc->Processor = 0;
    sc->NumberProcessors = get_cpu_amount();
    cpu_memory_rw_debug(cpu, kd.cca.KPRCB + OFFSET_KPRCB_CURRTHREAD,
                        PTR(sc->Thread), sizeof(sc->Thread), 0);
    sc->ProgramCounter = env->eip;

    // CONTROL REPORT

    sc->ControlReport.Dr6 = env->dr[6];
    sc->ControlReport.Dr7 = env->dr[7];
    // sc->ControlReport.ReportFlags = 0x3;
    sc->ControlReport.SegCs = env->segs[R_CS].selector;
    sc->ControlReport.SegDs = env->segs[R_DS].selector;
    sc->ControlReport.SegEs = env->segs[R_ES].selector;
    sc->ControlReport.SegFs = env->segs[R_FS].selector;
    sc->ControlReport.EFlags = env->eflags;

    err = cpu_memory_rw_debug(cpu, sc->ProgramCounter,
                              PTR(sc->ControlReport.InstructionStream[0]),
                              DBGKD_MAXSTREAM, 0);
    if (!err) {
        sc->ControlReport.InstructionCount = DBGKD_MAXSTREAM;
        windbg_breakpoint_remove_range(cpu, sc->ProgramCounter,
                                       sc->ProgramCounter + DBGKD_MAXSTREAM);
    }
}

EXCEPTION_STATE_CHANGE *kd_get_exception_sc(CPUState *cpu)
{
    CPUArchState *env = cpu->env_ptr;

    memset(&kd.esc, 0, sizeof(kd.esc));

    DBGKD_ANY_WAIT_STATE_CHANGE *sc = &kd.esc.StateChange;
    kd_init_common_sc(cpu, sc);

    sc->u.Exception.ExceptionRecord.ExceptionCode = 0x80000003; // Need get it
    // sc->u.Exception.ExceptionRecord.ExceptionFlags = 0x0;
    // sc->u.Exception.ExceptionRecord.ExceptionRecord = 0x0;
    sc->u.Exception.ExceptionRecord.ExceptionAddress = env->eip;
    // sc->u.Exception.ExceptionRecord.NumberParameters = 0x3;
    // sc->u.Exception.ExceptionRecord.__unusedAligment = 0x80;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[1] = 0xffffffff82966340;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[2] = 0xffffffff82959adc;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[3] = 0xc0;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[4] = 0xffffffffc020360c;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[5] = 0x80;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[6] = 0x0;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[7] = 0x0;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[8] = 0xffffffff82870d08;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[9] = 0xffffffff82959aec;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[10] = 0xffffffff82853508;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[11] = 0xffffffffbadb0d00;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[12] = 0xffffffff82959adc;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[13] = 0xffffffff82959aa4;
    // sc->u.Exception.ExceptionRecord.ExceptionInformation[14] = 0xffffffff828d9d15;
    sc->u.Exception.FirstChance = 0x1; // Need get it

    kd.esc.value = 0x1; // Need get it

    return &kd.esc;
}

SizedBuf *kd_get_load_symbols_sc(CPUState *cpu)
{
    int i;
    uint8_t path_name[128]; //For Win7
    size_t size = sizeof(DBGKD_ANY_WAIT_STATE_CHANGE),
           count = sizeof(path_name);

    DBGKD_ANY_WAIT_STATE_CHANGE sc;
    kd_init_common_sc(cpu, &sc);

    cpu_memory_rw_debug(cpu, NT_KRNL_PNAME_ADDR, path_name, count, 0);
    for (i = 0; i < count; i += 2) {
        if((path_name[i / 2] = path_name[i]) == '\0') {
            break;
        }
    }
    count = i / 2 + 1;
    kd.lssc.size = size + count;

    sc.NewState = DbgKdLoadSymbolsStateChange;
    sc.u.LoadSymbols.PathNameLength = count;
    // sc.u.LoadSymbols.BaseOfDll = cca.KernelBase << 8 | ;
    // sc.u.LoadSymbols.ProcessId = -1;
    // sc.u.LoadSymbols.CheckSum = ;
    // sc.u.LoadSymbols.SizeOfImage = ;
    // sc.u.LoadSymbols.UnloadSymbols = false;

    if (kd.lssc.data) {
        g_free(kd.lssc.data);
    }
    kd.lssc.data = g_malloc0(kd.lssc.size);
    memcpy(kd.lssc.data, &sc, size);
    memcpy(kd.lssc.data + size, path_name, count);

    return &kd.lssc;
}

CPU_CONTEXT *kd_get_context(CPUState *cpu)
{
    CPUArchState *env = cpu->env_ptr;
    int i;

    memset(&kd.cc, 0, sizeof(kd.cc));

  #if defined(TARGET_I386)

    kd.cc.ContextFlags = CPU_CONTEXT_ALL;

    if (kd.cc.ContextFlags & CPU_CONTEXT_FULL) {
        kd.cc.Edi    = env->regs[R_EDI];
        kd.cc.Esi    = env->regs[R_ESI];
        kd.cc.Ebx    = env->regs[R_EBX];
        kd.cc.Edx    = env->regs[R_EDX];
        kd.cc.Ecx    = env->regs[R_ECX];
        kd.cc.Eax    = env->regs[R_EAX];
        kd.cc.Ebp    = env->regs[R_EBP];
        kd.cc.Esp    = env->regs[R_ESP];

        kd.cc.Eip    = env->eip;
        kd.cc.EFlags = env->eflags;

        kd.cc.SegGs  = env->segs[R_GS].selector;
        kd.cc.SegFs  = env->segs[R_FS].selector;
        kd.cc.SegEs  = env->segs[R_ES].selector;
        kd.cc.SegDs  = env->segs[R_DS].selector;
        kd.cc.SegCs  = env->segs[R_CS].selector;
        kd.cc.SegSs  = env->segs[R_SS].selector;
    }

    if (kd.cc.ContextFlags & CPU_CONTEXT_FLOATING_POINT) {
        kd.cc.FloatSave.ControlWord    = env->fpuc;
        kd.cc.FloatSave.StatusWord     = env->fpus;
        kd.cc.FloatSave.TagWord        = env->fpstt;
        kd.cc.FloatSave.ErrorOffset    = UINT32(env->fpip, 0);
        kd.cc.FloatSave.ErrorSelector  = UINT32(env->fpip, 1);
        kd.cc.FloatSave.DataOffset     = UINT32(env->fpdp, 0);
        kd.cc.FloatSave.DataSelector   = UINT32(env->fpdp, 1);
        kd.cc.FloatSave.Cr0NpxState    = env->cr[0];

        for (i = 0; i < 8; ++i) {
            memcpy(PTR(kd.cc.FloatSave.RegisterArea[i * 10]),
                   PTR(env->fpregs[i].mmx), sizeof(MMXReg));
        }
    }

    if (kd.cc.ContextFlags & CPU_CONTEXT_DEBUG_REGISTERS) {
        kd.cc.Dr0    = env->dr[0];
        kd.cc.Dr1    = env->dr[1];
        kd.cc.Dr2    = env->dr[2];
        kd.cc.Dr3    = env->dr[3];
        kd.cc.Dr6    = env->dr[6];
        kd.cc.Dr7    = env->dr[7];
    }

    if (kd.cc.ContextFlags & CPU_CONTEXT_EXTENDED_REGISTERS) {
        for (i = 0; i < 8; ++i) {
            memcpy(PTR(kd.cc.ExtendedRegisters[(10 + i) * 16]),
                   PTR(env->xmm_regs[i]), sizeof(ZMMReg));
        }
        // offset 24
        UINT32(kd.cc.ExtendedRegisters, 6) = env->mxcsr;
    }

    kd.cc.ExtendedRegisters[0] = 0xaa;

  #elif defined(TARGET_X86_64)

  #endif

    return &kd.cc;
}

void kd_set_context(CPUState *cpu, uint8_t *data, int len)
{
    CPU_CONTEXT cc;
    memcpy(PTR(cc), data, MIN(len, sizeof(cc)));

  #if defined(TARGET_I386)

    if (cc.ContextFlags & CPU_CONTEXT_FULL) {

    }

    if (cc.ContextFlags & CPU_CONTEXT_FLOATING_POINT) {

    }

    if (cc.ContextFlags & CPU_CONTEXT_DEBUG_REGISTERS) {
        target_ulong new_dr[8] = {
            [0] = cc.Dr0,
            [1] = cc.Dr1,
            [2] = cc.Dr2,
            [3] = cc.Dr3,
            [6] = cc.Dr6,
            [7] = cc.Dr7
        };
        windbg_update_dr(cpu, new_dr);
    }

    if (cc.ContextFlags & CPU_CONTEXT_EXTENDED_REGISTERS) {

    }

  #elif defined(TARGET_X86_64)

  #endif
}

CPU_KSPECIAL_REGISTERS *kd_get_kspecial_registers(CPUState *cpu)
{
    CPUArchState *env = cpu->env_ptr;

    memset(&kd.ckr, 0, sizeof(kd.ckr));

    kd.ckr.Cr0 = env->cr[0];
    kd.ckr.Cr2 = env->cr[2];
    kd.ckr.Cr3 = env->cr[3];
    kd.ckr.Cr4 = env->cr[4];

    kd.ckr.KernelDr0 = dr[0].is_init ? dr[0].addr : env->dr[0];
    kd.ckr.KernelDr1 = dr[1].is_init ? dr[1].addr : env->dr[1];
    kd.ckr.KernelDr2 = dr[2].is_init ? dr[2].addr : env->dr[2];
    kd.ckr.KernelDr3 = dr[3].is_init ? dr[3].addr : env->dr[3];
    kd.ckr.KernelDr6 = dr[6].is_init ? dr[6].addr : env->dr[6];
    kd.ckr.KernelDr7 = dr[7].is_init ? dr[7].addr : env->dr[7];

    kd.ckr.Gdtr.Pad   = env->gdt.selector;
    kd.ckr.Gdtr.Limit = env->gdt.limit;
    kd.ckr.Gdtr.Base  = env->gdt.base;
    kd.ckr.Idtr.Pad   = env->idt.selector;
    kd.ckr.Idtr.Limit = env->idt.limit;
    kd.ckr.Idtr.Base  = env->idt.base;
    kd.ckr.Tr         = env->tr.selector;
    kd.ckr.Ldtr       = env->ldt.selector;

    // kd.ckr.Reserved[6];

    return &kd.ckr;
}

void kd_set_kspecial_registers(CPUState *cpu, uint8_t *data, int len, int offset)
{
}

void windbg_on_init(void)
{
    // init cpu_amount
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        ++cpu_amount;
    }
}

void windbg_on_exit(void)
{
    // clear lssc
    if (kd.lssc.data) {
        g_free(kd.lssc.data);
        kd.lssc.data = NULL;
    }
}

uint8_t get_cpu_amount(void)
{
    return cpu_amount;
}

uint32_t compute_checksum(uint8_t *data, uint16_t length)
{
    uint32_t checksum = 0;
    for(; length; --length) {
        checksum += *data++;
    }
    return checksum;
}