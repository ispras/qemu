#include "exec/windbgstub-utils.h"

#define IS_LOCAL_BP_ENABLED(dr7, index) (((dr7) >> ((index) * 2)) & 1)

#define IS_GLOBAL_BP_ENABLED(dr7, index) (((dr7) >> ((index) * 2)) & 2)

#define IS_BP_ENABLED(dr7, index) \
    (IS_LOCAL_BP_ENABLED(dr7, index) | IS_GLOBAL_BP_ENABLED(dr7, index))

#define BP_TYPE(dr7, index) \
    ((int) ((dr7) >> (DR7_TYPE_SHIFT + ((index) * 4))) & 3)

#define BP_LEN(dr7, index) ({                                    \
    int _len = (((dr7) >> (DR7_LEN_SHIFT + ((index) * 4))) & 3); \
    (_len == 2) ? 8 : _len + 1;                                  \
})

#define OFFSET_KPRCB            0x20
#define OFFSET_KPRCB_CURRTHREAD 0x4
#define OFFSET_VERSION          0x34
#define OFFSET_KRNL_BASE        0x10

#define NT_KRNL_PNAME_ADDR 0x89000fb8 //For Win7

#define KD_API_NAME(api)                                               \
    ((api >= DbgKdMinimumManipulate && api < DbgKdMaximumManipulate) ? \
        kd_api_names[api - DbgKdMinimumManipulate] :                   \
        kd_api_names[DbgKdMaximumManipulate])

typedef struct KDData {
    CPU_CTRL_ADDRS cca;
    SizedBuf lssc;
    EXCEPTION_STATE_CHANGE esc;
    InitedAddr bps[KD_BREAKPOINT_MAX];
} KDData;

static KDData kd;
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

static int windbg_hw_breakpoint_insert(CPUState *cpu, int index)
{
    CPUArchState *env = cpu->env_ptr;

    if (!IS_BP_ENABLED(env->dr[7], index)) {
        return 0;
    }

    target_ulong addr = env->dr[index];
    int type = BP_TYPE(env->dr[7], index);
    int len = BP_LEN(env->dr[7], index);
    int err = 0;

    switch (type) {
    case DR7_TYPE_DATA_WR:
        err = cpu_watchpoint_insert(cpu, addr, len, BP_MEM_WRITE | BP_GDB,
                                    &env->cpu_watchpoint[index]);
        break;
    case DR7_TYPE_DATA_RW:
        err = cpu_watchpoint_insert(cpu, addr, len, BP_MEM_ACCESS | BP_GDB,
                                    &env->cpu_watchpoint[index]);
        break;
    case DR7_TYPE_BP_INST:
        err = cpu_breakpoint_insert(cpu, addr, BP_GDB,
                                    &env->cpu_breakpoint[index]);
        break;
    case DR7_TYPE_IO_RW:
        return HF_IOBPT_MASK;
    default:
        return 0;
    }

    if (!err) {
        WINDBG_DEBUG("hw_breakpoint_insert: index %d, " FMT_ADDR, index, addr);
    }
    else {
        env->cpu_breakpoint[index] = NULL;
        WINDBG_ERROR("hw_breakpoint_insert: index %d, " FMT_ADDR ", " FMT_ERR,
                     index, addr, err);
    }
    return 0;
}

static int windbg_hw_breakpoint_remove(CPUState *cpu, int index)
{
    CPUArchState *env = cpu->env_ptr;
    target_ulong addr = env->dr[index];
    int type = BP_TYPE(env->dr[7], index);

    switch (type) {
    case DR7_TYPE_BP_INST:
        if (env->cpu_breakpoint[index]) {
            cpu_breakpoint_remove_by_ref(cpu, env->cpu_breakpoint[index]);
        }
        break;
    case DR7_TYPE_DATA_WR:
    case DR7_TYPE_DATA_RW:
        if (env->cpu_watchpoint[index]) {
            cpu_watchpoint_remove_by_ref(cpu, env->cpu_watchpoint[index]);
        }
        break;
    default:
        return 0;
    }

    env->cpu_breakpoint[index] = NULL;
    WINDBG_DEBUG("hw_breakpoint_remove: index %d, " FMT_ADDR, index, addr);
    return 0;
}

static void windbg_set_dr7(CPUState *cpu, target_ulong new_dr7)
{
    CPUArchState *env = cpu->env_ptr;
    target_ulong old_dr7 = env->dr[7];
    int iobpt = 0;
    int i;

    new_dr7 |= DR7_FIXED_1;
    if (new_dr7 == old_dr7) {
        return;
    }

    for (i = 0; i < DR7_MAX_BP; i++) {
        if (IS_BP_ENABLED(old_dr7, i) && !IS_BP_ENABLED(new_dr7, i)) {
            windbg_hw_breakpoint_remove(cpu, i);
        }
    }
    env->dr[7] = new_dr7;
    for (i = 0; i < DR7_MAX_BP; i++) {
        if (IS_BP_ENABLED(env->dr[7], i)) {
            iobpt |= windbg_hw_breakpoint_insert(cpu, i);
        }
    }

    env->hflags = (env->hflags & ~HF_IOBPT_MASK) | iobpt;
}

static void windbg_set_dr(CPUState *cpu, int index, target_ulong value)
{
    CPUArchState *env = cpu->env_ptr;

    switch (index) {
    case 0 ... 3:
        if (IS_BP_ENABLED(env->dr[7], index) && env->dr[index] != value) {
            windbg_hw_breakpoint_remove(cpu, index);
            env->dr[index] = value;
            windbg_hw_breakpoint_insert(cpu, index);
        }
        else {
            env->dr[index] = value;
        }
        return;
    case 6:
        env->dr[6] = value | DR6_FIXED_1;
        return;
    case 7:
        windbg_set_dr7(cpu, value);
        return;
    }
}

static int windbg_read_context(CPUState *cpu, uint8_t *buf, int len, int offset)
{
    const bool new_mem = (len != sizeof(CPU_CONTEXT) || offset != 0);
    CPUArchState *env = cpu->env_ptr;
    CPU_CONTEXT *cc;
    int err = 0;

    if (new_mem) {
        cc = (CPU_CONTEXT *) g_malloc(sizeof(CPU_CONTEXT));
    }
    else {
        cc = (CPU_CONTEXT *) buf;
    }

    memset(cc, 0, len);

  #ifdef TARGET_I386

    cc->ContextFlags = CPU_CONTEXT_ALL;

    if (cc->ContextFlags & CPU_CONTEXT_FULL) {
        cc->Edi    = env->regs[R_EDI];
        cc->Esi    = env->regs[R_ESI];
        cc->Ebx    = env->regs[R_EBX];
        cc->Edx    = env->regs[R_EDX];
        cc->Ecx    = env->regs[R_ECX];
        cc->Eax    = env->regs[R_EAX];
        cc->Ebp    = env->regs[R_EBP];
        cc->Esp    = env->regs[R_ESP];

        cc->Eip    = env->eip;
        cc->EFlags = env->eflags;

        cc->SegGs  = env->segs[R_GS].selector;
        cc->SegFs  = env->segs[R_FS].selector;
        cc->SegEs  = env->segs[R_ES].selector;
        cc->SegDs  = env->segs[R_DS].selector;
        cc->SegCs  = env->segs[R_CS].selector;
        cc->SegSs  = env->segs[R_SS].selector;
    }

    if (cc->ContextFlags & CPU_CONTEXT_FLOATING_POINT) {
        cc->FloatSave.ControlWord    = env->fpuc;
        cc->FloatSave.StatusWord     = env->fpus;
        cc->FloatSave.TagWord        = env->fpstt;
        cc->FloatSave.ErrorOffset    = UINT32P(env->fpip)[0];
        cc->FloatSave.ErrorSelector  = UINT32P(env->fpip)[1];
        cc->FloatSave.DataOffset     = UINT32P(env->fpdp)[0];
        cc->FloatSave.DataSelector   = UINT32P(env->fpdp)[1];
        cc->FloatSave.Cr0NpxState    = env->cr[0];

        // for (i = 0; i < 8; ++i) {
        //     memcpy(PTR(cc->FloatSave.RegisterArea[i * 10]),
        //            PTR(env->fpregs[i].mmx), sizeof(MMXReg));
        // }
    }

    if (cc->ContextFlags & CPU_CONTEXT_DEBUG_REGISTERS) {
        cc->Dr0    = env->dr[0];
        cc->Dr1    = env->dr[1];
        cc->Dr2    = env->dr[2];
        cc->Dr3    = env->dr[3];
        cc->Dr6    = env->dr[6];
        cc->Dr7    = env->dr[7];
    }

    if (cc->ContextFlags & CPU_CONTEXT_EXTENDED_REGISTERS) {
        // for (i = 0; i < 8; ++i) {
        //     memcpy(PTR(cc->ExtendedRegisters[(10 + i) * 16]),
        //            PTR(env->xmm_regs[i]), sizeof(ZMMReg));
        // }
        // // offset 24
        // UINT32P(cc->ExtendedRegisters)[6] = env->mxcsr;
    }

    cc->ExtendedRegisters[0] = 0xaa;

  #elif defined(TARGET_X86_64)
    err = -1;
  #endif

    if (new_mem) {
        memcpy(buf, (uint8_t *) cc + offset, len);
        g_free(cc);
    }
    return err;
}

static int windbg_write_context(CPUState *cpu, uint8_t *buf, int len, int offset)
{
    CPUArchState *env = cpu->env_ptr;
    int mem_size, field_size, field_offset;
    while (len > 0 && offset < sizeof(CPU_CONTEXT)) {
        mem_size = 1;
        switch (offset) {

  #ifdef TARGET_I386

        case offsetof(CPU_CONTEXT, ContextFlags):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, ContextFlags), len);
            break;

        case offsetof(CPU_CONTEXT, Dr0):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Dr0), len);
            windbg_set_dr(cpu, 0, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_CONTEXT, Dr1):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Dr1), len);
            windbg_set_dr(cpu, 1, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_CONTEXT, Dr2):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Dr2), len);
            windbg_set_dr(cpu, 2, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_CONTEXT, Dr3):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Dr3), len);
            windbg_set_dr(cpu, 3, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_CONTEXT, Dr6):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Dr6), len);
            windbg_set_dr(cpu, 6, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_CONTEXT, Dr7):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Dr7), len);
            windbg_set_dr(cpu, 7, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_CONTEXT, FloatSave.ControlWord):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, FloatSave.ControlWord), len);
            memcpy(PTR(env->fpuc), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.StatusWord):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, FloatSave.StatusWord), len);
            memcpy(PTR(env->fpus), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.TagWord):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, FloatSave.TagWord), len);
            memcpy(PTR(env->fpstt), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.ErrorOffset):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, FloatSave.ErrorOffset), len);
            memcpy(PTR(env->fpip), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.ErrorSelector):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, FloatSave.ErrorSelector), len);
            memcpy(PTR(env->fpip) + 4, buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.DataOffset):
            mem_size = MIN(SIZE_OF( CPU_CONTEXT, FloatSave.DataOffset), len);
            memcpy(PTR(env->fpdp), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.DataSelector):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, FloatSave.DataSelector), len);
            memcpy(PTR(env->fpdp) + 4, buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.RegisterArea) ...
             offsetof(CPU_CONTEXT, FloatSave.RegisterArea) +
             SIZE_OF(CPU_CONTEXT,  FloatSave.RegisterArea) - 1:
            field_size = SIZE_OF(CPU_CONTEXT, FloatSave.RegisterArea);
            field_offset = offsetof(CPU_CONTEXT, FloatSave.RegisterArea);
            mem_size = MIN(field_offset + field_size - offset, len);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.Cr0NpxState):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, FloatSave.Cr0NpxState), len);
            memcpy(PTR(env->cr[0]), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, SegGs):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, SegGs), len);
            memcpy(PTR(env->segs[R_GS].selector), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, SegFs):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, SegFs), len);
            memcpy(PTR(env->segs[R_FS].selector), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, SegEs):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, SegEs), len);
            memcpy(PTR(env->segs[R_ES].selector), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, SegDs):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, SegDs), len);
            memcpy(PTR(env->segs[R_DS].selector), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Edi):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Edi), len);
            memcpy(PTR(env->regs[R_EDI]), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Esi):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Esi), len);
            memcpy(PTR(env->regs[R_ESI]), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Ebx):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Ebx), len);
            memcpy(PTR(env->regs[R_EBX]), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Edx):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Edx), len);
            memcpy(PTR(env->regs[R_EDX]), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Ecx):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Ecx), len);
            memcpy(PTR(env->regs[R_ECX]), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Eax):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Eax), len);
            memcpy(PTR(env->regs[R_EAX]), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Ebp):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Ebp), len);
            memcpy(PTR(env->regs[R_EBP]), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Eip):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Eip), len);
            memcpy(PTR(env->eip), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, SegCs):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, SegCs), len);
            memcpy(PTR(env->segs[R_CS].selector), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, EFlags):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, EFlags), len);
            memcpy(PTR(env->eflags), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Esp):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, Esp), len);
            memcpy(PTR(env->regs[R_ESP]), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, SegSs):
            mem_size = MIN(SIZE_OF(CPU_CONTEXT, SegSs), len);
            memcpy(PTR(env->segs[R_SS].selector), buf + offset, mem_size);
            break;

        case offsetof(CPU_CONTEXT, ExtendedRegisters) ...
             offsetof(CPU_CONTEXT, ExtendedRegisters) +
             SIZE_OF(CPU_CONTEXT,  ExtendedRegisters) - 1:
            field_size = SIZE_OF(CPU_CONTEXT, ExtendedRegisters);
            field_offset = offsetof(CPU_CONTEXT, ExtendedRegisters);
            mem_size = MIN(field_offset + field_size - offset, len);
            break;

  #endif

        default:
            WINDBG_DEBUG("write_context: Unknown offset %d", offset);
            break;
        }

        offset += mem_size;
        len -= mem_size;
    }

    return 0;
}

static int windbg_read_ks_regs(CPUState *cpu, uint8_t *buf, int len, int offset)
{
    CPUArchState *env = cpu->env_ptr;
    const bool new_mem = (len != sizeof(CPU_KSPECIAL_REGISTERS) || offset != 0);
    CPU_KSPECIAL_REGISTERS *ckr;
    if (new_mem) {
        ckr = (CPU_KSPECIAL_REGISTERS *) g_malloc(sizeof(CPU_KSPECIAL_REGISTERS));
    }
    else {
        ckr = (CPU_KSPECIAL_REGISTERS *) buf;
    }

    memset(ckr, 0, len);

    ckr->Cr0 = env->cr[0];
    ckr->Cr2 = env->cr[2];
    ckr->Cr3 = env->cr[3];
    ckr->Cr4 = env->cr[4];

    ckr->KernelDr0 = env->dr[0];
    ckr->KernelDr1 = env->dr[1];
    ckr->KernelDr2 = env->dr[2];
    ckr->KernelDr3 = env->dr[3];
    ckr->KernelDr6 = env->dr[6];
    ckr->KernelDr7 = env->dr[7];

    ckr->Gdtr.Pad   = env->gdt.selector;
    ckr->Gdtr.Limit = env->gdt.limit;
    ckr->Gdtr.Base  = env->gdt.base;
    ckr->Idtr.Pad   = env->idt.selector;
    ckr->Idtr.Limit = env->idt.limit;
    ckr->Idtr.Base  = env->idt.base;
    ckr->Tr         = env->tr.selector;
    ckr->Ldtr       = env->ldt.selector;

    if (new_mem) {
        memcpy(buf, (uint8_t *) ckr + offset, len);
        g_free(ckr);
    }
    return 0;
}

static int windbg_write_ks_regs(CPUState *cpu, uint8_t *buf, int len, int offset)
{
    CPUArchState *env = cpu->env_ptr;
    int mem_size, field_size, field_offset;
    while (len > 0 && offset < sizeof(CPU_KSPECIAL_REGISTERS)) {
        mem_size = 1;
        switch (offset) {

  #ifdef TARGET_I386

        case offsetof(CPU_KSPECIAL_REGISTERS, Cr0):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Cr0), len);
            memcpy(PTR(env->cr[0]), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Cr2):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Cr2), len);
            memcpy(PTR(env->cr[2]), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Cr3):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Cr3), len);
            memcpy(PTR(env->cr[3]), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Cr4):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Cr4), len);
            memcpy(PTR(env->cr[4]), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr0):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, KernelDr0), len);
            windbg_set_dr(cpu, 0, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr1):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, KernelDr1), len);
            windbg_set_dr(cpu, 1, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr2):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, KernelDr2), len);
            windbg_set_dr(cpu, 2, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr3):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, KernelDr3), len);
            windbg_set_dr(cpu, 3, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr6):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, KernelDr6), len);
            windbg_set_dr(cpu, 6, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr7):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, KernelDr7), len);
            windbg_set_dr(cpu, 7, *TO_PTR(target_ulong, buf + offset));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Gdtr.Pad):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Gdtr.Pad), len);
            memcpy(PTR(env->gdt.selector), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Gdtr.Limit):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Gdtr.Limit), len);
            memcpy(PTR(env->gdt.limit), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Gdtr.Base):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Gdtr.Base), len);
            memcpy(PTR(env->gdt.base), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Idtr.Pad):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Idtr.Pad), len);
            memcpy(PTR(env->idt.selector), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Idtr.Limit):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Idtr.Limit), len);
            memcpy(PTR(env->idt.limit), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Idtr.Base):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Idtr.Base), len);
            memcpy(PTR(env->idt.base), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Tr):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Tr), len);
            memcpy(PTR(env->tr.selector), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Ldtr):
            mem_size = MIN(SIZE_OF(CPU_KSPECIAL_REGISTERS, Ldtr), len);
            memcpy(PTR(env->ldt.selector), buf + offset, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Reserved) ...
             offsetof(CPU_KSPECIAL_REGISTERS, Reserved) +
             SIZE_OF(CPU_KSPECIAL_REGISTERS, Reserved) - 1:
            field_size = SIZE_OF(CPU_KSPECIAL_REGISTERS, Reserved);
            field_offset = offsetof(CPU_KSPECIAL_REGISTERS, Reserved);
            mem_size = MIN(field_offset + field_size - offset, len);
            break;

  #endif

        default:
            WINDBG_DEBUG("write_context: Unknown offset %d", offset);
            break;
        }

        offset += mem_size;
        len -= mem_size;
    }

    return 0;
}

void kd_api_read_virtual_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_MEMORY64 *mem = &pd->m64->u.ReadMemory;

    mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - M64_SIZE);
    int err = cpu_memory_rw_debug(cpu, mem->TargetBaseAddress,
                                  pd->extra, mem->ActualBytesRead, 0);
    pd->extra_size = mem->ActualBytesRead;

    if (err) {
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;

        // tmp checking
        WINDBG_DEBUG("ReadVirtualMemoryApi: No physical page mapped: " FMT_ADDR,
                        (target_ulong) mem->TargetBaseAddress);
    }
}

void kd_api_write_virtual_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_WRITE_MEMORY64 *mem = &pd->m64->u.WriteMemory;

    mem->ActualBytesWritten = MIN(pd->extra_size, mem->TransferCount);
    int err = cpu_memory_rw_debug(cpu, mem->TargetBaseAddress,
                                  pd->extra, mem->ActualBytesWritten, 1);
    if (err) {
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
    }
    pd->extra_size = 0;
}

void kd_api_get_context(CPUState *cpu, PacketData *pd)
{
    pd->extra_size = sizeof(CPU_CONTEXT);
    int err = windbg_read_context(cpu, pd->extra, pd->extra_size, 0);

    if (err) {
        pd->extra_size = 0;
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
    }
}

void kd_api_set_context(CPUState *cpu, PacketData *pd)
{
    int err = windbg_write_context(cpu, pd->extra, pd->extra_size, 0);
    pd->extra_size = 0;

    if (err) {
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
    }
}

void kd_api_write_breakpoint(CPUState *cpu, PacketData *pd)
{
    DBGKD_WRITE_BREAKPOINT64 *m64cu = &pd->m64->u.WriteBreakPoint;
    target_ulong addr = m64cu->BreakPointAddress;
    int i = 0, err = 0;

    for (; i < KD_BREAKPOINT_MAX; ++i) {
        if (!kd.bps[i].is_init) {
            err = cpu_breakpoint_insert(cpu, addr, BP_GDB, NULL);
            if (!err) {
                tb_flush(cpu);
                kd.bps[i].addr = addr;
                kd.bps[i].is_init = true;
                WINDBG_DEBUG("write_breakpoint: " FMT_ADDR, addr);
                break;
            }
            else {
                WINDBG_ERROR("write_breakpoint: " FMT_ADDR ", " FMT_ERR, addr, err);
                pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
                return;
            }
        }
        else if (addr == kd.bps[i].addr) {
            break;
        }
    }

    if (!err) {
        m64cu->BreakPointHandle = i + 1;
        pd->m64->ReturnStatus = STATUS_SUCCESS;
    }
    else {
        WINDBG_ERROR("write_breakpoint: All breakpoints occupied");
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
    }
}

void kd_api_restore_breakpoint(CPUState *cpu, PacketData *pd)
{
    DBGKD_RESTORE_BREAKPOINT *m64cu = &pd->m64->u.RestoreBreakPoint;
    uint8_t index = m64cu->BreakPointHandle - 1;
    int err = -1;

    if (kd.bps[index].is_init) {
        err = cpu_breakpoint_remove(cpu, kd.bps[index].addr, BP_GDB);
        if (!err) {
            WINDBG_DEBUG("restore_breakpoint: " FMT_ADDR ", index %d",
                         kd.bps[index].addr, index);
        }
        else {
            WINDBG_ERROR("restore_breakpoint: " FMT_ADDR ", index %d, " FMT_ERR,
                         kd.bps[index].addr, index, err);
        }
        kd.bps[index].is_init = false;
        pd->m64->ReturnStatus = STATUS_SUCCESS;
    }
    else {
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
    }
}

void kd_api_continue(CPUState *cpu, PacketData *pd)
{
    if (NT_SUCCESS(pd->m64->ReturnStatus)) {
        cpu_single_step(cpu, pd->m64->u.Continue2.ControlSet.TraceFlag ?
                        SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER : 0);

        if (!runstate_needs_reset()) {
            vm_start();
        }
    }
}

void kd_api_read_control_space(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_MEMORY64 *mem = &pd->m64->u.ReadMemory;
    int err = -1;

    if (mem->TargetBaseAddress < sizeof(CPU_KPROCESSOR_STATE)) {
        mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - M64_SIZE);
        mem->ActualBytesRead = MIN(mem->ActualBytesRead,
                                   sizeof(CPU_KPROCESSOR_STATE) - mem->TargetBaseAddress);

        int from_context = MAX(0, (int) sizeof(CPU_CONTEXT) - (int) mem->TargetBaseAddress);
        int from_ks_regs = mem->ActualBytesRead - from_context;


        if (from_context > 0) {
            err = windbg_read_context(cpu, pd->extra, from_context,
                                      mem->TargetBaseAddress);
        }
        if (from_ks_regs > 0) {
            err = windbg_read_ks_regs(cpu, pd->extra + from_context, from_ks_regs,
                                      mem->TargetBaseAddress - sizeof(CPU_CONTEXT) + from_context);
        }
    }

    if (err) {
        pd->extra_size = mem->ActualBytesRead = 0;
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
    }
    else {
        pd->extra_size = mem->ActualBytesRead;
    }
}

void kd_api_write_control_space(CPUState *cpu, PacketData *pd)
{
    DBGKD_WRITE_MEMORY64 *mem = &pd->m64->u.WriteMemory;
    int err = -1;

    if (mem->TargetBaseAddress < sizeof(CPU_KPROCESSOR_STATE)) {
        mem->ActualBytesWritten = MIN(pd->extra_size, mem->TransferCount);
        mem->ActualBytesWritten = MIN(mem->ActualBytesWritten,
                                      sizeof(CPU_KPROCESSOR_STATE) - mem->TargetBaseAddress);

        int to_context = MAX(0, (int) sizeof(CPU_CONTEXT) - (int) mem->TargetBaseAddress);
        int to_ks_regs = mem->ActualBytesWritten - to_context;


        if (to_context > 0) {
            err = windbg_write_context(cpu, pd->extra, to_context,
                                       mem->TargetBaseAddress);
        }
        if (to_ks_regs > 0) {
            err = windbg_write_ks_regs(cpu, pd->extra + to_context, to_ks_regs,
                                       mem->TargetBaseAddress - sizeof(CPU_CONTEXT) + to_context);
        }
    }

    pd->extra_size = 0;
    if (err) {
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
        mem->ActualBytesWritten = 0;
    }
}

void kd_api_read_physical_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_MEMORY64 *mem = &pd->m64->u.ReadMemory;

    mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - M64_SIZE);
    cpu_physical_memory_rw(mem->TargetBaseAddress, pd->extra,
                           mem->ActualBytesRead, 0);
    pd->extra_size = mem->ActualBytesRead;
}

void kd_api_write_physical_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_WRITE_MEMORY64 *mem = &pd->m64->u.WriteMemory;

    mem->ActualBytesWritten = MIN(pd->extra_size, mem->TransferCount);
    cpu_physical_memory_rw(mem->TargetBaseAddress, pd->extra,
                            mem->ActualBytesWritten, 1);
    pd->extra_size = 0;
}

void kd_api_get_version(CPUState *cpu, PacketData *pd)
{
    int err = cpu_memory_rw_debug(cpu, kd.cca.Version,
                                  (uint8_t *) pd->m64 + 0x10,
                                  M64_SIZE - 0x10, 0);
    if (err) {
        WINDBG_ERROR("GetVersionApi: " FMT_ERR, err);
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
    }
}

void kd_api_read_io_space(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_WRITE_IO64 *io = &pd->m64->u.ReadWriteIo;
    CPUArchState *env = cpu->env_ptr;

    switch (io->DataSize) {
    case 1:
        io->DataValue = address_space_ldub(&address_space_io, io->IoAddress,
                                           cpu_get_mem_attrs(env), NULL);
        break;
    case 2:
        io->DataValue = address_space_lduw(&address_space_io, io->IoAddress,
                                           cpu_get_mem_attrs(env), NULL);
        break;
    case 4:
        io->DataValue = address_space_ldl(&address_space_io, io->IoAddress,
                                           cpu_get_mem_attrs(env), NULL);
        break;
    default:
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
        return;
    }

    pd->m64->ReturnStatus = STATUS_SUCCESS;
}

void kd_api_write_io_space(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_WRITE_IO64 *io = &pd->m64->u.ReadWriteIo;
    CPUArchState *env = cpu->env_ptr;

    switch (io->DataSize) {
    case 1:
        address_space_stb(&address_space_io, io->IoAddress, io->DataValue,
                          cpu_get_mem_attrs(env), NULL);
        break;
    case 2:
        address_space_stw(&address_space_io, io->IoAddress, io->DataValue,
                          cpu_get_mem_attrs(env), NULL);
        break;
    case 4:
        address_space_stl(&address_space_io, io->IoAddress, io->DataValue,
                          cpu_get_mem_attrs(env), NULL);
        break;
    default:
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
        return;
    }

    pd->m64->ReturnStatus = STATUS_SUCCESS;
}

void kd_api_read_msr(CPUState *cpu, PacketData *pd)
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

    m64cu->DataValueLow  = UINT32P(val)[0];
    m64cu->DataValueHigh = UINT32P(val)[1];
    pd->m64->ReturnStatus = STATUS_SUCCESS;
}

void kd_api_write_msr(CPUState *cpu, PacketData *pd)
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
    pd->m64->ReturnStatus = STATUS_SUCCESS;
}

void kd_api_search_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_SEARCH_MEMORY *m64cu = &pd->m64->u.SearchMemory;
    int s_len = MAX(1, m64cu->SearchLength);
    int p_len = MIN(m64cu->PatternLength, pd->extra_size);

    SizedBuf mem;
    mem.size = s_len - 1 + p_len;
    mem.data = g_malloc0(mem.size);

    int err = cpu_memory_rw_debug(cpu, m64cu->SearchAddress, mem.data, mem.size, 0);
    if (!err) {
        int i;
        pd->m64->ReturnStatus = STATUS_NO_MORE_ENTRIES;
        for (i = 0; i < s_len; ++i) {
            if (memcmp(mem.data + i, pd->extra, p_len) == 0) {
                m64cu->FoundAddress = m64cu->SearchAddress + i;
                pd->m64->ReturnStatus = STATUS_SUCCESS;
                break;
            }
        }
    }
    else {
        // tmp checking
        WINDBG_DEBUG("search_memory: No physical page mapped: " FMT_ADDR,
                     (target_ulong) m64cu->SearchAddress);
        pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
    }

    pd->extra_size = 0;
    g_free(mem.data);
}

void kd_api_query_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_QUERY_MEMORY *mem = &pd->m64->u.QueryMemory;

    if (mem->AddressSpace == DBGKD_QUERY_MEMORY_VIRTUAL) {
        mem->AddressSpace = DBGKD_QUERY_MEMORY_PROCESS;
        mem->Flags = DBGKD_QUERY_MEMORY_READ |
                     DBGKD_QUERY_MEMORY_WRITE |
                     DBGKD_QUERY_MEMORY_EXECUTE;
    }
}

void kd_api_unsupported(CPUState *cpu, PacketData *pd)
{
    WINDBG_ERROR("Catched unimplemented api: %s",
                 KD_API_NAME(pd->m64->ApiNumber));
    pd->m64->ReturnStatus = STATUS_UNSUCCESSFUL;
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

static void kd_breakpoint_remove_range(CPUState *cpu, target_ulong base, target_ulong limit)
{
    int i = 0, err = 0;
    for (; i < KD_BREAKPOINT_MAX; ++i) {
        if (kd.bps[i].is_init && kd.bps[i].addr >= base && kd.bps[i].addr < limit) {
            err = cpu_breakpoint_remove(cpu, kd.bps[i].addr, BP_GDB);
            if (!err) {
                WINDBG_DEBUG("breakpoint_remove_range: " FMT_ADDR ", index %d",
                            kd.bps[i].addr, i);
            }
            else {
                WINDBG_ERROR("breakpoint_remove_range: " FMT_ADDR ", index %d, " FMT_ERR,
                            kd.bps[i].addr, i, err);
            }
            kd.bps[i].is_init = false;
        }
    }
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
        kd_breakpoint_remove_range(cpu, sc->ProgramCounter,
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

void windbg_on_init(void)
{
    // init cpu ctrl addrs
    kd_get_cpu_ctrl_addrs(qemu_get_cpu(0));

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