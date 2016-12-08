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

#define BP_FLAG(dr7, index) ({                                 \
    int _type = BP_TYPE(dr7, index);                           \
    int _flag = _type == DR7_TYPE_DATA_WR ? BP_MEM_WRITE :     \
                _type == DR7_TYPE_DATA_RW ? BP_MEM_ACCESS : 0; \
    _flag | BP_GDB;                                            \
})

typedef struct InitedAddr {
    target_ulong addr;
    bool is_init;
} InitedAddr;

typedef struct KDData {
    CPU_CTRL_ADDRS cca;
    SizedData lssc;
    EXCEPTION_STATE_CHANGE esc;
    CPU_CONTEXT cc;
    CPU_KSPECIAL_REGISTERS ckr;
} KDData;

static KDData kd;
static InitedAddr bps[KD_BREAKPOINT_MAX];
static InitedAddr dr[8];
static uint8_t cpu_amount;

uint8_t windbg_breakpoint_insert(CPUState *cpu, target_ulong addr)
{
    int i = 0, s = ARRAY_SIZE(bps);
    for (; i < s; ++i) {
        if (!bps[i].is_init) {
            cpu_breakpoint_insert(cpu, addr, BP_GDB, NULL);
            tb_flush(cpu);
            bps[i].addr = addr;
            bps[i].is_init = true;
            return i;
        }
    }
    return -1;
}

void windbg_breakpoint_remove(CPUState *cpu, uint8_t index)
{
    if (bps[index].is_init) {
        cpu_breakpoint_remove(cpu, bps[index].addr, BP_GDB);
        bps[index].is_init = false;
    }
}

static void windbg_update_dr(CPUState *cpu, target_ulong *new_dr)
{
    int i;
    if (!dr[7].is_init || dr[7].addr != new_dr[7]) {
        for (i = 0; i < DR7_MAX_BP; ++i) {
            bool is_enabled = IS_BP_ENABLED(new_dr[7], i);
            if (!is_enabled) {
                if (dr[i].is_init) {
                    cpu_watchpoint_remove(cpu, dr[i].addr, BP_LEN(dr[7].addr, i), BP_FLAG(dr[7].addr, i));
                    dr[i].is_init = false;
                }
            }
            else if (is_enabled && (new_dr[i] != dr[i].addr)) {
                if (dr[i].is_init) {
                    cpu_watchpoint_remove(cpu, dr[i].addr, BP_LEN(dr[7].addr, i), BP_FLAG(dr[7].addr, i));
                    dr[i].is_init = false;
                }

                dr[i].addr = new_dr[i];
                dr[i].is_init = true;

                cpu_watchpoint_insert(cpu, dr[i].addr, BP_LEN(new_dr[7], i), BP_FLAG(new_dr[7], i), NULL);
            }
        }

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

CPU_CTRL_ADDRS *kd_get_cpu_ctrl_addrs(int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);
    CPUArchState *env = cpu->env_ptr;

    kd.cca.KPCR = env->segs[R_FS].base;

    cpu_memory_rw_debug(cpu, kd.cca.KPCR + OFFSET_KPRCB, PTR(kd.cca.KPRCB),
                        sizeof(kd.cca.KPRCB), 0);

    cpu_memory_rw_debug(cpu, kd.cca.KPCR + OFFSET_VERSION, PTR(kd.cca.Version),
                        sizeof(kd.cca.Version), 0);

    cpu_memory_rw_debug(cpu, kd.cca.Version + OFFSET_KRNL_BASE, PTR(kd.cca.KernelBase),
                        sizeof(kd.cca.KernelBase), 0);

    return &kd.cca;
}

EXCEPTION_STATE_CHANGE *kd_get_exception_sc(int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);
    CPUArchState *env = cpu->env_ptr;

    memset(&kd.esc, 0, sizeof(kd.esc));

    DBGKD_ANY_WAIT_STATE_CHANGE *sc = &kd.esc.StateChange;

    sc->NewState = DbgKdExceptionStateChange;
    //TODO: Get it
    sc->ProcessorLevel = 0x6; //Pentium 4
    //
    sc->Processor = cpu_index;
    sc->NumberProcessors = get_cpu_amount();
    //TODO: + 0xffffffff00000000
    cpu_memory_rw_debug(cpu, kd.cca.KPRCB + OFFSET_KPRCB_CURRTHREAD,
                        PTR(sc->Thread), sizeof(sc->Thread), 0);
    sc->ProgramCounter = env->eip;
    //
    //TODO: Get it
    sc->u.Exception.ExceptionRecord.ExceptionCode = 0x80000003;
    //sc->u.Exception.ExceptionRecord.ExceptionFlags = 0x0;
    //sc->u.Exception.ExceptionRecord.ExceptionRecord = 0x0;
    //
    //TODO: + 0xffffffff00000000
    sc->u.Exception.ExceptionRecord.ExceptionAddress = env->eip;
    //
    //TODO: Get it
    //sc->u.Exception.ExceptionRecord.NumberParameters = 0x3;
    //sc->u.Exception.ExceptionRecord.__unusedAligment = 0x80;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[1] = 0xffffffff82966340;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[2] = 0xffffffff82959adc;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[3] = 0xc0;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[4] = 0xffffffffc020360c;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[5] = 0x80;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[6] = 0x0;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[7] = 0x0;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[8] = 0xffffffff82870d08;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[9] = 0xffffffff82959aec;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[10] = 0xffffffff82853508;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[11] = 0xffffffffbadb0d00;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[12] = 0xffffffff82959adc;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[13] = 0xffffffff82959aa4;
    //sc->u.Exception.ExceptionRecord.ExceptionInformation[14] = 0xffffffff828d9d15;
    //
    //TODO: Get it
    sc->u.Exception.FirstChance = 0x1;
    //
    sc->ControlReport.Dr6 = env->dr[6];
    sc->ControlReport.Dr7 = env->dr[7];
    //TODO: Get it
    //sc->ControlReport.InstructionCount = 0x10;
    //sc->ControlReport.ReportFlags = 0x3;
    //
    cpu_memory_rw_debug(cpu, env->eip,
                        (uint8_t *) sc->ControlReport.InstructionStream,
                        sizeof(sc->ControlReport.InstructionStream), 0);
    sc->ControlReport.SegCs = env->segs[R_CS].selector;
    sc->ControlReport.SegDs = env->segs[R_DS].selector;
    sc->ControlReport.SegEs = env->segs[R_ES].selector;
    sc->ControlReport.SegFs = env->segs[R_FS].selector;
    sc->ControlReport.EFlags = env->eflags;
    //TODO: Get it
    kd.esc.value = 0x1;

    return &kd.esc;
}

SizedData *kd_get_load_symbols_sc(int cpu_index)
{
    int i;
    uint8_t path_name[128]; //For Win7
    size_t size = sizeof(DBGKD_ANY_WAIT_STATE_CHANGE),
           count = sizeof(path_name);

    CPUState *cpu = qemu_get_cpu(cpu_index);
    DBGKD_ANY_WAIT_STATE_CHANGE sc;

    memcpy(&sc, kd_get_exception_sc(0), size);

    cpu_memory_rw_debug(cpu, NT_KRNL_PNAME_ADDR, path_name, count, 0);
    for (i = 0; i < count; i++) {
        if((path_name[i / 2] = path_name[i]) == '\0') {
            break;
        }
        i++;
    }
    count = i / 2 + 1;
    kd.lssc.size = size + count;

    sc.NewState = DbgKdLoadSymbolsStateChange;
    sc.u.LoadSymbols.PathNameLength = count;
    ////TODO: Get it
    //sc.u.LoadSymbols.BaseOfDll = cca.KernelBase << 8 | ;
    //sc.u.LoadSymbols.ProcessId = -1;
    //sc.u.LoadSymbols.CheckSum = ;
    //sc.u.LoadSymbols.SizeOfImage = ;
    //sc.u.LoadSymbols.UnloadSymbols = false;
    ////

    if (kd.lssc.data) {
        g_free(kd.lssc.data);
    }
    kd.lssc.data = g_malloc0(kd.lssc.size);
    memcpy(kd.lssc.data, &sc, size);
    memcpy(kd.lssc.data + size, path_name, count);

    return &kd.lssc;
}

CPU_CONTEXT *kd_get_context(int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);
    CPUArchState *env = cpu->env_ptr;
    int i;

    memset(&kd.cc, 0, sizeof(kd.cc));

  #if defined(TARGET_I386)

    kd.cc.ContextFlags = CPU_CONTEXT_ALL;

    if (kd.cc.ContextFlags & CPU_CONTEXT_FULL) {
        kd.cc.Dr0    = env->dr[0];
        kd.cc.Dr1    = env->dr[1];
        kd.cc.Dr2    = env->dr[2];
        kd.cc.Dr3    = env->dr[3];
        kd.cc.Dr6    = env->dr[6];
        kd.cc.Dr7    = env->dr[7];

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
        kd.cc.FloatSave.ErrorOffset    = DWORD(env->fpip, 0);
        kd.cc.FloatSave.ErrorSelector  = DWORD(env->fpip, 1);
        kd.cc.FloatSave.DataOffset     = DWORD(env->fpdp, 0);
        kd.cc.FloatSave.DataSelector   = DWORD(env->fpdp, 1);
        kd.cc.FloatSave.Cr0NpxState    = env->cr[0];

        for (i = 0; i < 8; ++i) {
            memcpy(PTR(kd.cc.FloatSave.RegisterArea[i * 10]),
                   PTR(env->fpregs[i].mmx), sizeof(MMXReg));
        }
    }

    if (kd.cc.ContextFlags & CPU_CONTEXT_DEBUG_REGISTERS) {

    }

    if (kd.cc.ContextFlags & CPU_CONTEXT_EXTENDED_REGISTERS) {
        for (i = 0; i < 8; ++i) {
            memcpy(PTR(kd.cc.ExtendedRegisters[(10 + i) * 16]),
                   PTR(env->xmm_regs[i]), sizeof(ZMMReg));
        }
        // offset 24
        DWORD(kd.cc.ExtendedRegisters, 6) = env->mxcsr;
    }

    kd.cc.ExtendedRegisters[0] = 0xaa;

  #elif defined(TARGET_X86_64)

  #endif

    return &kd.cc;
}

void kd_set_context(uint8_t *data, int len, int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);

    CPU_CONTEXT cc;
    memcpy(PTR(cc), data, MIN(len, sizeof(cc)));

  #if defined(TARGET_I386)

    if (cc.ContextFlags & CPU_CONTEXT_FULL) {
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

    if (cc.ContextFlags & CPU_CONTEXT_FLOATING_POINT) {

    }

    if (cc.ContextFlags & CPU_CONTEXT_DEBUG_REGISTERS) {

    }

    if (cc.ContextFlags & CPU_CONTEXT_EXTENDED_REGISTERS) {

    }

  #elif defined(TARGET_X86_64)

  #endif
}

CPU_KSPECIAL_REGISTERS *kd_get_kspecial_registers(int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);
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

void kd_set_kspecial_registers(uint8_t *data, int len, int offset, int cpu_index)
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
    }
    kd.lssc.data = NULL;
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