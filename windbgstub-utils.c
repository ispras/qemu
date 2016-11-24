#include "exec/windbgstub-utils.h"

static CPU_CTRL_ADDRS cca;
static uint8_t *lssc;
static EXCEPTION_STATE_CHANGE esc;
static CPU_CONTEXT cc;
static CPU_KSPECIAL_REGISTERS ckr;

static size_t lssc_size = 0;

PCPU_CTRL_ADDRS get_cpu_ctrl_addrs(int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);
    CPUArchState *env = cpu->env_ptr;

    cca.KPCR = env->segs[R_FS].base;

    cpu_memory_rw_debug(cpu, cca.KPCR + OFFSET_KPRCB, PTR(cca.KPRCB),
                        sizeof(cca.KPRCB), 0);

    cpu_memory_rw_debug(cpu, cca.KPCR + OFFSET_VERSION, PTR(cca.Version),
                        sizeof(cca.Version), 0);

    cpu_memory_rw_debug(cpu, cca.Version + OFFSET_KRNL_BASE, PTR(cca.KernelBase),
                        sizeof(cca.KernelBase), 0);

    return &cca;
}

PEXCEPTION_STATE_CHANGE get_exception_sc(int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);
    CPUArchState *env = cpu->env_ptr;

    memset(&esc, 0, sizeof(esc));

    DBGKD_ANY_WAIT_STATE_CHANGE *sc = &esc.StateChange;

    sc->NewState = DbgKdExceptionStateChange;
    //TODO: Get it
    sc->ProcessorLevel = 0x6; //Pentium 4
    //
    sc->Processor = cpu_index;
    sc->NumberProcessors = cpu_amount();
    //TODO: + 0xffffffff00000000
    cpu_memory_rw_debug(cpu, cca.KPRCB + OFFSET_KPRCB_CURRTHREAD,
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
    sc->ControlReport.SegCs = env->segs[R_CS].selector;;
    sc->ControlReport.SegDs = env->segs[R_DS].selector;
    sc->ControlReport.SegEs = env->segs[R_ES].selector;
    sc->ControlReport.SegFs = env->segs[R_FS].selector;
    sc->ControlReport.EFlags = env->eflags;
    //TODO: Get it
    esc.value = 0x1;

    return &esc;
}

size_t sizeof_lssc(void)
{
    return lssc_size;
}

uint8_t *get_load_symbols_sc(int cpu_index)
{
    int i;
    uint8_t path_name[128]; //For Win7
    size_t size = sizeof(DBGKD_ANY_WAIT_STATE_CHANGE),
           count = sizeof(path_name);

    CPUState *cpu = qemu_get_cpu(cpu_index);
    DBGKD_ANY_WAIT_STATE_CHANGE sc;

    memcpy(&sc, get_exception_sc(0), size);

    cpu_memory_rw_debug(cpu, NT_KRNL_PNAME_ADDR, path_name, count, 0);
    for (i = 0; i < count; i++) {
        if((path_name[i / 2] = path_name[i]) == '\0') {
            break;
        }
        i++;
    }
    count = i / 2 + 1;
    lssc_size = size + count;

    sc.NewState = DbgKdLoadSymbolsStateChange;
    sc.u.LoadSymbols.PathNameLength = count;
    ////TODO: Get it
    //sc.u.LoadSymbols.BaseOfDll = cca.KernelBase << 8 | ;
    //sc.u.LoadSymbols.ProcessId = -1;
    //sc.u.LoadSymbols.CheckSum = ;
    //sc.u.LoadSymbols.SizeOfImage = ;
    //sc.u.LoadSymbols.UnloadSymbols = false;
    ////

    if (lssc) {
        g_free(lssc);
    }
    lssc = g_malloc0(lssc_size);
    memcpy(lssc, &sc, size);
    memcpy(lssc + size, path_name, count);

    return lssc;
}

PCPU_CONTEXT get_context(int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);
    CPUArchState *env = cpu->env_ptr;
    int i;

    memset(&cc, 0, sizeof(cc));

  #if defined(TARGET_I386)

    cc.ContextFlags = CPU_CONTEXT_ALL;

    if (cc.ContextFlags & CPU_CONTEXT_FULL) {
        cc.Dr0    = env->dr[0];
        cc.Dr1    = env->dr[1];
        cc.Dr2    = env->dr[2];
        cc.Dr3    = env->dr[3];
        cc.Dr6    = env->dr[6];
        cc.Dr7    = env->dr[7];

        cc.Edi    = env->regs[R_EDI];
        cc.Esi    = env->regs[R_ESI];
        cc.Ebx    = env->regs[R_EBX];
        cc.Edx    = env->regs[R_EDX];
        cc.Ecx    = env->regs[R_ECX];
        cc.Eax    = env->regs[R_EAX];
        cc.Ebp    = env->regs[R_EBP];
        cc.Esp    = env->regs[R_ESP];

        cc.Eip    = env->eip;
        cc.EFlags = env->eflags;

        cc.SegGs  = env->segs[R_GS].selector;
        cc.SegFs  = env->segs[R_FS].selector;
        cc.SegEs  = env->segs[R_ES].selector;
        cc.SegDs  = env->segs[R_DS].selector;
        cc.SegCs  = env->segs[R_CS].selector;
        cc.SegSs  = env->segs[R_SS].selector;
    }

    if (cc.ContextFlags & CPU_CONTEXT_FLOATING_POINT) {
        cc.FloatSave.ControlWord    = env->fpuc;
        cc.FloatSave.StatusWord     = env->fpus;
        cc.FloatSave.TagWord        = env->fpstt;
        cc.FloatSave.ErrorOffset    = DWORD(env->fpip, 0);
        cc.FloatSave.ErrorSelector  = DWORD(env->fpip, 1);
        cc.FloatSave.DataOffset     = DWORD(env->fpdp, 0);
        cc.FloatSave.DataSelector   = DWORD(env->fpdp, 1);
        cc.FloatSave.Cr0NpxState    = env->cr[0];

        for (i = 0; i < 8; ++i) {
            memcpy(PTR(cc.FloatSave.RegisterArea[i * 10]),
                   PTR(env->fpregs[i].mmx), sizeof(MMXReg));
        }
    }

    if (cc.ContextFlags & CPU_CONTEXT_DEBUG_REGISTERS) {

    }

    if (cc.ContextFlags & CPU_CONTEXT_EXTENDED_REGISTERS) {
        for (i = 0; i < 8; ++i) {
            memcpy(PTR(cc.ExtendedRegisters[(10 + i) * 16]),
                   PTR(env->xmm_regs[i]), sizeof(ZMMReg));
        }
        // offset 24
        DWORD(cc.ExtendedRegisters, 6) = env->mxcsr;
    }

    cc.ExtendedRegisters[0] = 0xaa;

  #elif defined(TARGET_X86_64)

  #endif

    return &cc;
}

void set_context(uint8_t *data, int len, int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);
    CPUArchState *env = cpu->env_ptr;
    int i;

    memcpy(PTR(cc), data, MIN(len, sizeof(cc)));

  #if defined(TARGET_I386)

    if (cc.ContextFlags & CPU_CONTEXT_FULL) {
        env->dr[0] = cc.Dr0;
        env->dr[1] = cc.Dr1;
        env->dr[2] = cc.Dr2;
        env->dr[3] = cc.Dr3;
        env->dr[6] = cc.Dr6;
        env->dr[7] = cc.Dr7;

        env->regs[R_EDI] = cc.Edi;
        env->regs[R_ESI] = cc.Esi;
        env->regs[R_EBX] = cc.Ebx;
        env->regs[R_EDX] = cc.Edx;
        env->regs[R_ECX] = cc.Ecx;
        env->regs[R_EAX] = cc.Eax;
        env->regs[R_EBP] = cc.Ebp;
        env->regs[R_ESP] = cc.Esp;

        env->eip    = cc.Eip;
        env->eflags = cc.EFlags;

        env->segs[R_GS].selector = cc.SegGs;
        env->segs[R_FS].selector = cc.SegFs;
        env->segs[R_ES].selector = cc.SegEs;
        env->segs[R_DS].selector = cc.SegDs;
        env->segs[R_CS].selector = cc.SegCs;
        env->segs[R_SS].selector = cc.SegSs;
    }

    if (cc.ContextFlags & CPU_CONTEXT_FLOATING_POINT) {
        env->fpuc  = cc.FloatSave.ControlWord;
        env->fpus  = cc.FloatSave.StatusWord;
        env->fpstt = cc.FloatSave.TagWord;
        DWORD(env->fpip, 0) = cc.FloatSave.ErrorOffset;
        DWORD(env->fpip, 1) = cc.FloatSave.ErrorSelector;
        DWORD(env->fpdp, 0) = cc.FloatSave.DataOffset;
        DWORD(env->fpdp, 1) = cc.FloatSave.DataSelector;
        env->cr[0] = cc.FloatSave.Cr0NpxState;

        for (i = 0; i < 8; ++i) {
            memcpy(PTR(env->fpregs[i].mmx),
                   PTR(cc.FloatSave.RegisterArea[i * 10]), sizeof(MMXReg));
        }
    }

    if (cc.ContextFlags & CPU_CONTEXT_DEBUG_REGISTERS) {

    }

    if (cc.ContextFlags & CPU_CONTEXT_EXTENDED_REGISTERS) {
        for (i = 0; i < 8; ++i) {
            memcpy(PTR(env->xmm_regs[i]),
                   PTR(cc.ExtendedRegisters[(10 + i) * 16]), sizeof(ZMMReg));
        }
        env->mxcsr = DWORD(cc.ExtendedRegisters, 6);
    }

  #elif defined(TARGET_X86_64)

  #endif
}

PCPU_KSPECIAL_REGISTERS get_kspecial_registers(int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);
    CPUArchState *env = cpu->env_ptr;

    memset(&ckr, 0, sizeof(ckr));

    ckr.Cr0 = env->cr[0];
    ckr.Cr2 = env->cr[2];
    ckr.Cr3 = env->cr[3];
    ckr.Cr4 = env->cr[4];

    ckr.KernelDr0 = env->dr[0];
    ckr.KernelDr1 = env->dr[1];
    ckr.KernelDr2 = env->dr[2];
    ckr.KernelDr3 = env->dr[3];
    ckr.KernelDr6 = env->dr[6];
    ckr.KernelDr7 = env->dr[7];

    ckr.Gdtr.Pad   = env->gdt.selector;
    ckr.Gdtr.Limit = env->gdt.limit;
    ckr.Gdtr.Base  = env->gdt.base;
    ckr.Idtr.Pad   = env->idt.selector;
    ckr.Idtr.Limit = env->idt.limit;
    ckr.Idtr.Base  = env->idt.base;
    ckr.Tr         = env->tr.selector;
    ckr.Ldtr       = env->ldt.selector;

    // ckr.Reserved[6];

    return &ckr;
}

void set_kspecial_registers(uint8_t *data, int len, int offset, int cpu_index)
{
    CPUState *cpu = qemu_get_cpu(cpu_index);
    CPUArchState *env = cpu->env_ptr;

    memcpy(PTR(ckr) + offset, data, MIN(len, sizeof(ckr) - offset));

    env->cr[0] = ckr.Cr0;
    env->cr[2] = ckr.Cr2;
    env->cr[3] = ckr.Cr3;
    env->cr[4] = ckr.Cr4;

    env->dr[0] = ckr.KernelDr0;
    env->dr[1] = ckr.KernelDr1;
    env->dr[2] = ckr.KernelDr2;
    env->dr[3] = ckr.KernelDr3;
    env->dr[6] = ckr.KernelDr6;
    env->dr[7] = ckr.KernelDr7;

    env->gdt.selector = ckr.Gdtr.Pad;
    env->gdt.limit    = ckr.Gdtr.Limit;
    env->gdt.base     = ckr.Gdtr.Base;
    env->idt.selector = ckr.Idtr.Pad;
    env->idt.limit    = ckr.Idtr.Limit;
    env->idt.base     = ckr.Idtr.Base;
    env->tr.selector  = ckr.Tr;
    env->ldt.selector = ckr.Ldtr;

    // ckr.Reserved[6];
}

void on_init(void)
{
    lssc = NULL;
}

void on_exit(void)
{
    if (lssc) {
        g_free(lssc);
    }
    lssc = NULL;
}

uint8_t cpu_amount(void)
{
    uint8_t amount = 0;
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        ++amount;
    }

    return amount;
}

uint32_t compute_checksum(uint8_t *data, uint16_t length)
{
    uint32_t checksum = 0;
    for(; length; --length) {
        checksum += *data++;
    }
    return checksum;
}