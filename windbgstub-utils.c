#include "exec/windbgstub-utils.h"

static CPU_CTRL_ADDRS pca;
static EXCEPTION_STATE_CHANGE esc;
static CONTEXT c;
static KSPECIAL_REGISTERS kr;

PCPU_CTRL_ADDRS get_KPCRAddress(int index)
{
    CPUState *cpu = find_cpu(index);
    CPUArchState *env = CPU_ARCH_STATE(cpu);

    pca.KPCR = env->segs[R_FS].base;

    cpu_memory_rw_debug(cpu, pca.KPCR + OFFSET_KPRCB,
                        PTR(pca.KPRCB), sizeof(pca.KPRCB), 0);

    cpu_memory_rw_debug(cpu, pca.KPCR + OFFSET_VERSION,
                        PTR(pca.Version), sizeof(pca.Version), 0);
    return &pca;
}

PEXCEPTION_STATE_CHANGE get_ExceptionStateChange(int index)
{
    CPUState *cpu = find_cpu(index);
    CPUArchState *env = CPU_ARCH_STATE(cpu);

    memset(&esc, 0, sizeof(esc));

    esc.StateChange.NewState = DbgKdExceptionStateChange;
    //TODO: Get it
    esc.StateChange.ProcessorLevel = 0x6; //Pentium 4
    //
    esc.StateChange.Processor = index;
    esc.StateChange.NumberProcessors = cpu_amount();
    //TODO: + 0xffffffff00000000
    cpu_memory_rw_debug(cpu, pca.KPRCB + OFFSET_KPRCB_CURRTHREAD,
                        PTR(esc.StateChange.Thread),
                        sizeof(esc.StateChange.Thread), 0);
    esc.StateChange.ProgramCounter = env->eip;
    //
    //TODO: Get it
    esc.StateChange.u.Exception.ExceptionRecord.ExceptionCode = 0x80000003;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionFlags = 0x0;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionRecord = 0x0;
    //
    //TODO: + 0xffffffff00000000
    esc.StateChange.u.Exception.ExceptionRecord.ExceptionAddress = env->eip;
    //
    //TODO: Get it
    //esc.StateChange.u.Exception.ExceptionRecord.NumberParameters = 0x3;
    //esc.StateChange.u.Exception.ExceptionRecord.__unusedAligment = 0x80;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[1] = 0xffffffff82966340;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[2] = 0xffffffff82959adc;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[3] = 0xc0;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[4] = 0xffffffffc020360c;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[5] = 0x80;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[6] = 0x0;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[7] = 0x0;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[8] = 0xffffffff82870d08;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[9] = 0xffffffff82959aec;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[10] = 0xffffffff82853508;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[11] = 0xffffffffbadb0d00;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[12] = 0xffffffff82959adc;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[13] = 0xffffffff82959aa4;
    //esc.StateChange.u.Exception.ExceptionRecord.ExceptionInformation[14] = 0xffffffff828d9d15;
    //
    //TODO: Get it
    esc.StateChange.u.Exception.FirstChance = 0x1;
    //
    esc.StateChange.ControlReport.Dr6 = env->dr[6];
    esc.StateChange.ControlReport.Dr7 = env->dr[7];
    //TODO: Get it
    //esc.StateChange.ControlReport.InstructionCount = 0x10;
    //esc.StateChange.ControlReport.ReportFlags = 0x3;
    //
    cpu_memory_rw_debug(cpu, env->eip,
                        (uint8_t *)esc.StateChange.ControlReport.InstructionStream,
                        sizeof(esc.StateChange.ControlReport.InstructionStream), 0);
    esc.StateChange.ControlReport.SegCs = env->segs[R_CS].selector;;
    esc.StateChange.ControlReport.SegDs = env->segs[R_DS].selector;
    esc.StateChange.ControlReport.SegEs = env->segs[R_ES].selector;
    esc.StateChange.ControlReport.SegFs = env->segs[R_FS].selector;
    esc.StateChange.ControlReport.EFlags = env->eflags;
    //TODO: Get it
    //esc.value = 0x1;

    return &esc;
}

PCONTEXT get_Context(int index)
{
    // CPUState *cpu = find_cpu(index);
    // CPUArchState *env = CPU_ARCH_STATE(cpu);

    memset(&c, 0, sizeof(c));

    return &c;
}

void set_Context(uint8_t *data, int len, int index)
{
    // CPUState *cpu = find_cpu(index);
    // CPUArchState *env = CPU_ARCH_STATE(cpu);

    memcpy(PTR(c), data, ROUND(len, sizeof(c)));
}

PKSPECIAL_REGISTERS get_KSpecialRegisters(int index)
{
    CPUState *cpu = find_cpu(index);
    CPUArchState *env = CPU_ARCH_STATE(cpu);

    memset(&kr, 0, sizeof(kr));

    kr.Cr0 = env->cr[0];
    kr.Cr2 = env->cr[2];
    kr.Cr3 = env->cr[3];
    kr.Cr4 = env->cr[4];

    kr.KernelDr0 = env->dr[0];
    kr.KernelDr1 = env->dr[1];
    kr.KernelDr2 = env->dr[2];
    kr.KernelDr3 = env->dr[3];
    kr.KernelDr6 = env->dr[6];
    kr.KernelDr7 = env->dr[7];

    kr.Gdtr.Pad   = env->gdt.selector;
    kr.Gdtr.Limit = env->gdt.limit;
    kr.Gdtr.Base  = env->gdt.base;
    kr.Idtr.Pad   = env->idt.selector;
    kr.Idtr.Limit = env->idt.limit;
    kr.Idtr.Base  = env->idt.base;
    kr.Tr         = env->tr.selector;
    kr.Ldtr       = env->ldt.selector;

    // kr.Reserved[6];

    return &kr;
}

void set_KSpecialRegisters(uint8_t *data, int len, int offset, int index)
{
    CPUState *cpu = find_cpu(index);
    CPUArchState *env = CPU_ARCH_STATE(cpu);

    memcpy(PTR(kr) + offset, data, ROUND(len, sizeof(kr) - offset));

    env->cr[0] = kr.Cr0;
    env->cr[2] = kr.Cr2;
    env->cr[3] = kr.Cr3;
    env->cr[4] = kr.Cr4;

    env->dr[0] = kr.KernelDr0;
    env->dr[1] = kr.KernelDr1;
    env->dr[2] = kr.KernelDr2;
    env->dr[3] = kr.KernelDr3;
    env->dr[6] = kr.KernelDr6;
    env->dr[7] = kr.KernelDr7;

    env->gdt.selector   = kr.Gdtr.Pad;
    env->gdt.limit      = kr.Gdtr.Limit;
    env->gdt.base       = kr.Gdtr.Base;
    env->idt.selector   = kr.Idtr.Pad;
    env->idt.limit      = kr.Idtr.Limit;
    env->idt.base       = kr.Idtr.Base;
    env->tr.selector    = kr.Tr;
    env->ldt.selector   = kr.Ldtr;

    // kr.Reserved[6];
}

CPUState *find_cpu(int index)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu->cpu_index == index) {
            return cpu;
        }
    }

    return NULL;
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

uint32_t data_checksum_compute(uint8_t *data, uint16_t length)
{
    uint32_t checksum = 0;
    for(; length; --length) {
        checksum += (uint32_t)*data++;
    }
    return checksum;
}