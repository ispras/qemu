#include "exec/windbgstub-utils.h"

static EXCEPTION_STATE_CHANGE esc;

PEXCEPTION_STATE_CHANGE get_ExceptionStateChange(int index)
{
    CPUArchState *env = find_cpu(index);

    memset(&esc, 0, sizeof(esc));

    esc.StateChange.NewState = DbgKdExceptionStateChange;
    //TODO: Get it
    esc.StateChange.ProcessorLevel = 0x6; //Pentium 4
    //
    esc.StateChange.Processor = index;
    esc.StateChange.NumberProcessors = num_cpu();
    //TODO: + 0xffffffff00000000
    cpu_memory_rw_debug(env, pca.KPRCB + OFFSET_KPRCB_CURRTHREAD,
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
    cpu_memory_rw_debug(env, env->eip,
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

static CPUState *find_cpu(uint32_t thread_id)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu_index(cpu) == thread_id) {
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