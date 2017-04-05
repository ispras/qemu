#include "exec/windbgstub-utils.h"
#include "sysemu/sysemu.h"
#include "exec/address-spaces.h"

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

#ifdef TARGET_X86_64
# define OFFSET_SELF_PCR         0x18
# define OFFSET_KPRCB            0x20
# define OFFSET_KPRCB_CURRTHREAD 0x8
# define OFFSET_VERS             0x108
#else
# define OFFSET_SELF_PCR         0x1C
# define OFFSET_KPRCB            0x20
# define OFFSET_KPRCB_CURRTHREAD 0x4
# define OFFSET_VERS             0x34
#endif

#ifdef TARGET_X86_64

#define CPU_CONTEXT_AMD64 0x100000

#define CPU_CONTEXT_CONTROL         (CPU_CONTEXT_AMD64 | 0x1)
#define CPU_CONTEXT_INTEGER         (CPU_CONTEXT_AMD64 | 0x2)
#define CPU_CONTEXT_SEGMENTS        (CPU_CONTEXT_AMD64 | 0x4)
#define CPU_CONTEXT_FLOATING_POINT  (CPU_CONTEXT_AMD64 | 0x8)
#define CPU_CONTEXT_DEBUG_REGISTERS (CPU_CONTEXT_AMD64 | 0x10)

#define CPU_CONTEXT_FULL \
    (CPU_CONTEXT_CONTROL | CPU_CONTEXT_INTEGER | CPU_CONTEXT_FLOATING_POINT)
#define CPU_CONTEXT_ALL \
    (CPU_CONTEXT_FULL | CPU_CONTEXT_SEGMENTS | CPU_CONTEXT_DEBUG_REGISTERS)

typedef struct _CPU_DESCRIPTOR {
	uint16_t Pad[3];
	uint16_t Limit;
	uint64_t Base;
} CPU_DESCRIPTOR, *PCPU_DESCRIPTOR;

typedef struct _CPU_KSPECIAL_REGISTERS {
	uint64_t Cr0;
	uint64_t Cr2;
	uint64_t Cr3;
	uint64_t Cr4;
	uint64_t KernelDr0;
	uint64_t KernelDr1;
	uint64_t KernelDr2;
	uint64_t KernelDr3;
	uint64_t KernelDr6;
	uint64_t KernelDr7;
	CPU_DESCRIPTOR Gdtr;
	CPU_DESCRIPTOR Idtr;
	uint16_t Tr;
	uint16_t Ldtr;
	uint32_t MxCsr;
	uint64_t DebugControl;
	uint64_t LastBranchToRip;
	uint64_t LastBranchFromRip;
	uint64_t LastExceptionToRip;
	uint64_t LastExceptionFromRip;
	uint64_t Cr8;
	uint64_t MsrGsBase;
	uint64_t MsrGsSwap;
	uint64_t MsrStar;
	uint64_t MsrLStar;
	uint64_t MsrCStar;
	uint64_t MsrSyscallMask;
	uint64_t Xcr0;
} CPU_KSPECIAL_REGISTERS, *PCPU_KSPECIAL_REGISTERS;

#pragma pack(push, 2)
typedef struct _CPU_M128A {
    uint64_t Low;
    int64_t High;
} CPU_M128A, *PCPU_M128A;
#pragma pack(pop)

typedef struct _CPU_XMM_SAVE_AREA32 {
    uint16_t ControlWord;
    uint16_t StatusWord;
    uint8_t TagWord;
    uint8_t Reserved1;
    uint16_t ErrorOpcode;
    uint32_t ErrorOffset;
    uint16_t ErrorSelector;
    uint16_t Reserved2;
    uint32_t DataOffset;
    uint16_t DataSelector;
    uint16_t Reserved3;
    uint32_t MxCsr;
    uint32_t MxCsr_Mask;
    CPU_M128A FloatRegisters[8];
    CPU_M128A XmmRegisters[16];
    uint8_t Reserved4[96];
} CPU_XMM_SAVE_AREA32, *PCPU_XMM_SAVE_AREA32;

#pragma pack(push, 2)
typedef struct _CPU_CONTEXT {
    uint64_t P1Home;
    uint64_t P2Home;
    uint64_t P3Home;
    uint64_t P4Home;
    uint64_t P5Home;
    uint64_t P6Home;
    uint32_t ContextFlags;
    uint32_t MxCsr;
    uint16_t SegCs;
    uint16_t SegDs;
    uint16_t SegEs;
    uint16_t SegFs;
    uint16_t SegGs;
    uint16_t SegSs;
    uint32_t EFlags;
    uint64_t Dr0;
    uint64_t Dr1;
    uint64_t Dr2;
    uint64_t Dr3;
    uint64_t Dr6;
    uint64_t Dr7;
    uint64_t Rax;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rbx;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;
    uint64_t Rip;
    union {
        CPU_XMM_SAVE_AREA32 FltSave;
        CPU_XMM_SAVE_AREA32 FloatSave;
        struct {
            CPU_M128A Header[2];
            CPU_M128A Legacy[8];
            CPU_M128A Xmm0;
            CPU_M128A Xmm1;
            CPU_M128A Xmm2;
            CPU_M128A Xmm3;
            CPU_M128A Xmm4;
            CPU_M128A Xmm5;
            CPU_M128A Xmm6;
            CPU_M128A Xmm7;
            CPU_M128A Xmm8;
            CPU_M128A Xmm9;
            CPU_M128A Xmm10;
            CPU_M128A Xmm11;
            CPU_M128A Xmm12;
            CPU_M128A Xmm13;
            CPU_M128A Xmm14;
            CPU_M128A Xmm15;
        };
    };
    CPU_M128A VectorRegister[26];
    uint64_t VectorControl;
    uint64_t DebugControl;
    uint64_t LastBranchToRip;
    uint64_t LastBranchFromRip;
    uint64_t LastExceptionToRip;
    uint64_t LastExceptionFromRip;
} CPU_CONTEXT, *PCPU_CONTEXT;
#pragma pack(pop)

#else

#define SIZE_OF_X86_REG 80
#define MAX_SUP_EXT 512

#define CPU_CONTEXT_i386 0x10000

#define CPU_CONTEXT_CONTROL            (CPU_CONTEXT_i386 | 0x1)
#define CPU_CONTEXT_INTEGER            (CPU_CONTEXT_i386 | 0x2)
#define CPU_CONTEXT_SEGMENTS           (CPU_CONTEXT_i386 | 0x4)
#define CPU_CONTEXT_FLOATING_POINT     (CPU_CONTEXT_i386 | 0x8)
#define CPU_CONTEXT_DEBUG_REGISTERS    (CPU_CONTEXT_i386 | 0x10)
#define CPU_CONTEXT_EXTENDED_REGISTERS (CPU_CONTEXT_i386 | 0x20)

#define CPU_CONTEXT_FULL \
    (CPU_CONTEXT_CONTROL | CPU_CONTEXT_INTEGER | CPU_CONTEXT_SEGMENTS)
#define CPU_CONTEXT_ALL \
    (CPU_CONTEXT_FULL | CPU_CONTEXT_FLOATING_POINT | \
     CPU_CONTEXT_DEBUG_REGISTERS | CPU_CONTEXT_EXTENDED_REGISTERS)

typedef struct _CPU_DESCRIPTOR {
    uint16_t Pad;
    uint16_t Limit;
    uint32_t Base;
} CPU_DESCRIPTOR, *PCPU_DESCRIPTOR;

typedef struct _CPU_KSPECIAL_REGISTERS {
    uint32_t Cr0;
    uint32_t Cr2;
    uint32_t Cr3;
    uint32_t Cr4;
    uint32_t KernelDr0;
    uint32_t KernelDr1;
    uint32_t KernelDr2;
    uint32_t KernelDr3;
    uint32_t KernelDr6;
    uint32_t KernelDr7;
    CPU_DESCRIPTOR Gdtr;
    CPU_DESCRIPTOR Idtr;
    uint16_t Tr;
    uint16_t Ldtr;
    uint32_t Reserved[6];
} CPU_KSPECIAL_REGISTERS, *PCPU_KSPECIAL_REGISTERS;

typedef struct _CPU_FLOATING_SAVE_AREA {
    uint32_t ControlWord;
    uint32_t StatusWord;
    uint32_t TagWord;
    uint32_t ErrorOffset;
    uint32_t ErrorSelector;
    uint32_t DataOffset;
    uint32_t DataSelector;
    uint8_t RegisterArea[SIZE_OF_X86_REG];
    uint32_t Cr0NpxState;
} CPU_FLOATING_SAVE_AREA, *PCPU_FLOATING_SAVE_AREA;

typedef struct _CPU_CONTEXT {
    uint32_t ContextFlags;
    uint32_t Dr0;
    uint32_t Dr1;
    uint32_t Dr2;
    uint32_t Dr3;
    uint32_t Dr6;
    uint32_t Dr7;
    CPU_FLOATING_SAVE_AREA FloatSave;
    uint32_t SegGs;
    uint32_t SegFs;
    uint32_t SegEs;
    uint32_t SegDs;

    uint32_t Edi;
    uint32_t Esi;
    uint32_t Ebx;
    uint32_t Edx;
    uint32_t Ecx;
    uint32_t Eax;
    uint32_t Ebp;
    uint32_t Eip;
    uint32_t SegCs;
    uint32_t EFlags;
    uint32_t Esp;
    uint32_t SegSs;
    uint8_t ExtendedRegisters[MAX_SUP_EXT];
} CPU_CONTEXT, *PCPU_CONTEXT;

typedef struct _CPU_KPROCESSOR_STATE {
    CPU_CONTEXT ContextFrame;
    CPU_KSPECIAL_REGISTERS SpecialRegisters;
} CPU_KPROCESSOR_STATE, *PCPU_KPROCESSOR_STATE;

#endif

typedef struct KDData {
    target_ulong KPCR;
    target_ulong version;

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

static const char *kd_packet_type_names[] = {
    "PACKET_TYPE_UNUSED",
    "PACKET_TYPE_KD_STATE_CHANGE32",
    "PACKET_TYPE_KD_STATE_MANIPULATE",
    "PACKET_TYPE_KD_DEBUG_IO",
    "PACKET_TYPE_KD_ACKNOWLEDGE",
    "PACKET_TYPE_KD_RESEND",
    "PACKET_TYPE_KD_RESET",
    "PACKET_TYPE_KD_STATE_CHANGE64",
    "PACKET_TYPE_KD_POLL_BREAKIN",
    "PACKET_TYPE_KD_TRACE_IO",
    "PACKET_TYPE_KD_CONTROL_REQUEST",
    "PACKET_TYPE_KD_FILE_IO",
    "PACKET_TYPE_MAX"
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
        WINDBG_DEBUG("hw_breakpoint_insert: index(%d), " FMT_ADDR, index, addr);
    }
    else {
        env->cpu_breakpoint[index] = NULL;
        WINDBG_ERROR("hw_breakpoint_insert: index(%d), " FMT_ADDR ", " FMT_ERR,
                     index, addr, err);
    }
    return 0;
}

static int windbg_hw_breakpoint_remove(CPUState *cpu, int index)
{
    CPUArchState *env = cpu->env_ptr;
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
    WINDBG_DEBUG("hw_breakpoint_remove: index(%d), " FMT_ADDR, index, env->dr[index]);
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

UNUSED
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

UNUSED
static void windbg_set_sr(CPUState *cpu, int sr, uint16_t selector)
{
    CPUArchState *env = cpu->env_ptr;

    if (selector != env->segs[sr].selector &&
        (!(env->cr[0] & CR0_PE_MASK) || (env->eflags & VM_MASK))) {
        unsigned int limit, flags;
        target_ulong base;

        int dpl = (env->eflags & VM_MASK) ? 3 : 0;
        base = selector << 4;
        limit = 0xffff;
        flags = DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                DESC_A_MASK | (dpl << DESC_DPL_SHIFT);
        cpu_x86_load_seg_cache(env, sr, selector, base, limit, flags);
    }
}

static int windbg_read_context(CPUState *cpu, uint8_t *buf, int len, int offset)
{
    const bool new_mem = (len != sizeof(CPU_CONTEXT) || offset != 0);
    UNUSED CPUArchState *env = cpu->env_ptr;
    CPU_CONTEXT *cc;
    UNUSED int err = 0, i;

    if (new_mem) {
        cc = (CPU_CONTEXT *) g_malloc(sizeof(CPU_CONTEXT));
    }
    else {
        cc = (CPU_CONTEXT *) buf;
    }

    memset(cc, 0, len);

    cc->ContextFlags = CPU_CONTEXT_ALL;

    if (cc->ContextFlags & CPU_CONTEXT_SEGMENTS) {
        cc->SegCs = env->segs[R_CS].selector;
        cc->SegDs = env->segs[R_DS].selector;
        cc->SegEs = env->segs[R_ES].selector;
        cc->SegFs = env->segs[R_FS].selector;
        cc->SegGs = env->segs[R_GS].selector;
        cc->SegSs = env->segs[R_SS].selector;
    }

    if (cc->ContextFlags & CPU_CONTEXT_DEBUG_REGISTERS) {
        cc->Dr0 = env->dr[0];
        cc->Dr1 = env->dr[1];
        cc->Dr2 = env->dr[2];
        cc->Dr3 = env->dr[3];
        cc->Dr6 = env->dr[6];
        cc->Dr7 = env->dr[7];
    }

  #ifdef TARGET_X86_64

    cc->P1Home = 0;
    cc->P2Home = 0;
    cc->P3Home = 0;
    cc->P4Home = 0;
    cc->P5Home = 0;
    cc->P6Home = 0;

    if (cc->ContextFlags & CPU_CONTEXT_INTEGER) {
        cc->MxCsr  = env->mxcsr;
        cc->EFlags = env->eflags;

        cc->Rax = env->regs[0];
        cc->Rcx = env->regs[1];
        cc->Rdx = env->regs[2];
        cc->Rbx = env->regs[3];
        cc->Rsp = env->regs[4];
        cc->Rbp = env->regs[5];
        cc->Rsi = env->regs[6];
        cc->Rdi = env->regs[7];
        cc->R8  = env->regs[8];
        cc->R9  = env->regs[9];
        cc->R10 = env->regs[10];
        cc->R11 = env->regs[11];
        cc->R12 = env->regs[12];
        cc->R13 = env->regs[13];
        cc->R14 = env->regs[14];
        cc->R15 = env->regs[15];
        cc->Rip = env->eip;
    }

    if (cc->ContextFlags & CPU_CONTEXT_FLOATING_POINT) {

    }

    cc->VectorControl        = 0;
    cc->DebugControl         = 0;
    cc->LastBranchToRip      = 0;
    cc->LastBranchFromRip    = 0;
    cc->LastExceptionToRip   = 0;
    cc->LastExceptionFromRip = 0;


/*

typedef struct _CPU_M128A {
    uint64_t Low;
    int64_t High;
} CPU_M128A, *PCPU_M128A;

typedef struct _CPU_XMM_SAVE_AREA32 {
    uint16_t ControlWord;
    uint16_t StatusWord;
    uint8_t TagWord;
    uint8_t Reserved1;
    uint16_t ErrorOpcode;
    uint32_t ErrorOffset;
    uint16_t ErrorSelector;
    uint16_t Reserved2;
    uint32_t DataOffset;
    uint16_t DataSelector;
    uint16_t Reserved3;
    uint32_t MxCsr;
    uint32_t MxCsr_Mask;
    CPU_M128A FloatRegisters[8];
    CPU_M128A XmmRegisters[16];
    uint8_t Reserved4[96];
} CPU_XMM_SAVE_AREA32, *PCPU_XMM_SAVE_AREA32;

    union {
        CPU_XMM_SAVE_AREA32 FltSave;
        CPU_XMM_SAVE_AREA32 FloatSave;
        struct {
            CPU_M128A Header[2];
            CPU_M128A Legacy[8];
            CPU_M128A Xmm0;
            CPU_M128A Xmm1;
            CPU_M128A Xmm2;
            CPU_M128A Xmm3;
            CPU_M128A Xmm4;
            CPU_M128A Xmm5;
            CPU_M128A Xmm6;
            CPU_M128A Xmm7;
            CPU_M128A Xmm8;
            CPU_M128A Xmm9;
            CPU_M128A Xmm10;
            CPU_M128A Xmm11;
            CPU_M128A Xmm12;
            CPU_M128A Xmm13;
            CPU_M128A Xmm14;
            CPU_M128A Xmm15;
        };
    };
    CPU_M128A VectorRegister[26];

  */

  #else

    if (cc->ContextFlags & CPU_CONTEXT_INTEGER) {
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
    }

    if (cc->ContextFlags & CPU_CONTEXT_FLOATING_POINT) {
        uint32_t swd = 0, twd = 0;
        swd = env->fpus & ~(7 << 11);
        swd |= (env->fpstt & 7) << 11;
        for (i = 0; i < 8; ++i) {
            twd |= (!env->fptags[i]) << i;
        }

        cc->FloatSave.ControlWord    = env->fpuc;
        cc->FloatSave.StatusWord     = swd;
        cc->FloatSave.TagWord        = twd;
        cc->FloatSave.ErrorOffset    = UINT32_P(&env->fpip)[0]; // ?
        cc->FloatSave.ErrorSelector  = UINT32_P(&env->fpip)[1]; // ?
        cc->FloatSave.DataOffset     = UINT32_P(&env->fpdp)[0]; // ?
        cc->FloatSave.DataSelector   = UINT32_P(&env->fpdp)[1]; // ?
        cc->FloatSave.Cr0NpxState    = env->xcr0; // ?

        for (i = 0; i < 8; ++i) {
            memcpy(PTR(cc->FloatSave.RegisterArea[i * 10]),
                   PTR(env->fpregs[i]), 10);
        }
    }

    if (cc->ContextFlags & CPU_CONTEXT_EXTENDED_REGISTERS) {
        uint8_t *ptr = cc->ExtendedRegisters + 160;
        for (i = 0; i < 8; ++i, ptr += 16) {
            memcpy(ptr,     &env->xmm_regs[i].ZMM_Q(0), 8);
            memcpy(ptr + 8, &env->xmm_regs[i].ZMM_Q(1), 8);
        }

        UINT32_P(cc->ExtendedRegisters + 24)[0] = env->mxcsr;
    }

    // cc->ExtendedRegisters[0] = 0xaa;

  #endif

    if (new_mem) {
        memcpy(buf, (uint8_t *) cc + offset, len);
        g_free(cc);
    }
    return err;
}

static int windbg_write_context(CPUState *cpu, uint8_t *buf, int len, int offset)
{
    UNUSED CPUArchState *env = cpu->env_ptr;
    UNUSED int mem_size, i, tmp;
    uint8_t *mem_ptr = buf;

  #ifdef TARGET_X86_64
    return 0;
  #endif

    while (len > 0 && offset < sizeof(CPU_CONTEXT)) {
        mem_size = 1;
        switch (offset) {

  #ifdef TARGET_X86_64

  #else

        case offsetof(CPU_CONTEXT, ContextFlags):
            mem_size = sizeof_field(CPU_CONTEXT, ContextFlags);
            break;

        case offsetof(CPU_CONTEXT, Dr0):
            mem_size = sizeof_field(CPU_CONTEXT, Dr0);
            windbg_set_dr(cpu, 0, *FIELD_P(CPU_CONTEXT, Dr0, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, Dr1):
            mem_size = sizeof_field(CPU_CONTEXT, Dr1);
            windbg_set_dr(cpu, 1, *FIELD_P(CPU_CONTEXT, Dr1, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, Dr2):
            mem_size = sizeof_field(CPU_CONTEXT, Dr2);
            windbg_set_dr(cpu, 2, *FIELD_P(CPU_CONTEXT, Dr2, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, Dr3):
            mem_size = sizeof_field(CPU_CONTEXT, Dr3);
            windbg_set_dr(cpu, 3, *FIELD_P(CPU_CONTEXT, Dr3, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, Dr6):
            mem_size = sizeof_field(CPU_CONTEXT, Dr6);
            windbg_set_dr(cpu, 6, *FIELD_P(CPU_CONTEXT, Dr6, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, Dr7):
            mem_size = sizeof_field(CPU_CONTEXT, Dr7);
            windbg_set_dr(cpu, 7, *FIELD_P(CPU_CONTEXT, Dr7, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, FloatSave.ControlWord):
            mem_size = sizeof_field(CPU_CONTEXT, FloatSave.ControlWord);
            cpu_set_fpuc(env, *FIELD_P(CPU_CONTEXT, FloatSave.ControlWord, mem_ptr));
            memcpy(PTR(env->fpuc), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.StatusWord):
            mem_size = sizeof_field(CPU_CONTEXT, FloatSave.StatusWord);
            tmp = *FIELD_P(CPU_CONTEXT, FloatSave.StatusWord, mem_ptr);
            env->fpstt = (tmp >> 11) & 7;
            env->fpus = tmp & ~0x3800;
            break;

        case offsetof(CPU_CONTEXT, FloatSave.TagWord):
            mem_size = sizeof_field(CPU_CONTEXT, FloatSave.TagWord);
            tmp = *FIELD_P(CPU_CONTEXT, FloatSave.TagWord, mem_ptr);
            for (i = 0; i < 8; ++i) {
                env->fptags[i] = !((tmp >> i) & 1);
            }
            break;

        case offsetof(CPU_CONTEXT, FloatSave.ErrorOffset):
            mem_size = sizeof_field(CPU_CONTEXT, FloatSave.ErrorOffset);
            memcpy(PTR(env->fpip), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.ErrorSelector):
            mem_size = sizeof_field(CPU_CONTEXT, FloatSave.ErrorSelector);
            memcpy(PTR(env->fpip) + 4, mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.DataOffset):
            mem_size = sizeof_field( CPU_CONTEXT, FloatSave.DataOffset);
            memcpy(PTR(env->fpdp), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.DataSelector):
            mem_size = sizeof_field(CPU_CONTEXT, FloatSave.DataSelector);
            memcpy(PTR(env->fpdp) + 4, mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, FloatSave.RegisterArea):
            mem_size = sizeof_field(CPU_CONTEXT, FloatSave.RegisterArea);

            for (i = 0; i < 8; ++i) {
                memcpy(PTR(env->fpregs[i]), mem_ptr + i * 10, 10);
            }
            break;

        case offsetof(CPU_CONTEXT, FloatSave.Cr0NpxState):
            mem_size = sizeof_field(CPU_CONTEXT, FloatSave.Cr0NpxState);
            memcpy(PTR(env->xcr0), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, SegGs):
            mem_size = sizeof_field(CPU_CONTEXT, SegGs);
            windbg_set_sr(cpu, R_GS, *FIELD_P(CPU_CONTEXT, SegGs, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, SegFs):
            mem_size = sizeof_field(CPU_CONTEXT, SegFs);
            windbg_set_sr(cpu, R_FS, *FIELD_P(CPU_CONTEXT, SegFs, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, SegEs):
            mem_size = sizeof_field(CPU_CONTEXT, SegEs);
            windbg_set_sr(cpu, R_ES, *FIELD_P(CPU_CONTEXT, SegEs, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, SegDs):
            mem_size = sizeof_field(CPU_CONTEXT, SegDs);
            windbg_set_sr(cpu, R_DS, *FIELD_P(CPU_CONTEXT, SegDs, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, Edi):
            mem_size = sizeof_field(CPU_CONTEXT, Edi);
            memcpy(PTR(env->regs[R_EDI]), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Esi):
            mem_size = sizeof_field(CPU_CONTEXT, Esi);
            memcpy(PTR(env->regs[R_ESI]), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Ebx):
            mem_size = sizeof_field(CPU_CONTEXT, Ebx);
            memcpy(PTR(env->regs[R_EBX]), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Edx):
            mem_size = sizeof_field(CPU_CONTEXT, Edx);
            memcpy(PTR(env->regs[R_EDX]), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Ecx):
            mem_size = sizeof_field(CPU_CONTEXT, Ecx);
            memcpy(PTR(env->regs[R_ECX]), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Eax):
            mem_size = sizeof_field(CPU_CONTEXT, Eax);
            memcpy(PTR(env->regs[R_EAX]), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Ebp):
            mem_size = sizeof_field(CPU_CONTEXT, Ebp);
            memcpy(PTR(env->regs[R_EBP]), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Eip):
            mem_size = sizeof_field(CPU_CONTEXT, Eip);
            memcpy(PTR(env->eip), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, SegCs):
            mem_size = sizeof_field(CPU_CONTEXT, SegCs);
            windbg_set_sr(cpu, R_CS, *FIELD_P(CPU_CONTEXT, SegCs, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, EFlags):
            mem_size = sizeof_field(CPU_CONTEXT, EFlags);
            memcpy(PTR(env->eflags), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, Esp):
            mem_size = sizeof_field(CPU_CONTEXT, Esp);
            memcpy(PTR(env->regs[R_ESP]), mem_ptr, mem_size);
            break;

        case offsetof(CPU_CONTEXT, SegSs):
            mem_size = sizeof_field(CPU_CONTEXT, SegSs);
            windbg_set_sr(cpu, R_SS, *FIELD_P(CPU_CONTEXT, SegSs, mem_ptr));
            break;

        case offsetof(CPU_CONTEXT, ExtendedRegisters):
            mem_size = sizeof_field(CPU_CONTEXT, ExtendedRegisters);

            uint8_t *ptr = mem_ptr + 160;
            for (i = 0; i < 8; ++i, ptr += 16) {
                memcpy(&env->xmm_regs[i].ZMM_Q(0), ptr,     8);
                memcpy(&env->xmm_regs[i].ZMM_Q(1), ptr + 8, 8);
            }

            cpu_set_mxcsr(env, UINT32_P(mem_ptr + 24)[0]);
            break;
  #endif

        default:
            WINDBG_ERROR("write_context: Unknown offset %d", offset);
            return -1;
        }

        mem_ptr += mem_size;
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

  #ifdef TARGET_X86_64
    // *UINT32_P(ckr->Gdtr.Pad) = env->gdt.selector;
    // *UINT32_P(ckr->Idtr.Pad) = env->idt.selector;
  #else
    ckr->Gdtr.Pad   = env->gdt.selector;
    ckr->Idtr.Pad   = env->idt.selector;
  #endif

    ckr->Gdtr.Limit = env->gdt.limit;
    ckr->Gdtr.Base  = env->gdt.base;
    ckr->Idtr.Limit = env->idt.limit;
    ckr->Idtr.Base  = env->idt.base;
    ckr->Tr         = env->tr.selector;
    ckr->Ldtr       = env->ldt.selector;

  #ifdef TARGET_X86_64

    // ckr->MxCsr                = env->mxcsr;
    // ckr->DebugControl         = 0;
    // ckr->LastBranchToRip      = 0;
    // ckr->LastBranchFromRip    = 0;
    // ckr->LastExceptionToRip   = 0;
    // ckr->LastExceptionFromRip = 0;
    // ckr->Cr8                  = 0;
    // ckr->MsrGsBase            = 0;
    // ckr->MsrGsSwap            = 0;
    // ckr->MsrStar              = 0;
    // ckr->MsrLStar             = 0;
    // ckr->MsrCStar             = 0;
    // ckr->MsrSyscallMask       = 0;
    // ckr->Xcr0                 = 0;
    // ckr->Cr8                  = 0;

  #endif

    if (new_mem) {
        memcpy(buf, (uint8_t *) ckr + offset, len);
        g_free(ckr);
    }
    return 0;
}

static int windbg_write_ks_regs(CPUState *cpu, uint8_t *buf, int len, int offset)
{
  #ifdef TARGET_X86_64

    return 0;

  #else

    CPUArchState *env = cpu->env_ptr;
    int mem_size;
    uint8_t *mem_ptr = buf;
    while (len > 0 && offset < sizeof(CPU_KSPECIAL_REGISTERS)) {
        mem_size = 1;
        switch (offset) {

        case offsetof(CPU_KSPECIAL_REGISTERS, Cr0):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Cr0);
            cpu_x86_update_cr0(env, *FIELD_P(CPU_KSPECIAL_REGISTERS, Cr0, mem_ptr));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Cr2):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Cr2);
            memcpy(PTR(env->cr[2]), mem_ptr, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Cr3):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Cr3);
            cpu_x86_update_cr3(env, *FIELD_P(CPU_KSPECIAL_REGISTERS, Cr3, mem_ptr));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Cr4):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Cr4);
            cpu_x86_update_cr4(env, *FIELD_P(CPU_KSPECIAL_REGISTERS, Cr4, mem_ptr));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr0):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, KernelDr0);
            windbg_set_dr(cpu, 0, *FIELD_P(CPU_CONTEXT, Dr0, mem_ptr));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr1):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, KernelDr1);
            windbg_set_dr(cpu, 1, *FIELD_P(CPU_CONTEXT, Dr0, mem_ptr));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr2):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, KernelDr2);
            windbg_set_dr(cpu, 2, *FIELD_P(CPU_CONTEXT, Dr0, mem_ptr));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr3):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, KernelDr3);
            windbg_set_dr(cpu, 3, *FIELD_P(CPU_CONTEXT, Dr0, mem_ptr));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr6):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, KernelDr6);
            windbg_set_dr(cpu, 6, *FIELD_P(CPU_CONTEXT, Dr0, mem_ptr));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, KernelDr7):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, KernelDr7);
            windbg_set_dr(cpu, 7, *FIELD_P(CPU_CONTEXT, Dr0, mem_ptr));
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Gdtr.Pad):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Gdtr.Pad);
            memcpy(PTR(env->gdt.selector), mem_ptr, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Gdtr.Limit):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Gdtr.Limit);
            memcpy(PTR(env->gdt.limit), mem_ptr, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Gdtr.Base):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Gdtr.Base);
            memcpy(PTR(env->gdt.base), mem_ptr, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Idtr.Pad):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Idtr.Pad);
            memcpy(PTR(env->idt.selector), mem_ptr, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Idtr.Limit):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Idtr.Limit);
            memcpy(PTR(env->idt.limit), mem_ptr, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Idtr.Base):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Idtr.Base);
            memcpy(PTR(env->idt.base), mem_ptr, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Tr):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Tr);
            memcpy(PTR(env->tr.selector), mem_ptr, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Ldtr):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Ldtr);
            memcpy(PTR(env->ldt.selector), mem_ptr, mem_size);
            break;

        case offsetof(CPU_KSPECIAL_REGISTERS, Reserved):
            mem_size = sizeof_field(CPU_KSPECIAL_REGISTERS, Reserved);
            break;

        default:
            WINDBG_ERROR("write_context: Unknown offset %d", offset);
            return -1;
        }

        mem_ptr += mem_size;
        offset += mem_size;
        len -= mem_size;
    }

    return 0;

  #endif
}

void kd_api_read_virtual_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_MEMORY64 *mem = &pd->m64.u.ReadMemory;

    mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - M64_SIZE);
    int err = cpu_memory_rw_debug(cpu, mem->TargetBaseAddress,
                                  pd->extra, mem->ActualBytesRead, 0);
    pd->extra_size = mem->ActualBytesRead;

    if (err) {
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
        pd->extra_size = 0;

        // tmp checking
        WINDBG_DEBUG("read_virtual_memory: No physical page mapped: " FMT_ADDR,
                     (target_ulong) mem->TargetBaseAddress);
    }
}

void kd_api_write_virtual_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_WRITE_MEMORY64 *mem = &pd->m64.u.WriteMemory;

    mem->ActualBytesWritten = MIN(pd->extra_size, mem->TransferCount);
    int err = cpu_memory_rw_debug(cpu, mem->TargetBaseAddress,
                                  pd->extra, mem->ActualBytesWritten, 1);
    if (err) {
        // tmp checking
        WINDBG_DEBUG("read_write_memory: No physical page mapped: " FMT_ADDR,
                     (target_ulong) mem->TargetBaseAddress);
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
    }
    pd->extra_size = 0;
}

void kd_api_get_context(CPUState *cpu, PacketData *pd)
{
    pd->extra_size = sizeof(CPU_CONTEXT);
    int err = windbg_read_context(cpu, pd->extra, pd->extra_size, 0);

    if (err) {
        pd->extra_size = 0;
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
    }
}

void kd_api_set_context(CPUState *cpu, PacketData *pd)
{
    int err = windbg_write_context(cpu, pd->extra, pd->extra_size, 0);
    pd->extra_size = 0;

    if (err) {
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
    }
}

void kd_api_write_breakpoint(CPUState *cpu, PacketData *pd)
{
    DBGKD_WRITE_BREAKPOINT64 *m64c = &pd->m64.u.WriteBreakPoint;
    target_ulong addr = m64c->BreakPointAddress;
    int i = 0, err = 0;

    for (; i < KD_BREAKPOINT_MAX; ++i) {
        if (!kd.bps[i].is_init) {
            err = cpu_breakpoint_insert(cpu, addr, BP_GDB, NULL);
            if (!err) {
                kd.bps[i].addr = addr;
                kd.bps[i].is_init = true;
                WINDBG_DEBUG("write_breakpoint: " FMT_ADDR, addr);
                break;
            }
            else {
                WINDBG_ERROR("write_breakpoint: " FMT_ADDR ", " FMT_ERR, addr, err);
                pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
                return;
            }
        }
        else if (addr == kd.bps[i].addr) {
            break;
        }
    }

    if (!err) {
        m64c->BreakPointHandle = i + 1;
        pd->m64.ReturnStatus = STATUS_SUCCESS;
    }
    else {
        WINDBG_ERROR("write_breakpoint: All breakpoints occupied");
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
    }
}

void kd_api_restore_breakpoint(CPUState *cpu, PacketData *pd)
{
    DBGKD_RESTORE_BREAKPOINT *m64c = &pd->m64.u.RestoreBreakPoint;
    uint8_t index = m64c->BreakPointHandle - 1;
    int err = -1;

    if (kd.bps[index].is_init) {
        err = cpu_breakpoint_remove(cpu, kd.bps[index].addr, BP_GDB);
        if (!err) {
            WINDBG_DEBUG("restore_breakpoint: " FMT_ADDR ", index(%d)",
                         kd.bps[index].addr, index);
        }
        else {
            WINDBG_ERROR("restore_breakpoint: " FMT_ADDR ", index(%d), " FMT_ERR,
                         kd.bps[index].addr, index, err);
        }
        kd.bps[index].is_init = false;
        pd->m64.ReturnStatus = STATUS_SUCCESS;
    }
    else {
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
    }
}

void kd_api_continue(CPUState *cpu, PacketData *pd)
{
    if (NT_SUCCESS(pd->m64.u.Continue2.ContinueStatus)) {
        cpu_single_step(cpu, pd->m64.u.Continue2.ControlSet.TraceFlag ?
                        SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER : 0);

        if (!runstate_needs_reset()) {
            vm_start();
        }
    }
}

void kd_api_read_control_space(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_MEMORY64 *mem = &pd->m64.u.ReadMemory;
    int err = -1;

    mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - M64_SIZE);

  #ifdef TARGET_X86_64

    memset(pd->extra, 0, pd->extra_size);
    return;

    target_ulong from = 0;
    switch (mem->TargetBaseAddress) {
    case AMD64_DEBUG_CONTROL_SPACE_KPCR:
        from = kd.KPCR;
        mem->ActualBytesRead = sizeof(target_ulong);
        break;

    case AMD64_DEBUG_CONTROL_SPACE_KPRCB:
        from = FROM_VADDR(cpu, kd.KPCR + OFFSET_KPRCB, target_ulong);
        mem->ActualBytesRead = sizeof(target_ulong);
        break;

    case AMD64_DEBUG_CONTROL_SPACE_KSPECIAL:
        mem->ActualBytesRead = MIN(mem->ActualBytesRead, sizeof(CPU_KSPECIAL_REGISTERS));
        err = windbg_read_ks_regs(cpu, pd->extra, 0, mem->ActualBytesRead);
        break;

    case AMD64_DEBUG_CONTROL_SPACE_KTHREAD:
        from = FROM_VADDR(cpu, kd.KPCR + OFFSET_KPRCB, target_ulong);
        from = FROM_VADDR(cpu, from + OFFSET_KPRCB_CURRTHREAD, target_ulong);
        mem->ActualBytesRead = sizeof(target_ulong);
        break;
    }

    if (from != 0) {
        err = cpu_memory_rw_debug(cpu, from, pd->extra, mem->ActualBytesRead, 0);
    }

  #else

    if (mem->TargetBaseAddress < sizeof(CPU_KPROCESSOR_STATE)) {
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

  #endif

    if (err) {
        pd->extra_size = mem->ActualBytesRead = 0;
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
    }
    else {
        pd->extra_size = mem->ActualBytesRead;
    }
}

void kd_api_write_control_space(CPUState *cpu, PacketData *pd)
{
    DBGKD_WRITE_MEMORY64 *mem = &pd->m64.u.WriteMemory;
    int err = -1;

    mem->ActualBytesWritten = MIN(pd->extra_size, mem->TransferCount);

  #ifdef TARGET_X86_64

    if (mem->TargetBaseAddress == AMD64_DEBUG_CONTROL_SPACE_KSPECIAL) {
        mem->ActualBytesWritten = MIN(mem->ActualBytesWritten, sizeof(CPU_KSPECIAL_REGISTERS));
        err = windbg_write_ks_regs(cpu, pd->extra, 0, mem->ActualBytesWritten);
    }

  #else

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

  #endif

    pd->extra_size = 0;
    if (err) {
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
        mem->ActualBytesWritten = 0;
    }
}

void kd_api_read_io_space(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_WRITE_IO64 *io = &pd->m64.u.ReadWriteIo;
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
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
        return;
    }

    pd->m64.ReturnStatus = STATUS_SUCCESS;
}

void kd_api_write_io_space(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_WRITE_IO64 *io = &pd->m64.u.ReadWriteIo;
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
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
        return;
    }

    pd->m64.ReturnStatus = STATUS_SUCCESS;
}

void kd_api_read_physical_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_MEMORY64 *mem = &pd->m64.u.ReadMemory;

    mem->ActualBytesRead = MIN(mem->TransferCount, PACKET_MAX_SIZE - M64_SIZE);
    cpu_physical_memory_rw(mem->TargetBaseAddress, pd->extra,
                           mem->ActualBytesRead, 0);
    pd->extra_size = mem->ActualBytesRead;
}

void kd_api_write_physical_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_WRITE_MEMORY64 *mem = &pd->m64.u.WriteMemory;

    mem->ActualBytesWritten = MIN(pd->extra_size, mem->TransferCount);
    cpu_physical_memory_rw(mem->TargetBaseAddress, pd->extra,
                            mem->ActualBytesWritten, 1);
    pd->extra_size = 0;
}

void kd_api_get_version(CPUState *cpu, PacketData *pd)
{
    int err = cpu_memory_rw_debug(cpu, kd.version,
                                  PTR(pd->m64) + 0x10,
                                  M64_SIZE - 0x10, 0);
    if (err) {
        WINDBG_ERROR("get_version: " FMT_ERR, err);
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
    }
}

void kd_api_read_msr(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_WRITE_MSR *m64c = &pd->m64.u.ReadWriteMsr;
    CPUArchState *env = cpu->env_ptr;
    uint64_t val;

    cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 0);

    switch (m64c->Msr) {
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

    m64c->DataValueLow  = UINT32_P(val)[0];
    m64c->DataValueHigh = UINT32_P(val)[1];
    pd->m64.ReturnStatus = STATUS_SUCCESS;
}

void kd_api_write_msr(CPUState *cpu, PacketData *pd)
{
    DBGKD_READ_WRITE_MSR *m64c = &pd->m64.u.ReadWriteMsr;
    CPUArchState *env = cpu->env_ptr;
    uint64_t val;

    cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 1);

    val = m64c->DataValueLow | ((uint64_t) m64c->DataValueHigh) << 32;

    switch (m64c->Msr) {
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
    pd->m64.ReturnStatus = STATUS_SUCCESS;
}

void kd_api_search_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_SEARCH_MEMORY *m64c = &pd->m64.u.SearchMemory;
    int s_len = MAX(1, m64c->SearchLength);
    int p_len = MIN(m64c->PatternLength, pd->extra_size);

    uint8_t mem[s_len - 1 + p_len];

    int err = cpu_memory_rw_debug(cpu, m64c->SearchAddress, mem, sizeof(mem), 0);
    if (!err) {
        int i;
        pd->m64.ReturnStatus = STATUS_NO_MORE_ENTRIES;
        for (i = 0; i < s_len; ++i) {
            if (memcmp(mem + i, pd->extra, p_len) == 0) {
                m64c->FoundAddress = m64c->SearchAddress + i;
                pd->m64.ReturnStatus = STATUS_SUCCESS;
                break;
            }
        }
    }
    else {
        // tmp checking
        WINDBG_DEBUG("search_memory: No physical page mapped: " FMT_ADDR,
                     (target_ulong) m64c->SearchAddress);
        pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
    }

    pd->extra_size = 0;
}

void kd_api_fill_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_FILL_MEMORY *m64c = &pd->m64.u.FillMemory;

    uint8_t mem[m64c->Length];
    int i, err;
    for (i = 0; i < m64c->Length; ++i) {
        mem[i] = pd->extra[i % m64c->PatternLength];
    }

    switch (m64c->Flags) {
    case DBGKD_FILL_MEMORY_VIRTUAL:
        err = cpu_memory_rw_debug(cpu, m64c->Address, mem, m64c->Length, 1);
        if (err) {
            // tmp checking
            WINDBG_DEBUG("fill_memory: No physical page mapped: " FMT_ADDR,
                        (target_ulong) m64c->Address);
            pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
        }
        break;

    case DBGKD_FILL_MEMORY_PHYSICAL:
        cpu_physical_memory_rw(m64c->Address, mem, m64c->Length, 1);
        break;

    default:
        break;
    }

    pd->extra_size = 0;
}

void kd_api_query_memory(CPUState *cpu, PacketData *pd)
{
    DBGKD_QUERY_MEMORY *mem = &pd->m64.u.QueryMemory;

    if (mem->AddressSpace == DBGKD_QUERY_MEMORY_VIRTUAL) {
        mem->AddressSpace = DBGKD_QUERY_MEMORY_PROCESS;
        mem->Flags = DBGKD_QUERY_MEMORY_READ |
                     DBGKD_QUERY_MEMORY_WRITE |
                     DBGKD_QUERY_MEMORY_EXECUTE;
    }
}

void kd_api_unsupported(CPUState *cpu, PacketData *pd)
{
    WINDBG_ERROR("Catched unimplemented api %s",
                 kd_get_api_name(pd->m64.ApiNumber));
    pd->m64.ReturnStatus = STATUS_UNSUCCESSFUL;
    pd->extra_size = 0;

    exit(1);
}

static void kd_breakpoint_remove_range(CPUState *cpu, target_ulong base, target_ulong limit)
{
    int i = 0, err = 0;
    for (; i < KD_BREAKPOINT_MAX; ++i) {
        if (kd.bps[i].is_init && kd.bps[i].addr >= base && kd.bps[i].addr < limit) {
            err = cpu_breakpoint_remove(cpu, kd.bps[i].addr, BP_GDB);
            if (!err) {
                WINDBG_DEBUG("breakpoint_remove_range: " FMT_ADDR ", index(%d)",
                            kd.bps[i].addr, i);
            }
            else {
                WINDBG_ERROR("breakpoint_remove_range: " FMT_ADDR ", index(%d), " FMT_ERR,
                            kd.bps[i].addr, i, err);
            }
            kd.bps[i].is_init = false;
        }
    }
}

static void kd_init_state_change(CPUState *cpu, DBGKD_ANY_WAIT_STATE_CHANGE *sc)
{
    CPUArchState *env = cpu->env_ptr;
    int err = 0;

    // HEADER

    // sc->ProcessorLevel = 0x6;
    sc->Processor = 0;
    sc->NumberProcessors = cpu_amount;
    target_ulong KPRCB = FROM_VADDR(cpu, kd.KPCR + OFFSET_KPRCB, target_ulong);
    sc->Thread = FROM_VADDR(cpu, KPRCB + OFFSET_KPRCB_CURRTHREAD, target_ulong);
    sc->ProgramCounter = env->eip;
    COUT_HEX(sc->ProgramCounter);

    // CONTROL REPORT

    sc->ControlReport.Dr6 = env->dr[6];
    sc->ControlReport.Dr7 = env->dr[7];
    sc->ControlReport.ReportFlags = REPORT_INCLUDES_SEGS | REPORT_STANDARD_CS;
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

SizedBuf kd_gen_exception_sc(CPUState *cpu)
{
    CPUArchState *env = cpu->env_ptr;
    SizedBuf buf;
    SBUF_MALLOC(buf, sizeof(DBGKD_ANY_WAIT_STATE_CHANGE) + sizeof(int));

    DBGKD_ANY_WAIT_STATE_CHANGE *sc = (DBGKD_ANY_WAIT_STATE_CHANGE *) buf.data;
    kd_init_state_change(cpu, sc);

    sc->NewState = DbgKdExceptionStateChange;

    // sc->u.Exception.ExceptionRecord.ExceptionCode = 0x80000003;
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
    // sc->u.Exception.FirstChance = 0x1;

    // UINT32_P(buf.data + sizeof(DBGKD_ANY_WAIT_STATE_CHANGE))[0] = 0x1;

    return buf;
}

SizedBuf kd_gen_load_symbols_sc(CPUState *cpu)
{
    SizedBuf buf;
    SBUF_MALLOC(buf, sizeof(DBGKD_ANY_WAIT_STATE_CHANGE));

    DBGKD_ANY_WAIT_STATE_CHANGE *sc = (DBGKD_ANY_WAIT_STATE_CHANGE *) buf.data;
    kd_init_state_change(cpu, sc);

    sc->NewState = DbgKdLoadSymbolsStateChange;

    sc->u.LoadSymbols.PathNameLength = 0;
    // sc->u.LoadSymbols.BaseOfDll = cca.KernelBase << 8 | ;
    // sc->u.LoadSymbols.ProcessId = -1;
    // sc->u.LoadSymbols.CheckSum = ;
    // sc->u.LoadSymbols.SizeOfImage = ;
    // sc->u.LoadSymbols.UnloadSymbols = false;

    return buf;
}

bool windbg_on_load(void)
{
    CPUState *cpu = qemu_get_cpu(0);
    CPUArchState *env = cpu->env_ptr;

    if (!kd.KPCR) {

 #ifdef TARGET_X86_64
        kd.KPCR = env->segs[R_GS].base;
 #else
        kd.KPCR = env->segs[R_FS].base;
 #endif

        static target_ulong prev_KPCR = 0;
        if (!kd.KPCR || prev_KPCR == kd.KPCR) {
            return false;
        }
        prev_KPCR = kd.KPCR;

        if (kd.KPCR != FROM_VADDR(cpu, kd.KPCR + OFFSET_SELF_PCR, target_ulong)) {
            return false;
        }
    }

    kd.version = FROM_VADDR(cpu, kd.KPCR + OFFSET_VERS, target_ulong);

    static bool once_version = false;
    if (!kd.version) {
        if (!once_version) {
            once_version = true;
            WINDBG_DEBUG("windbg_on_load: version " FMT_ADDR, kd.version);
        }
        return false;
    }
    once_version = false;

    WINDBG_DEBUG("windbg_on_load: KPCR " FMT_ADDR, kd.KPCR);
    WINDBG_DEBUG("windbg_on_load: version " FMT_ADDR, kd.version);

    cpu_amount = 0;
    CPU_FOREACH(cpu) {
        ++cpu_amount;
    }
    WINDBG_DEBUG("windbg_on_load: cpu_amount:%d", cpu_amount);

    return true;
}

void windbg_on_exit(void)
{

}

uint32_t compute_checksum(uint8_t *data, uint16_t length)
{
    uint32_t checksum = 0;
    for (; length; --length, checksum += *data++);
    return checksum;
}

uint8_t get_cpu_amount(void)
{
    return cpu_amount;
}

const char *kd_get_api_name(int id)
{
    return (id >= DbgKdMinimumManipulate && id < DbgKdMaximumManipulate) ?
            kd_api_names[id - DbgKdMinimumManipulate] :
            kd_api_names[DbgKdMaximumManipulate - DbgKdMinimumManipulate];
}

const char *kd_get_packet_type_name(int id)
{
    return kd_packet_type_names[id];
}