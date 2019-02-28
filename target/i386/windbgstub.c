/*
 * windbgstub.c
 *
 * Copyright (c) 2010-2019 Institute for System Programming
 *                         of the Russian Academy of Sciences.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "exec/windbgstub-utils.h"

#ifdef TARGET_X86_64
#define OFFSET_KPCR_SELF 0x18
#define OFFSET_KPCR_LOCK_ARRAY 0x28
#define OFFSET_KPRCB 0x20
#define OFFSET_KPRCB_CURRTHREAD 0x8
#else  /* TARGET_I386 */
#define OFFSET_KPCR_SELF 0x1C
#define OFFSET_KPCR_VERSION 0x34
#define OFFSET_KPRCB 0x20
#define OFFSET_KPRCB_CURRTHREAD 0x4
#endif /* TARGET_I386 */

#ifdef TARGET_X86_64
#define TARGET_SAFE(i386_obj, x86_64_obj) x86_64_obj
#else  /* TARGET_I386 */
#define TARGET_SAFE(i386_obj, x86_64_obj) i386_obj
#endif /* TARGET_I386 */

/*
 * Next code copied from winnt.h
 */
#ifdef TARGET_X86_64

#define CPU_CONTEXT_AMD64 0x100000

#define CPU_CONTEXT_CONTROL (CPU_CONTEXT_AMD64 | 0x1)
#define CPU_CONTEXT_INTEGER (CPU_CONTEXT_AMD64 | 0x2)
#define CPU_CONTEXT_SEGMENTS (CPU_CONTEXT_AMD64 | 0x4)
#define CPU_CONTEXT_FLOATING_POINT (CPU_CONTEXT_AMD64 | 0x8)
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

typedef struct _CPU_M128A {
    uint64_t Low;
    int64_t High;
} QEMU_ALIGNED(16) CPU_M128A, *PCPU_M128A;

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

typedef struct _CPU_CONTEXT { /* sizeof = 1232 */
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
} QEMU_ALIGNED(16) CPU_CONTEXT, *PCPU_CONTEXT;

#else /* TARGET_I386 */

#define SIZE_OF_X86_REG 80
#define MAX_SUP_EXT 512

#define CPU_CONTEXT_i386 0x10000

#define CPU_CONTEXT_CONTROL (CPU_CONTEXT_i386 | 0x1)
#define CPU_CONTEXT_INTEGER (CPU_CONTEXT_i386 | 0x2)
#define CPU_CONTEXT_SEGMENTS (CPU_CONTEXT_i386 | 0x4)
#define CPU_CONTEXT_FLOATING_POINT (CPU_CONTEXT_i386 | 0x8)
#define CPU_CONTEXT_DEBUG_REGISTERS (CPU_CONTEXT_i386 | 0x10)
#define CPU_CONTEXT_EXTENDED_REGISTERS (CPU_CONTEXT_i386 | 0x20)

#define CPU_CONTEXT_FULL                                                       \
    (CPU_CONTEXT_CONTROL | CPU_CONTEXT_INTEGER | CPU_CONTEXT_SEGMENTS)
#define CPU_CONTEXT_ALL                                                        \
    (CPU_CONTEXT_FULL | CPU_CONTEXT_FLOATING_POINT                             \
     | CPU_CONTEXT_DEBUG_REGISTERS | CPU_CONTEXT_EXTENDED_REGISTERS)

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

typedef struct _CPU_CONTEXT { /* sizeof = 716 */
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

#endif /* TARGET_I386 */

typedef struct _CPU_KPROCESSOR_STATE {
    CPU_CONTEXT ContextFrame;
    CPU_KSPECIAL_REGISTERS SpecialRegisters;
} CPU_KPROCESSOR_STATE, *PCPU_KPROCESSOR_STATE;

static InitedAddr KPCR;
#ifdef TARGET_X86_64
static InitedAddr kdDebuggerDataBlock;
#else  /* TARGET_I386 */
static InitedAddr kdVersion;
#endif /* TARGET_I386 */

static void windbg_set_dr(CPUState *cs, int index, target_ulong value)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    switch (index) {
    case 0 ... 3:
        env->dr[index] = value;
        return;
    case 6:
        env->dr[6] = value | DR6_FIXED_1;
        return;
    case 7:
        cpu_x86_update_dr7(env, value);
        return;
    }
}

/* copy from gdbstub.c */
static void windbg_set_sr(CPUState *cs, int sreg, uint16_t selector)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    if (selector != env->segs[sreg].selector) {
#if defined(CONFIG_USER_ONLY)
        cpu_x86_load_seg(env, sreg, selector);
#else
        unsigned int limit, flags;
        target_ulong base;

        if (!(env->cr[0] & CR0_PE_MASK) || (env->eflags & VM_MASK)) {
            int dpl = (env->eflags & VM_MASK) ? 3 : 0;
            base = selector << 4;
            limit = 0xffff;
            flags = DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                    DESC_A_MASK | (dpl << DESC_DPL_SHIFT);
        } else {
            if (!cpu_x86_get_descr_debug(env, selector, &base, &limit,
                                         &flags)) {
                return;
            }
        }
        cpu_x86_load_seg_cache(env, sreg, selector, base, limit, flags);
#endif
    }
}

#define rwuw_p(ptr, var, is_read)                                              \
    do {                                                                       \
        if (is_read) {                                                         \
            var = lduw_p(ptr);                                                 \
        } else {                                                               \
            stw_p(ptr, var);                                                   \
        }                                                                      \
    } while (0)

#define rwl_p(ptr, var, is_read)                                               \
    do {                                                                       \
        if (is_read) {                                                         \
            var = ldl_p(ptr);                                                  \
        } else {                                                               \
            stl_p(ptr, var);                                                   \
        }                                                                      \
    } while (0)

#define rwtul_p(ptr, var, is_read)                                             \
    do {                                                                       \
        if (is_read) {                                                         \
            var = ldtul_p(ptr);                                                \
        } else {                                                               \
            sttul_p(ptr, var);                                                 \
        }                                                                      \
    } while (0)

#define RW_DR(ptr, cs, dr_index, is_read)                                      \
    do {                                                                       \
        if (is_read) {                                                         \
            windbg_set_dr(cs, dr_index, ldtul_p(ptr));                         \
        } else {                                                               \
            sttul_p(ptr, X86_CPU(cs)->env.dr[dr_index]);                       \
        }                                                                      \
    } while (0)

#define RW_SR(ptr, cs, sr_index, is_read)                                      \
    do {                                                                       \
        if (is_read) {                                                         \
            windbg_set_sr(cs, sr_index, lduw_p(ptr));                          \
        } else {                                                               \
            stw_p(ptr, X86_CPU(cs)->env.segs[R_CS].selector);                  \
        }                                                                      \
    } while (0)

#define RW_CR(ptr, cs, cr_index, is_read)                                      \
    do {                                                                       \
        if (is_read) {                                                         \
            cpu_x86_update_cr##cr_index(env, (int32_t) ldtul_p(ptr));          \
        } else {                                                               \
            sttul_p(ptr, (target_ulong) X86_CPU(cs)->env.cr[cr_index]);        \
        }                                                                      \
    } while (0)

#define CASE_FIELD(stct, field, field_size, block)                             \
    case offsetof(stct, field):                                                \
        field_size = sizeof_field(stct, field);                                \
        block;                                                                 \
        break;

#define CASE_FIELD_X32_64(stct, field_x32, field_x64, field_size, block) \
    CASE_FIELD(stct, TARGET_SAFE(field_x32, field_x64), field_size, block)

#ifdef TARGET_X86_64
#define CASE_FIELD_X32(stct, field, field_size, block)
#define CASE_FIELD_X64(stct, field, field_size, block) \
    CASE_FIELD(stct, field, field_size, block)
#else  /* TARGET_I386 */
#define CASE_FIELD_X64(stct, field, field_size, block)
#define CASE_FIELD_X32(stct, field, field_size, block) \
    CASE_FIELD(stct, field, field_size, block)
#endif /* TARGET_I386 */

#define GEN_WINDBG_CONTEXT_RW(fun_name, is_read)                               \
static int fun_name(CPUState *cs, uint8_t *buf, int buf_size,                  \
                    int offset, int len)                                       \
{                                                                              \
    X86CPU *cpu = X86_CPU(cs);                                                 \
    CPUX86State *env = &cpu->env;                                              \
    uint32_t ctx_flags = CPU_CONTEXT_ALL;                                      \
    uint32_t tmp32, i;                                                         \
    uint32_t f_size = 0;                                                       \
                                                                               \
    if (len < 0 || len > buf_size) {                                           \
        WINDBG_ERROR("" #fun_name ": incorrect length %d", len);               \
        return 1;                                                              \
    }                                                                          \
                                                                               \
    if (offset < 0 || offset + len > sizeof(CPU_CONTEXT)) {                    \
        WINDBG_ERROR("" #fun_name ": incorrect offset %d", offset);            \
        return 2;                                                              \
    }                                                                          \
                                                                               \
    len = MIN(len, sizeof(CPU_CONTEXT) - offset);                              \
                                                                               \
    while (offset < len) {                                                     \
        switch (offset) {                                                      \
        CASE_FIELD(CPU_CONTEXT, ContextFlags, f_size, {                        \
            rwl_p(buf, ctx_flags, is_read);                                    \
        });                                                                    \
        /* DEBUG REGISTERS */                                                  \
        CASE_FIELD(CPU_CONTEXT, Dr0, f_size, {                                 \
            if (ctx_flags & CPU_CONTEXT_DEBUG_REGISTERS) {                     \
                RW_DR(buf, cs, 0, is_read);                                    \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, Dr1, f_size, {                                 \
            if (ctx_flags & CPU_CONTEXT_DEBUG_REGISTERS) {                     \
                RW_DR(buf, cs, 1, is_read);                                    \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, Dr2, f_size, {                                 \
            if (ctx_flags & CPU_CONTEXT_DEBUG_REGISTERS) {                     \
                RW_DR(buf, cs, 2, is_read);                                    \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, Dr3, f_size, {                                 \
            if (ctx_flags & CPU_CONTEXT_DEBUG_REGISTERS) {                     \
                RW_DR(buf, cs, 3, is_read);                                    \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, Dr6, f_size, {                                 \
            if (ctx_flags & CPU_CONTEXT_DEBUG_REGISTERS) {                     \
                RW_DR(buf, cs, 6, is_read);                                    \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, Dr7, f_size, {                                 \
            if (ctx_flags & CPU_CONTEXT_DEBUG_REGISTERS) {                     \
                RW_DR(buf, cs, 7, is_read);                                    \
            }                                                                  \
        });                                                                    \
        /* SEGMENT REGISTERS */                                                \
        CASE_FIELD(CPU_CONTEXT, SegCs, f_size, {                               \
            if (ctx_flags & CPU_CONTEXT_SEGMENTS) {                            \
                RW_SR(buf, cs, R_CS, is_read);                                 \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, SegDs, f_size, {                               \
            if (ctx_flags & CPU_CONTEXT_SEGMENTS) {                            \
                RW_SR(buf, cs, R_DS, is_read);                                 \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, SegEs, f_size, {                               \
            if (ctx_flags & CPU_CONTEXT_SEGMENTS) {                            \
                RW_SR(buf, cs, R_ES, is_read);                                 \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, SegFs, f_size, {                               \
            if (ctx_flags & CPU_CONTEXT_SEGMENTS) {                            \
                RW_SR(buf, cs, R_FS, is_read);                                 \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, SegGs, f_size, {                               \
            if (ctx_flags & CPU_CONTEXT_SEGMENTS) {                            \
                RW_SR(buf, cs, R_GS, is_read);                                 \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, SegSs, f_size, {                               \
            if (ctx_flags & CPU_CONTEXT_SEGMENTS) {                            \
                RW_SR(buf, cs, R_SS, is_read);                                 \
            }                                                                  \
        });                                                                    \
        /* INTEGER REGISTERS */                                                \
        CASE_FIELD_X32_64(CPU_CONTEXT, Eax, Rax, f_size, {                     \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[R_EAX], is_read);                       \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X32_64(CPU_CONTEXT, Ecx, Rcx, f_size, {                     \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[R_ECX], is_read);                       \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X32_64(CPU_CONTEXT, Edx, Rdx, f_size, {                     \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[R_EDX], is_read);                       \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X32_64(CPU_CONTEXT, Ebx, Rbx, f_size, {                     \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[R_EBX], is_read);                       \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X32_64(CPU_CONTEXT, Esi, Rsi, f_size, {                     \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[R_ESI], is_read);                       \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X32_64(CPU_CONTEXT, Edi, Rdi, f_size, {                     \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[R_EDI], is_read);                       \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, R8, f_size, {                              \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[8], is_read);                           \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, R9, f_size, {                              \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[9], is_read);                           \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, R10, f_size, {                             \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[10], is_read);                          \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, R11, f_size, {                             \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[11], is_read);                          \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, R12, f_size, {                             \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[12], is_read);                          \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, R13, f_size, {                             \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[13], is_read);                          \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, R14, f_size, {                             \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[14], is_read);                          \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, R15, f_size, {                             \
            if (ctx_flags & CPU_CONTEXT_INTEGER) {                             \
                rwtul_p(buf, env->regs[15], is_read);                          \
            }                                                                  \
        });                                                                    \
        /* CONTROL REGISTERS */                                                \
        CASE_FIELD_X32_64(CPU_CONTEXT, Esp, Rsp, f_size, {                     \
            if (ctx_flags & CPU_CONTEXT_CONTROL) {                             \
                rwtul_p(buf, env->regs[R_ESP], is_read);                       \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X32_64(CPU_CONTEXT, Ebp, Rbp, f_size, {                     \
            if (ctx_flags & CPU_CONTEXT_CONTROL) {                             \
                rwtul_p(buf, env->regs[R_EBP], is_read);                       \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X32_64(CPU_CONTEXT, Eip, Rip, f_size, {                     \
            if (ctx_flags & CPU_CONTEXT_CONTROL) {                             \
                rwtul_p(buf, env->eip, is_read);                               \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, EFlags, f_size, {                              \
            if (ctx_flags & CPU_CONTEXT_CONTROL) {                             \
                rwl_p(buf, env->eflags, is_read);                              \
            }                                                                  \
        });                                                                    \
        /* FLOAT REGISTERS */                                                  \
        CASE_FIELD(CPU_CONTEXT, FloatSave.ControlWord, f_size, {               \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                if (is_read) {                                                 \
                    cpu_set_fpuc(env, TARGET_SAFE(ldl_p, lduw_p)(buf));        \
                } else {                                                       \
                    TARGET_SAFE(stl_p, stw_p)(buf, env->fpuc);                 \
                }                                                              \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, FloatSave.StatusWord, f_size, {                \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                if (is_read) {                                                 \
                    tmp32 = TARGET_SAFE(ldl_p, lduw_p)(buf);                   \
                    env->fpstt = (tmp32 >> 11) & 7;                            \
                    env->fpus = tmp32 & ~0x3800;                               \
                } else {                                                       \
                    tmp32 = env->fpus & ~(7 << 11);                            \
                    tmp32 |= (env->fpstt & 7) << 11;                           \
                    TARGET_SAFE(stl_p, stw_p)(buf, tmp32);                     \
                }                                                              \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, FloatSave.TagWord, f_size, {                   \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                if (is_read) {                                                 \
                    tmp32 = TARGET_SAFE(ldl_p(buf), buf[0]);                   \
                    for (i = 0; i < 8; ++i) {                                  \
                        env->fptags[i] = !((tmp32 >> i) & 1);                  \
                    }                                                          \
                } else {                                                       \
                    tmp32 = 0;                                                 \
                    for (i = 0; i < 8; ++i) {                                  \
                        tmp32 |= (!env->fptags[i]) << i;                       \
                    }                                                          \
                    TARGET_SAFE(stl_p, stb_p)(buf, tmp32);                     \
                }                                                              \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, FloatSave.Reserved1, f_size, {});          \
        CASE_FIELD_X64(CPU_CONTEXT, FloatSave.ErrorOpcode, f_size, {           \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                rwuw_p(buf, env->fpop, is_read);                               \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, FloatSave.ErrorOffset, f_size, {               \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                if (is_read) {                                                 \
                    env->fpip &= ~0xffffffffL;                                 \
                    env->fpip |= ldl_p(buf);                                   \
                } else {                                                       \
                    stl_p(buf, env->fpip & 0xffffffff);                        \
                }                                                              \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, FloatSave.ErrorSelector, f_size, {             \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                if (is_read) {                                                 \
                    env->fpip &= 0xffffffffL;                                  \
                    env->fpip |= ((uint64_t) ldl_p(buf)) << 32;                \
                } else {                                                       \
                    stl_p(buf, (env->fpip >> 32) & 0xffffffff);                \
                }                                                              \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, FloatSave.Reserved2, f_size, {});          \
        CASE_FIELD(CPU_CONTEXT, FloatSave.DataOffset, f_size, {                \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                if (is_read) {                                                 \
                    env->fpdp &= ~0xffffffffL;                                 \
                    env->fpdp |= ldl_p(buf);                                   \
                } else {                                                       \
                    stl_p(buf, env->fpdp & 0xffffffff);                        \
                }                                                              \
            }                                                                  \
        });                                                                    \
        CASE_FIELD(CPU_CONTEXT, FloatSave.DataSelector, f_size, {              \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                if (is_read) {                                                 \
                    env->fpdp &= 0xffffffffL;                                  \
                    env->fpdp |= ((uint64_t) ldl_p(buf)) << 32;                \
                } else {                                                       \
                    stl_p(buf, (env->fpdp >> 32) & 0xffffffff);                \
                }                                                              \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, FloatSave.Reserved3, f_size, {});          \
        CASE_FIELD_X32(CPU_CONTEXT, FloatSave.Cr0NpxState, f_size, {           \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                rwl_p(buf, env->xcr0, is_read);                                \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, FloatSave.MxCsr, f_size, {                 \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                rwl_p(buf, env->mxcsr, is_read);                               \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, FloatSave.MxCsr_Mask, f_size, {            \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                /* FIXME: this is unimplemented in qemu? */                    \
                /* rwl_p(buf, env->mxcsr_mask, is_read); */                    \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X32_64(CPU_CONTEXT, FloatSave.RegisterArea,                 \
                                       FloatSave.FloatRegisters, f_size, {     \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                uint8_t *mem = buf;                                            \
                for (i = 0; i < 8; ++i, mem += TARGET_SAFE(10, 16)) {          \
                    floatx80 fl = env->fpregs[i].d;                            \
                    if (is_read) {                                             \
                        fl.low = ldq_p(mem);                                   \
                        fl.high = TARGET_SAFE(lduw_p, ldq_p)(mem + 8);         \
                    } else {                                                   \
                        stq_p(mem, fl.low);                                    \
                        TARGET_SAFE(stw_p, stq_p)(mem + 8, fl.high);           \
                    }                                                          \
                }                                                              \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, FloatSave.XmmRegisters, f_size, {          \
            if (ctx_flags & CPU_CONTEXT_FLOATING_POINT) {                      \
                uint8_t *mem = buf;                                            \
                if (is_read) {                                                 \
                    for (i = 0; i < CPU_NB_REGS; ++i, mem += 16) {             \
                        env->xmm_regs[i].ZMM_Q(0) = ldl_p(mem);                \
                        env->xmm_regs[i].ZMM_Q(1) = ldl_p(mem + 8);            \
                    }                                                          \
                } else {                                                       \
                    for (i = 0; i < CPU_NB_REGS; ++i, mem += 16) {             \
                        stq_p(mem, env->xmm_regs[i].ZMM_Q(0));                 \
                        stq_p(mem + 8, env->xmm_regs[i].ZMM_Q(1));             \
                    }                                                          \
                }                                                              \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, FloatSave.Reserved4, f_size, {});          \
        /* EXTENDED REGISTERS I386 */                                          \
        CASE_FIELD_X32(CPU_CONTEXT, ExtendedRegisters, f_size, {               \
            if (ctx_flags & CPU_CONTEXT_EXTENDED_REGISTERS) {                  \
                uint8_t *mem = buf + 160;                                      \
                if (is_read) {                                                 \
                    for (i = 0; i < CPU_NB_REGS; ++i, mem += 16) {             \
                        env->xmm_regs[i].ZMM_Q(0) = ldl_p(mem);                \
                        env->xmm_regs[i].ZMM_Q(1) = ldl_p(mem + 8);            \
                    }                                                          \
                    cpu_set_mxcsr(env, ldl_p(mem + 24));                       \
                } else {                                                       \
                    for (i = 0; i < CPU_NB_REGS; ++i, mem += 16) {             \
                        stq_p(mem, env->xmm_regs[i].ZMM_Q(0));                 \
                        stq_p(mem + 8, env->xmm_regs[i].ZMM_Q(1));             \
                    }                                                          \
                    stl_p(mem + 24, env->mxcsr);                               \
                }                                                              \
            }                                                                  \
        });                                                                    \
        /* UNKNOWN REGISTERS */                                                \
        CASE_FIELD_X64(CPU_CONTEXT, P1Home, f_size, {});                       \
        CASE_FIELD_X64(CPU_CONTEXT, P2Home, f_size, {});                       \
        CASE_FIELD_X64(CPU_CONTEXT, P3Home, f_size, {});                       \
        CASE_FIELD_X64(CPU_CONTEXT, P4Home, f_size, {});                       \
        CASE_FIELD_X64(CPU_CONTEXT, P5Home, f_size, {});                       \
        CASE_FIELD_X64(CPU_CONTEXT, P6Home, f_size, {});                       \
        CASE_FIELD_X64(CPU_CONTEXT, MxCsr, f_size, {                           \
            if (is_read) {                                                     \
                cpu_set_mxcsr(env, ldl_p(buf));                                \
            } else {                                                           \
                stl_p(buf, env->mxcsr);                                        \
            }                                                                  \
        });                                                                    \
        CASE_FIELD_X64(CPU_CONTEXT, VectorRegister, f_size, {});               \
        CASE_FIELD_X64(CPU_CONTEXT, VectorControl, f_size, {});                \
        CASE_FIELD_X64(CPU_CONTEXT, DebugControl, f_size, {});                 \
        CASE_FIELD_X64(CPU_CONTEXT, LastBranchToRip, f_size, {});              \
        CASE_FIELD_X64(CPU_CONTEXT, LastBranchFromRip, f_size, {});            \
        CASE_FIELD_X64(CPU_CONTEXT, LastExceptionToRip, f_size, {});           \
        CASE_FIELD_X64(CPU_CONTEXT, LastExceptionFromRip, f_size, {});         \
        default:                                                               \
            f_size = 1;                                                        \
        }                                                                      \
        offset += f_size;                                                      \
        buf += f_size;                                                         \
    }                                                                          \
    return 0;                                                                  \
}

__attribute__ ((unused)) /* unused yet */
GEN_WINDBG_CONTEXT_RW(windbg_read_context, false)

__attribute__ ((unused)) /* unused yet */
GEN_WINDBG_CONTEXT_RW(windbg_write_context, true)

static bool find_KPCR(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    if (!KPCR.is_init) {
        KPCR.addr = env->segs[TARGET_SAFE(R_FS, R_GS)].base;

        static target_ulong prev_KPCR;
        if (!KPCR.addr || prev_KPCR == KPCR.addr) {
            return false;
        }
        prev_KPCR = KPCR.addr;

        if (KPCR.addr != VMEM_ADDR(cs, KPCR.addr + OFFSET_KPCR_SELF)) {
            return false;
        }
        KPCR.is_init = true;

        DPRINTF("find KPCR " FMT_ADDR, KPCR.addr);
    }

    return KPCR.is_init;
}

#ifdef TARGET_X86_64
static bool find_kdDebuggerDataBlock(CPUState *cs)
{
    target_ulong lockArray;
    target_ulong dDataList;
    const uint8_t tag[] = { 'K', 'D', 'B', 'G' };
    target_ulong start = 0xfffff80000000000LL;
    target_ulong finish = 0xfffff81000000000LL;
    InitedAddr find;

    /*
     * kdDebuggerDataBlock is located in
     *  - range of [0xfffff80000000000 ... 0xfffff81000000000]
     *  - at offset of ('KDBG') - 0x10
     */
    if (!kdDebuggerDataBlock.is_init && KPCR.is_init) {
        /*
         * At first, find lockArray. If it is NULL,
         * then kdDebuggerDataBlock is also NULL (empirically).
         */
        lockArray = VMEM_ADDR(cs, KPCR.addr + OFFSET_KPCR_LOCK_ARRAY);
        if (!lockArray) {
            return false;
        }
        DPRINTF("find LockArray " FMT_ADDR, lockArray);

        while (true) {
            find = windbg_search_vmaddr(cs, start, finish, tag,
                                        ARRAY_SIZE(tag));
            if (!find.is_init) {
                return false;
            }

            /* Valid address to 'KDBG ' is always aligned */
            if (!(find.addr & 0xf)) {
                dDataList = VMEM_ADDR(cs, find.addr - 0x10);

                /*
                 * Valid address to 'dDataList ' is always
                 * in range [0xfffff80000000000 ... 0xfffff8ffffffffff]
                 */
                if ((dDataList >> 40) == 0xfffff8) {
                    kdDebuggerDataBlock.addr = find.addr - 0x10;
                    kdDebuggerDataBlock.is_init = true;
                    DPRINTF("find kdDebuggerDataBlock " FMT_ADDR,
                            kdDebuggerDataBlock.addr);
                    break;
                }
            }

            start = find.addr + 0x8; /* next addr */
        }
    }

    return kdDebuggerDataBlock.is_init;
}
#else  /* TARGET_I386 */
static bool find_kdVersion(CPUState *cs)
{
    if (!kdVersion.is_init && KPCR.is_init) {
        kdVersion.addr = VMEM_ADDR(cs, KPCR.addr + OFFSET_KPCR_VERSION);
        if (!kdVersion.addr) {
            return false;
        }
        kdVersion.is_init = true;

        DPRINTF("find kdVersion " FMT_ADDR, kdVersion.addr);
    }

    return kdVersion.is_init;
}
#endif /* TARGET_I386 */

bool windbg_on_load(void)
{
    CPUState *cs = qemu_get_cpu(0);

    if (!find_KPCR(cs)) {
        return false;
    }

#ifdef TARGET_X86_64
    if (!find_kdDebuggerDataBlock(cs)) {
        return false;
    }
#else
    if (!find_kdVersion(cs)) {
        return false;
    }
#endif

    return true;
}

void windbg_on_reset(void)
{
    KPCR.is_init = false;
#ifdef TARGET_X86_64
    kdDebuggerDataBlock.is_init = false;
#else
    kdVersion.is_init = false;
#endif
}

static void kd_state_change_common(CPUState *cs, PacketData *data)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    DBGKD_ANY_WAIT_STATE_CHANGE *sc = (DBGKD_ANY_WAIT_STATE_CHANGE *) data->buf;
    DBGKD_CONTROL_REPORT *cr = &sc->ControlReport;
    target_ulong KPRCB = VMEM_ADDR(cs, KPCR.addr + OFFSET_KPRCB);
    target_ulong thread = VMEM_ADDR(cs, KPRCB + OFFSET_KPRCB_CURRTHREAD);
    int number_processors = 0;

    CPUState *cpu_tmp;
    CPU_FOREACH(cpu_tmp) {
        ++number_processors;
    }

    /* HEADER */

    /* TODO: Fix this hardcoded value. */
    stw_p(&sc->ProcessorLevel, 0);
    /* TODO: Fix this hardcoded value. */
    stw_p(&sc->Processor, 0);
    stl_p(&sc->NumberProcessors, number_processors);
    sttul_p(&sc->Thread, thread);
    sttul_p(&sc->ProgramCounter, env->eip);

    /* CONTROL REPORT */

    sttul_p(&cr->Dr6, env->dr[6]);
    sttul_p(&cr->Dr7, env->dr[7]);
    stw_p(&cr->ReportFlags, REPORT_INCLUDES_SEGS | REPORT_STANDARD_CS);
    stw_p(&cr->SegCs, env->segs[R_CS].selector);
    stw_p(&cr->SegDs, env->segs[R_DS].selector);
    stw_p(&cr->SegEs, env->segs[R_ES].selector);
    stw_p(&cr->SegFs, env->segs[R_FS].selector);
    stl_p(&cr->EFlags, env->eflags);

    /* This is a feature */
    memset(cr->InstructionStream, 0, DBGKD_MAXSTREAM);
    stw_p(&cr->InstructionCount, 0);
}

static void kd_state_change_load_symbols(CPUState *cs, PacketData *data)
{
    DBGKD_ANY_WAIT_STATE_CHANGE *sc = (DBGKD_ANY_WAIT_STATE_CHANGE *) data->buf;

    kd_state_change_common(cs, data);

    stl_p(&sc->NewState, DbgKdLoadSymbolsStateChange);

    /* TODO: Path to load symbold (with extra array). */
    stl_p(&sc->u.LoadSymbols.PathNameLength, 0);

    data->size = sizeof(DBGKD_ANY_WAIT_STATE_CHANGE);
}

static void kd_state_change_excp(CPUState *cs, PacketData *data, uint32_t code)
{
    DBGKD_ANY_WAIT_STATE_CHANGE *sc = (DBGKD_ANY_WAIT_STATE_CHANGE *) data->buf;
    DBGKM_EXCEPTION_RECORD64 *exc = &sc->u.Exception.ExceptionRecord;
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    kd_state_change_common(cs, data);

    stl_p(&sc->NewState, DbgKdExceptionStateChange);
    sttul_p(&exc->ExceptionAddress, env->eip);

    stl_p(&exc->ExceptionCode, code);

    data->size = sizeof(DBGKD_ANY_WAIT_STATE_CHANGE);
}

bool kd_init_state_change(CPUState *cs, PacketData *data,
                          KdStateChangeType type)
{
    switch (type) {
    case STATE_CHANGE_LOAD_SYMBOLS:
        kd_state_change_load_symbols(cs, data);
        return true;
    case STATE_CHANGE_BREAKPOINT:
        kd_state_change_excp(cs, data, NT_STATUS_BREAKPOINT);
        return true;
    }

    return false;
}
