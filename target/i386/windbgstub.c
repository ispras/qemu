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

static InitedAddr KPCR;
#ifdef TARGET_X86_64
static InitedAddr kdDebuggerDataBlock;
#else  /* TARGET_I386 */
static InitedAddr kdVersion;
#endif /* TARGET_I386 */

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

__attribute__ ((unused)) /* unused yet */
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
