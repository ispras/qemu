/*
 * windbgstub-utils.c
 *
 * Copyright (c) 2010-2019 Institute for System Programming
 *                         of the Russian Academy of Sciences.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "exec/windbgstub-utils.h"
#include "exec/address-spaces.h"
#include "sysemu/sysemu.h"

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
    "DbgKdWriteCustomBreakpointApi",
    "DbgKdGetContextExApi",
    "DbgKdSetContextExApi",
    "DbgKdUnknownApi",
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
    "PACKET_TYPE_MAX",
};

static InitedAddr bps[KD_BREAKPOINT_MAX];

static void prep_bmbc(const uint8_t *pattern, int pLen, int bmBc[])
{
    int i;

    for (i = 0; i < 256; ++i) {
        bmBc[i] = pLen;
    }
    for (i = 0; i < pLen - 1; ++i) {
        bmBc[pattern[i]] = pLen - i - 1;
    }
}

static void prep_suffixes(const uint8_t *pattern, int pLen, int *suff)
{
    int f, g, i;

    suff[pLen - 1] = pLen;
    f = 0;
    g = pLen - 1;
    for (i = pLen - 2; i >= 0; --i) {
        if (i > g && suff[i + pLen - 1 - f] < i - g) {
            suff[i] = suff[i + pLen - 1 - f];
        } else {
            if (i < g) {
                g = i;
            }
            f = i;
            while (g >= 0 && pattern[g] == pattern[g + pLen - 1 - f]) {
                --g;
            }
            suff[i] = f - g;
        }
    }
}

static void prep_bmgs(const uint8_t *pattern, int pLen, int bmGs[])
{
    int i, j, suff[pLen];

    prep_suffixes(pattern, pLen, suff);

    for (i = 0; i < pLen; ++i) {
        bmGs[i] = pLen;
    }

    j = 0;
    for (i = pLen - 1; i >= 0; --i) {
        if (suff[i] == i + 1) {
            for (; j < pLen - 1 - i; ++j) {
                if (bmGs[j] == pLen) {
                    bmGs[j] = pLen - 1 - i;
                }
            }
        }
    }

    for (i = 0; i <= pLen - 2; ++i) {
        bmGs[pLen - 1 - suff[i]] = pLen - 1 - i;
    }
}

static int search_boyermoore(const uint8_t *data, int dLen,
                             const uint8_t *pattern, int pLen, int bmGs[],
                             int bmBc[])
{
    int i;
    int j = 0;
    while (j <= dLen - pLen) {
        i = pLen - 1;
        while (i >= 0 && pattern[i] == data[i + j]) {
            --i;
        }
        if (i < 0) {
            return j;
        } else {
            j += MAX(bmGs[i], bmBc[data[i + j]] - pLen + 1 + i);
        }
    }
    return -1;
}

InitedAddr windbg_search_vmaddr(CPUState *cs, target_ulong start,
                                target_ulong finish, const uint8_t *pattern,
                                int pLen)
{
    InitedAddr ret = {
        .addr = 0,
        .is_init = false,
    };
    int bmGs[pLen], bmBc[256];
    int find;
    target_ulong offset = start;
    target_ulong step = MIN(MAX(finish - start, 0x10000), pLen * 2);

    if (finish <= start || pLen > finish - start) {
        return ret;
    }

    uint8_t *buf = g_new(uint8_t, step);

    prep_bmgs(pattern, pLen, bmGs);
    prep_bmbc(pattern, pLen, bmBc);

    while (offset < finish) {
        step = MIN(step, finish - offset);
        if (cpu_memory_rw_debug(cs, offset, buf, step, 0) == 0) {
            find = search_boyermoore(buf, step, pattern, pLen, bmGs, bmBc);
            if (find >= 0) {
                ret.addr = offset + find;
                ret.is_init = true;
                break;
            }
        }
        offset += step - pLen;
    }

    g_free(buf);
    return ret;
}

void kd_api_read_virtual_memory(CPUState *cs, PacketData *pd)
{
    DBGKD_READ_MEMORY64 *mem = &pd->m64.u.ReadMemory;
    uint32_t len;
    target_ulong addr;
    int err;

    len = MIN(ldl_p(&mem->TransferCount), PACKET_MAX_SIZE - M64_SIZE);
    addr = ldtul_p(&mem->TargetBaseAddress);
    err = cpu_memory_rw_debug(cs, addr, pd->m64_extra, len, 0);

    if (err) {
        len = 0;
        pd->m64.ReturnStatus = NT_STATUS_UNSUCCESSFUL;

        DPRINTF("read_virtual_memory: No physical page mapped: " FMT_ADDR,
                addr);
    } else {
        pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
    }

    stl_p(&mem->ActualBytesRead, len);
    pd->size = M64_SIZE + len;
}

void kd_api_write_virtual_memory(CPUState *cs, PacketData *pd)
{
    DBGKD_WRITE_MEMORY64 *mem = &pd->m64.u.WriteMemory;
    uint32_t len;
    target_ulong addr;
    int err;

    len = MIN(ldl_p(&mem->TransferCount), pd->size - M64_SIZE);
    addr = ldtul_p(&mem->TargetBaseAddress);
    err = cpu_memory_rw_debug(cs, addr, pd->m64_extra, len, 1);

    if (err) {
        len = 0;
        pd->m64.ReturnStatus = NT_STATUS_UNSUCCESSFUL;

        DPRINTF("read_write_memory: No physical page mapped: " FMT_ADDR, addr);
    } else {
        pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
    }

    stl_p(&mem->ActualBytesWritten, len);
    pd->size = M64_SIZE + 0;
}

void kd_api_write_breakpoint(CPUState *cs, PacketData *pd)
{
    DBGKD_WRITE_BREAKPOINT64 *m64c = &pd->m64.u.WriteBreakPoint;
    target_ulong addr;
    int i, err = 0;

    addr = ldtul_p(&m64c->BreakPointAddress);

    for (i = 0; i < KD_BREAKPOINT_MAX; ++i) {
        if (!bps[i].is_init) {
            err = cpu_breakpoint_insert(cs, addr, BP_GDB, NULL);
            if (!err) {
                bps[i].addr = addr;
                bps[i].is_init = true;
                DPRINTF("write_breakpoint: " FMT_ADDR ", index(%d)", addr, i);
                break;
            } else {
                WINDBG_ERROR("write_breakpoint: " FMT_ADDR ", " FMT_ERR,
                             addr, err);
                pd->m64.ReturnStatus = NT_STATUS_UNSUCCESSFUL;
                return;
            }
        } else if (addr == bps[i].addr) {
            break;
        }
    }

    if (!err) {
        stl_p(&m64c->BreakPointHandle, i + 1);
        pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
    } else {
        WINDBG_ERROR("write_breakpoint: all breakpoints occupied");
        pd->m64.ReturnStatus = NT_STATUS_UNSUCCESSFUL;
    }
}

void kd_api_restore_breakpoint(CPUState *cs, PacketData *pd)
{
    DBGKD_RESTORE_BREAKPOINT *m64c = &pd->m64.u.RestoreBreakPoint;
    uint8_t index;
    int err = -1;

    index = ldtul_p(&m64c->BreakPointHandle) - 1;

    if (bps[index].is_init) {
        err = cpu_breakpoint_remove(cs, bps[index].addr, BP_GDB);
        if (!err) {
            DPRINTF("restore_breakpoint: " FMT_ADDR ", index(%d)",
                    bps[index].addr, index);
        } else {
            WINDBG_ERROR("restore_breakpoint: " FMT_ADDR
                         ", index(%d), " FMT_ERR,
                         bps[index].addr, index, err);
        }
        bps[index].is_init = false;
        pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
    } else {
        pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
    }
}

void kd_api_continue(CPUState *cs, PacketData *pd)
{
    uint32_t status = ldl_p(&pd->m64.u.Continue2.ContinueStatus);
    uint32_t trace = ldl_p(&pd->m64.u.Continue2.ControlSet.TraceFlag);
    int ssFlag = trace ? SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER : 0;

    if (NT_SUCCESS(status)) {
        cpu_single_step(cs, ssFlag);
        if (!runstate_needs_reset()) {
            vm_start();
        }
    }

    pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
}

void kd_api_read_io_space(CPUState *cs, PacketData *pd)
{
    DBGKD_READ_WRITE_IO64 *io = &pd->m64.u.ReadWriteIo;
    CPUArchState *env = cs->env_ptr;

    target_ulong addr = ldtul_p(&io->IoAddress);
    uint32_t value = 0;

    switch (io->DataSize) {
    case 1:
        value = address_space_ldub(&address_space_io, addr,
                                   cpu_get_mem_attrs(env), NULL);
        stl_p(&io->DataValue, value);
        break;
    case 2:
        value = address_space_lduw(&address_space_io, addr,
                                   cpu_get_mem_attrs(env), NULL);
        stl_p(&io->DataValue, value);
        break;
    case 4:
        value = address_space_ldl(&address_space_io, addr,
                                  cpu_get_mem_attrs(env), NULL);
        stl_p(&io->DataValue, value);
        break;
    default:
        pd->m64.ReturnStatus = NT_STATUS_UNSUCCESSFUL;
        return;
    }

    pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
}

void kd_api_write_io_space(CPUState *cs, PacketData *pd)
{
    DBGKD_READ_WRITE_IO64 *io = &pd->m64.u.ReadWriteIo;
    CPUArchState *env = cs->env_ptr;

    target_ulong addr = ldtul_p(&io->IoAddress);
    uint32_t value = ldl_p(&io->DataValue);

    switch (io->DataSize) {
    case 1:
        address_space_stb(&address_space_io, addr, value,
                          cpu_get_mem_attrs(env), NULL);
        break;
    case 2:
        address_space_stw(&address_space_io, addr, value,
                          cpu_get_mem_attrs(env), NULL);
        break;
    case 4:
        address_space_stl(&address_space_io, addr, value,
                          cpu_get_mem_attrs(env), NULL);
        break;
    default:
        pd->m64.ReturnStatus = NT_STATUS_UNSUCCESSFUL;
        return;
    }

    pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
}

void kd_api_read_physical_memory(CPUState *cs, PacketData *pd)
{
    DBGKD_READ_MEMORY64 *mem = &pd->m64.u.ReadMemory;
    uint32_t len;
    target_ulong addr;

    len = MIN(ldl_p(&mem->TransferCount), PACKET_MAX_SIZE - M64_SIZE);
    addr = ldtul_p(&mem->TargetBaseAddress);

    cpu_physical_memory_rw(addr, pd->m64_extra, len, 0);
    stl_p(&mem->ActualBytesRead, len);

    pd->size = M64_SIZE + len;
    pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
}

void kd_api_write_physical_memory(CPUState *cs, PacketData *pd)
{
    DBGKD_WRITE_MEMORY64 *mem = &pd->m64.u.WriteMemory;
    uint32_t len;
    target_ulong addr;

    len = MIN(ldl_p(&mem->TransferCount), pd->size - M64_SIZE);
    addr = ldtul_p(&mem->TargetBaseAddress);

    cpu_physical_memory_rw(addr, pd->m64_extra, len, 1);
    stl_p(&mem->ActualBytesWritten, len);

    pd->size = M64_SIZE + 0;
    pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
}

void kd_api_search_memory(CPUState *cs, PacketData *pd)
{
    DBGKD_SEARCH_MEMORY *m64c = &pd->m64.u.SearchMemory;
    target_ulong s_len = MAX(ldq_p(&m64c->SearchLength), 1);
    uint32_t p_len = MIN(ldl_p(&m64c->PatternLength), pd->size - M64_SIZE);
    target_ulong addr = ldq_p(&m64c->SearchAddress);

    InitedAddr find =
        windbg_search_vmaddr(cs, addr, addr + s_len, pd->m64_extra, p_len);

    if (find.is_init) {
        stl_p(&m64c->FoundAddress, find.addr);
        pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
    } else {
        pd->m64.ReturnStatus = NT_STATUS_NO_MORE_ENTRIES;
    }
    pd->size = M64_SIZE + 0;
}

void kd_api_clear_all_internal_breakpoints(CPUState *cs, PacketData *pd)
{
    pd->m64.ReturnStatus = NT_STATUS_SUCCESS;
}

void kd_api_unsupported(CPUState *cs, PacketData *pd)
{
    WINDBG_ERROR("Caught unimplemented api %s", kd_api_name(pd->m64.ApiNumber));

    pd->m64.ReturnStatus = NT_STATUS_UNSUCCESSFUL;
    pd->size = M64_SIZE + 0;
}

const char *kd_api_name(int id)
{
    return (id >= DbgKdMinimumManipulate && id < DbgKdMaximumManipulate)
        ? kd_api_names[id - DbgKdMinimumManipulate]
        : kd_api_names[DbgKdMaximumManipulate - DbgKdMinimumManipulate];
}

const char *kd_pkt_type_name(int id)
{
    return (id >= 0 && id < PACKET_TYPE_MAX)
        ? kd_packet_type_names[id]
        : kd_packet_type_names[PACKET_TYPE_MAX - 1];
}
