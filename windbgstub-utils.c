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
