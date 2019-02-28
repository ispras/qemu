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
