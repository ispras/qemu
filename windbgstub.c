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
#include "exec/windbgstub.h"
#include "exec/windbgstub-utils.h"

typedef struct WindbgState {
    bool is_loaded;
    bool catched_breakin_byte;
    uint32_t wait_packet_type;
    uint32_t curr_packet_id;
} WindbgState;

static WindbgState *windbg_state;

static void windbg_state_clean(WindbgState *state)
{
    state->is_loaded = false;
    state->catched_breakin_byte = false;
    state->wait_packet_type = 0;
    state->curr_packet_id = INITIAL_PACKET_ID | SYNC_PACKET_ID;
}

static void windbg_exit(void)
{
    g_free(windbg_state);
}

int windbg_server_start(const char *device)
{
    if (windbg_state) {
        WINDBG_ERROR("Multiple instances of windbg are not supported.");
        exit(1);
    }

    windbg_state = g_new0(WindbgState, 1);
    windbg_state_clean(windbg_state);

    atexit(windbg_exit);
    return 0;
}
