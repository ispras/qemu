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
#include "qapi/error.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "qemu/cutils.h"
#include "exec/windbgstub.h"
#include "exec/windbgstub-utils.h"

typedef struct WindbgState {
    bool is_loaded;
    bool catched_breakin_byte;
    uint32_t wait_packet_type;
    uint32_t curr_packet_id;

    CharBackend chr;
} WindbgState;

static WindbgState *windbg_state;

static void windbg_state_clean(WindbgState *state)
{
    state->is_loaded = false;
    state->catched_breakin_byte = false;
    state->wait_packet_type = 0;
    state->curr_packet_id = INITIAL_PACKET_ID | SYNC_PACKET_ID;
}

static int windbg_chr_can_receive(void *opaque)
{
    return PACKET_MAX_SIZE;
}

static void windbg_chr_receive(void *opaque, const uint8_t *buf, int size)
{
}

static void windbg_exit(void)
{
    g_free(windbg_state);
}

int windbg_server_start(const char *device)
{
    Chardev *chr = NULL;

    if (windbg_state) {
        WINDBG_ERROR("Multiple instances of windbg are not supported.");
        exit(1);
    }

    if (!strstart(device, "pipe:", NULL)) {
        WINDBG_ERROR("Unsupported device. Supported only pipe.");
        exit(1);
    }

    windbg_state = g_new0(WindbgState, 1);
    windbg_state_clean(windbg_state);

    chr = qemu_chr_new_noreplay("windbg", device, true, NULL);
    if (!chr) {
        return -1;
    }

    qemu_chr_fe_init(&windbg_state->chr, chr, &error_abort);
    qemu_chr_fe_set_handlers(&windbg_state->chr, windbg_chr_can_receive,
                             windbg_chr_receive, NULL, NULL, NULL, NULL, true);

    atexit(windbg_exit);
    return 0;
}
