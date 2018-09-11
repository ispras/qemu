/*
 * replay-debugging.c
 *
 * Copyright (c) 2010-2018 Institute for System Programming
 *                         of the Russian Academy of Sciences.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "sysemu/replay.h"
#include "replay-internal.h"
#include "hmp.h"
#include "monitor/monitor.h"
#include "qapi/qapi-commands-misc.h"
#include "qapi/qmp/qdict.h"
#include "qemu/timer.h"

void hmp_info_replay(Monitor *mon, const QDict *qdict)
{
    if (replay_mode == REPLAY_MODE_NONE) {
        monitor_printf(mon, "No record/replay\n");
    } else {
        monitor_printf(mon, "%s execution '%s': current step = %"PRId64"\n",
            replay_mode == REPLAY_MODE_RECORD ? "Recording" : "Replaying",
            replay_filename, replay_get_current_step());
    }
}

ReplayInfo *qmp_query_replay(Error **errp)
{
    ReplayInfo *retval = g_new0(ReplayInfo, 1);
    retval->mode = replay_mode;
    if (replay_filename) {
        retval->filename = g_strdup(replay_filename);
        retval->has_filename = true;
    }
    retval->step = replay_get_current_step();
    return retval;
}

void replay_break(int64_t step, QEMUTimerCB callback, void *opaque)
{
    assert(replay_mode == REPLAY_MODE_PLAY);
    assert(replay_mutex_locked());

    replay_break_step = step;
    if (replay_break_timer) {
        timer_del(replay_break_timer);
        timer_free(replay_break_timer);
        replay_break_timer = NULL;
    }

    if (replay_break_step == -1LL) {
        return;
    }
    assert(replay_break_step >= replay_get_current_step());
    assert(callback);

    replay_break_timer = timer_new_ns(QEMU_CLOCK_REALTIME, callback, opaque);
}

static void replay_stop_vm(void *opaque)
{
    vm_stop(RUN_STATE_PAUSED);
    replay_break(-1LL, NULL, NULL);
}

void qmp_replay_break(int64_t step, Error **errp)
{
    if (replay_mode ==  REPLAY_MODE_PLAY) {
        if (step >= replay_get_current_step()) {
            replay_break(step, replay_stop_vm, NULL);
        } else {
            error_setg(errp, "cannot set break at the step in the past");
        }
    } else {
        error_setg(errp, "setting the break is allowed only in play mode");
    }
}

void hmp_replay_break(Monitor *mon, const QDict *qdict)
{
    int64_t step = qdict_get_try_int(qdict, "step", -1LL);
    Error *err = NULL;

    qmp_replay_break(step, &err);
    if (err) {
        monitor_printf(mon, "replay_break error: %s\n", error_get_pretty(err));
        error_free(err);
        return;
    }
}
