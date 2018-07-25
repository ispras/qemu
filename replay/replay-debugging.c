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
#include "block/snapshot.h"
#include "migration/snapshot.h"

static bool replay_is_debugging;

bool replay_running_debug(void)
{
    return replay_is_debugging;
}

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

static char *replay_find_nearest_snapshot(int64_t step, int64_t* snapshot_step)
{
    BlockDriverState *bs;
    QEMUSnapshotInfo *sn_tab;
    QEMUSnapshotInfo *nearest = NULL;
    char *ret = NULL;
    int nb_sns, i;
    AioContext *aio_context;

    *snapshot_step = -1;

    bs = bdrv_all_find_vmstate_bs();
    if (!bs) {
        goto fail;
    }
    aio_context = bdrv_get_aio_context(bs);

    aio_context_acquire(aio_context);
    nb_sns = bdrv_snapshot_list(bs, &sn_tab);
    aio_context_release(aio_context);

    for (i = 0; i < nb_sns; i++) {
        if (bdrv_all_find_snapshot(sn_tab[i].name, &bs) == 0) {
            if (sn_tab[i].icount != -1ULL
                && sn_tab[i].icount <= step
                && (!nearest || nearest->icount < sn_tab[i].icount)) {
                nearest = &sn_tab[i];
            }
        }
    }
    if (nearest) {
        ret = g_strdup(nearest->name);
        *snapshot_step = nearest->icount;
    }
    g_free(sn_tab);

fail:
    return ret;
}

static void replay_seek(int64_t step, Error **errp, QEMUTimerCB callback)
{
    char *snapshot = NULL;
    if (replay_mode != REPLAY_MODE_PLAY) {
        error_setg(errp, "replay must be enabled to seek");
        return;
    }
    if (!replay_snapshot) {
        error_setg(errp, "snapshotting is disabled");
        return;
    }
    int64_t snapshot_step = -1;
    snapshot = replay_find_nearest_snapshot(step, &snapshot_step);
    if (snapshot) {
        if (step < replay_get_current_step()
            || replay_get_current_step() < snapshot_step) {
            vm_stop(RUN_STATE_RESTORE_VM);
            load_snapshot(snapshot, errp);
        }
        g_free(snapshot);
    }
    if (replay_get_current_step() <= step) {
        replay_break(step, callback, NULL);
        vm_start();
    } else {
        error_setg(errp, "cannot seek to the specified step");
    }
}

void qmp_replay_seek(int64_t step, Error **errp)
{
    replay_seek(step, errp, replay_stop_vm);
}

void hmp_replay_seek(Monitor *mon, const QDict *qdict)
{
    int64_t step = qdict_get_try_int(qdict, "step", -1LL);
    Error *err = NULL;

    qmp_replay_seek(step, &err);
    if (err) {
        monitor_printf(mon, "replay_seek error: %s\n", error_get_pretty(err));
        error_free(err);
        return;
    }
}

static void replay_stop_vm_debug(void *opaque)
{
    replay_is_debugging = false;
    vm_stop(RUN_STATE_DEBUG);
    replay_break(-1LL, NULL, NULL);
}

bool replay_reverse_step(void)
{
    Error *err = NULL;

    assert(replay_mode == REPLAY_MODE_PLAY);

    if (replay_get_current_step() != 0) {
        replay_seek(replay_get_current_step() - 1, &err, replay_stop_vm_debug);
        if (err) {
            error_free(err);
            return false;
        }
        replay_is_debugging = true;
        return true;
    }

    return false;
}
