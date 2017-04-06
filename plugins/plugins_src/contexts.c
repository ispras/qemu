#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"

#include "plugins/plugin.h"

#include "qmp-commands.h"
#include "tcg/tcg.h"
#include "tcg-op.h"
#include "exec/helper-proto.h"
#include <exec/helper-head.h>
#include "exec/exec-all.h"

const struct pi_info init_info = 
{
    .signals_list = (const char *[]){"contexts", NULL},
    .dependencies = (const char *[]){NULL},
    .os_ver = NULL
};


//hash table for detected contexts;
typedef struct ContextHashed{
        target_ulong ctxt;   /* key */

        UT_hash_handle hh;  /* makes this structure hashable */
} ContextHashed;


static SignalInfo *cb;
static ContextHashed *old_contexts = NULL;
static bool stop_on_new_ctxt = false;
static target_ulong curr_ctxt = 0;


static void pd_upd(void *data, CPUArchState *env)
{
    //yay! we got context update, time to handle it
    //look for this context, add to hash and gen signal if new
    ContextHashed *context;

    target_ulong gotten_context = *(target_ulong*)data;
    curr_ctxt = gotten_context;
    set_current_ctxt(curr_ctxt);

    HASH_FIND(hh, old_contexts, &curr_ctxt, sizeof(target_ulong), context);
    if (context == NULL) {
        context = (ContextHashed *) g_malloc (sizeof(ContextHashed));
        context->ctxt = gotten_context;
        HASH_ADD(hh, old_contexts, ctxt, sizeof(target_ulong), context);
        plugin_gen_signal(cb, "NEW_CONTEXT", NULL, env);

        //this should be set to 'false' by default, and can be switched via monitor
        if (stop_on_new_ctxt) {
            //what process we got here?
            printf("QEMU stopped on process: %#x \n", (int) context->ctxt);
            //stopping qemu
            qmp_stop(NULL);
        }
    }
}

static void plug_exit(const PluginInterface *pi)
{
    CPUState *cpu;

    plugin_del_subscriber(pd_upd, "qemu", "PLUGIN_QEMU_PAGE_DIR_UPD");
    /* Flushing everything before exiting plugin*/
    CPU_FOREACH(cpu) {
        tlb_flush(cpu);
    }
    fprintf(pi->output,"Contexts plugin ended its work\n");
}

static void unload_signal(void)
{
    plugin_del_signal(cb);
    plugin_del_subscriber(pd_upd, "qemu", "PLUGIN_QEMU_PAGE_DIR_UPD");
}

static void do_enable_ctxt_stop(Monitor *mon, const QDict *qdict)
{
    stop_on_new_ctxt = true;
}

static void do_disable_ctxt_stop(Monitor *mon, const QDict *qdict)
{
    stop_on_new_ctxt = false;
}

void pi_start(PluginInterface *pi)
{
    pi->exit = plug_exit;
    pi->unload_signal = unload_signal;

    /* I added trace_stop cmd, but im not gonna test it now
       so not sure if it would work properly or work at all */
    static mon_cmd_t mon_cmds[] = {
        {
            .name       = "context_enable_stop",
            .args_type  = "",
            .params     = "",
            .help       = "Enable stopping the qemu for any new context being detected",
            .cmd        = do_enable_ctxt_stop,
        },
        {
            .name       = "context_disable_stop",
            .args_type  = "",
            .params     = "",
            .help       = "Disable stopping the qemu for any new context being detected",
            .cmd        = do_disable_ctxt_stop,
        },
        {
            .name       = NULL,
        },
    };
    pi->cmd_table = mon_cmds;

    cb = plugin_reg_signal("contexts");
    plugin_subscribe(pd_upd, "qemu", "PLUGIN_QEMU_PAGE_DIR_UPD");
}

