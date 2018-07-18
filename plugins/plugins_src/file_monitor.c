#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"

#include "plugins/plugin.h"
#include "exec/cpu_ldst.h"
#include "tcg/tcg-op.h"

#include "syscalls.h"
#include "handle_map.h"
#include "file_monitor.h"

static FILE *syscallfile;
static HandleMap *hm;

const struct pi_info init_info = 
{
    .signals_list = (const char *[]){"files", NULL},
    .dependencies = (const char *[]){"contexts", "syscall", NULL},
    .os_ver = NULL
};

static void cpus_exit(const PluginInterface *pi)
{
    if (syscallfile)
        fclose(syscallfile);

    hm_free(hm);
}

/* syscall functions */

static void syscall_open_cb(void *msg, CPUArchState *env)
{
    Parameters_oc *params = (Parameters_oc *) msg;
    if (!params->ret) {
        Parameters_oc *params_cpy = g_malloc(sizeof(Parameters_oc));
        memcpy(params_cpy, params, sizeof(Parameters_oc));
        params_cpy->name = g_strdup(params->name);
        hm_insert(hm, params->handle, get_current_context(), params_cpy);
    }
    if (syscallfile) {
        if (!params->ret)
        {
            fprintf(syscallfile, "OPEN\n");
            fprintf(syscallfile, "\tName: %s\n", params->name);
            fprintf(syscallfile, "\tHandle: %"PRIx64"\n", params->handle);
            fprintf(syscallfile, "\tAccess: %x\n", params->access);
        }
        else
        {
            fprintf(syscallfile, "File %s cannot be opened\n", params->name);
        }
    }
}

static void syscall_create_cb(void *msg, CPUArchState *env)
{
    Parameters_oc *params = (Parameters_oc *) msg;
    if (!params->ret) {
        Parameters_oc *params_cpy = g_malloc(sizeof(Parameters_oc));
        memcpy(params_cpy, params, sizeof(Parameters_oc));
        params_cpy->name = g_strdup(params->name);
        hm_insert(hm, params->handle, get_current_context(), params_cpy);
    }
    if (syscallfile) {
        if (!params->ret)
        {
            fprintf(syscallfile, "CREATE\n");
            fprintf(syscallfile, "\tName: %s\n", params->name);
            fprintf(syscallfile, "\tHandle: %"PRIx64"\n", params->handle);
            fprintf(syscallfile, "\tAccess: %x\n", params->access);
        }
        else
        {
            fprintf(syscallfile, "File %s cannot be opened\n", params->name);
        }
    }
}

static void syscall_read_cb(void *msg, CPUArchState *env)
{
    Parameters_rw *params = (Parameters_rw *) msg;
    if (syscallfile) {
        if (!params->ret)
        {
            fprintf(syscallfile, "READ\n");
            fprintf(syscallfile, "\tHandle: %"PRIx64"\n", params->handle);
            fprintf(syscallfile, "\tLength: %x\n", params->length);
            fprintf(syscallfile, "\tBuffer: ");
            int i = 0;
            for (; i < params->length; i++)
            {
                fprintf(syscallfile, "%02x ", params->buffer[i]);
            }
            fprintf(syscallfile, "\n");
        }
        else
        {
            fprintf(syscallfile, "File %"PRIx64" cannot read\n", params->handle);
        }
    }
}

static void syscall_write_cb(void *msg, CPUArchState *env)
{
    Parameters_rw *params = (Parameters_rw *) msg;
    if (syscallfile) {
        if (!params->ret)
        {
            fprintf(syscallfile, "WRITE\n");
            fprintf(syscallfile, "\tHandle: %"PRIx64"\n", params->handle);
            fprintf(syscallfile, "\tLength: %x\n", params->length);
            fprintf(syscallfile, "\tBuffer: ");
            int i = 0;
            for (; i < params->length; i++)
            {
                fprintf(syscallfile, "%02x ", params->buffer[i]);
            }
            fprintf(syscallfile, "\n");
        }
        else
        {
            fprintf(syscallfile, "File %"PRIx64" cannot write\n", params->handle);
        }
    }
}

static void syscall_duplicate_cb(void *msg, CPUArchState *env)
{
    Parameters_do *params = (Parameters_do *) msg;
    if (syscallfile) {
        fprintf(syscallfile, "DUPLICATE\n");
        fprintf(syscallfile, "\tSourceHandle: %x\n", (int) params->sourceHandle);
        fprintf(syscallfile, "\tTargetHandle: %x\n", (int) params->pTargetHandle);
    }
    
    Parameters_oc *params_open = hm_find(hm, params->sourceHandle, get_current_context());
    if (params_open)
    {
        if (syscallfile) {
            fprintf(syscallfile, "we found the handle\n");
            if (params_open->name) {
                fprintf(syscallfile, "\tName: %s\n", params_open->name);
            }
            fprintf(syscallfile, "\tHandle: %"PRIx64"\n", params_open->handle);
            fprintf(syscallfile, "\tAccess: %x\n", params_open->access);
        }
        Parameters_oc *params_new = g_malloc(sizeof(Parameters_oc));
        if (params_open->name) {
            params_new->name = g_strdup(params_open->name);
        }
        params_new->handle = params_open->handle;
        params_new->access = params_open->access;
        hm_insert(hm, params_new->handle, get_current_context(), params_new);
    }
}

static void syscall_close_cb(void *msg, CPUArchState *env)
{
    Parameters_c *params = (Parameters_c *) msg;
    if (hm_find(hm, params->handle, get_current_context()))
    {
        if (syscallfile) {
            fprintf(syscallfile, "CLOSE\n");
        }
        //fprintf(syscallfile, "\tHandle: %x\n", params->handle);
        Parameters_oc *params_oc = hm_find(hm, params->handle, get_current_context());
        if (params_oc) {
            if (syscallfile) {
                fprintf(syscallfile, "\tName: %s\n\tHandle: %"PRIx64"\n", (params_oc->name) ? params_oc->name : "", params->handle);
            }
            if (params_oc->name) {
                g_free(params_oc->name);
            }
            hm_erase(hm, params->handle, get_current_context());
        }
    }
}


static HandleMap *get_files_list(void)
{
    return hm;
}

static void start_syscall_log(Monitor *mon, const QDict *qdict)
{
    const char *fname = "syscall_general.log";
    syscallfile = fopen(fname, "w");
    if (!syscallfile)
        monitor_printf(mon, "Can\'t open file %s\n", fname);
}

void pi_start(PluginInterface *pi)
{
    pi->exit = cpus_exit;

    static const struct fileMonFuncs funcs = { .f1 = get_files_list};
    pi->funcs = &funcs;

    static mon_cmd_t mon_cmds[] = {
        {
            .name       = "enable_filemon_log",
            .args_type  = "",
            .params     = "",
            .help       = "begin logging of syscalls",
            .cmd = start_syscall_log,
        },
        {
            .name       = NULL,
        },
    };
    pi->cmd_table = mon_cmds;

    hm = hm_new();
    char name[] = "syscall";

    plugin_subscribe(syscall_create_cb, name, "VMI_SC_CREATE");
    plugin_subscribe(syscall_open_cb, name, "VMI_SC_OPEN");
    plugin_subscribe(syscall_read_cb, name, "VMI_SC_READ");
    plugin_subscribe(syscall_write_cb, name, "VMI_SC_WRITE");
    plugin_subscribe(syscall_duplicate_cb, name, "VMI_SC_DUPLICATE_OBJ");
    plugin_subscribe(syscall_close_cb, name, "VMI_SC_CLOSE");
}