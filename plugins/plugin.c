/*
 * Copyright (C) 2015 ISP RAS
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "plugin.h"
#include "tcg-op.h"
#include "exec/exec-all.h"   /* TranslationBlock */
#include "qom/cpu.h"         /* CPUState */
#include "sysemu/sysemu.h"   /* max_cpus */
#include "qemu/queue.h"      /* QLIST macros */

#include <regex.h> /* regular expressions */
#include <dlfcn.h>   /* dlopen(3), dlsym(3), */
#include <dirent.h> /* to work with directories */
#include <libgen.h>
#ifdef CONFIG_WIN32
#include <windows.h>
#endif

#define PLUGIN_EXTENSION ".plugin"

static bool atexit_func_defined = false;
static const char *os_version;
SignalInfo *signals = NULL;

static target_ulong curr_ctxt = 0;

ContextList *procsToInstrument = NULL;

typedef struct Plugin {         //Plugin list's element
    PluginInterface *pi;
    QLIST_ENTRY(Plugin) entry;
} Plugin;

static QLIST_HEAD(plugins, Plugin) plugins; //List for storing all loaded plugins

/* Set os version to choose correct tcg plugins. */
void plugins_set_os(const char *os_ver)
{
    os_version = os_ver;
}

void set_current_ctxt(target_ulong ctxt)
{
    curr_ctxt = ctxt;
}

uint64_t get_current_context(void)
{
    //guess we need to force load of contexts plugin here
    return curr_ctxt;
}

static bool plugin_check_os(const struct pi_info *init_info)
{
    if (!os_version || !init_info->os_ver) {
        return true;
    }

    const char **v = init_info->os_ver;
    while (*v) {
        if (!strcmp(os_version, *v)) {
            return true;
        }
        ++v;
    }
    return false;
}

static char *get_libexec_path(void)
{
    char *libexec = g_malloc0(1024); //magic numbers
    char *exec_dir = qemu_get_exec_dir();
    strcpy(libexec, exec_dir);
#ifndef CONFIG_WIN32
    libexec = dirname(libexec);
#endif
    strcat(libexec, "/libexec/");
    g_free(exec_dir);
    return libexec;
}

/* Load the dynamic shared object "name" and call its function
 * "pi_init()" to initialize itself. */
bool plugin_load(const char *name)
{
    if (!atexit_func_defined)
    {
        atexit(plugin_exit);
        atexit_func_defined = true;
    }
    PluginInterface *pi = NULL;
#if !defined(CONFIG_SOFTMMU)
    unsigned int max_cpus = 1;
#endif
    pi_init_t pi_start;
    char *path = NULL;
    bool done = false;
    void *handle;
    /* Check if "name" refers to an installed plugin (short form).  */
    if (name[0] != '.' && name[0] != '/') {
        const char *format = "plugin-%s-" TARGET_NAME PLUGIN_EXTENSION;
        char *fullpath = get_libexec_path();
        strcat(fullpath, format);
        size_t size = strlen(fullpath) + strlen(name) + 1;
        
        int status;
        path = g_malloc0(size);
        snprintf(path, size, fullpath, name);
        status = access(path, F_OK);
        if (status) {
            g_free(path);
            path = NULL;
        }
        g_free(fullpath);
    }

    Plugin *pl;
    QLIST_FOREACH(pl, &plugins, entry) 
    {
        if (!strcmp((pl->pi)->name, (path ? path : name))) {
            printf("Plugin \"%s\" is already loaded. Couldn't load plugin with the same name.\n", (pl->pi)->name );
            return false;
        }
    }
    handle = dlopen(path ?: name, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "plugin: error: %s\n", dlerror());
        goto error;
    }

    dlerror();
    const struct pi_info *init_info = dlsym(handle, "init_info");
    char *err = dlerror();
    if (err)
    {
        fprintf(stderr, "plugin: error retrieving initialization info: %s \n", err);
        //goto error;
    }

    pi_start = dlsym(handle, "pi_start");
    if (!pi_start) {
        fprintf(stderr, "plugin: error: %s\n", dlerror());
        goto error;
    }

    pi = g_malloc0(sizeof(*pi));

    pi->name = g_strdup(path ? path : name);

    pi->signals = init_info->signals_list;
    pi->os_ver = init_info->os_ver;

    /* Trying to load dependencies (plugins) */
    if (init_info->dependencies) {
        const char **pl_deps = init_info->dependencies;
        while (*pl_deps) {
            if (!plugin_load_provider_plugin(*pl_deps)) {
                fprintf(stderr, "Unable to load dependency plugin \" %s \" \n", *pl_deps);
                goto error;
            }
            pl_deps++;
        }
    }

    pi->output = fdopen(dup(fileno(stderr)), "a");
    if (!pi->output)
        pi->output = stderr;

    /* Check OS version */
    if (!plugin_check_os(init_info)) {
        fprintf(stderr, "plugin: error: can't load plugin '%s' when current os is %s\n", 
                name, os_version);
        goto error;
    }

    /*
     * Tell the plugin to initialize itself.
     */
    pi_start(pi);

    tb_flush(first_cpu);

    done = true;

error:
    if (path)
        g_free(path);

    if (!done) {
        if (pi) {
            g_free(pi->name);
            g_free(pi);
        }
        return false;
    } else {
        Plugin *Pl;
        Pl = g_malloc(sizeof(*Pl));
        Pl->pi = pi;
        QLIST_INSERT_HEAD(&plugins, Pl, entry);
    }

    return true;
}

/* Loads list of comma-separated plugins */
void plugins_load(const char *name)
{
    char *s = g_strdup(name);
    char *plugin = strtok(s, ",");
    while (plugin) {
        plugin_load(plugin);
        plugin = strtok(NULL, ",");
    }
    g_free(s);
}

bool plugin_unload(const char *name)
{
    char *path = NULL;

    /* Check if "name" refers to an installed plugin (short form).  */
    if (name && name[0] != '.' && name[0] != '/') {
        const char *format = "plugin-%s-" TARGET_NAME PLUGIN_EXTENSION;
        char *fullpath = get_libexec_path();
        strcat(fullpath, format);
        size_t size = strlen(fullpath) + strlen(name) + 1;
        
        int status;
        path = g_malloc0(size);
        snprintf(path, size, fullpath, name);
        status = access(path, F_OK);
        if (status) {
            g_free(path);
            path = NULL;
        } else {
            name = path;
        }
        g_free(fullpath);
    }

    Plugin *pl;
    Plugin *pl_next;

    QLIST_FOREACH_SAFE(pl, &plugins, entry, pl_next) {
        if (name) {
            if (strcmp(name, pl->pi->name) == 0) {
                if ((pl->pi)->unload_signal) {
                    (pl->pi)->unload_signal();
                }
                if ((pl->pi)->exit) {
                    (pl->pi)->exit(pl->pi);
                }

                if ((pl->pi)->signals) {
                    SignalInfo *sig;
                    const char **pl_sigs = (pl->pi)->signals;
                    while (*pl_sigs) {    
                        HASH_FIND_STR(signals, *pl_sigs, sig);
                        if (sig) {
                            HASH_DEL(signals, sig);
                        }
                        pl_sigs++;
                    }
                }

                g_free(pl->pi->name);
                g_free(pl->pi);
                QLIST_REMOVE(pl, entry);
                return true;
            }
        } else {
            if ((pl->pi)->unload_signal) {
                (pl->pi)->unload_signal();
            }
            if ((pl->pi)->exit) {
                (pl->pi)->exit(pl->pi);
            }

            if ((pl->pi)->signals) {
                SignalInfo *sig;
                const char **pl_sigs = (pl->pi)->signals;
                while (*pl_sigs) {    
                    HASH_FIND_STR(signals, *pl_sigs, sig);
                    if (sig) {
                        HASH_DEL(signals, sig);
                    }
                    pl_sigs++;
                }
            }

            g_free(pl->pi->name);
            g_free(pl->pi);
            QLIST_REMOVE(pl, entry);
        }
    }
    if (name) {
        return false;
    }
    return true;
}

const void *plugin_get_functions_list(const char *plugin_name)
{
    /* the idea is to keep track of all loaded plugin's pi's after
    they are loaded, in a pi-plugin_name fashion list. in this function
    we are looking through this list comparing names, and if comparison
    was successful we will take the pi->funcs list and send it back */
    /* for pi->name we usually use full path, it may be better to use 
    short names here*/

    char *path = NULL;
    /* Check if "name" refers to an installed plugin (short form).  */
    if (plugin_name[0] != '.' && plugin_name[0] != '/') {
        const char *format = "plugin-%s-" TARGET_NAME PLUGIN_EXTENSION;
        char *fullpath = get_libexec_path();
        strcat(fullpath, format);
        size_t size = strlen(fullpath) + strlen(plugin_name) + 1;
        
        int status;
        path = g_malloc0(size);
        snprintf(path, size, fullpath, plugin_name);
        status = access(path, F_OK);
        if (status) {
            g_free(path);
            path = NULL;
        }
        g_free(fullpath);
    }
    char *name  = g_strdup(path ? path : plugin_name);

    Plugin *pl;
    QLIST_FOREACH(pl, &plugins, entry) {
        if (strcmp((pl->pi)->name, name) == 0) {
            return (pl->pi)->funcs;
        }
    }
    // TODO: auto-load plugin here
    return NULL;
}

void plugin_list(Monitor *mon)
{
    Plugin *pl;
    bool empty = true; //shitty, but easy to understand
    QLIST_FOREACH(pl, &plugins, entry) 
    {
        if(empty)
        {
            monitor_printf(mon, "List of loaded plugins:\n");
        }
        empty = false;
        monitor_printf(mon, "\t %s \n", (pl->pi)->name);
   }
    if (empty)
    {
        monitor_printf(mon, "No plugins are loaded yet.\n");
    }
}

/* Hook called once qemu exits.  */
void plugin_exit(void)
{
    Plugin *pl;
    QLIST_FOREACH(pl, &plugins, entry) 
    {
        if ((pl->pi)->exit)
        {
            (pl->pi)->exit(pl->pi);
        }
    }
}

SignalInfo *plugin_reg_signal(const char *name)
{
    //if (searching_for_providers)
    //    return NULL;
    SignalInfo *sig;
    HASH_FIND_STR(signals, name, sig);
    if (sig)
    {
        printf("Can't register the signal. There already is a signal with \"%s\" name\n", name);
        return NULL;
    }
    sig = (SignalInfo*) g_malloc (sizeof (SignalInfo));
    strcpy(sig->name, name);
    sig->subs_group = NULL;
    HASH_ADD_STR(signals, name, sig);
    return sig;
}

void plugin_subscribe(void *func, const char *name, const char *str_id)
{
    SignalInfo *sig;
    Subs_group *sb_group;
    Subscriber *sb, *tmp;

    /* Try to find signal before trying to load */
    HASH_FIND_STR(signals, name, sig);

    if (!sig) {
        //searching_for_providers = true;
        if (!plugin_load_provider_plugin(name))
        {
            printf("No plugins with \"%s\" signal were found\n", name);
            //searching_for_providers = false;
            return;
        }
        //searching_for_providers = false;
    }

    HASH_FIND_STR(signals, name, sig);

    if (sig) {
        HASH_FIND_STR(sig->subs_group, str_id, sb_group);
        if(!sb_group) {
            sb_group =  (Subs_group*) g_malloc (sizeof (Subs_group));
            strcpy(sb_group->str_id, str_id);
            sb_group->subs = NULL;
            HASH_ADD_STR(sig->subs_group, str_id, sb_group);
        }
        sb = sb_group->subs;
        if (sb == NULL) {
            sb = (Subscriber*) g_malloc (sizeof (Subscriber));
            sb->callback = func;
            sb->next = NULL;

            sb_group->subs = sb;
        } else {
            tmp = (Subscriber*) g_malloc (sizeof (Subscriber));
            tmp->callback = func;
            tmp->next = sb;
    
            sb_group->subs = tmp;
        }
    } else {
        printf("No \"%s\" signal providers were found\n", name);
    }
}

static void plugin_gen_sub_callback(SignalInfo *sig, const char *str_id, void *data, CPUArchState *env)
{
    Subs_group *sb_group = plugin_get_subscribers(sig, str_id);
    plugin_send_to_subscribers(sb_group, data, env);
}

void plugin_send_to_subscribers(Subs_group *sb_group, void *data, CPUArchState *env)
{
    if (sb_group) {
        Subscriber *subscribers = sb_group->subs;
        while (subscribers) {
            (*subscribers->callback)(data, env);
            subscribers = subscribers->next;
        }
    }
}

Subs_group *plugin_get_subscribers(SignalInfo *sig, const char *str_id)
{
    Subs_group *sb_group = NULL;
    if (sig) {
        HASH_FIND_STR(sig->subs_group, str_id, sb_group);
    }
    if (!sb_group) {
        /* add group without subscribers */
        sb_group =  g_new0(Subs_group, 1);
        strcpy(sb_group->str_id, str_id);
        HASH_ADD_STR(sig->subs_group, str_id, sb_group);
    }
    return sb_group;
}

void plugin_gen_signal(SignalInfo *sig, const char *str_id, void *data, CPUArchState *env)
{
    //some process dependent signal generation will be here, but for now - just generate a signal
    plugin_gen_sub_callback(sig, str_id, data, env);
}

void plugin_del_signal(SignalInfo *sig)
{
    HASH_DEL(signals, sig);
    g_free(sig);
}

void plugin_del_subscriber(void *func, const char *name, const char *str_id)
{
    SignalInfo *sig;
    Subs_group *sb_group;
    Subscriber *sb;

    HASH_FIND_STR(signals, name, sig);

    if (sig) {
        HASH_FIND_STR(sig->subs_group, str_id, sb_group);
        if(sb_group) {
            sb = sb_group->subs;
            if (sb) {
                if (sb->callback == func) {
                    sb_group->subs = sb->next;
                    g_free(sb);
                }
                else {
                    do {
                        if(sb->next) {
                            if(sb->next->callback == func) {
                                sb->next = (sb->next)->next;
                                g_free(sb->next);
                            }
                        }
                        sb = sb->next;
                    } while (sb);
                }
            }
        }
    }
}

const mon_cmd_t *plugin_parse_command(Monitor *mon, const char **cmdline)
{
    const mon_cmd_t *cmd = NULL;
    Plugin *pl;
    const char *start = *cmdline;
    QLIST_FOREACH(pl, &plugins, entry) {
        if (pl->pi->cmd_table) {
            *cmdline = start;
            cmd = monitor_parse_command(mon, cmdline, pl->pi->cmd_table);
            if (cmd) {
                return cmd;
            }
        }
    }
    return NULL;
}

void plugin_help_cmd_dump(Monitor *mon, char **args, int nb_args, int arg_index)
{
    Plugin *pl;
    QLIST_FOREACH(pl, &plugins, entry) {
        if (pl->pi->cmd_table) {
            help_cmd_dump(mon, pl->pi->cmd_table, args, nb_args, arg_index);
        }
    }
}

void plugin_find_completion_by_table(Monitor *mon, char **args, int nb_args)
{
    Plugin *pl;
    QLIST_FOREACH(pl, &plugins, entry) {
        if (pl->pi->cmd_table) {
            monitor_find_completion_by_table(mon, pl->pi->cmd_table, args, nb_args);
        }
    }
}

bool plugin_check_loaded_signals(const char* name)
{
    Plugin *pl;
    QLIST_FOREACH(pl, &plugins, entry) {
        if ((pl->pi)->signals) {
            const char **signals = (pl->pi)->signals;
            while (*signals) {
                if (!strcmp(*signals, name)) {
                    return true;
                }
                signals++;
            }
        }
    }
    return false;
}

bool plugin_load_provider_plugin(const char* name)
{
    DIR *dir;
    struct dirent *ent;
    void *handle;
    if (plugin_check_loaded_signals(name)) {
        return true;
    }
    char *all_signals = (char *) malloc(10240 * sizeof(char)); //Magic size that i hope would be sufficient
    strcpy(all_signals, "List of signals available for loading:\n");
    char *libexec_path =  get_libexec_path();
    if ((dir = opendir (libexec_path)) != NULL) {
        regex_t regex;
        regcomp(&regex, "[.]*-" TARGET_NAME PLUGIN_EXTENSION, 0);

        /* check all the files and directories within directory */
        while ((ent = readdir (dir)) != NULL) {
            if (!regexec(&regex, ent->d_name, 0, NULL, 0)) {
                char path[PATH_MAX + 1];
                strcpy(path, libexec_path);
                strcat(path, ent->d_name);
                handle = dlopen(path, RTLD_NOW);
                if (handle) {
                    const struct pi_info *init_info = dlsym(handle, "init_info");
                    char *err = dlerror();
                    if (!err
                        && plugin_check_os(init_info)
                        && init_info->signals_list) {
                        const char **signals = init_info->signals_list;
                        while (*signals) {
                            strcat(all_signals, "\t");
                            strcat(all_signals, *signals);
                            strcat(all_signals, "\n");
                            if (!strcmp(*signals, name)) {
                                if (!plugin_load(path)) {
                                    printf("Error occured while loading plugin \"%s\" needed for signals. \n", path);
                                    g_free(all_signals);
                                    g_free(libexec_path);
                                    return false;
                                }
                                g_free(all_signals);
                                g_free(libexec_path);
                                return true;
                            }
                            signals++;
                        }
                        strcat(all_signals, "..in ");
                        strcat(all_signals, path);
                        strcat(all_signals, "\n");
                    }
                } else {
                    printf("dlopen error for %s: %s\n", path, dlerror());
                }
            }
        }

        closedir(dir);
        regfree(&regex);
    } else {
        /* could not open directory */
        printf("Couldn't open directory with plugins.\n");
        g_free(all_signals);
        g_free(libexec_path);
        return false;
    }
    // Not sure
    printf("%s", all_signals);
    g_free(all_signals);
    g_free(libexec_path);
    return false;
}
