#ifndef PLUGINS_H
#define PLUGINS_H

typedef struct QemuPluginInfo QemuPluginInfo;

void qemu_plugin_parse_cmd_args(const char *optarg);
QemuPluginInfo *qemu_plugin_load(const char *filename, const char *args);
void qemu_plugins_init(void);
void monitor_load_plugin(Monitor *mon, const QDict *qdict);

#endif /* PLUGINS_H */
