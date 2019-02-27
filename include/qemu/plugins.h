#ifndef PLUGINS_H
#define PLUGINS_H

void qemu_plugin_parse_cmd_args(const char *optarg);
void qemu_plugin_load(const char *filename, const char *args);
void qemu_plugins_init(void);

#endif /* PLUGINS_H */
