#ifndef WINDBGSTUB_H
#define WINDBGSTUB_H

bool windbg_check_single_step(void);
void windbg_vm_stop(void);
void windbg_start_sync(void);
int windbgserver_start(const char *device);

#endif