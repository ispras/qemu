#ifndef WINDBGSTUB_H
#define WINDBGSTUB_H

bool windbg_check_bp(void);
void windbg_set_bp(int index);
void windbg_start_sync(void);
int windbgserver_start(const char *device);

#endif