#ifndef WINDBGSTUB_H
#define WINDBGSTUB_H

// windbg.exe -b -k com:pipe,baud=115200,port=\\.\pipe\windbg,resets=0
// qemu.exe -windbg pipe:windbg_chr

#define WINDBG_DEBUG_ON true

void windbg_debug_parser_hook(bool is_kernel, const uint8_t *buf, int len);
void windbg_start_sync(void);
int windbg_start(const char *device);

#endif