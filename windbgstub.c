#include "qemu-common.h"
#include "sysemu/char.h"
#include "sysemu/sysemu.h"
#include "exec/windbgstub.h"
#include "exec/windbgstub-utils.h"

//windbg.exe -b -k com:pipe,baud=115200,port=\\.\pipe\windbg,resets=0
//qemu.exe -windbg pipe:async,windbg

void windbg_start_sync(void)
{

}

int windbgserver_start(const char *device)
{
    return 0;
}