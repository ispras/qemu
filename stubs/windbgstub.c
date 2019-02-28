/*
 * windbgstub.c
 *
 * Copyright (c) 2010-2019 Institute for System Programming
 *                         of the Russian Academy of Sciences.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "exec/windbgstub.h"

void windbg_try_load(void)
{
}

int windbg_server_start(const char *device)
{
    return 0;
}

#ifdef WINDBG_CATCH_INTERRUPTS
void windbg_interrupt_handler(CPUState *cs, uint64_t instr_pointer)
{
}
#endif
