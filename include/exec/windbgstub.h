/*
 * windbgstub.h
 *
 * Copyright (c) 2010-2019 Institute for System Programming
 *                         of the Russian Academy of Sciences.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef WINDBGSTUB_H
#define WINDBGSTUB_H

#ifdef DEBUG_WINDBG
#define WINDBG_DPRINT true
#else
#define WINDBG_DPRINT false
#endif

void windbg_try_load(void);

int windbg_server_start(const char *device);

#endif /* WINDBGSTUB_H */
