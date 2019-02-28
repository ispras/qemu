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

// #define DEBUG_WINDBG
// #define WINDBG_PARSER
// #define WINDBG_PARSER_CLIENT
// #define WINDBG_PARSER_SERVER
// #define WINDBG_PARSER_FULL_HANDLER
// #define WINDBG_PARSER_API_HANDLER
#define WINDBG_CATCH_INTERRUPTS

#ifdef DEBUG_WINDBG
#define WINDBG_DPRINT true
#else
#define WINDBG_DPRINT false
#endif

void windbg_try_load(void);

int windbg_server_start(const char *device);

#ifdef WINDBG_CATCH_INTERRUPTS
void windbg_interrupt_handler(CPUState *cs, uint64_t instr_pointer);
#else
#define windbg_interrupt_handler(cs, instr_pointer)
#endif

#ifdef WINDBG_PARSER
void windbg_debug_parser_hook(bool is_server, const uint8_t *buf, int len);
#else
#define windbg_debug_parser_hook(is_server, buf, len)
#endif

#endif /* WINDBGSTUB_H */
