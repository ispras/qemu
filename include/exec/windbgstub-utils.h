/*
 * windbgstub-utils.h
 *
 * Copyright (c) 2010-2019 Institute for System Programming
 *                         of the Russian Academy of Sciences.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef WINDBGSTUB_UTILS_H
#define WINDBGSTUB_UTILS_H

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "log.h"
#include "cpu.h"
#include "exec/windbgstub.h"
#include "exec/windbgkd.h"

#define DPRINTF(fmt, ...)                                                      \
    do {                                                                       \
        if (WINDBG_DPRINT) {                                                   \
            qemu_log("windbg: " fmt "\n", ##__VA_ARGS__);                      \
        }                                                                      \
    } while (0)

#define WINDBG_ERROR(...) error_report("windbg: " __VA_ARGS__)

#define FMT_ADDR "addr:0x" TARGET_FMT_lx
#define FMT_ERR "Error:%d"

#define PTR(var) ((uint8_t *) (&var))

#define VMEM_ADDR(cpu, addr)                                                   \
    ({                                                                         \
        target_ulong _addr;                                                    \
        cpu_memory_rw_debug(cpu, addr, PTR(_addr), sizeof(target_ulong), 0);   \
        ldtul_p(&_addr);                                                       \
    })

#if TARGET_LONG_BITS == 64
#define sttul_p(p, v) stq_p(p, v)
#define ldtul_p(p) ldq_p(p)
#else
#define sttul_p(p, v) stl_p(p, v)
#define ldtul_p(p) ldl_p(p)
#endif

typedef struct InitedAddr {
    target_ulong addr;
    bool is_init;
} InitedAddr;

const char *kd_api_name(int id);
const char *kd_pkt_type_name(int id);

#endif /* WINDBGSTUB_UTILS_H */
