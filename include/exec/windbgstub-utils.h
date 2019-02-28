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

#define M64_SIZE sizeof(DBGKD_MANIPULATE_STATE64)

typedef enum {
    STATE_CHANGE_LOAD_SYMBOLS,
    STATE_CHANGE_BREAKPOINT
} KdStateChangeType;

typedef struct InitedAddr {
    target_ulong addr;
    bool is_init;
} InitedAddr;

typedef struct PacketData {
    union {
        uint8_t buf[PACKET_MAX_SIZE];
        struct {
            DBGKD_MANIPULATE_STATE64 m64;
            uint8_t m64_extra[0];
        };
    };
    uint16_t size;
} PacketData;

const char *kd_api_name(int id);
const char *kd_pkt_type_name(int id);

void kd_api_read_virtual_memory(CPUState *cs, PacketData *pd);
void kd_api_write_virtual_memory(CPUState *cs, PacketData *pd);
void kd_api_get_context(CPUState *cs, PacketData *pd);
void kd_api_set_context(CPUState *cs, PacketData *pd);
void kd_api_unsupported(CPUState *cs, PacketData *pd);

bool kd_init_state_change(CPUState *cs, PacketData *data,
                          KdStateChangeType type);

bool windbg_on_load(void);
void windbg_on_reset(void);

InitedAddr windbg_search_vmaddr(CPUState *cs, target_ulong start,
                                target_ulong finish, const uint8_t *pattern,
                                int pLen);

#endif /* WINDBGSTUB_UTILS_H */
