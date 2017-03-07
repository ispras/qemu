#ifndef WINDBGSTUB_UTILS_H
#define WINDBGSTUB_UTILS_H

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "exec/windbgkd.h"
#include "exec/windbgstub.h"

// #include "qemu/cutils.h"

#if (WINDBG_DEBUG_ON)
# define COUT(...) printf("" __VA_ARGS__)
# define WINDBG_DEBUG(...) COUT_LN("Debug: " __VA_ARGS__)
# define WINDBG_ERROR(...) COUT_LN("Error: " __VA_ARGS__)
#else
# define COUT(...)
# define WINDBG_DEBUG(...)
# define WINDBG_ERROR(...) error_report(WINDBG ": " __VA_ARGS__)
#endif

// Debug only
#define COUT_LN(fmt, ...) COUT(fmt "\n", ##__VA_ARGS__)
#define COUT_FMT(name, fmt, ...) COUT_LN(name " = [" fmt "]", ##__VA_ARGS__)
#define COUT_DEC(var) COUT_FMT(#var, "%d", (uint32_t) (var))
#define COUT_HEX(var) COUT_FMT(#var, "0x%x", (uint32_t) (var))
#define COUT_BOOL(var) COUT_FMT(#var, "%s", (var) ? "true" : "false")
#define COUT_SIZEOF(var) COUT_FMT("sizeof " #var, "%lld", sizeof(var))
#define COUT_STRUCT(var) COUT_ARRAY(&var, 1)
#define COUT_PSTRUCT(var) COUT_ARRAY(var, 1)
#define COUT_ARRAY(var, count) _COUT_STRUCT(var, sizeof(*(var)), count)
#define _COUT_STRUCT(var, size, count) {                           \
    COUT(#var " ");                                                \
    COUT_LN("[size: %d, count: %d]", (int) (size), (int) (count)); \
    _COUT_BLOCK(var, size * count);                                \
}
#define _COUT_BLOCK(ptr, size) {     \
    uint8_t *_p = (uint8_t *) (ptr); \
    uint32_t _s = (size);            \
                                     \
    int _i = 0;                      \
    for (; _i < _s; ++_i) {          \
        if (!(_i % 16) && _i) {      \
            COUT_LN();               \
        }                            \
        COUT("%02x ", _p[_i]);       \
    }                                \
    COUT_LN();                       \
}

#define FMT_ADDR "addr:0x" TARGET_FMT_lx
#define FMT_ERR  "Error:%d"

#define TO_PTR(type, par) ((type *) (par))
#define UINT8_P(var) TO_PTR(uint8_t, &var)
#define UINT32_P(var) TO_PTR(uint32_t, &var)
#define FIELD_P(type, field, ptr) TO_PTR(typeof_field(type, field), ptr)
#define PTR(var) UINT8_P(var)

#define M64_SIZE sizeof(DBGKD_MANIPULATE_STATE64)

#define sizeof_field(type, field) sizeof(((type *) NULL)->field)

#define FCLOSE(file)  \
    if (file) {       \
        fclose(file); \
        file = NULL;  \
    }

#define UNUSED __attribute__ ((unused))

typedef struct SizedBuf {
    uint8_t *data;
    size_t size;
} SizedBuf;

typedef struct InitedAddr {
    target_ulong addr;
    bool is_init;
} InitedAddr;

typedef struct PacketData {
    union {
        struct {
            DBGKD_MANIPULATE_STATE64 m64;
            uint8_t extra[PACKET_MAX_SIZE - sizeof(DBGKD_MANIPULATE_STATE64)];
        };
        uint8_t buf[PACKET_MAX_SIZE];
    };
    uint16_t extra_size;
} PacketData;

void kd_api_read_virtual_memory(CPUState *cpu, PacketData *pd);
void kd_api_write_virtual_memory(CPUState *cpu, PacketData *pd);
void kd_api_get_context(CPUState *cpu, PacketData *pd);
void kd_api_set_context(CPUState *cpu, PacketData *pd);
void kd_api_write_breakpoint(CPUState *cpu, PacketData *pd);
void kd_api_restore_breakpoint(CPUState *cpu, PacketData *pd);
void kd_api_continue(CPUState *cpu, PacketData *pd);
void kd_api_read_control_space(CPUState *cpu, PacketData *pd);
void kd_api_write_control_space(CPUState *cpu, PacketData *pd);
void kd_api_read_io_space(CPUState *cpu, PacketData *pd);
void kd_api_write_io_space(CPUState *cpu, PacketData *pd);
// void kd_api_reboot_api(CPUState *cpu, PacketData *pd);
void kd_api_read_physical_memory(CPUState *cpu, PacketData *pd);
void kd_api_write_physical_memory(CPUState *cpu, PacketData *pd);
// void kd_api_query_special_calls(CPUState *cpu, PacketData *pd);
// void kd_api_set_special_call(CPUState *cpu, PacketData *pd);
// void kd_api_clear_special_calls(CPUState *cpu, PacketData *pd);
// void kd_api_set_internal_breakpoint(CPUState *cpu, PacketData *pd);
// void kd_api_get_internal_breakpoint(CPUState *cpu, PacketData *pd);
// void kd_api_read_io_space_extended(CPUState *cpu, PacketData *pd);
// void kd_api_write_io_space_extended(CPUState *cpu, PacketData *pd);
void kd_api_get_version(CPUState *cpu, PacketData *pd);
// void kd_api_write_breakpoint_ex(CPUState *cpu, PacketData *pd);
// void kd_api_restore_breakpoint_ex(CPUState *cpu, PacketData *pd);
// void kd_api_cause_bug_check(CPUState *cpu, PacketData *pd);
// void kd_api_switch_processor(CPUState *cpu, PacketData *pd); unused
// void kd_api_page_in(CPUState *cpu, PacketData *pd);
void kd_api_read_msr(CPUState *cpu, PacketData *pd);
void kd_api_write_msr(CPUState *cpu, PacketData *pd);
// void kd_api_old_vlm1(CPUState *cpu, PacketData *pd);
// void kd_api_old_vlm2(CPUState *cpu, PacketData *pd);
void kd_api_search_memory(CPUState *cpu, PacketData *pd);
// void kd_api_get_bus_data(CPUState *cpu, PacketData *pd);
// void kd_api_set_bus_data(CPUState *cpu, PacketData *pd);
// void kd_api_check_low_memory(CPUState *cpu, PacketData *pd);
// void kd_api_clear_all_internal_breakpoints(CPUState *cpu, PacketData *pd); unused
void kd_api_fill_memory(CPUState *cpu, PacketData *pd);
void kd_api_query_memory(CPUState *cpu, PacketData *pd);
// void kd_api_switch_partition(CPUState *cpu, PacketData *pd);
void kd_api_unsupported(CPUState *cpu, PacketData *pd);

EXCEPTION_STATE_CHANGE *kd_get_exception_sc(CPUState *cpu);
SizedBuf               *kd_get_load_symbols_sc(CPUState *cpu);

const char *kd_get_api_name(int id);
const char *kd_get_packet_type_name(int id);

void windbg_dump(const char *fmt, ...);
bool windbg_on_loaded(void);
void windbg_on_exit(void);

uint32_t compute_checksum(uint8_t *data, uint16_t len);
uint8_t get_cpu_amount(void);

#endif