#include "qemu/osdep.h"
#include "qapi/error.h"
#include "plugins/plugin.h"
#include "include/exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "cpu.h"

#include "guest_string.h"

char *guest_strdup(CPUArchState *env, target_ulong ptr)
{
    if (!ptr) {
        return NULL;
    }
    CPUState *cpu = ENV_GET_CPU(env);
    uint8_t c;
    target_ulong len = 0;
    do {
        cpu_memory_rw_debug(cpu, ptr + len, &c, 1, 0);
        ++len;
    } while (c);
    char *str = g_malloc(len);
    cpu_memory_rw_debug(cpu, ptr, (uint8_t*)str, len, 0);
    return str;
}

wchar_t *guest_strdupw(CPUArchState *env, target_ulong ptr, target_ulong *len)
{
    if (!ptr) {
        return NULL;
    }
    CPUState *cpu = ENV_GET_CPU(env);
    uint8_t c[2];
    //target_ulong len = 0;
    do {
        cpu_memory_rw_debug(cpu, ptr + *len, c, 2, 0);
        *len += 2;
    } while (c[0] || c[1]);
    wchar_t *str = g_malloc0(*len / 2 * sizeof(wchar_t));
    target_ulong i;
    for (i = 0; i < *len; i += 2) {
        cpu_memory_rw_debug(cpu, ptr + i, c, 2, 0);
        str[i / 2] = lduw_p(c);
    }
    return str;
}

target_ulong guest_read_tl(CPUArchState *env, target_ulong ptr)
{
    CPUState *cpu = ENV_GET_CPU(env);
    uint8_t buf[TARGET_LONG_BITS / 8];
    cpu_memory_rw_debug(cpu, ptr, buf, sizeof(buf), 0);
#if TARGET_LONG_BITS == 64
    return ldq_p(buf);
#else
    return ldl_p(buf);
#endif
}
