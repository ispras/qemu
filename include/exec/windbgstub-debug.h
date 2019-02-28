/*
 * windbgstub-debug.h
 *
 * Copyright (c) 2010-2019 Institute for System Programming
 *                         of the Russian Academy of Sciences.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef WINDBGSTUB_TMP_H
#define WINDBGSTUB_TMP_H

#include "sysemu/sysemu.h"
#include "exec/windbgstub.h"

#define UNUSED __attribute__((unused))

#define UINT8_P(ptr) ((uint8_t *) (ptr))
#define UINT32_P(ptr) ((uint32_t *) (ptr))
#define TULONG_P(ptr) ((target_ulong *) (ptr))
#define FIELD_P(type, field, ptr) ((typeof_field(type, field) *) (ptr))

#define _OUT(file, log, fmt, ...)                                              \
    do {                                                                       \
        if (file != NULL) {                                                    \
            fprintf(file, fmt, ##__VA_ARGS__);                                 \
        }                                                                      \
        if (WINDBG_DPRINT && log) {                                            \
            qemu_log(fmt, ##__VA_ARGS__);                                      \
        }                                                                      \
    } while (0)
#define _OUT_STRUCT(f, l, var) _OUT_ARRAY(f, l, &var, 1)
#define _OUT_PSTRUCT(f, l, var) _OUT_ARRAY(f, l, var, 1)
#define _OUT_ARRAY(f, l, var, count) \
    _OUT_BLOCK(f, l, var, sizeof(*(var)), count)
#define _OUT_BLOCK(f, l, var, size, count)                                     \
    do {                                                                       \
        _OUT(f, l, #var " ");                                                  \
        _OUT(f, l, "[size: %d, count: %d]\n", (int) (size), (int) (count));    \
        _OUT_MEMORY(f, l, var, size * count, 0, false, true);                  \
    } while (0)

#define _OUT_MEMORY(f, l, ptr, size, offset, with_offset, with_chars)          \
    do {                                                                       \
        uint8_t *_p = (uint8_t *) (ptr);                                       \
        uint32_t _s = (size);                                                  \
        int _line_size = 80;                                                   \
        char _line[_line_size + 1];                                            \
                                                                               \
        int _i, _rest, _str_offset;                                            \
        target_ulong _offset = (offset);                                       \
        for (_i = 0; _i < _s; _i += 0x10) {                                    \
            _str_offset = 0;                                                   \
            _rest = MIN(_s - _i, 0x10);                                        \
            memset(_line, ' ', _line_size);                                    \
                                                                               \
            if (with_offset) {                                                 \
                _str_offset += _dformat_offset(_line, _offset + _i);           \
            }                                                                  \
                                                                               \
            _dformat_mem(_line + _str_offset, _p + _i, _rest);                 \
            _str_offset += 0x10 * 3 + 1;                                       \
                                                                               \
            if (with_chars) {                                                  \
                _dformat_mem_chars(_line + _str_offset, _p + _i, _rest);       \
            }                                                                  \
                                                                               \
            _line[_line_size] = 0;                                             \
            _OUT(f, l, "%s\n", _line);                                         \
        }                                                                      \
    } while (0)

UNUSED
static int _dformat_mem(char *str, uint8_t *mem, int size)
{
    int i;
    for (i = 0; i < size; ++i) {
        sprintf(str + (i * 3), "%02x", mem[i]);
        str[i * 3 + 2] = ' ';
    }
    return size * 3 + 2;
}

UNUSED
static int _dformat_mem_chars(char *str, uint8_t *mem, int size)
{
    int i;
    for (i = 0; i < size; ++i) {
        str[i] = (mem[i] < 33 || mem[i] > 126) ? '.' : mem[i];
    }
    return size;
}

UNUSED
static int _dformat_offset(char *str, target_ulong offset)
{
    sprintf(str, TARGET_FMT_lx ": ", offset);
    int len = strlen(str);
    str[len] = ' ';
    return len;
}

#define DPRINT(fmt, ...) _OUT(NULL, true, fmt, ##__VA_ARGS__)
#define DPRINT_STRUCT(var) _OUT_STRUCT(NULL, true, var)
#define DPRINT_PSTRUCT(var) _OUT_PSTRUCT(NULL, true, var)
#define DPRINT_ARRAY(var, count) _OUT_ARRAY(NULL, true, var, count)
#define DPRINT_BLOCK(var, size, count) \
    _OUT_BLOCK(NULL, true, var, size, count)
#define DPRINT_MEMORY(ptr, size, offset, with_offset, with_chars) \
    _OUT_MEMORY(NULL, true, ptr, size, offset, with_offset, with_chars)

#define FPRINT(file, fmt, ...) _OUT(file, false, fmt, ##__VA_ARGS__)
#define FPRINT_STRUCT(file, var) _OUT_STRUCT(file, false, var)
#define FPRINT_PSTRUCT(file, var) _OUT_PSTRUCT(file, false, var)
#define FPRINT_ARRAY(file, var, count) _OUT_ARRAY(file, false, var, count)
#define FPRINT_BLOCK(file, var, size, count) \
    _OUT_BLOCK(file, false, var, size, count)
#define FPRINT_MEMORY(file, ptr, size, offset, with_offset, with_chars) \
    _OUT_MEMORY(file, false, ptr, size, offset, with_offset, with_chars)

#define DBG_RVMEM(cpu, addr, size)                                             \
    ({                                                                         \
        int _size = (size);                                                    \
        uint8_t *_buf = g_new0(uint8_t, _size);                                \
        if (cpu_memory_rw_debug(cpu, addr, _buf, _size, 0) != 0) {             \
            memset(_buf, 0, _size);                                            \
        }                                                                      \
        _buf;                                                                  \
    })

#define DPRINT_VMEMORY(cpu, addr, size, with_chars)                            \
    do {                                                                       \
        target_ulong _addr = (addr);                                           \
        UNUSED int __size = (size);                                            \
        uint8_t *_mem = DBG_RVMEM(cpu, _addr, __size);                         \
        DPRINT_MEMORY(_mem, __size, _addr, true, with_chars);                  \
        g_free(_mem);                                                          \
    } while (0)

#define CAT(a, ...) a ## __VA_ARGS__
#define EAT(...)
#define EXPAND(...) __VA_ARGS__
#define _IF(c) glue(_IF_, c)
#define _IF_1(...) __VA_ARGS__ EAT
#define _IF_0(...) EXPAND

#define COMPL(x) glue(COMPL_, x)
#define COMPL_1 0
#define COMPL_0 1

#define CHECK_N(x, n, ...) n
#define CHECK(...) CHECK_N(__VA_ARGS__, 0)
#define PROBE(x) x, 1

#define NOT(x) CHECK(glue(NOT_, x))
#define NOT_0 PROBE(~)
#define BOOL(x) COMPL(NOT(x))

#define IF(c) _IF(BOOL(c))

#define IS_EMPTY(x) CHECK(CAT(IS_EMPTY_, x))
#define IS_EMPTY_ PROBE(~)

#define EMPTY()
#define DEFER(id) id EMPTY()
#define OBSTRUCT(id) id DEFER(EMPTY)()

#define  EVAL(...) EVAL1(EVAL1(EVAL1(EVAL1(EVAL1(__VA_ARGS__)))))
#define EVAL1(...) EVAL2(EVAL2(EVAL2(EVAL2(EVAL2(__VA_ARGS__)))))
#define EVAL2(...) EVAL3(EVAL3(EVAL3(EVAL3(EVAL3(__VA_ARGS__)))))
#define EVAL3(...) EVAL4(EVAL4(EVAL4(EVAL4(EVAL4(__VA_ARGS__)))))
#define EVAL4(...) EVAL5(EVAL5(EVAL5(EVAL5(EVAL5(__VA_ARGS__)))))
#define EVAL5(...) __VA_ARGS__

#define TUPLE(...) (__VA_ARGS__)
#define TUPLE_N(typle, N) glue(ARG_, N)typle
#define ARG_0(x, ...) x
#define ARG_1(_0, x, ...) x
#define ARG_2(_0, _1, x, ...) x
#define ARG_3(_0, _1, _2, x, ...) x

#define FOREACH(macro, ...) EVAL(FOREACH_(macro, __VA_ARGS__))
#define FOREACH_(macro, x, ...)                                                \
    IF(IS_EMPTY(x))                                                            \
    () /* stop */                                                              \
    (                                                                          \
        macro(x);                                                              \
        OBSTRUCT(FOREACH_INDIRECT)()(macro, __VA_ARGS__)                       \
    )
#define FOREACH_INDIRECT() FOREACH_

#define FOREACH_WITH(macro, arg, ...) \
    EVAL(FOREACH_WITH_(macro, arg, __VA_ARGS__))
#define FOREACH_WITH_(macro, arg, x, ...)                                      \
    IF(IS_EMPTY(x))                                                            \
    () /* stop */                                                              \
    (                                                                          \
        macro(x, arg);                                                         \
        OBSTRUCT(FOREACH_WITH_INDIRECT)()(macro, arg, __VA_ARGS__)             \
    )
#define FOREACH_WITH_INDIRECT(...) FOREACH_WITH_

#define REFLECTION_PRINT(field, t) do {                                        \
    uint32_t _offset = (uint32_t) offsetof(TUPLE_N(t, 0), field);              \
    uint32_t _size = (uint32_t) sizeof_field(TUPLE_N(t, 0), field);            \
    int _str_size = 80;                                                        \
    char _str[_str_size + 1];                                                  \
    memset(_str, ' ', _str_size);                                              \
    sprintf(_str + 60, ":%u", _offset);                                        \
    uint8_t *_ptr = (uint8_t *) (TUPLE_N(t, 1));                               \
    uint64_t _value = 0L;                                                      \
    switch (_size) {                                                           \
    case 1:                                                                    \
        _value = (uint64_t) ((uint8_t *) (_ptr + _offset))[0];                 \
        sprintf(_str, "    t1 " #field " = 0x%llx;", _value);                  \
        break;                                                                 \
    case 2:                                                                    \
        _value = (uint64_t) ((uint16_t *) (_ptr + _offset))[0];                \
        sprintf(_str, "    t2 " #field " = 0x%llx;", _value);                  \
        break;                                                                 \
    case 4:                                                                    \
        _value = (uint64_t) ((uint32_t *) (_ptr + _offset))[0];                \
        sprintf(_str, "    t4 " #field " = 0x%llx;", _value);                  \
        break;                                                                 \
    case 8:                                                                    \
        _value = (uint64_t) ((uint64_t *) (_ptr + _offset))[0];                \
        sprintf(_str, "    t8 " #field " = 0x%llx;", _value);                  \
        break;                                                                 \
    default:                                                                   \
        sprintf(_str, "    t%u " #field " = [...];", _size);                   \
        break;                                                                 \
    }                                                                          \
    _str[strlen(_str)] = ' ';                                                  \
    _str[_str_size] = 0;                                                       \
    fprintf(TUPLE_N(t, 2), "%s\n", _str);                                      \
} while (0)

#define REFLECTION(stct, ptr, file, ...) do {                                  \
    fprintf(file, "struct " #stct " { sizeof: %llu\n", sizeof(stct));          \
    FOREACH_WITH(REFLECTION_PRINT, (stct, ptr, file), __VA_ARGS__);            \
    fprintf(file, "}\n");                                                      \
    fflush(file);                                                              \
} while (0)

#endif
