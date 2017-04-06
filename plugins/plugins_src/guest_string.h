#ifndef GUEST_STRING_H
#define GUEST_STRING_H

char *guest_strdup(CPUArchState *env, target_ulong ptr);
wchar_t *guest_strdupw(CPUArchState *env, target_ulong ptr, target_ulong *len);
target_ulong guest_read_tl(CPUArchState *env, target_ulong ptr);

#endif
