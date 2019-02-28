#ifndef INSTRUMENT_H
#define INSTRUMENT_H

#ifdef CONFIG_PLUGINS

bool plugins_need_before_insn(target_ulong pc, CPUState *cpu);
void plugins_instrument_before_insn(target_ulong pc, CPUState *cpu);

#else /* CONFIG_PLUGINS */

inline bool plugins_need_before_insn(target_ulong pc, CPUState *cpu)
{
    return false;
}
inline void plugins_instrument_before_insn(target_ulong pc, CPUState *cpu) {}

#endif /* CONFIG_PLUGINS */

#endif /* INSTRUMENT_H */
