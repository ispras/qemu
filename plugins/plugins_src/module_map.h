#ifndef MODULES_MAP_H
#define MODULES_MAP_H

typedef struct ModuleMap ModuleMap;
typedef void (*MMIterator)(void *, uint64_t, uint64_t, void *);

ModuleMap *mm_new(void);
void mm_free(ModuleMap *mm);

/** Inserts new module and associates pointer to data with it. 
 *  Data is owned and freed by the map.
 */
void mm_insert(ModuleMap *mm, uint64_t address, uint64_t size, uint64_t context, void *opaque);
bool mm_erase(ModuleMap *mm, uint64_t address, uint64_t context);
bool mm_erase_map(ModuleMap *mm, uint64_t address, uint64_t context, void *opaque);
int mm_erase_range(ModuleMap *mm, uint64_t address, uint64_t length, uint64_t context);
void mm_iterate(ModuleMap *hm, MMIterator func, void *mon);

/** Returns pointer associated with the map. */
void *mm_find(ModuleMap *mm, uint64_t address, uint64_t context);

#endif
