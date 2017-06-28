#ifndef HANDLES_MAP_H
#define HANDLES_MAP_H

typedef struct HandleMap HandleMap;

HandleMap *hm_new(void);
void hm_free(HandleMap *hm);

/** Inserts new handle and associates pointer to data with it. 
 *  Data is owned and freed by the map.
 */
void hm_insert(HandleMap *hm, uint64_t handle, uint64_t context, void *opaque);
void hm_erase(HandleMap *hm, uint64_t handle, uint64_t context);
/** Returns pointer to the stored data by the handle. */
void *hm_find(HandleMap *hm, uint64_t handle, uint64_t context);
void hm_iterate(HandleMap *hm, void (*func)(void *, uint64_t, uint64_t, void *), void *mon);

#endif