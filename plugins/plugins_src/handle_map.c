#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "handle_map.h"

#include "uthash.h"

typedef struct HMKey {
    uint64_t handle;
    uint64_t context;
} HMKey;

typedef struct HMItem {
    HMKey key;
    void *opaque;
    UT_hash_handle hh;
} HMItem;

struct HandleMap {
    HMItem *handles;
};

static HMItem *find_item(HandleMap *hm, uint64_t handle, uint64_t context)
{
    HMKey key = { .handle = handle, .context = context };
    HMItem *p = NULL;
    HASH_FIND(hh, hm->handles, &key, sizeof(key), p);
    return p;
}

void hm_insert(HandleMap *hm, uint64_t handle, uint64_t context, void *opaque)
{
    HMItem *item = find_item(hm, handle, context);
    if (item) {
        HASH_DEL(hm->handles, item);
        g_free(item->opaque);
        g_free(item);
    }
    item = g_new0(HMItem, 1);
    *item = (HMItem) {
        .key = (HMKey) {. handle = handle, .context = context },
        .opaque = opaque
    };
    HASH_ADD(hh, hm->handles, key, sizeof(HMKey), item);
}

void hm_erase(HandleMap *hm, uint64_t handle, uint64_t context)
{
    HMItem *h = find_item(hm, handle, context);
    if (h) {
        HASH_DEL(hm->handles, h);
        g_free(h->opaque);
        g_free(h);
    }
}

void *hm_find(HandleMap *hm, uint64_t handle, uint64_t context)
{
    HMItem *h = find_item(hm, handle, context);
    if (h) {
        return h->opaque;
    }
    return NULL;
}

HandleMap *hm_new(void)
{
    HandleMap *map = g_malloc0(sizeof(HandleMap));
    return map;
}

void hm_free(HandleMap *hm)
{
    HMItem *item, *tmp;
    HASH_ITER(hh, hm->handles, item, tmp) {
        HASH_DEL(hm->handles, item);
        g_free(item->opaque);
        g_free(item);
    }
}

void hm_iterate(HandleMap *hm, void (*func)(void *, uint64_t, uint64_t, void *), void *mon)
{
    HMItem *item, *tmp;
    HASH_ITER(hh, hm->handles, item, tmp) {
        (*func)(mon, item->key.handle, item->key.context, item->opaque);
    }
}