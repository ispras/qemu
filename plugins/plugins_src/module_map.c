#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "module_map.h"
#include "handle_map.h"
#include "monitor/monitor.h"

typedef struct MMKey {
    uint64_t address;
    uint64_t size;
} MMKey;

typedef GTree ModuleTree;

struct ModuleMap {
    // TODO: Use another hash container, without unused handle
    HandleMap *trees;
};

static gint compare(gconstpointer a, gconstpointer b, gpointer opaque)
{
    const MMKey *k1 = a;
    const MMKey *k2 = b;
    if (k1->address < k2->address) {
        return -1;
    } else if (k1->address > k2->address) {
        return 1;
    } else if (k1->size < k2->size) {
        return -1;
    } else {
        return k1->size > k2->size;
    }
}

/* Hack to remove found items */
typedef struct MMSearch {
    uint64_t address, length;
    const MMKey *key;
} MMSearch;

static gint search(gconstpointer a, gconstpointer b)
{
    const MMKey *k = a;
    MMSearch *s = (MMSearch*)b;
    if (s->address < k->address) {
        return -1;
    } else if (s->address < k->address + k->size) {
        s->key = k;
        return 0;
    } else {
        return 1;
    }
}

static gint search_range(gconstpointer a, gconstpointer b)
{
    const MMKey *k = a;
    MMSearch *s = (MMSearch*)b;
    if (s->address < k->address) {
        if (s->address + s->length > k->address) {
            s->key = k;
            return 0;
        }
        return -1;
    } else if (s->address < k->address + k->size) {
        s->key = k;
        return 0;
    } else {
        return 1;
    }
}

static ModuleTree *mm_get_context(ModuleMap *mm, uint64_t context)
{
    ModuleTree *tree = hm_find(mm->trees, 0, context);
    if (!tree) {
        tree = g_tree_new_full(compare, NULL, g_free, g_free);
        hm_insert(mm->trees, 0, context, tree);
    }
    return tree;
}

/*static gboolean mm_print_tree(gpointer k, gpointer v, gpointer d)
{
    MMKey *key = k;
    printf("(%"PRIx64"; %"PRIx64") ", key->address, key->size);
    return false;
}*/

void mm_insert(ModuleMap *mm, uint64_t address, uint64_t size, uint64_t context, void *opaque)
{
    ModuleTree *tree = mm_get_context(mm, context);
    MMKey *key = g_new0(MMKey, 1);
    key->address = address;
    key->size = size;
    g_tree_insert(tree, key, opaque);
    //printf("after insert %"PRIx64"\n", address);
    //g_tree_foreach(tree, mm_print_tree, NULL);
    //printf("\n");
}

bool mm_erase_map(ModuleMap *mm, uint64_t address, uint64_t context, void *opaque)
{
    ModuleTree *tree = mm_get_context(mm, context);
    MMSearch s = { .address = address };
    void *x = g_tree_search(tree, search, &s);
    assert(s.key && x == opaque);
    g_tree_remove(tree, s.key);
    return true;
}

bool mm_erase(ModuleMap *mm, uint64_t address, uint64_t context)
{
    ModuleTree *tree = mm_get_context(mm, context);
    MMSearch s = { .address = address };
    g_tree_search(tree, search, &s);
    if (s.key) {
        //printf("before erase %"PRIx64"\n", address);
        //g_tree_foreach(tree, mm_print_tree, NULL);
        //printf("\n");
        if (g_tree_remove(tree, s.key)) {
            return true;
        }
    }
    return false;
}

int mm_erase_range(ModuleMap *mm, uint64_t address, uint64_t length, uint64_t context)
{
    ModuleTree *tree = mm_get_context(mm, context);
    MMSearch s = { .address = address, .length = length };
    int count = 0;
    do {
        s.key = 0;
        g_tree_search(tree, search_range, &s);
        if (s.key) {
            g_tree_remove(tree, s.key);
            ++count;
        }
    } while (s.key);

    return count;
}

void *mm_find(ModuleMap *mm, uint64_t address, uint64_t context)
{
    MMSearch s = { .address = address };
    ModuleTree *tree = mm_get_context(mm, context);
    return g_tree_search(tree, search, &s);
}

ModuleMap *mm_new(void)
{
    ModuleMap *map = g_malloc0(sizeof(ModuleMap));
    // TODO: pass destructor to HM
    map->trees = hm_new();
    return map;
}

void mm_free(ModuleMap *mm)
{
    hm_free(mm->trees);
    g_free(mm);
}

/* This will be removed after creating Modules plugin */
static MMIterator iterator;

static gboolean mm_iterate_tree(gpointer k, gpointer v, gpointer d)
{
    Monitor *mon = d;
    iterator(mon, 0, 0, v);
    return false;
}

static void mm_iterate_context(void *m, uint64_t dummy, uint64_t context, void *opaque)
{
    ModuleTree *tree = opaque;
    Monitor *mon = m;
    monitor_printf(mon, "Modules for process 0x%"PRIx64"\n", context);
    g_tree_foreach(tree, mm_iterate_tree, mon);
}

void mm_iterate(ModuleMap *mm, MMIterator func, void *mon)
{
    iterator = func;
    hm_iterate(mm->trees, mm_iterate_context, mon);
}
