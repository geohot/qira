/*
 * <malloc.c>
 *
 * Open Hack'Ware BIOS: memory management
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* functions prototypes are here */
/* NULL is declared here */
#include <stdlib.h>
/* memcpy is defined here */
#include <string.h>
/* set_errno is defined here */
#include <errno.h>

//#define DEBUG_MEMOPS
#if defined (DEBUG_MEMOPS)
#define MEMOPS_PRINTF(fmt, args...) do { dprintf(fmt , ##args); } while (0)
#else
#define MEMOPS_PRINTF(fmt, args...) do { } while (0)
#endif

#define unused __attribute__ (( unused ))

/* XXX: TODO: put this elsewhere */
void *page_get (int nb_pages);
void page_put (void *addr, int nb_pages);

/* XXX: TOTO: put this elsewhere */
#if defined (__i386__)
#define NATURAL_ALIGN_BITS 2
#define PAGE_BITS 12
#define __32_BITS 1
#elif defined (__powerpc__) || defined (_ARCH_PPC)
#define NATURAL_ALIGN_BITS 2
#define PAGE_BITS 12
#define __32_BITS 1
#elif defined (__x86_64__)
#define NATURAL_ALIGN_BITS 3
#define PAGE_BITS 12
#else
#error "Unsupported architecture"
#endif
#define PAGE_SIZE (1 << PAGE_BITS)
#define PAGE(addr) ((void *)((unsigned long)(addr) & ~(PAGE_SIZE - 1)))


#define MIN_ELEM_BITS (NATURAL_ALIGN_BITS + 1)
#define MIN_ELEM_SIZE (1 << (MIN_ELEM_BITS))
#define MAX_ELEM_BITS (PAGE_BITS)
#define MAX_ELEM_SIZE (1 << (MAX_ELEM_BITS - 1))
#define POOL_MAX ((MAX_ELEM_BITS) - (MIN_ELEM_BITS))
#define CACHE_MAX 16

typedef struct free_slot_t free_slot_t;
struct free_slot_t {
    struct free_slot_t *next;
};

typedef struct page_descr_t page_descr_t;
struct page_descr_t {
    struct page_descr_t *next;
    struct page_descr_t *prev;
    void *addr;
    unsigned long nb;
};

/*
 * This points to the first descriptor page where stand:
 * - 1 descriptor for this page.
 * - 1 decriptor pages list head.
 * - POOL_MAX pool descriptors list heads.
 * - CACHE_MAX page cache entries list heads.
 */
static void *malloc_base;

/* Shared functions */
static inline page_descr_t *main_descr_get (void)
{
    return (page_descr_t *)malloc_base + 1;
}

static inline page_descr_t *pool_head_get (int pool_idx)
{
    return main_descr_get() + 1 + pool_idx;
}

static inline page_descr_t *cache_head_get (int cache_idx)
{
    return pool_head_get(POOL_MAX) + 1 + cache_idx;
}

static void free_slots_init (void *page, int incr, int size)
{
    free_slot_t *slot, *next;
    
    for (slot = page;
         slot < (free_slot_t *)((char *)page + size); slot = next) {
        next = (void *)((char *)slot + incr);
        slot->next = next;
    }
    slot = (void *)((char *)slot - incr);
    slot->next = NULL;
}

static page_descr_t *descr_find_free (page_descr_t *head_descr,
                                      page_descr_t *skip_descr)
{
    page_descr_t *cur_descr, *best;
    unsigned long max_used;

    /* Try to always return the page with the less free slots to reduce
     * memory fragmentation.
     */
    max_used = 0;
    best = NULL;
    for (cur_descr = head_descr->next;
         cur_descr != head_descr; cur_descr = cur_descr->next) {
        if (cur_descr != skip_descr && cur_descr->addr != NULL &&
            cur_descr->nb >= max_used) {
            max_used = cur_descr->nb;
            best = cur_descr;
        }
    }

    return best;
}

/* Page descriptors management */
static void page_descr_free (page_descr_t *head_descr)
{
    head_descr->next->prev = head_descr->prev;
    head_descr->prev->next = head_descr->next;
    page_put(head_descr, 1);
}

static page_descr_t *page_descr_get (void)
{
    page_descr_t *main_descr, *head_descr, *page_descr;
    free_slot_t *first_free;

    main_descr = main_descr_get();
    head_descr = main_descr->addr;
    first_free = head_descr->addr;
    if (first_free == NULL) {
        /* Find a page with free descriptors */
        head_descr = descr_find_free(main_descr, NULL);
        if (head_descr != NULL) {
            /* Get the first free slot */
            first_free = head_descr->addr;
        } else {
            /* Allocate a new page */
            head_descr = page_get(1);
            if (head_descr == NULL) {
                MEMOPS_PRINTF("%s: cannot get new head descriptor\n",
                              __func__);
                return NULL;
            }
            /* Initialise free slots */
            free_slots_init(head_descr, sizeof(page_descr_t), PAGE_SIZE);
            /* Initialise page head descriptor */
            head_descr->addr = head_descr + 1;
            head_descr->nb = 0;
            head_descr->next = main_descr;
            head_descr->prev = main_descr->prev;
            /* Update main descriptor */
            main_descr->prev->next = head_descr;
            main_descr->prev = head_descr;
            main_descr->nb++;
            first_free = head_descr->addr;
        }
        main_descr->addr = head_descr;
    }
    head_descr->addr = first_free->next;
    if (head_descr->nb == 0)
        main_descr->nb--;
    head_descr->nb++;
    page_descr = (page_descr_t *)first_free;
    page_descr->prev = NULL;
    page_descr->next = NULL;
    page_descr->addr = NULL;
    page_descr->nb = 0;
    
    return page_descr;
}

static void page_descr_put (page_descr_t *page_descr)
{
    page_descr_t *main_descr, *head_descr, *next_descr, *free_descr;
    free_slot_t *first_free, *next_free;
    
    head_descr = PAGE(page_descr);
    /* Mark this descriptor as free */
    next_free = head_descr->addr;
    first_free = (free_slot_t *)page_descr;
    first_free->next = next_free;
    /* Update page descriptor */
    head_descr->addr = first_free;
    head_descr->nb--;
    main_descr = main_descr_get();
    if (head_descr->nb == 0) {
        /* Try to free this page */
        if (main_descr->addr == head_descr ||
            main_descr->addr == NULL ||
            main_descr->nb > 0)
            free_descr = descr_find_free(main_descr, head_descr);
        else
            free_descr = main_descr->addr;
        if (free_descr != NULL) {
            /* Update main descriptor */
            page_descr_free(head_descr);
            main_descr->addr = free_descr;
        } else {
            main_descr->addr = head_descr;
            main_descr->nb++;
        }
    } else if (next_free == NULL) {
        free_descr = head_descr;
        for (head_descr = main_descr->next;
             main_descr->nb > 0 && head_descr != main_descr;
             head_descr = next_descr) {
            next_descr = head_descr->next;
            if (head_descr->nb == 0) {
                if (main_descr->addr == head_descr)
                    main_descr->addr = NULL;
                page_descr_free(head_descr);
                main_descr->nb--;
            }
        }
        if (main_descr->addr == NULL)
            main_descr->addr = free_descr;
    }
}

/* Page cache management */
static inline unsigned long cache_idx (void *addr)
{
    return ((unsigned long)addr >> PAGE_BITS) & (CACHE_MAX - 1);
}

static inline unsigned long page_cache_pool_idx (page_descr_t *cache_descr)
{
    return (cache_descr->nb & 0xF);
}

static inline page_descr_t *page_cache_page_descr (page_descr_t *cache_descr)
{
    return (page_descr_t *)(cache_descr->nb & ~0xF);
}

static int page_cache_add_page (page_descr_t *page_descr, int pool_idx)
{
    page_descr_t *main_descr, *cache_head, *cache_descr;

    main_descr = main_descr_get();
    cache_head = cache_head_get(cache_idx(page_descr->addr));
    cache_descr = page_descr_get();
    if (cache_descr == NULL) {
        MEMOPS_PRINTF("%s: cannot get cache page\n", __func__);
        return -1;
    }
    cache_descr->nb = pool_idx | (unsigned long)page_descr;
    cache_descr->prev = cache_head;
    cache_descr->next = cache_head->next;
    cache_descr->addr = page_descr->addr;
    cache_head->next->prev = cache_descr;
    cache_head->next = cache_descr;

    return 0;
}

static page_descr_t *page_cache_get_descr (void *addr)
{
    page_descr_t *main_descr, *cache_head, *cache_descr;

    main_descr = main_descr_get();
    cache_head = cache_head_get(cache_idx(addr));
    for (cache_descr = cache_head->next;
         cache_descr != cache_head; cache_descr = cache_descr->next) {
        if (cache_descr->addr == addr) {
            return cache_descr;
        }
    }
    MEMOPS_PRINTF("%s: cannot get cache page descr\n", __func__);

    return NULL;
}

static void page_cache_remove_descr (page_descr_t *cache_descr)
{
    cache_descr->next->prev = cache_descr->prev;
    cache_descr->prev->next = cache_descr->next;
    page_descr_put(cache_descr);
}

/* Allocation by pool (size <= PAGE_SIZE / 2) */
static void pool_descr_free (page_descr_t *cache_descr,
                             page_descr_t *pool_descr)
{
    page_put(PAGE(pool_descr->addr), 1);
    page_cache_remove_descr(cache_descr);
    pool_descr->next->prev = pool_descr->prev;
    pool_descr->prev->next = pool_descr->next;
    page_descr_put(pool_descr);
}

static void *pool_malloc (int pool_idx)
{
    page_descr_t *main_descr, *pool_head, *pool_descr;
    free_slot_t *first_free, *next_free;

    main_descr = main_descr_get();
    pool_head = pool_head_get(pool_idx);
    pool_descr = pool_head->addr;
    if (pool_descr == NULL || pool_descr->addr == NULL) {
        pool_descr = descr_find_free(pool_head, NULL);
        if (pool_descr == NULL) {
            pool_descr = page_descr_get();
            if (pool_descr == NULL) {
                MEMOPS_PRINTF("%s: cannot get pool descr\n", __func__);
                return NULL;
            }
            pool_descr->addr = page_get(1);
            if (pool_descr->addr == NULL) {
                MEMOPS_PRINTF("%s: cannot allocate new page\n", __func__);
                page_descr_put(pool_descr);
                return NULL;
            }
            if (page_cache_add_page(pool_descr, pool_idx) < 0) {
                MEMOPS_PRINTF("%s: cannot add new page to cache\n", __func__);
                page_put(pool_descr->addr, 1);
                page_descr_put(pool_descr);
                return NULL;
            }
            free_slots_init(pool_descr->addr,
                            1 << (MIN_ELEM_BITS + pool_idx), PAGE_SIZE);
            pool_descr->nb = 0;
            pool_descr->prev = pool_head->prev;
            pool_descr->next = pool_head;
            pool_head->prev->next = pool_descr;
            pool_head->prev = pool_descr;
            pool_head->nb++;
        }
        pool_head->addr = pool_descr;
    }
    first_free = pool_descr->addr;
    next_free = first_free->next;
    //    memset(first_free, 0, 1 << (MIN_ELEM_BITS + pool_idx));
    pool_descr->addr = next_free;
    if (pool_descr->nb == 0)
        pool_head->nb--;
    pool_descr->nb++;

    return first_free;
}

unused static void pool_free (page_descr_t *cache_descr, void *area)
{
    page_descr_t *pool_head, *pool_descr, *pool_next, *free_pool;
    free_slot_t *first_free, *next_free;
    unsigned long size, pool_idx;
    
    pool_descr = page_cache_page_descr(cache_descr);
    first_free = area;
    next_free = pool_descr->addr;
    pool_idx = page_cache_pool_idx(cache_descr);
    size = 1 << (MIN_ELEM_BITS + pool_idx);
    first_free->next = next_free;
    pool_descr->addr = first_free;
    pool_descr->nb--;
    pool_head = pool_head_get(pool_idx);
    if (pool_descr->nb == 0) {
        if (pool_head->addr == pool_descr ||
            pool_head->addr == NULL ||
            pool_head->nb > 0)
            free_pool = descr_find_free(pool_head, pool_descr);
        else
            free_pool = pool_head->addr;
        if (free_pool != NULL) {
            /* Free page & descriptor */
            pool_descr_free(cache_descr, pool_descr);
            pool_head->addr = free_pool;
        } else {
            pool_head->addr = pool_descr;
            pool_head->nb++;
        }
    } else if (next_free == NULL) {
        free_pool = pool_descr;
        for (pool_descr = pool_head->next;
             pool_head->nb > 0 && pool_descr != pool_head;
             pool_descr = pool_next) {
            pool_next = pool_descr->next;
            if (pool_descr->nb == 0) {
                if (pool_head->addr == pool_descr)
                    pool_head->addr = NULL;
                cache_descr = page_cache_get_descr(PAGE(pool_descr->addr));
                if (cache_descr != NULL) {
                    pool_descr_free(cache_descr, pool_descr);
                    pool_head->nb--;
                } else {
                    /* Incoherency: what to do ? */
                }
            }
        }
        if (pool_head->addr == NULL)
            pool_head->addr = free_pool;
    }
}

/* Big area management (size > PAGE_SIZE / 2) */
static void *big_malloc (int nb_pages)
{
    page_descr_t *main_descr, *pool_head, *pool_descr;

    main_descr = main_descr_get();
    pool_head = pool_head_get(POOL_MAX);
    pool_descr = page_descr_get();
    if (pool_descr == NULL) {
        MEMOPS_PRINTF("%s: cannot get pool descr\n", __func__);
        return NULL;
    }
    pool_descr->addr = page_get(nb_pages);
    if (pool_descr->addr == NULL) {
        page_descr_put(pool_descr);
        MEMOPS_PRINTF("%s: cannot get page\n", __func__);
        return NULL;
    }
    if (page_cache_add_page(pool_descr, POOL_MAX) < 0) {
        page_put(pool_descr->addr, nb_pages);
        page_descr_put(pool_descr);
        MEMOPS_PRINTF("%s: cannot get add page to cache\n", __func__);
        return NULL;
    }
    pool_descr->prev = pool_head->prev;
    pool_descr->next = pool_head;
    pool_descr->nb = nb_pages;
    pool_head->prev->next = pool_descr;
    pool_head->prev = pool_descr;

    return pool_descr->addr;
}

static void big_free (page_descr_t *cache_descr)
{
    page_descr_t *pool_descr;

    pool_descr = page_cache_page_descr(cache_descr);
    if (pool_descr->addr != NULL && pool_descr->nb != 0) {
        page_put(pool_descr->addr, pool_descr->nb);
        pool_descr->next->prev = pool_descr->prev;
        pool_descr->prev->next = pool_descr->next;
        page_descr_put(pool_descr);
        page_cache_remove_descr(cache_descr);
    } else {
        MEMOPS_PRINTF("%s: ERROR %p %d\n",
                      __func__, pool_descr->addr, (int)pool_descr->nb);
    }
}

unused static void *big_realloc (page_descr_t *cache_descr, int new_size)
{
    void *new_area;
    page_descr_t *pool_descr;
    unsigned long new_nb;

    pool_descr = page_cache_page_descr(cache_descr);
    new_nb = (new_size + PAGE_SIZE - 1) / PAGE_SIZE;
    if (new_nb == pool_descr->nb) {
        new_area = cache_descr->addr;
    } else {
        new_area = big_malloc(new_size);
        memcpy(new_area, cache_descr->addr, pool_descr->nb * PAGE_SIZE);
        big_free(cache_descr);
    }

    return new_area;
}

/* Global entry points */
int page_descrs_init (void)
{
    page_descr_t *main_descr, *page_descr, *pool_head, *cache_head;
    int i;

    /* Allocate first descriptor page */
    malloc_base = page_get(1);
    if (malloc_base == NULL) {
        set_errno(ENOMEM);
        MEMOPS_PRINTF("%s: cannot get main descriptor\n", __func__);
        return -1;
    }
    /* Init free slots in this page */
    free_slots_init(malloc_base, sizeof(page_descr_t), PAGE_SIZE);
    /* Init main descriptor */
    page_descr = malloc_base;
    main_descr = main_descr_get();
    main_descr->addr = page_descr;
    main_descr->nb = 0;
    main_descr->next = page_descr;
    main_descr->prev = page_descr;
    page_descr->nb = 1;
    page_descr->addr = page_descr + 2;
    page_descr->next = main_descr;
    page_descr->prev = main_descr;
    /* Init pool lists heads */
    for (i = 0; i <= POOL_MAX; i++) {
        pool_head = page_descr_get();
        if (pool_head == NULL) {
            page_put(malloc_base, 1);
            malloc_base = NULL;
            MEMOPS_PRINTF("%s: cannot get pool descriptor %d\n", __func__, i);
            return -1;
        }
        pool_head->prev = pool_head;
        pool_head->next = pool_head;
        pool_head->addr = NULL;
    }
    /* Init page caches lists heads */
    for (i = 0; i < CACHE_MAX; i++) {
        cache_head = page_descr_get();
        if (cache_head == NULL) {
            page_put(malloc_base, 1);
            malloc_base = NULL;
            MEMOPS_PRINTF("%s: cannot get page cache descriptor %d\n",
                          __func__, i);
            return -1;
        }
        cache_head->prev = cache_head;
        cache_head->next = cache_head;
    }

    return 0;
}

static inline int get_pool_idx (size_t size)
{
    int pool_idx;
    
    pool_idx = 0;
    for (size /= MIN_ELEM_SIZE; size != 0; size = size / 2)
        pool_idx++;

    return pool_idx;
}

#if 1
void *malloc (size_t size)
{
    void *ret;
    int pool_idx;
    
    if (malloc_base == NULL || size == 0) {
        ret = NULL;
    } else if (size >= MAX_ELEM_SIZE) {
        ret = big_malloc((size + PAGE_SIZE - 1) / PAGE_SIZE);
    } else {
        if (size <= MIN_ELEM_SIZE)
            pool_idx = 0;
        else {
            pool_idx = get_pool_idx(size);
        }
        ret = pool_malloc(pool_idx);
    }
    if (ret != NULL)
        memset(ret, 0, size);
#if 0
    memory_dump();
    printf("%s(%d) => %p\n", __func__, size, ret);
#endif

    return ret;
}
#endif

#if 0
void free (void *area)
{
    page_descr_t *cache_descr;
    int pool_idx;

    if (malloc_base == NULL || area == NULL)
        return;
    cache_descr = page_cache_get_descr(PAGE(area));
    if (cache_descr != NULL) {
        pool_idx = page_cache_pool_idx(cache_descr);
        if (pool_idx == POOL_MAX) {
            big_free(cache_descr);
        } else {
            pool_free(cache_descr, area);
        }
    } else {
        /* Given area is not valid */
        MEMOPS_PRINTF("ERROR: area to free not found: %p\n", area);
    }
}
#endif

#if 0
void *realloc (void *area, size_t new_size)
{
    void *new_area;
    page_descr_t *pool_descr, *cache_descr;
    size_t size;
    int pool_idx, new_pool_idx;

    if (malloc_base == NULL || new_size == 0) {
        free(area);
        return NULL;
    }
    if (area == NULL)
        return malloc(new_size);
    cache_descr = page_cache_get_descr(PAGE(area));
    if (cache_descr == NULL) {
        /* Given area is not valid */
        return NULL;
    }
    pool_idx = page_cache_pool_idx(cache_descr);
    if (new_size >= MAX_ELEM_SIZE) {
        new_pool_idx = POOL_MAX;
        if (pool_idx == POOL_MAX)
            return big_realloc(cache_descr, new_size);
    } else {
        if (new_size <= MIN_ELEM_SIZE)
            new_pool_idx = 0;
        else
            new_pool_idx = get_pool_idx(size);
        if (pool_idx == new_pool_idx)
            return area;
    }
    /* Common case: alloc, copy & free */
    if (new_pool_idx == POOL_MAX)
        new_area = big_malloc((new_size + PAGE_SIZE - 1) / PAGE_SIZE);
    else
        new_area = pool_malloc(new_pool_idx);
    if (new_area == NULL)
        return NULL;
    if (pool_idx == POOL_MAX) {
        pool_descr = page_cache_page_descr(cache_descr);
        size = pool_descr->nb * PAGE_SIZE;
    } else {
        size = MIN_ELEM_SIZE << pool_idx;
    }
    memcpy(new_area, area, size);
    if (pool_idx == POOL_MAX)
        big_free(cache_descr);
    else
        pool_free(cache_descr, area);
    
    return new_area;
}
#endif

void memory_dump (void)
{
#if defined (DEBUG_MEMOPS)
    page_descr_t *main_descr, *page_descr;
    page_descr_t *pool_head, *pool_descr, *cache_head, *cache_descr;
    int i, n;

    main_descr = main_descr_get();
    /* Dump descriptor pages */
    printf("Descriptor pages dump: %p max=%d %d pages with no alloc descrs\n",
           main_descr, (int)(PAGE_SIZE / sizeof(page_descr_t)), (int)main_descr->nb);
    n = 0;
    for (page_descr = main_descr->next;
         page_descr != main_descr; page_descr = page_descr->next) {
        printf("Descr %d : %p %p used: %d\n",
               n, page_descr, page_descr->addr, (int)page_descr->nb);
        n++;
    }
    /* Dump pool areas pages */
    for (i = 0; i < POOL_MAX; i++) {
        n = 0;
        pool_head = pool_head_get(i);
        printf("Pool %d %p\n", i, pool_head);
        for (pool_descr = pool_head->next;
             pool_descr != pool_head; pool_descr = pool_descr->next) {
            printf("Pool %d descr %d : %p %p used: %d size %d free: %p %p\n",
                   i, n, pool_descr, PAGE(pool_descr->addr), (int)pool_descr->nb,
                   1 << (MIN_ELEM_BITS + i), pool_descr->addr,
                   ((free_slot_t *)pool_descr->addr)->next);
            n++;
        }
        printf(" => %d pages allocated\n", n);
    }
#if 0
    /* Dump big area pages */
    printf("Pool %d\n", POOL_MAX);
    n = 0;
    pool_head = pool_head_get(POOL_MAX);
    for (pool_descr = pool_head->next;
         pool_descr != pool_head; pool_descr = pool_descr->next) {
        printf("Pool %d descr %d : %p nb pages: %d\n",
               POOL_MAX, n, pool_descr->addr, (int)pool_descr->nb);
        n++;
    }
    printf(" => %d pages allocated\n", n);
    /* Dump page cache */
    for (i = 0; i < CACHE_MAX; i++) {
        printf("Page cache 0x____%x___\n", i);
        n = 0;
        cache_head = cache_head_get(i);
        for (cache_descr = cache_head->next;
             cache_descr != cache_head; cache_descr = cache_descr->next) {
            pool_descr = page_cache_page_descr(cache_descr);
            printf("Cache %d descr %d : %p pool: %d descr: %p %p %d\n",
                   i, n, cache_descr->addr,
                   (int)page_cache_pool_idx(cache_descr),
                   pool_descr, pool_descr->addr, (int)pool_descr->nb);
            n++;
        }
        printf(" => %d pages allocated\n", n);
    }
#endif
#endif
}
