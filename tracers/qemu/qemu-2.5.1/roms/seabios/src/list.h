#ifndef __LIST_H
#define __LIST_H

#include "types.h" // container_of


/****************************************************************
 * hlist - Double linked lists with a single pointer list head
 ****************************************************************/

struct hlist_node {
    struct hlist_node *next, **pprev;
};

struct hlist_head {
    struct hlist_node *first;
};

static inline int
hlist_empty(const struct hlist_head *h)
{
    return !h->first;
}

static inline void
hlist_del(struct hlist_node *n)
{
    struct hlist_node *next = n->next;
    struct hlist_node **pprev = n->pprev;
    *pprev = next;
    if (next)
        next->pprev = pprev;
}

static inline void
hlist_add(struct hlist_node *n, struct hlist_node **pprev)
{
    struct hlist_node *next = *pprev;
    n->pprev = pprev;
    n->next = next;
    if (next)
        next->pprev = &n->next;
    *pprev = n;
}

static inline void
hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
    hlist_add(n, &h->first);
}

static inline void
hlist_add_before(struct hlist_node *n, struct hlist_node *next)
{
    hlist_add(n, next->pprev);
}

static inline void
hlist_add_after(struct hlist_node *n, struct hlist_node *prev)
{
    hlist_add(n, &prev->next);
}

#define hlist_for_each_entry(pos, head, member)                         \
    for (pos = container_of((head)->first, typeof(*pos), member)        \
         ; pos != container_of(NULL, typeof(*pos), member)              \
         ; pos = container_of(pos->member.next, typeof(*pos), member))

#define hlist_for_each_entry_safe(pos, n, head, member)                 \
    for (pos = container_of((head)->first, typeof(*pos), member)        \
         ; pos != container_of(NULL, typeof(*pos), member)              \
             && ({ n = pos->member.next; 1; })                          \
         ; pos = container_of(n, typeof(*pos), member))

#define hlist_for_each_entry_pprev(pos, pprev, head, member)            \
    for (pprev = &(head)->first                                         \
         ; *pprev && ({ pos=container_of(*pprev, typeof(*pos), member); 1; }) \
         ; pprev = &(*pprev)->next)


#endif // list.h
