#ifndef _IPXE_LIST_H
#define _IPXE_LIST_H

/** @file
 *
 * Linked lists
 *
 * This linked list handling code is based on the Linux kernel's
 * list.h.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <assert.h>

/** A doubly-linked list entry (or list head) */
struct list_head {
	/** Next list entry */
	struct list_head *next;
	/** Previous list entry */
	struct list_head *prev;
};

/**
 * Initialise a static list head
 *
 * @v list		List head
 */
#define LIST_HEAD_INIT( list ) { &(list), &(list) }

/**
 * Declare a static list head
 *
 * @v list		List head
 */
#define LIST_HEAD( list ) \
	struct list_head list = LIST_HEAD_INIT ( list )

/**
 * Initialise a list head
 *
 * @v list		List head
 */
#define INIT_LIST_HEAD( list ) do {				\
	(list)->next = (list);					\
	(list)->prev = (list);					\
	} while ( 0 )

/**
 * Check a list entry or list head is valid
 *
 * @v list		List entry or head
 */
#define list_check( list ) ( {					\
	assert ( (list) != NULL );				\
	assert ( (list)->prev != NULL );			\
	assert ( (list)->next != NULL );			\
	assert ( (list)->next->prev == (list) );		\
	assert ( (list)->prev->next == (list) );		\
	} )

/**
 * Add a new entry to the head of a list
 *
 * @v new		New entry to be added
 * @v head		List head, or entry after which to add the new entry
 */
#define list_add( new, head ) do {				\
	list_check ( (head) );					\
	extern_list_add ( (new), (head) );			\
	list_check ( (head) );					\
	list_check ( (new) );					\
	} while ( 0 )
static inline void inline_list_add ( struct list_head *new,
				     struct list_head *head ) {
	struct list_head *prev = head;
	struct list_head *next = head->next;
	next->prev = (new);
	(new)->next = next;
	(new)->prev = prev;
	prev->next = (new);
}
extern void extern_list_add ( struct list_head *new,
			      struct list_head *head );

/**
 * Add a new entry to the tail of a list
 *
 * @v new		New entry to be added
 * @v head		List head, or entry before which to add the new entry
 */
#define list_add_tail( new, head ) do {				\
	list_check ( (head) );					\
	extern_list_add_tail ( (new), (head) );			\
	list_check ( (head) );					\
	list_check ( (new) );					\
	} while ( 0 )
static inline void inline_list_add_tail ( struct list_head *new,
					  struct list_head *head ) {
	struct list_head *prev = head->prev;
	struct list_head *next = head;
	next->prev = (new);
	(new)->next = next;
	(new)->prev = prev;
	prev->next = (new);
}
extern void extern_list_add_tail ( struct list_head *new,
				   struct list_head *head );

/**
 * Delete an entry from a list
 *
 * @v list		List entry
 *
 * Note that list_empty() on entry does not return true after this;
 * the entry is in an undefined state.
 */
#define list_del( list ) do {					\
	list_check ( (list) );					\
	inline_list_del ( (list) );				\
	} while ( 0 )
static inline void inline_list_del ( struct list_head *list ) {
	struct list_head *next = (list)->next;
	struct list_head *prev = (list)->prev;
	next->prev = prev;
	prev->next = next;
}
extern void extern_list_del ( struct list_head *list );

/**
 * Test whether a list is empty
 *
 * @v list		List head
 */
#define list_empty( list ) ( {					\
	list_check ( (list) );					\
	inline_list_empty ( (list) ); } )
static inline int inline_list_empty ( const struct list_head *list ) {
	return ( list->next == list );
}
extern int extern_list_empty ( const struct list_head *list );

/**
 * Test whether a list has just one entry
 *
 * @v list		List to test
 */
#define list_is_singular( list ) ( {				\
	list_check ( (list) );					\
	inline_list_is_singular ( (list) ); } )
static inline int inline_list_is_singular ( const struct list_head *list ) {
	return ( ( ! list_empty ( list ) ) && ( list->next == list->prev ) );
}
extern int extern_list_is_singular ( const struct list_head *list );

/**
 * Test whether an entry is the last entry in list
 *
 * @v list		List entry to test
 * @v head		List head
 */
#define list_is_last( list, head ) ( {				\
	list_check ( (list) );					\
	list_check ( (head) );					\
	inline_list_is_last ( (list), (head) ); } )
static inline int inline_list_is_last ( const struct list_head *list,
					const struct list_head *head ) {
	return ( list->next == head );
}
extern int extern_list_is_last ( const struct list_head *list,
				 const struct list_head *head );

/**
 * Cut a list into two
 *
 * @v new		A new list to contain all removed entries
 * @v list		An existing list
 * @v entry		An entry within the existing list
 *
 * All entries from @c list up to and including @c entry are moved to
 * @c new, which should be an empty list.  @c entry may be equal to @c
 * list, in which case no entries are moved.
 */
#define list_cut_position( new, list, entry ) do {		\
	list_check ( (new) );					\
	assert ( list_empty ( (new) ) );			\
	list_check ( (list) );					\
	list_check ( (entry) );					\
	extern_list_cut_position ( (new), (list), (entry) );	\
	} while ( 0 )
static inline void inline_list_cut_position ( struct list_head *new,
					      struct list_head *list,
					      struct list_head *entry ) {
	struct list_head *first = entry->next;

	if ( list != entry ) {
		new->next = list->next;
		new->next->prev = new;
		new->prev = entry;
		new->prev->next = new;
		list->next = first;
		list->next->prev = list;
	}
}
extern void extern_list_cut_position ( struct list_head *new,
				       struct list_head *list,
				       struct list_head *entry );

/**
 * Move all entries from one list into another list
 *
 * @v list		List of entries to add
 * @v entry		Entry after which to add the new entries
 *
 * All entries from @c list are inserted after @c entry.  Note that @c
 * list is left in an undefined state; use @c list_splice_init() if
 * you want @c list to become an empty list.
 */
#define list_splice( list, entry ) do {				\
	list_check ( (list) );					\
	list_check ( (entry) );					\
	extern_list_splice ( (list), (entry) );			\
	} while ( 0 )
static inline void inline_list_splice ( const struct list_head *list,
					struct list_head *entry ) {
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	if ( ! list_empty ( list ) ) {
		last->next = entry->next;
		last->next->prev = last;
		first->prev = entry;
		first->prev->next = first;
	}
}
extern void extern_list_splice ( const struct list_head *list,
				 struct list_head *entry );

/**
 * Move all entries from one list into another list
 *
 * @v list		List of entries to add
 * @v entry		Entry before which to add the new entries
 *
 * All entries from @c list are inserted before @c entry.  Note that @c
 * list is left in an undefined state; use @c list_splice_tail_init() if
 * you want @c list to become an empty list.
 */
#define list_splice_tail( list, entry ) do {			\
	list_check ( (list) );					\
	list_check ( (entry) );					\
	extern_list_splice_tail ( (list), (entry) );		\
	} while ( 0 )
static inline void inline_list_splice_tail ( const struct list_head *list,
					     struct list_head *entry ) {
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	if ( ! list_empty ( list ) ) {
		first->prev = entry->prev;
		first->prev->next = first;
		last->next = entry;
		last->next->prev = last;
	}
}
extern void extern_list_splice_tail ( const struct list_head *list,
				      struct list_head *entry );

/**
 * Move all entries from one list into another list and reinitialise empty list
 *
 * @v list		List of entries to add
 * @v entry		Entry after which to add the new entries
 *
 * All entries from @c list are inserted after @c entry.
 */
#define list_splice_init( list, entry ) do {			\
	list_check ( (list) );					\
	list_check ( (entry) );					\
	extern_list_splice_init ( (list), (entry) );		\
	} while ( 0 )
static inline void inline_list_splice_init ( struct list_head *list,
					     struct list_head *entry ) {
	list_splice ( list, entry );
	INIT_LIST_HEAD ( list );
}
extern void extern_list_splice_init ( struct list_head *list,
				      struct list_head *entry );

/**
 * Move all entries from one list into another list and reinitialise empty list
 *
 * @v list		List of entries to add
 * @v entry		Entry before which to add the new entries
 *
 * All entries from @c list are inserted before @c entry.
 */
#define list_splice_tail_init( list, entry ) do {		\
	list_check ( (list) );					\
	list_check ( (entry) );					\
	extern_list_splice_tail_init ( (list), (entry) );	\
	} while ( 0 )

static inline void inline_list_splice_tail_init ( struct list_head *list,
						  struct list_head *entry ) {
	list_splice_tail ( list, entry );
	INIT_LIST_HEAD ( list );
}
extern void extern_list_splice_tail_init ( struct list_head *list,
					   struct list_head *entry );

/**
 * Get the container of a list entry
 *
 * @v list		List entry
 * @v type		Containing type
 * @v member		Name of list field within containing type
 * @ret container	Containing object
 */
#define list_entry( list, type, member ) ( {			\
	list_check ( (list) );					\
	container_of ( list, type, member ); } )

/**
 * Get the container of the first entry in a list
 *
 * @v list		List head
 * @v type		Containing type
 * @v member		Name of list field within containing type
 * @ret first		First list entry, or NULL
 */
#define list_first_entry( list, type, member )			\
	( list_empty ( (list) ) ?				\
	  ( type * ) NULL :					\
	  list_entry ( (list)->next, type, member ) )

/**
 * Get the container of the last entry in a list
 *
 * @v list		List head
 * @v type		Containing type
 * @v member		Name of list field within containing type
 * @ret first		First list entry, or NULL
 */
#define list_last_entry( list, type, member )			\
	( list_empty ( (list) ) ?				\
	  ( type * ) NULL :					\
	  list_entry ( (list)->prev, type, member ) )

/**
 * Iterate over a list
 *
 * @v pos		Iterator
 * @v head		List head
 */
#define list_for_each( pos, head )					      \
	for ( list_check ( (head) ),					      \
	      pos = (head)->next;					      \
	      pos != (head);						      \
	      pos = (pos)->next )

/**
 * Iterate over entries in a list
 *
 * @v pos		Iterator
 * @v head		List head
 * @v member		Name of list field within iterator's type
 */
#define list_for_each_entry( pos, head, member )			      \
	for ( list_check ( (head) ),					      \
	      pos = list_entry ( (head)->next, typeof ( *pos ), member );     \
	      &pos->member != (head);					      \
	      pos = list_entry ( pos->member.next, typeof ( *pos ), member ) )

/**
 * Iterate over entries in a list in reverse order
 *
 * @v pos		Iterator
 * @v head		List head
 * @v member		Name of list field within iterator's type
 */
#define list_for_each_entry_reverse( pos, head, member )		      \
	for ( list_check ( (head) ),					      \
	      pos = list_entry ( (head)->prev, typeof ( *pos ), member );     \
	      &pos->member != (head);					      \
	      pos = list_entry ( pos->member.prev, typeof ( *pos ), member ) )

/**
 * Iterate over entries in a list, safe against deletion of the current entry
 *
 * @v pos		Iterator
 * @v tmp		Temporary value (of same type as iterator)
 * @v head		List head
 * @v member		Name of list field within iterator's type
 */
#define list_for_each_entry_safe( pos, tmp, head, member )		      \
	for ( list_check ( (head) ),					      \
	      pos = list_entry ( (head)->next, typeof ( *pos ), member ),     \
	      tmp = list_entry ( pos->member.next, typeof ( *tmp ), member ); \
	      &pos->member != (head);					      \
	      pos = tmp,						      \
	      tmp = list_entry ( tmp->member.next, typeof ( *tmp ), member ) )

/**
 * Iterate over entries in a list, starting after current position
 *
 * @v pos		Iterator
 * @v head		List head
 * @v member		Name of list field within iterator's type
 */
#define list_for_each_entry_continue( pos, head, member )		      \
	for ( list_check ( (head) ),					      \
	      pos = list_entry ( pos->member.next, typeof ( *pos ), member ); \
	      &pos->member != (head);					      \
	      pos = list_entry ( pos->member.next, typeof ( *pos ), member ) )

/**
 * Iterate over entries in a list in reverse, starting after current position
 *
 * @v pos		Iterator
 * @v head		List head
 * @v member		Name of list field within iterator's type
 */
#define list_for_each_entry_continue_reverse( pos, head, member )	      \
	for ( list_check ( (head) ),					      \
	      pos = list_entry ( pos->member.prev, typeof ( *pos ), member ); \
	      &pos->member != (head);					      \
	      pos = list_entry ( pos->member.prev, typeof ( *pos ), member ) )

/**
 * Test if list contains a specified entry
 *
 * @v entry		Entry
 * @v head		List head
 * @ret present		List contains specified entry
 */
#define list_contains( entry, head ) ( {			\
	list_check ( (head) );					\
	list_check ( (entry) );					\
	extern_list_contains ( (entry), (head) ); } )
static inline int inline_list_contains ( struct list_head *entry,
					 struct list_head *head ) {
	struct list_head *tmp;

	list_for_each ( tmp, head ) {
		if ( tmp == entry )
			return 1;
	}
	return 0;
}
extern int extern_list_contains ( struct list_head *entry,
				  struct list_head *head );

/**
 * Test if list contains a specified entry
 *
 * @v entry		Entry
 * @v head		List head
 * @ret present		List contains specified entry
 */
#define list_contains_entry( entry, head, member )		\
	list_contains ( &(entry)->member, (head) )

/**
 * Check list contains a specified entry
 *
 * @v entry		Entry
 * @v head		List head
 * @v member		Name of list field within iterator's type
 */
#define list_check_contains_entry( entry, head, member ) do {		      \
	assert ( list_contains_entry ( (entry), (head), member ) );	      \
	} while ( 0 )

#endif /* _IPXE_LIST_H */
