#ifndef _IPXE_POOL_H
#define _IPXE_POOL_H

/** @file
 *
 * Pooled connections
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/interface.h>
#include <ipxe/list.h>
#include <ipxe/retry.h>

/** A pooled connection */
struct pooled_connection {
	/** List of pooled connections
	 *
	 * Note that each connecton in the pool has a running expiry
	 * timer which holds a reference to the connection.  We
	 * therefore do not require the connection pool list to hold a
	 * reference for each pooled connection.
	 */
	struct list_head list;
	/** Expiry timer */
	struct retry_timer timer;
	/** Close expired pooled connection
	 *
	 * @v pool		Pooled connection
	 */
	void ( * expired ) ( struct pooled_connection *pool );
	/** Flags */
	unsigned int flags;
};

/** Pooled connection flags */
enum pooled_connection_flags {
	/** Connection should be recycled after closing */
	POOL_RECYCLABLE = 0x0001,
	/** Connection has been recycled */
	POOL_RECYCLED = 0x0002,
	/** Connection is known to be alive */
	POOL_ALIVE = 0x0004,
};

extern void pool_add ( struct pooled_connection *pool, struct list_head *list,
		       unsigned long expiry );
extern void pool_del ( struct pooled_connection *pool );
extern void pool_expired ( struct retry_timer *timer, int over );

/**
 * Initialise a pooled connection
 *
 * @v pool		Pooled connection
 * @v expired		Close expired pooled connection method
 * @v refcnt		Containing object reference counter
 */
static inline __attribute__ (( always_inline )) void
pool_init ( struct pooled_connection *pool,
	    void ( * expired ) ( struct pooled_connection *pool ),
	    struct refcnt *refcnt ) {

	INIT_LIST_HEAD ( &pool->list );
	timer_init ( &pool->timer, pool_expired, refcnt );
	pool->expired = expired;
}

/**
 * Mark pooled connection as recyclable
 *
 * @v pool		Pooled connection
 */
static inline __attribute__ (( always_inline )) void
pool_recyclable ( struct pooled_connection *pool ) {

	pool->flags |= POOL_RECYCLABLE;
}

/**
 * Mark pooled connection as alive
 *
 * @v pool		Pooled connection
 */
static inline __attribute__ (( always_inline )) void
pool_alive ( struct pooled_connection *pool ) {

	pool->flags |= POOL_ALIVE;
}

/**
 * Check if pooled connection is recyclable
 *
 * @v pool		Pooled connection
 * @ret recyclable	Pooled connection is recyclable
 */
static inline __attribute__ (( always_inline )) int
pool_is_recyclable ( struct pooled_connection *pool ) {

	return ( pool->flags & POOL_RECYCLABLE );
}

/**
 * Check if pooled connection is reopenable
 *
 * @v pool		Pooled connection
 * @ret reopenable	Pooled connection is reopenable
 */
static inline __attribute__ (( always_inline )) int
pool_is_reopenable ( struct pooled_connection *pool ) {

	/* A connection is reopenable if it has been recycled but is
	 * not yet known to be alive.
	 */
	return ( ( pool->flags & POOL_RECYCLED ) &
		 ( ! ( pool->flags & POOL_ALIVE ) ) );
}

extern void pool_recycle ( struct interface *intf );
#define pool_recycle_TYPE( object_type ) \
	typeof ( void ( object_type ) )

extern void pool_reopen ( struct interface *intf );
#define pool_reopen_TYPE( object_type ) \
	typeof ( void ( object_type ) )

#endif /* _IPXE_POOL_H */
