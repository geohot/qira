/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * @file
 *
 * Pooled connections
 *
 */

#include <assert.h>
#include <ipxe/pool.h>

/**
 * Recycle this connection after closing
 *
 * @v intf		Data transfer interface
 */
void pool_recycle ( struct interface *intf ) {

	intf_poke ( intf, pool_recycle );
}

/**
 * Reopen a defunct connection
 *
 * @v intf		Data transfer interface
 */
void pool_reopen ( struct interface *intf ) {

	intf_poke ( intf, pool_reopen );
}

/**
 * Add connection to pool
 *
 * @v pool		Pooled connection
 * @v list		List of pooled connections
 * @v expiry		Expiry time
 */
void pool_add ( struct pooled_connection *pool, struct list_head *list,
		unsigned long expiry ) {

	/* Sanity check */
	assert ( list_empty ( &pool->list ) );
	assert ( ! timer_running ( &pool->timer ) );

	/* Add to list of pooled connections */
	list_add_tail ( &pool->list, list );

	/* Start expiry timer */
	start_timer_fixed ( &pool->timer, expiry );
}

/**
 * Remove connection from pool
 *
 * @v pool		Pooled connection
 */
void pool_del ( struct pooled_connection *pool ) {

	/* Remove from list of pooled connections */
	list_del ( &pool->list );
	INIT_LIST_HEAD ( &pool->list );

	/* Stop expiry timer */
	stop_timer ( &pool->timer );

	/* Mark as a freshly recycled connection */
	pool->flags = POOL_RECYCLED;
}

/**
 * Close expired pooled connection
 *
 * @v timer		Expiry timer
 * @v over		Failure indicator
 */
void pool_expired ( struct retry_timer *timer, int over __unused ) {
	struct pooled_connection *pool =
		container_of ( timer, struct pooled_connection, timer );

	/* Sanity check */
	assert ( ! list_empty ( &pool->list ) );

	/* Remove from connection pool */
	list_del ( &pool->list );
	INIT_LIST_HEAD ( &pool->list );

	/* Close expired connection */
	pool->expired ( pool );
}
