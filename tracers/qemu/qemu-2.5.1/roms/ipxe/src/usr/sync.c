/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stddef.h>
#include <ipxe/job.h>
#include <ipxe/monojob.h>
#include <ipxe/pending.h>
#include <usr/sync.h>

/** @file
 *
 * Wait for pending operations to complete
 *
 */

/**
 * Report progress
 *
 * @v intf		Interface
 * @v progress		Progress report to fill in
 * @ret ongoing_rc	Ongoing job status code (if known)
 */
static int sync_progress ( struct interface *intf,
			   struct job_progress *progress __unused ) {

	/* Terminate successfully if no pending operations remain */
	if ( ! have_pending() )
		intf_close ( intf, 0 );

	return 0;
}

/** Synchroniser interface operations */
static struct interface_operation sync_intf_op[] = {
	INTF_OP ( job_progress, struct interface *, sync_progress ),
};

/** Synchroniser interface descriptor */
static struct interface_descriptor sync_intf_desc =
	INTF_DESC_PURE ( sync_intf_op );

/** Synchroniser */
static struct interface sync_intf = INTF_INIT ( sync_intf_desc );

/**
 * Wait for pending operations to complete
 *
 * @v timeout		Timeout period, in ticks (0=indefinite)
 * @ret rc		Return status code
 */
int sync ( unsigned long timeout ) {

	/* Attach synchroniser and wait for completion */
	intf_plug_plug ( &monojob, &sync_intf );
	return monojob_wait ( NULL, timeout );
}
