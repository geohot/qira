/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/process.h>
#include <ipxe/socket.h>
#include <ipxe/resolv.h>

/** @file
 *
 * Name resolution
 *
 */

/***************************************************************************
 *
 * Name resolution interfaces
 *
 ***************************************************************************
 */

/**
 * Name resolved
 *
 * @v intf		Object interface
 * @v sa		Completed socket address (if successful)
 */
void resolv_done ( struct interface *intf, struct sockaddr *sa ) {
	struct interface *dest;
	resolv_done_TYPE ( void * ) *op =
		intf_get_dest_op ( intf, resolv_done, &dest );
	void *object = intf_object ( dest );

	DBGC ( INTF_COL ( intf ), "INTF " INTF_INTF_FMT " resolv_done\n",
	       INTF_INTF_DBG ( intf, dest ) );

	if ( op ) {
		op ( object, sa );
	} else {
		/* Default is to ignore resolutions */
	}

	intf_put ( dest );
}

/***************************************************************************
 *
 * Numeric name resolver
 *
 ***************************************************************************
 */

/** A numeric name resolver */
struct numeric_resolv {
	/** Reference counter */
	struct refcnt refcnt;
	/** Name resolution interface */
	struct interface resolv;
	/** Process */
	struct process process;
	/** Completed socket address */
	struct sockaddr sa;
	/** Overall status code */
	int rc;
};

static void numeric_step ( struct numeric_resolv *numeric ) {

	if ( numeric->rc == 0 )
		resolv_done ( &numeric->resolv, &numeric->sa );
	intf_shutdown ( &numeric->resolv, numeric->rc );
}

static struct process_descriptor numeric_process_desc =
	PROC_DESC_ONCE ( struct numeric_resolv, process, numeric_step );

static int numeric_resolv ( struct interface *resolv,
			    const char *name, struct sockaddr *sa ) {
	struct numeric_resolv *numeric;

	/* Allocate and initialise structure */
	numeric = zalloc ( sizeof ( *numeric ) );
	if ( ! numeric )
		return -ENOMEM;
	ref_init ( &numeric->refcnt, NULL );
	intf_init ( &numeric->resolv, &null_intf_desc, &numeric->refcnt );
	process_init ( &numeric->process, &numeric_process_desc,
		       &numeric->refcnt );
	memcpy ( &numeric->sa, sa, sizeof ( numeric->sa ) );

	/* Attempt to resolve name */
	numeric->rc = sock_aton ( name, &numeric->sa );

	/* Attach to parent interface, mortalise self, and return */
	intf_plug_plug ( &numeric->resolv, resolv );
	ref_put ( &numeric->refcnt );
	return 0;
}

struct resolver numeric_resolver __resolver ( RESOLV_NUMERIC ) = {
	.name = "NUMERIC",
	.resolv = numeric_resolv,
};

/***************************************************************************
 *
 * Name resolution multiplexer
 *
 ***************************************************************************
 */

/** A name resolution multiplexer */
struct resolv_mux {
	/** Reference counter */
	struct refcnt refcnt;
	/** Parent name resolution interface */
	struct interface parent;

	/** Child name resolution interface */
	struct interface child;
	/** Current child resolver */
	struct resolver *resolver;

	/** Socket address to complete */
	struct sockaddr sa;
	/** Name to be resolved
	 *
	 * Must be at end of structure
	 */
	char name[0];
};

/**
 * Try current child name resolver
 *
 * @v mux		Name resolution multiplexer
 * @ret rc		Return status code
 */
static int resmux_try ( struct resolv_mux *mux ) {
	struct resolver *resolver = mux->resolver;
	int rc;

	DBGC ( mux, "RESOLV %p trying method %s\n", mux, resolver->name );

	if ( ( rc = resolver->resolv ( &mux->child, mux->name,
				       &mux->sa ) ) != 0 ) {
		DBGC ( mux, "RESOLV %p could not use method %s: %s\n",
		       mux, resolver->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Child resolved name
 *
 * @v mux		Name resolution multiplexer
 * @v sa		Completed socket address
 */
static void resmux_child_resolv_done ( struct resolv_mux *mux,
				       struct sockaddr *sa ) {

	DBGC ( mux, "RESOLV %p resolved \"%s\" to %s using method %s\n",
	       mux, mux->name, sock_ntoa ( sa ), mux->resolver->name );

	/* Pass resolution to parent */
	resolv_done ( &mux->parent, sa );
}

/**
 * Child finished resolution
 *
 * @v mux		Name resolution multiplexer
 * @v rc		Return status code
 */
static void resmux_child_close ( struct resolv_mux *mux, int rc ) {

	/* Restart child interface */
	intf_restart ( &mux->child, rc );

	/* If this resolution succeeded, stop now */
	if ( rc == 0 ) {
		DBGC ( mux, "RESOLV %p succeeded using method %s\n",
		       mux, mux->resolver->name );
		goto finished;
	}

	/* Attempt next child resolver, if possible */
	mux->resolver++;
	if ( mux->resolver >= table_end ( RESOLVERS ) ) {
		DBGC ( mux, "RESOLV %p failed to resolve name\n", mux );
		goto finished;
	}
	if ( ( rc = resmux_try ( mux ) ) != 0 )
		goto finished;

	/* Next resolver is now running */
	return;

 finished:
	intf_shutdown ( &mux->parent, rc );
}

/** Name resolution multiplexer child interface operations */
static struct interface_operation resmux_child_op[] = {
	INTF_OP ( resolv_done, struct resolv_mux *, resmux_child_resolv_done ),
	INTF_OP ( intf_close, struct resolv_mux *, resmux_child_close ),
};

/** Name resolution multiplexer child interface descriptor */
static struct interface_descriptor resmux_child_desc =
	INTF_DESC ( struct resolv_mux, child, resmux_child_op );

/**
 * Start name resolution
 *
 * @v resolv		Name resolution interface
 * @v name		Name to resolve
 * @v sa		Socket address to complete
 * @ret rc		Return status code
 */
int resolv ( struct interface *resolv, const char *name,
	     struct sockaddr *sa ) {
	struct resolv_mux *mux;
	size_t name_len = ( strlen ( name ) + 1 );
	int rc;

	/* Allocate and initialise structure */
	mux = zalloc ( sizeof ( *mux ) + name_len );
	if ( ! mux )
		return -ENOMEM;
	ref_init ( &mux->refcnt, NULL );
	intf_init ( &mux->parent, &null_intf_desc, &mux->refcnt );
	intf_init ( &mux->child, &resmux_child_desc, &mux->refcnt );
	mux->resolver = table_start ( RESOLVERS );
	if ( sa )
		memcpy ( &mux->sa, sa, sizeof ( mux->sa ) );
	memcpy ( mux->name, name, name_len );

	DBGC ( mux, "RESOLV %p attempting to resolve \"%s\"\n", mux, name );

	/* Start first resolver in chain.  There will always be at
	 * least one resolver (the numeric resolver), so no need to
	 * check for the zero-resolvers-available case.
	 */
	if ( ( rc = resmux_try ( mux ) ) != 0 )
		goto err;

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &mux->parent, resolv );
	ref_put ( &mux->refcnt );
	return 0;

 err:
	ref_put ( &mux->refcnt );
	return rc;	
}

/***************************************************************************
 *
 * Named socket opening
 *
 ***************************************************************************
 */

/** A named socket */
struct named_socket {
	/** Reference counter */
	struct refcnt refcnt;
	/** Data transfer interface */
	struct interface xfer;
	/** Name resolution interface */
	struct interface resolv;
	/** Communication semantics (e.g. SOCK_STREAM) */
	int semantics;
	/** Stored local socket address, if applicable */
	struct sockaddr local;
	/** Stored local socket address exists */
	int have_local;
};

/**
 * Terminate named socket opener
 *
 * @v named		Named socket
 * @v rc		Reason for termination
 */
static void named_close ( struct named_socket *named, int rc ) {
	/* Shut down interfaces */
	intf_shutdown ( &named->resolv, rc );
	intf_shutdown ( &named->xfer, rc );
}

/**
 * Check flow control window
 *
 * @v named		Named socket
 * @ret len		Length of window
 */
static size_t named_window ( struct named_socket *named __unused ) {
	/* Not ready for data until we have redirected away */
	return 0;
}

/** Named socket opener data transfer interface operations */
static struct interface_operation named_xfer_ops[] = {
	INTF_OP ( xfer_window, struct named_socket *, named_window ),
	INTF_OP ( intf_close, struct named_socket *, named_close ),
};

/** Named socket opener data transfer interface descriptor */
static struct interface_descriptor named_xfer_desc =
	INTF_DESC ( struct named_socket, xfer, named_xfer_ops );

/**
 * Name resolved
 *
 * @v named		Named socket
 * @v sa		Completed socket address
 */
static void named_resolv_done ( struct named_socket *named,
				struct sockaddr *sa ) {
	int rc;

	/* Nullify data transfer interface */
	intf_nullify ( &named->xfer );

	/* Redirect data-xfer interface */
	if ( ( rc = xfer_redirect ( &named->xfer, LOCATION_SOCKET,
				    named->semantics, sa,
				    ( named->have_local ?
				      &named->local : NULL ) ) ) != 0 ) {
		/* Redirection failed - do not unplug data-xfer interface */
		DBGC ( named, "NAMED %p could not redirect: %s\n",
		       named, strerror ( rc ) );
	} else {
		/* Redirection succeeded - unplug data-xfer interface */
		DBGC ( named, "NAMED %p redirected successfully\n", named );
		intf_unplug ( &named->xfer );
	}

	/* Terminate named socket opener */
	named_close ( named, rc );
}

/** Named socket opener resolver interface operations */
static struct interface_operation named_resolv_op[] = {
	INTF_OP ( intf_close, struct named_socket *, named_close ),
	INTF_OP ( resolv_done, struct named_socket *, named_resolv_done ),
};

/** Named socket opener resolver interface descriptor */
static struct interface_descriptor named_resolv_desc =
	INTF_DESC ( struct named_socket, resolv, named_resolv_op );

/**
 * Open named socket
 *
 * @v semantics		Communication semantics (e.g. SOCK_STREAM)
 * @v peer		Peer socket address to complete
 * @v name		Name to resolve
 * @v local		Local socket address, or NULL
 * @ret rc		Return status code
 */
int xfer_open_named_socket ( struct interface *xfer, int semantics,
			     struct sockaddr *peer, const char *name,
			     struct sockaddr *local ) {
	struct named_socket *named;
	int rc;

	/* Allocate and initialise structure */
	named = zalloc ( sizeof ( *named ) );
	if ( ! named )
		return -ENOMEM;
	ref_init ( &named->refcnt, NULL );
	intf_init ( &named->xfer, &named_xfer_desc, &named->refcnt );
	intf_init ( &named->resolv, &named_resolv_desc, &named->refcnt );
	named->semantics = semantics;
	if ( local ) {
		memcpy ( &named->local, local, sizeof ( named->local ) );
		named->have_local = 1;
	}

	DBGC ( named, "NAMED %p opening \"%s\"\n",
	       named, name );

	/* Start name resolution */
	if ( ( rc = resolv ( &named->resolv, name, peer ) ) != 0 )
		goto err;

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &named->xfer, xfer );
	ref_put ( &named->refcnt );
	return 0;

 err:
	ref_put ( &named->refcnt );
	return rc;
}
