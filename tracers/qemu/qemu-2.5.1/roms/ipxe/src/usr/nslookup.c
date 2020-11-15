/*
 * Copyright (C) 2012 Patrick Plenefisch <phplenefisch@wpi.edu>.
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipxe/resolv.h>
#include <ipxe/tcpip.h>
#include <ipxe/monojob.h>
#include <ipxe/settings.h>
#include <usr/nslookup.h>

/** @file
 *
 * Standalone name resolution
 *
 */

/** A name resolution request */
struct nslookup {
	/** Reference count for this object */
	struct refcnt refcnt;

	/** Job control interface */
	struct interface job;
	/** Data transfer interface */
	struct interface resolver;

	/** Setting name */
	char *setting_name;
};

/**
 * Terminate name resolution
 *
 * @v nslookup		Name resolution request
 * @v rc		Reason for termination
 */
static void nslookup_close ( struct nslookup *nslookup, int rc ) {

	/* Shut down interfaces */
	intf_shutdown ( &nslookup->resolver, rc );
	intf_shutdown ( &nslookup->job, rc );
}

/**
 * Handle resolved name
 *
 * @v nslookup		Name resolution request
 * @v sa		Completed socket address
 */
static void nslookup_resolv_done ( struct nslookup *nslookup,
				   struct sockaddr *sa ) {
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	const struct setting_type *default_type;
	struct settings *settings;
	struct setting setting;
	void *data;
	size_t len;
	int rc;

	/* Extract address */
	switch ( sa->sa_family ) {
	case AF_INET:
		sin = ( ( struct sockaddr_in * ) sa );
		data = &sin->sin_addr;
		len = sizeof ( sin->sin_addr );
		default_type = &setting_type_ipv4;
		break;
	case AF_INET6:
		sin6 = ( ( struct sockaddr_in6 * ) sa );
		data = &sin6->sin6_addr;
		len = sizeof ( sin6->sin6_addr );
		default_type = &setting_type_ipv6;
		break;
	default:
		rc = -ENOTSUP;
		goto err;
	}

	/* Parse specified setting name */
	if ( ( rc = parse_setting_name ( nslookup->setting_name,
					 autovivify_child_settings, &settings,
					 &setting ) ) != 0 )
		goto err;

	/* Apply default type if necessary */
	if ( ! setting.type )
		setting.type = default_type;

	/* Store in specified setting */
	if ( ( rc = store_setting ( settings, &setting, data, len ) ) != 0 )
		goto err;

 err:
	/* Terminate name resolution */
	nslookup_close ( nslookup, rc );
}

/** Name resolution resolver interface operations */
static struct interface_operation nslookup_resolver_operations[] = {
	INTF_OP ( resolv_done, struct nslookup *, nslookup_resolv_done ),
	INTF_OP ( intf_close, struct nslookup *, nslookup_close ),
};

/** Name resolution resolver interface descriptor */
static struct interface_descriptor nslookup_resolver_desc =
	INTF_DESC_PASSTHRU ( struct nslookup, resolver,
			     nslookup_resolver_operations, job );

/** Name resolution job control interface operations */
static struct interface_operation nslookup_job_operations[] = {
	INTF_OP ( intf_close, struct nslookup *, nslookup_close ),
};

/** Name resolution job control interface descriptor */
static struct interface_descriptor nslookup_job_desc =
	INTF_DESC_PASSTHRU ( struct nslookup, job,
			     nslookup_job_operations, resolver );

/**
 * Initiate standalone name resolution
 *
 * @v job		Parent interface
 * @v name		Name to resolve
 * @v setting_name	Setting name
 * @ret rc		Return status code
 */
static int resolv_setting ( struct interface *job, const char *name,
			    const char *setting_name ) {
	struct nslookup *nslookup;
	struct sockaddr sa;
	char *setting_name_copy;
	int rc;

	/* Allocate and initialise structure */
	nslookup = zalloc ( sizeof ( *nslookup ) + strlen ( setting_name )
			    + 1 /* NUL */ );
	if ( ! nslookup )
		return -ENOMEM;
	ref_init ( &nslookup->refcnt, NULL );
	intf_init ( &nslookup->job, &nslookup_job_desc, &nslookup->refcnt );
	intf_init ( &nslookup->resolver, &nslookup_resolver_desc,
		    &nslookup->refcnt );
	setting_name_copy = ( ( void * ) ( nslookup + 1 ) );
	strcpy ( setting_name_copy, setting_name );
	nslookup->setting_name = setting_name_copy;

	/* Start name resolution */
	memset ( &sa, 0, sizeof ( sa ) );
	if ( ( rc = resolv ( &nslookup->resolver, name, &sa ) ) != 0 )
		goto err_resolv;

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &nslookup->job, job );
	ref_put ( &nslookup->refcnt );
	return 0;

 err_resolv:
	ref_put ( &nslookup->refcnt );
	return rc;
}

/**
 * Perform (blocking) standalone name resolution
 *
 * @v name		Name to resolve
 * @v setting_name	Setting name
 * @ret rc		Return status code
 */
int nslookup ( const char *name, const char *setting_name ) {
	int rc;

	/* Perform name resolution */
	if ( ( rc = resolv_setting ( &monojob, name, setting_name ) ) == 0 )
		rc = monojob_wait ( NULL, 0 );
	if ( rc != 0 ) {
		printf ( "Could not resolve %s: %s\n", name, strerror ( rc ) );
		return rc;
	}

	return 0;
}
