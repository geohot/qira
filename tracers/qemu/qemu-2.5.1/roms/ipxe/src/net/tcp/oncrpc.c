/*
 * Copyright (C) 2013 Marin Hannache <ipxe@mareo.fr>.
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/socket.h>
#include <ipxe/tcpip.h>
#include <ipxe/in.h>
#include <ipxe/iobuf.h>
#include <ipxe/dhcp.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/features.h>
#include <ipxe/oncrpc.h>
#include <ipxe/oncrpc_iob.h>
#include <ipxe/init.h>
#include <ipxe/settings.h>
#include <ipxe/version.h>

/** @file
 *
 * SUN ONC RPC protocol
 *
 */

/** Set most significant bit to 1. */
#define SET_LAST_FRAME( x ) ( (x) | 1 << 31 )
#define GET_FRAME_SIZE( x ) ( (x) & ~( 1 << 31 ) )

#define ONCRPC_CALL     0
#define ONCRPC_REPLY    1

/** AUTH NONE authentication flavor */
struct oncrpc_cred oncrpc_auth_none = {
	.flavor = ONCRPC_AUTH_NONE,
	.length = 0
};

const struct setting uid_setting __setting ( SETTING_AUTH, uid ) = {
	.name        = "uid",
	.description = "User ID",
	.tag         = DHCP_EB_UID,
	.type        = &setting_type_uint32
};

const struct setting gid_setting __setting ( SETTING_AUTH, gid ) = {
	.name        = "gid",
	.description = "Group ID",
	.tag         = DHCP_EB_GID,
	.type        = &setting_type_uint32
};

/**
 * Initialize an ONC RPC AUTH SYS credential structure
 *
 * @v auth_sys          The structure to initialize
 *
 * The hostname field is filled with the value of the hostname setting, if the
 * hostname setting is empty, PRODUCT_SHORT_NAME (usually "iPXE") is used
 * instead.
 */
int oncrpc_init_cred_sys ( struct oncrpc_cred_sys *auth_sys ) {
	if ( ! auth_sys )
		return -EINVAL;

	fetch_string_setting_copy ( NULL, &hostname_setting,
	                            &auth_sys->hostname );
	if ( ! auth_sys->hostname )
		if ( ! ( auth_sys->hostname = strdup ( product_short_name ) ) )
			return -ENOMEM;

	auth_sys->uid         = fetch_uintz_setting ( NULL, &uid_setting );
	auth_sys->gid         = fetch_uintz_setting ( NULL, &uid_setting );
	auth_sys->aux_gid_len = 0;
	auth_sys->stamp       = 0;

	auth_sys->credential.flavor = ONCRPC_AUTH_SYS;
	auth_sys->credential.length = 16 +
	                              oncrpc_strlen ( auth_sys->hostname );

	return 0;
}

/**
 * Prepare an ONC RPC session structure to be used by the ONC RPC layer
 *
 * @v session           ONC RPC session
 * @v credential        Credential structure pointer
 * @v verifier          Verifier structure pointer
 * @v prog_name         ONC RPC program number
 * @v prog_vers         ONC RPC program version number
 */
void oncrpc_init_session ( struct oncrpc_session *session,
                           struct oncrpc_cred *credential,
                           struct oncrpc_cred *verifier, uint32_t prog_name,
                           uint32_t prog_vers ) {
	if ( ! session )
		return;

	session->rpc_id     = rand();
	session->credential = credential;
	session->verifier   = verifier;
	session->prog_name  = prog_name;
	session->prog_vers  = prog_vers;
}

int oncrpc_call ( struct interface *intf, struct oncrpc_session *session,
                  uint32_t proc_name, const struct oncrpc_field fields[] ) {
	int              rc;
	size_t           frame_size;
	struct io_buffer *io_buf;

	if ( ! session )
		return -EINVAL;

	struct oncrpc_field header[] = {
		ONCRPC_FIELD ( int32, 0 ),
		ONCRPC_FIELD ( int32, ++session->rpc_id ),
		ONCRPC_FIELD ( int32, ONCRPC_CALL ),
		ONCRPC_FIELD ( int32, ONCRPC_VERS ),
		ONCRPC_FIELD ( int32, session->prog_name ),
		ONCRPC_FIELD ( int32, session->prog_vers ),
		ONCRPC_FIELD ( int32, proc_name ),
		ONCRPC_FIELD ( cred, session->credential ),
		ONCRPC_FIELD ( cred, session->verifier ),
		ONCRPC_FIELD_END,
	};

	frame_size  = oncrpc_compute_size ( header );
	frame_size += oncrpc_compute_size ( fields );

	io_buf = alloc_iob ( frame_size );
	if ( ! io_buf )
		return -ENOBUFS;

	header[0].value.int32 = SET_LAST_FRAME ( frame_size -
	                                         sizeof ( uint32_t ) );

	oncrpc_iob_add_fields ( io_buf, header );
	oncrpc_iob_add_fields ( io_buf, fields );

	rc = xfer_deliver_iob ( intf, io_buf );
	if ( rc != 0 )
		free_iob ( io_buf );

	return rc;
}

size_t oncrpc_compute_size ( const struct oncrpc_field fields[] ) {

	size_t i;
	size_t size = 0;

	for ( i = 0; fields[i].type != oncrpc_none; i++ ) {
		switch ( fields[i].type ) {
		case oncrpc_int32:
			size += sizeof ( uint32_t );
			break;

		case oncrpc_int64:
			size += sizeof ( uint64_t );
			break;

		case oncrpc_str:
			size += oncrpc_strlen ( fields[i].value.str );
			break;

		case oncrpc_array:
			size += oncrpc_align ( fields[i].value.array.length );
			size += sizeof ( uint32_t );
			break;

		case oncrpc_intarray:
			size += sizeof ( uint32_t ) *
				fields[i].value.intarray.length;
			size += sizeof ( uint32_t );
			break;

		case oncrpc_cred:
			size += fields[i].value.cred->length;
			size += 2 * sizeof ( uint32_t );
			break;

		default:
			return size;
		}
	}

	return size;
}

/**
 * Parse an I/O buffer to extract a ONC RPC REPLY
 * @v session	        ONC RPC session
 * @v reply             Reply structure where data will be saved
 * @v io_buf            I/O buffer
 */
int oncrpc_get_reply ( struct oncrpc_session *session __unused,
                       struct oncrpc_reply *reply, struct io_buffer *io_buf ) {
	if ( ! reply || ! io_buf )
		return -EINVAL;

	reply->frame_size = GET_FRAME_SIZE ( oncrpc_iob_get_int ( io_buf ) );
	reply->rpc_id     = oncrpc_iob_get_int ( io_buf );

	/* iPXE has no support for handling ONC RPC call */
	if ( oncrpc_iob_get_int ( io_buf ) != ONCRPC_REPLY )
		return -ENOSYS;

	reply->reply_state = oncrpc_iob_get_int ( io_buf );

	if ( reply->reply_state == 0 )
	{
		/* verifier.flavor */
		oncrpc_iob_get_int ( io_buf );
		/* verifier.length */
		iob_pull ( io_buf, oncrpc_iob_get_int ( io_buf ));

		/* We don't use the verifier in iPXE, let it be an empty
		   verifier. */
		reply->verifier = &oncrpc_auth_none;
	}

	reply->accept_state = oncrpc_iob_get_int ( io_buf );
	reply->data         = io_buf;

	return 0;
}
