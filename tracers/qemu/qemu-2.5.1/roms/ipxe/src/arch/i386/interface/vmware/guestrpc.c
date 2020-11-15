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

/** @file
 *
 * VMware GuestRPC mechanism
 *
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/vmware.h>
#include <ipxe/guestrpc.h>

/* Disambiguate the various error causes */
#define EPROTO_OPEN __einfo_error ( EINFO_EPROTO_OPEN )
#define EINFO_EPROTO_OPEN \
	__einfo_uniqify ( EINFO_EPROTO, 0x00, "GuestRPC open failed" )
#define EPROTO_COMMAND_LEN __einfo_error ( EINFO_EPROTO_COMMAND_LEN )
#define EINFO_EPROTO_COMMAND_LEN \
	__einfo_uniqify ( EINFO_EPROTO, 0x01, "GuestRPC command length failed" )
#define EPROTO_COMMAND_DATA __einfo_error ( EINFO_EPROTO_COMMAND_DATA )
#define EINFO_EPROTO_COMMAND_DATA \
	__einfo_uniqify ( EINFO_EPROTO, 0x02, "GuestRPC command data failed" )
#define EPROTO_REPLY_LEN __einfo_error ( EINFO_EPROTO_REPLY_LEN )
#define EINFO_EPROTO_REPLY_LEN \
	__einfo_uniqify ( EINFO_EPROTO, 0x03, "GuestRPC reply length failed" )
#define EPROTO_REPLY_DATA __einfo_error ( EINFO_EPROTO_REPLY_DATA )
#define EINFO_EPROTO_REPLY_DATA \
	__einfo_uniqify ( EINFO_EPROTO, 0x04, "GuestRPC reply data failed" )
#define EPROTO_REPLY_FINISH __einfo_error ( EINFO_EPROTO_REPLY_FINISH )
#define EINFO_EPROTO_REPLY_FINISH \
	__einfo_uniqify ( EINFO_EPROTO, 0x05, "GuestRPC reply finish failed" )
#define EPROTO_CLOSE __einfo_error ( EINFO_EPROTO_CLOSE )
#define EINFO_EPROTO_CLOSE \
	__einfo_uniqify ( EINFO_EPROTO, 0x06, "GuestRPC close failed" )

/**
 * Open GuestRPC channel
 *
 * @ret channel		Channel number, or negative error
 */
int guestrpc_open ( void ) {
	uint16_t channel;
	uint32_t discard_b;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( 0, GUESTRPC_OPEN, GUESTRPC_MAGIC,
				       &channel, &discard_b );
	if ( status != GUESTRPC_OPEN_SUCCESS ) {
		DBGC ( GUESTRPC_MAGIC, "GuestRPC open failed: status %08x\n",
		       status );
		return -EPROTO_OPEN;
	}

	DBGC ( GUESTRPC_MAGIC, "GuestRPC channel %d opened\n", channel );
	return channel;
}

/**
 * Send GuestRPC command length
 *
 * @v channel		Channel number
 * @v len		Command length
 * @ret rc		Return status code
 */
static int guestrpc_command_len ( int channel, size_t len ) {
	uint16_t discard_d;
	uint32_t discard_b;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_COMMAND_LEN, len,
				       &discard_d, &discard_b );
	if ( status != GUESTRPC_COMMAND_LEN_SUCCESS ) {
		DBGC ( GUESTRPC_MAGIC, "GuestRPC channel %d send command "
		       "length %zd failed: status %08x\n",
		       channel, len, status );
		return -EPROTO_COMMAND_LEN;
	}

	return 0;
}

/**
 * Send GuestRPC command data
 *
 * @v channel		Channel number
 * @v data		Command data
 * @ret rc		Return status code
 */
static int guestrpc_command_data ( int channel, uint32_t data ) {
	uint16_t discard_d;
	uint32_t discard_b;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_COMMAND_DATA, data,
				       &discard_d, &discard_b );
	if ( status != GUESTRPC_COMMAND_DATA_SUCCESS ) {
		DBGC ( GUESTRPC_MAGIC, "GuestRPC channel %d send command "
		       "data %08x failed: status %08x\n",
		       channel, data, status );
		return -EPROTO_COMMAND_DATA;
	}

	return 0;
}

/**
 * Receive GuestRPC reply length
 *
 * @v channel		Channel number
 * @ret reply_id	Reply ID
 * @ret len		Reply length, or negative error
 */
static int guestrpc_reply_len ( int channel, uint16_t *reply_id ) {
	uint32_t len;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_REPLY_LEN, 0,
				       reply_id, &len );
	if ( status != GUESTRPC_REPLY_LEN_SUCCESS ) {
		DBGC ( GUESTRPC_MAGIC, "GuestRPC channel %d receive reply "
		       "length failed: status %08x\n", channel, status );
		return -EPROTO_REPLY_LEN;
	}

	return len;
}

/**
 * Receive GuestRPC reply data
 *
 * @v channel		Channel number
 * @v reply_id		Reply ID
 * @ret data		Reply data
 * @ret rc		Return status code
 */
static int guestrpc_reply_data ( int channel, uint16_t reply_id,
				 uint32_t *data ) {
	uint16_t discard_d;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_REPLY_DATA, reply_id,
				       &discard_d, data );
	if ( status != GUESTRPC_REPLY_DATA_SUCCESS ) {
		DBGC ( GUESTRPC_MAGIC, "GuestRPC channel %d receive reply "
		       "%d data failed: status %08x\n",
		       channel, reply_id, status );
		return -EPROTO_REPLY_DATA;
	}

	return 0;
}

/**
 * Finish receiving GuestRPC reply
 *
 * @v channel		Channel number
 * @v reply_id		Reply ID
 * @ret rc		Return status code
 */
static int guestrpc_reply_finish ( int channel, uint16_t reply_id ) {
	uint16_t discard_d;
	uint32_t discard_b;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_REPLY_FINISH, reply_id,
				       &discard_d, &discard_b );
	if ( status != GUESTRPC_REPLY_FINISH_SUCCESS ) {
		DBGC ( GUESTRPC_MAGIC, "GuestRPC channel %d finish reply %d "
		       "failed: status %08x\n", channel, reply_id, status );
		return -EPROTO_REPLY_FINISH;
	}

	return 0;
}

/**
 * Close GuestRPC channel
 *
 * @v channel		Channel number
 */
void guestrpc_close ( int channel ) {
	uint16_t discard_d;
	uint32_t discard_b;
	uint32_t status;

	/* Issue GuestRPC command */
	status = vmware_cmd_guestrpc ( channel, GUESTRPC_CLOSE, 0,
				       &discard_d, &discard_b );
	if ( status != GUESTRPC_CLOSE_SUCCESS ) {
		DBGC ( GUESTRPC_MAGIC, "GuestRPC channel %d close failed: "
		       "status %08x\n", channel, status );
		return;
	}

	DBGC ( GUESTRPC_MAGIC, "GuestRPC channel %d closed\n", channel );
}

/**
 * Issue GuestRPC command
 *
 * @v channel		Channel number
 * @v command		Command
 * @v reply		Reply buffer
 * @v reply_len		Length of reply buffer
 * @ret len		Length of reply, or negative error
 *
 * The actual length of the reply will be returned even if the buffer
 * was too small.
 */
int guestrpc_command ( int channel, const char *command, char *reply,
		       size_t reply_len ) {
	const uint8_t *command_bytes = ( ( const void * ) command );
	uint8_t *reply_bytes = ( ( void * ) reply );
	size_t command_len = strlen ( command );
	int orig_reply_len = reply_len;
	uint16_t status;
	uint8_t *status_bytes = ( ( void * ) &status );
	size_t status_len = sizeof ( status );
	uint32_t data;
	uint16_t reply_id;
	int len;
	int remaining;
	unsigned int i;
	int rc;

	DBGC2 ( GUESTRPC_MAGIC, "GuestRPC channel %d issuing command:\n",
		channel );
	DBGC2_HDA ( GUESTRPC_MAGIC, 0, command, command_len );

	/* Sanity check */
	assert ( ( reply != NULL ) || ( reply_len == 0 ) );

	/* Send command length */
	if ( ( rc = guestrpc_command_len ( channel, command_len ) ) < 0 )
		return rc;

	/* Send command data */
	while ( command_len ) {
		data = 0;
		for ( i = sizeof ( data ) ; i ; i-- ) {
			if ( command_len ) {
				data = ( ( data & ~0xff ) |
					 *(command_bytes++) );
				command_len--;
			}
			data = ( ( data << 24 ) | ( data >> 8 ) );
		}
		if ( ( rc = guestrpc_command_data ( channel, data ) ) < 0 )
			return rc;
	}

	/* Receive reply length */
	if ( ( len = guestrpc_reply_len ( channel, &reply_id ) ) < 0 ) {
		rc = len;
		return rc;
	}

	/* Receive reply */
	for ( remaining = len ; remaining > 0 ; remaining -= sizeof ( data ) ) {
		if ( ( rc = guestrpc_reply_data ( channel, reply_id,
						  &data ) ) < 0 ) {
			return rc;
		}
		for ( i = sizeof ( data ) ; i ; i-- ) {
			if ( status_len ) {
				*(status_bytes++) = ( data & 0xff );
				status_len--;
				len--;
			} else if ( reply_len ) {
				*(reply_bytes++) = ( data & 0xff );
				reply_len--;
			}
			data = ( ( data << 24 ) | ( data >> 8 ) );
		}
	}

	/* Finish receiving RPC reply */
	if ( ( rc = guestrpc_reply_finish ( channel, reply_id ) ) < 0 )
		return rc;

	DBGC2 ( GUESTRPC_MAGIC, "GuestRPC channel %d received reply (id %d, "
		"length %d):\n", channel, reply_id, len );
	DBGC2_HDA ( GUESTRPC_MAGIC, 0, &status, sizeof ( status ) );
	DBGC2_HDA ( GUESTRPC_MAGIC, sizeof ( status ), reply,
		    ( ( len < orig_reply_len ) ? len : orig_reply_len ) );

	/* Check reply status */
	if ( status != GUESTRPC_SUCCESS ) {
		DBGC ( GUESTRPC_MAGIC, "GuestRPC channel %d command failed "
		       "(status %04x, reply id %d, reply length %d):\n",
		       channel, status, reply_id, len );
		DBGC_HDA ( GUESTRPC_MAGIC, 0, command, command_len );
		DBGC_HDA ( GUESTRPC_MAGIC, 0, &status, sizeof ( status ) );
		DBGC_HDA ( GUESTRPC_MAGIC, sizeof ( status ), reply,
			   ( ( len < orig_reply_len ) ? len : orig_reply_len ));
		return -EIO;
	}

	return len;
}
