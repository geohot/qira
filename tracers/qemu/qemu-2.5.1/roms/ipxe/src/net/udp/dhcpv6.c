/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/interface.h>
#include <ipxe/xfer.h>
#include <ipxe/iobuf.h>
#include <ipxe/open.h>
#include <ipxe/netdevice.h>
#include <ipxe/settings.h>
#include <ipxe/retry.h>
#include <ipxe/timer.h>
#include <ipxe/in.h>
#include <ipxe/crc32.h>
#include <ipxe/errortab.h>
#include <ipxe/ipv6.h>
#include <ipxe/dhcpv6.h>

/** @file
 *
 * Dynamic Host Configuration Protocol for IPv6
 *
 */

/* Disambiguate the various error causes */
#define EPROTO_UNSPECFAIL __einfo_error ( EINFO_EPROTO_UNSPECFAIL )
#define EINFO_EPROTO_UNSPECFAIL \
	__einfo_uniqify ( EINFO_EPROTO, 1, "Unspecified server failure" )
#define EPROTO_NOADDRSAVAIL __einfo_error ( EINFO_EPROTO_NOADDRSAVAIL )
#define EINFO_EPROTO_NOADDRSAVAIL \
	__einfo_uniqify ( EINFO_EPROTO, 2, "No addresses available" )
#define EPROTO_NOBINDING __einfo_error ( EINFO_EPROTO_NOBINDING )
#define EINFO_EPROTO_NOBINDING \
	__einfo_uniqify ( EINFO_EPROTO, 3, "Client record unavailable" )
#define EPROTO_NOTONLINK __einfo_error ( EINFO_EPROTO_NOTONLINK )
#define EINFO_EPROTO_NOTONLINK \
	__einfo_uniqify ( EINFO_EPROTO, 4, "Prefix not on link" )
#define EPROTO_USEMULTICAST __einfo_error ( EINFO_EPROTO_USEMULTICAST )
#define EINFO_EPROTO_USEMULTICAST \
	__einfo_uniqify ( EINFO_EPROTO, 5, "Use multicast address" )
#define EPROTO_STATUS( status )						\
	EUNIQ ( EINFO_EPROTO, ( (status) & 0x0f ), EPROTO_UNSPECFAIL,	\
		EPROTO_NOADDRSAVAIL, EPROTO_NOBINDING,			\
		EPROTO_NOTONLINK, EPROTO_USEMULTICAST )

/** Human-readable error messages */
struct errortab dhcpv6_errors[] __errortab = {
	__einfo_errortab ( EINFO_EPROTO_NOADDRSAVAIL ),
};

/****************************************************************************
 *
 * DHCPv6 option lists
 *
 */

/** A DHCPv6 option list */
struct dhcpv6_option_list {
	/** Data buffer */
	const void *data;
	/** Length of data buffer */
	size_t len;
};

/**
 * Find DHCPv6 option
 *
 * @v options		DHCPv6 option list
 * @v code		Option code
 * @ret option		DHCPv6 option, or NULL if not found
 */
static const union dhcpv6_any_option *
dhcpv6_option ( struct dhcpv6_option_list *options, unsigned int code ) {
	const union dhcpv6_any_option *option = options->data;
	size_t remaining = options->len;
	size_t data_len;

	/* Scan through list of options */
	while ( remaining >= sizeof ( option->header ) ) {

		/* Calculate and validate option length */
		remaining -= sizeof ( option->header );
		data_len = ntohs ( option->header.len );
		if ( data_len > remaining ) {
			/* Malformed option list */
			return NULL;
		}

		/* Return if we have found the specified option */
		if ( option->header.code == htons ( code ) )
			return option;

		/* Otherwise, move to the next option */
		option = ( ( ( void * ) option->header.data ) + data_len );
		remaining -= data_len;
	}

	return NULL;
}

/**
 * Check DHCPv6 client or server identifier
 *
 * @v options		DHCPv6 option list
 * @v code		Option code
 * @v expected		Expected value
 * @v len		Length of expected value
 * @ret rc		Return status code
 */
static int dhcpv6_check_duid ( struct dhcpv6_option_list *options,
			       unsigned int code, const void *expected,
			       size_t len ) {
	const union dhcpv6_any_option *option;
	const struct dhcpv6_duid_option *duid;

	/* Find option */
	option = dhcpv6_option ( options, code );
	if ( ! option )
		return -ENOENT;
	duid = &option->duid;

	/* Check option length */
	if ( ntohs ( duid->header.len ) != len )
		return -EINVAL;

	/* Compare option value */
	if ( memcmp ( duid->duid, expected, len ) != 0 )
		return -EINVAL;

	return 0;
}

/**
 * Get DHCPv6 status code
 *
 * @v options		DHCPv6 option list
 * @ret rc		Return status code
 */
static int dhcpv6_status_code ( struct dhcpv6_option_list *options ) {
	const union dhcpv6_any_option *option;
	const struct dhcpv6_status_code_option *status_code;
	unsigned int status;

	/* Find status code option, if present */
	option = dhcpv6_option ( options, DHCPV6_STATUS_CODE );
	if ( ! option ) {
		/* Omitted status code should be treated as "success" */
		return 0;
	}
	status_code = &option->status_code;

	/* Sanity check */
	if ( ntohs ( status_code->header.len ) <
	     ( sizeof ( *status_code ) - sizeof ( status_code->header ) ) ) {
		return -EINVAL;
	}

	/* Calculate iPXE error code from DHCPv6 status code */
	status = ntohs ( status_code->status );
	return ( status ? -EPROTO_STATUS ( status ) : 0 );
}

/**
 * Get DHCPv6 identity association address
 *
 * @v options		DHCPv6 option list
 * @v iaid		Identity association ID
 * @v address		IPv6 address to fill in
 * @ret rc		Return status code
 */
static int dhcpv6_iaaddr ( struct dhcpv6_option_list *options, uint32_t iaid,
			   struct in6_addr *address ) {
	const union dhcpv6_any_option *option;
	const struct dhcpv6_ia_na_option *ia_na;
	const struct dhcpv6_iaaddr_option *iaaddr;
	struct dhcpv6_option_list suboptions;
	size_t len;
	int rc;

	/* Find identity association option, if present */
	option = dhcpv6_option ( options, DHCPV6_IA_NA );
	if ( ! option )
		return -ENOENT;
	ia_na = &option->ia_na;

	/* Sanity check */
	len = ntohs ( ia_na->header.len );
	if ( len < ( sizeof ( *ia_na ) - sizeof ( ia_na->header ) ) )
		return -EINVAL;

	/* Check identity association ID */
	if ( ia_na->iaid != htonl ( iaid ) )
		return -EINVAL;

	/* Construct IA_NA sub-options list */
	suboptions.data = ia_na->options;
	suboptions.len = ( len + sizeof ( ia_na->header ) -
			   offsetof ( typeof ( *ia_na ), options ) );

	/* Check IA_NA status code */
	if ( ( rc = dhcpv6_status_code ( &suboptions ) ) != 0 )
		return rc;

	/* Find identity association address, if present */
	option = dhcpv6_option ( &suboptions, DHCPV6_IAADDR );
	if ( ! option )
		return -ENOENT;
	iaaddr = &option->iaaddr;

	/* Sanity check */
	len = ntohs ( iaaddr->header.len );
	if ( len < ( sizeof ( *iaaddr ) - sizeof ( iaaddr->header ) ) )
		return -EINVAL;

	/* Construct IAADDR sub-options list */
	suboptions.data = iaaddr->options;
	suboptions.len = ( len + sizeof ( iaaddr->header ) -
			   offsetof ( typeof ( *iaaddr ), options ) );

	/* Check IAADDR status code */
	if ( ( rc = dhcpv6_status_code ( &suboptions ) ) != 0 )
		return rc;

	/* Extract IPv6 address */
	memcpy ( address, &iaaddr->address, sizeof ( *address ) );

	return 0;
}

/****************************************************************************
 *
 * DHCPv6 settings blocks
 *
 */

/** A DHCPv6 settings block */
struct dhcpv6_settings {
	/** Reference count */
	struct refcnt refcnt;
	/** Settings block */
	struct settings settings;
	/** Option list */
	struct dhcpv6_option_list options;
};

/**
 * Check applicability of DHCPv6 setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
static int dhcpv6_applies ( struct settings *settings __unused,
			    const struct setting *setting ) {

	return ( setting->scope == &ipv6_scope );
}

/**
 * Fetch value of DHCPv6 setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int dhcpv6_fetch ( struct settings *settings,
			  struct setting *setting,
			  void *data, size_t len ) {
	struct dhcpv6_settings *dhcpv6set =
		container_of ( settings, struct dhcpv6_settings, settings );
	const union dhcpv6_any_option *option;
	size_t option_len;

	/* Find option */
	option = dhcpv6_option ( &dhcpv6set->options, setting->tag );
	if ( ! option )
		return -ENOENT;

	/* Copy option to data buffer */
	option_len = ntohs ( option->header.len );
	if ( len > option_len )
		len = option_len;
	memcpy ( data, option->header.data, len );
	return option_len;
}

/** DHCPv6 settings operations */
static struct settings_operations dhcpv6_settings_operations = {
	.applies = dhcpv6_applies,
	.fetch = dhcpv6_fetch,
};

/**
 * Register DHCPv6 options as network device settings
 *
 * @v options		DHCPv6 option list
 * @v parent		Parent settings block
 * @ret rc		Return status code
 */
static int dhcpv6_register ( struct dhcpv6_option_list *options,
			     struct settings *parent ) {
	struct dhcpv6_settings *dhcpv6set;
	void *data;
	size_t len;
	int rc;

	/* Allocate and initialise structure */
	dhcpv6set = zalloc ( sizeof ( *dhcpv6set ) + options->len );
	if ( ! dhcpv6set ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	ref_init ( &dhcpv6set->refcnt, NULL );
	settings_init ( &dhcpv6set->settings, &dhcpv6_settings_operations,
			&dhcpv6set->refcnt, &ipv6_scope );
	data = ( ( ( void * ) dhcpv6set ) + sizeof ( *dhcpv6set ) );
	len = options->len;
	memcpy ( data, options->data, len );
	dhcpv6set->options.data = data;
	dhcpv6set->options.len = len;

	/* Register settings */
	if ( ( rc = register_settings ( &dhcpv6set->settings, parent,
					DHCPV6_SETTINGS_NAME ) ) != 0 )
		goto err_register;

 err_register:
	ref_put ( &dhcpv6set->refcnt );
 err_alloc:
	return rc;
}

/****************************************************************************
 *
 * DHCPv6 protocol
 *
 */

/** Options to be requested */
static uint16_t dhcpv6_requested_options[] = {
	htons ( DHCPV6_DNS_SERVERS ), htons ( DHCPV6_DOMAIN_LIST ),
	htons ( DHCPV6_BOOTFILE_URL ), htons ( DHCPV6_BOOTFILE_PARAM ),
};

/**
 * Name a DHCPv6 packet type
 *
 * @v type		DHCPv6 packet type
 * @ret name		DHCPv6 packet type name
 */
static __attribute__ (( unused )) const char *
dhcpv6_type_name ( unsigned int type ) {
	static char buf[ 12 /* "UNKNOWN-xxx" + NUL */ ];

	switch ( type ) {
	case DHCPV6_SOLICIT:			return "SOLICIT";
	case DHCPV6_ADVERTISE:			return "ADVERTISE";
	case DHCPV6_REQUEST:			return "REQUEST";
	case DHCPV6_REPLY:			return "REPLY";
	case DHCPV6_INFORMATION_REQUEST:	return "INFORMATION-REQUEST";
	default:
		snprintf ( buf, sizeof ( buf ), "UNKNOWN-%d", type );
		return buf;
	}
}

/** A DHCPv6 session state */
struct dhcpv6_session_state {
	/** Current transmitted packet type */
	uint8_t tx_type;
	/** Current expected received packet type */
	uint8_t rx_type;
	/** Flags */
	uint8_t flags;
	/** Next state (or NULL to terminate) */
	struct dhcpv6_session_state *next;
};

/** DHCPv6 session state flags */
enum dhcpv6_session_state_flags {
	/** Include identity association within request */
	DHCPV6_TX_IA_NA = 0x01,
	/** Include leased IPv6 address within request */
	DHCPV6_TX_IAADDR = 0x02,
	/** Record received server ID */
	DHCPV6_RX_RECORD_SERVER_ID = 0x04,
	/** Record received IPv6 address */
	DHCPV6_RX_RECORD_IAADDR = 0x08,
	/** Apply received IPv6 address */
	DHCPV6_RX_APPLY_IAADDR = 0x10,
};

/** DHCPv6 request state */
static struct dhcpv6_session_state dhcpv6_request = {
	.tx_type = DHCPV6_REQUEST,
	.rx_type = DHCPV6_REPLY,
	.flags = ( DHCPV6_TX_IA_NA | DHCPV6_TX_IAADDR |
		   DHCPV6_RX_RECORD_IAADDR | DHCPV6_RX_APPLY_IAADDR ),
	.next = NULL,
};

/** DHCPv6 solicitation state */
static struct dhcpv6_session_state dhcpv6_solicit = {
	.tx_type = DHCPV6_SOLICIT,
	.rx_type = DHCPV6_ADVERTISE,
	.flags = ( DHCPV6_TX_IA_NA | DHCPV6_RX_RECORD_SERVER_ID |
		   DHCPV6_RX_RECORD_IAADDR ),
	.next = &dhcpv6_request,
};

/** DHCPv6 information request state */
static struct dhcpv6_session_state dhcpv6_information_request = {
	.tx_type = DHCPV6_INFORMATION_REQUEST,
	.rx_type = DHCPV6_REPLY,
	.flags = 0,
	.next = NULL,
};

/** A DHCPv6 session */
struct dhcpv6_session {
	/** Reference counter */
	struct refcnt refcnt;
	/** Job control interface */
	struct interface job;
	/** Data transfer interface */
	struct interface xfer;

	/** Network device being configured */
	struct net_device *netdev;
	/** Transaction ID */
	uint8_t xid[3];
	/** Identity association ID */
	uint32_t iaid;
	/** Start time (in ticks) */
	unsigned long start;
	/** Client DUID */
	struct dhcpv6_duid_uuid client_duid;
	/** Server DUID, if known */
	void *server_duid;
	/** Server DUID length */
	size_t server_duid_len;
	/** Leased IPv6 address */
	struct in6_addr lease;

	/** Retransmission timer */
	struct retry_timer timer;

	/** Current session state */
	struct dhcpv6_session_state *state;
	/** Current timeout status code */
	int rc;
};

/**
 * Free DHCPv6 session
 *
 * @v refcnt		Reference count
 */
static void dhcpv6_free ( struct refcnt *refcnt ) {
	struct dhcpv6_session *dhcpv6 =
		container_of ( refcnt, struct dhcpv6_session, refcnt );

	netdev_put ( dhcpv6->netdev );
	free ( dhcpv6->server_duid );
	free ( dhcpv6 );
}

/**
 * Terminate DHCPv6 session
 *
 * @v dhcpv6		DHCPv6 session
 * @v rc		Reason for close
 */
static void dhcpv6_finished ( struct dhcpv6_session *dhcpv6, int rc ) {

	/* Stop timer */
	stop_timer ( &dhcpv6->timer );

	/* Shut down interfaces */
	intf_shutdown ( &dhcpv6->xfer, rc );
	intf_shutdown ( &dhcpv6->job, rc );
}

/**
 * Transition to new DHCPv6 session state
 *
 * @v dhcpv6		DHCPv6 session
 * @v state		New session state
 */
static void dhcpv6_set_state ( struct dhcpv6_session *dhcpv6,
			       struct dhcpv6_session_state *state ) {

	DBGC ( dhcpv6, "DHCPv6 %s entering %s state\n", dhcpv6->netdev->name,
	       dhcpv6_type_name ( state->tx_type ) );

	/* Record state */
	dhcpv6->state = state;

	/* Default to -ETIMEDOUT if no more specific error is recorded */
	dhcpv6->rc = -ETIMEDOUT;

	/* Start timer to trigger transmission */
	start_timer_nodelay ( &dhcpv6->timer );
}

/**
 * Get DHCPv6 user class
 *
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret len		Length of user class
 */
static size_t dhcpv6_user_class ( void *data, size_t len ) {
	static const char default_user_class[4] = { 'i', 'P', 'X', 'E' };
	int actual_len;

	/* Fetch user-class setting, if defined */
	actual_len = fetch_raw_setting ( NULL, &user_class_setting, data, len );
	if ( actual_len >= 0 )
		return actual_len;

	/* Otherwise, use the default user class ("iPXE") */
	if ( len > sizeof ( default_user_class ) )
		len = sizeof ( default_user_class );
	memcpy ( data, default_user_class, len );
	return sizeof ( default_user_class );
}

/**
 * Transmit current request
 *
 * @v dhcpv6		DHCPv6 session
 * @ret rc		Return status code
 */
static int dhcpv6_tx ( struct dhcpv6_session *dhcpv6 ) {
	struct dhcpv6_duid_option *client_id;
	struct dhcpv6_duid_option *server_id;
	struct dhcpv6_ia_na_option *ia_na;
	struct dhcpv6_iaaddr_option *iaaddr;
	struct dhcpv6_option_request_option *option_request;
	struct dhcpv6_user_class_option *user_class;
	struct dhcpv6_elapsed_time_option *elapsed;
	struct dhcpv6_header *dhcphdr;
	struct io_buffer *iobuf;
	size_t client_id_len;
	size_t server_id_len;
	size_t ia_na_len;
	size_t option_request_len;
	size_t user_class_string_len;
	size_t user_class_len;
	size_t elapsed_len;
	size_t total_len;
	int rc;

	/* Calculate lengths */
	client_id_len = ( sizeof ( *client_id ) +
			  sizeof ( dhcpv6->client_duid ) );
	server_id_len = ( dhcpv6->server_duid ? ( sizeof ( *server_id ) +
						  dhcpv6->server_duid_len ) :0);
	if ( dhcpv6->state->flags & DHCPV6_TX_IA_NA ) {
		ia_na_len = sizeof ( *ia_na );
		if ( dhcpv6->state->flags & DHCPV6_TX_IAADDR )
			ia_na_len += sizeof ( *iaaddr );
	} else {
		ia_na_len = 0;
	}
	option_request_len = ( sizeof ( *option_request ) +
			       sizeof ( dhcpv6_requested_options ) );
	user_class_string_len = dhcpv6_user_class ( NULL, 0 );
	user_class_len = ( sizeof ( *user_class ) +
			   sizeof ( user_class->user_class[0] ) +
			   user_class_string_len );
	elapsed_len = sizeof ( *elapsed );
	total_len = ( sizeof ( *dhcphdr ) + client_id_len + server_id_len +
		      ia_na_len + option_request_len + user_class_len +
		      elapsed_len );

	/* Allocate packet */
	iobuf = xfer_alloc_iob ( &dhcpv6->xfer, total_len );
	if ( ! iobuf )
		return -ENOMEM;

	/* Construct header */
	dhcphdr = iob_put ( iobuf, sizeof ( *dhcphdr ) );
	dhcphdr->type = dhcpv6->state->tx_type;
	memcpy ( dhcphdr->xid, dhcpv6->xid, sizeof ( dhcphdr->xid ) );

	/* Construct client identifier */
	client_id = iob_put ( iobuf, client_id_len );
	client_id->header.code = htons ( DHCPV6_CLIENT_ID );
	client_id->header.len = htons ( client_id_len -
					sizeof ( client_id->header ) );
	memcpy ( client_id->duid, &dhcpv6->client_duid,
		 sizeof ( dhcpv6->client_duid ) );

	/* Construct server identifier, if applicable */
	if ( server_id_len ) {
		server_id = iob_put ( iobuf, server_id_len );
		server_id->header.code = htons ( DHCPV6_SERVER_ID );
		server_id->header.len = htons ( server_id_len -
						sizeof ( server_id->header ) );
		memcpy ( server_id->duid, dhcpv6->server_duid,
			 dhcpv6->server_duid_len );
	}

	/* Construct identity association, if applicable */
	if ( ia_na_len ) {
		ia_na = iob_put ( iobuf, ia_na_len );
		ia_na->header.code = htons ( DHCPV6_IA_NA );
		ia_na->header.len = htons ( ia_na_len -
					    sizeof ( ia_na->header ) );
		ia_na->iaid = htonl ( dhcpv6->iaid );
		ia_na->renew = htonl ( 0 );
		ia_na->rebind = htonl ( 0 );
		if ( dhcpv6->state->flags & DHCPV6_TX_IAADDR ) {
			iaaddr = ( ( void * ) ia_na->options );
			iaaddr->header.code = htons ( DHCPV6_IAADDR );
			iaaddr->header.len = htons ( sizeof ( *iaaddr ) -
						     sizeof ( iaaddr->header ));
			memcpy ( &iaaddr->address, &dhcpv6->lease,
				 sizeof ( iaaddr->address ) );
			iaaddr->preferred = htonl ( 0 );
			iaaddr->valid = htonl ( 0 );
		}
	}

	/* Construct option request */
	option_request = iob_put ( iobuf, option_request_len );
	option_request->header.code = htons ( DHCPV6_OPTION_REQUEST );
	option_request->header.len = htons ( option_request_len -
					     sizeof ( option_request->header ));
	memcpy ( option_request->requested, dhcpv6_requested_options,
		 sizeof ( dhcpv6_requested_options ) );

	/* Construct user class */
	user_class = iob_put ( iobuf, user_class_len );
	user_class->header.code = htons ( DHCPV6_USER_CLASS );
	user_class->header.len = htons ( user_class_len -
					 sizeof ( user_class->header ) );
	user_class->user_class[0].len = htons ( user_class_string_len );
	dhcpv6_user_class ( user_class->user_class[0].string,
			    user_class_string_len );

	/* Construct elapsed time */
	elapsed = iob_put ( iobuf, elapsed_len );
	elapsed->header.code = htons ( DHCPV6_ELAPSED_TIME );
	elapsed->header.len = htons ( elapsed_len -
				      sizeof ( elapsed->header ) );
	elapsed->elapsed = htons ( ( ( currticks() - dhcpv6->start ) * 100 ) /
				   TICKS_PER_SEC );

	/* Sanity check */
	assert ( iob_len ( iobuf ) == total_len );

	/* Transmit packet */
	if ( ( rc = xfer_deliver_iob ( &dhcpv6->xfer, iobuf ) ) != 0 ) {
		DBGC ( dhcpv6, "DHCPv6 %s could not transmit: %s\n",
		       dhcpv6->netdev->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Handle timer expiry
 *
 * @v timer		Retransmission timer
 * @v fail		Failure indicator
 */
static void dhcpv6_timer_expired ( struct retry_timer *timer, int fail ) {
	struct dhcpv6_session *dhcpv6 =
		container_of ( timer, struct dhcpv6_session, timer );

	/* If we have failed, terminate DHCPv6 */
	if ( fail ) {
		dhcpv6_finished ( dhcpv6, dhcpv6->rc );
		return;
	}

	/* Restart timer */
	start_timer ( &dhcpv6->timer );

	/* (Re)transmit current request */
	dhcpv6_tx ( dhcpv6 );
}

/**
 * Receive new data
 *
 * @v dhcpv6		DHCPv6 session
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int dhcpv6_rx ( struct dhcpv6_session *dhcpv6,
		       struct io_buffer *iobuf,
		       struct xfer_metadata *meta ) {
	struct settings *parent = netdev_settings ( dhcpv6->netdev );
	struct sockaddr_in6 *src = ( ( struct sockaddr_in6 * ) meta->src );
	struct dhcpv6_header *dhcphdr = iobuf->data;
	struct dhcpv6_option_list options;
	const union dhcpv6_any_option *option;
	int rc;

	/* Sanity checks */
	if ( iob_len ( iobuf ) < sizeof ( *dhcphdr ) ) {
		DBGC ( dhcpv6, "DHCPv6 %s received packet too short (%zd "
		       "bytes, min %zd bytes)\n", dhcpv6->netdev->name,
		       iob_len ( iobuf ), sizeof ( *dhcphdr ) );
		rc = -EINVAL;
		goto done;
	}
	assert ( src != NULL );
	assert ( src->sin6_family == AF_INET6 );
	DBGC ( dhcpv6, "DHCPv6 %s received %s from %s\n",
	       dhcpv6->netdev->name, dhcpv6_type_name ( dhcphdr->type ),
	       inet6_ntoa ( &src->sin6_addr ) );

	/* Construct option list */
	options.data = dhcphdr->options;
	options.len = ( iob_len ( iobuf ) -
			offsetof ( typeof ( *dhcphdr ), options ) );

	/* Verify client identifier */
	if ( ( rc = dhcpv6_check_duid ( &options, DHCPV6_CLIENT_ID,
					&dhcpv6->client_duid,
					sizeof ( dhcpv6->client_duid ) ) ) !=0){
		DBGC ( dhcpv6, "DHCPv6 %s received %s without correct client "
		       "ID: %s\n", dhcpv6->netdev->name,
		       dhcpv6_type_name ( dhcphdr->type ), strerror ( rc ) );
		goto done;
	}

	/* Verify server identifier, if applicable */
	if ( dhcpv6->server_duid &&
	     ( ( rc = dhcpv6_check_duid ( &options, DHCPV6_SERVER_ID,
					  dhcpv6->server_duid,
					  dhcpv6->server_duid_len ) ) != 0 ) ) {
		DBGC ( dhcpv6, "DHCPv6 %s received %s without correct server "
		       "ID: %s\n", dhcpv6->netdev->name,
		       dhcpv6_type_name ( dhcphdr->type ), strerror ( rc ) );
		goto done;
	}

	/* Check message type */
	if ( dhcphdr->type != dhcpv6->state->rx_type ) {
		DBGC ( dhcpv6, "DHCPv6 %s received %s while expecting %s\n",
		       dhcpv6->netdev->name, dhcpv6_type_name ( dhcphdr->type ),
		       dhcpv6_type_name ( dhcpv6->state->rx_type ) );
		rc = -ENOTTY;
		goto done;
	}

	/* Fetch status code, if present */
	if ( ( rc = dhcpv6_status_code ( &options ) ) != 0 ) {
		DBGC ( dhcpv6, "DHCPv6 %s received %s with error status: %s\n",
		       dhcpv6->netdev->name, dhcpv6_type_name ( dhcphdr->type ),
		       strerror ( rc ) );
		/* This is plausibly the error we want to return */
		dhcpv6->rc = rc;
		goto done;
	}

	/* Record identity association address, if applicable */
	if ( dhcpv6->state->flags & DHCPV6_RX_RECORD_IAADDR ) {
		if ( ( rc = dhcpv6_iaaddr ( &options, dhcpv6->iaid,
					    &dhcpv6->lease ) ) != 0 ) {
			DBGC ( dhcpv6, "DHCPv6 %s received %s with unusable "
			       "IAADDR: %s\n", dhcpv6->netdev->name,
			       dhcpv6_type_name ( dhcphdr->type ),
			       strerror ( rc ) );
			/* This is plausibly the error we want to return */
			dhcpv6->rc = rc;
			goto done;
		}
		DBGC ( dhcpv6, "DHCPv6 %s received %s is for %s\n",
		       dhcpv6->netdev->name, dhcpv6_type_name ( dhcphdr->type ),
		       inet6_ntoa ( &dhcpv6->lease ) );
	}

	/* Record server ID, if applicable */
	if ( dhcpv6->state->flags & DHCPV6_RX_RECORD_SERVER_ID ) {
		assert ( dhcpv6->server_duid == NULL );
		option = dhcpv6_option ( &options, DHCPV6_SERVER_ID );
		if ( ! option ) {
			DBGC ( dhcpv6, "DHCPv6 %s received %s missing server "
			       "ID\n", dhcpv6->netdev->name,
			       dhcpv6_type_name ( dhcphdr->type ) );
			rc = -EINVAL;
			goto done;
		}
		dhcpv6->server_duid_len = ntohs ( option->duid.header.len );
		dhcpv6->server_duid = malloc ( dhcpv6->server_duid_len );
		if ( ! dhcpv6->server_duid ) {
			rc = -ENOMEM;
			goto done;
		}
		memcpy ( dhcpv6->server_duid, option->duid.duid,
			 dhcpv6->server_duid_len );
	}

	/* Apply identity association address, if applicable */
	if ( dhcpv6->state->flags & DHCPV6_RX_APPLY_IAADDR ) {
		if ( ( rc = ipv6_set_address ( dhcpv6->netdev,
					       &dhcpv6->lease ) ) != 0 ) {
			DBGC ( dhcpv6, "DHCPv6 %s could not apply %s: %s\n",
			       dhcpv6->netdev->name,
			       inet6_ntoa ( &dhcpv6->lease ), strerror ( rc ) );
			/* This is plausibly the error we want to return */
			dhcpv6->rc = rc;
			goto done;
		}
	}

	/* Transition to next state or complete DHCPv6, as applicable */
	if ( dhcpv6->state->next ) {

		/* Transition to next state */
		dhcpv6_set_state ( dhcpv6, dhcpv6->state->next );
		rc = 0;

	} else {

		/* Register settings */
		if ( ( rc = dhcpv6_register ( &options, parent ) ) != 0 ) {
			DBGC ( dhcpv6, "DHCPv6 %s could not register "
			       "settings: %s\n", dhcpv6->netdev->name,
			       strerror ( rc ) );
			goto done;
		}

		/* Mark as complete */
		dhcpv6_finished ( dhcpv6, 0 );
		DBGC ( dhcpv6, "DHCPv6 %s complete\n", dhcpv6->netdev->name );
	}

 done:
	free_iob ( iobuf );
	return rc;
}

/** DHCPv6 job control interface operations */
static struct interface_operation dhcpv6_job_op[] = {
	INTF_OP ( intf_close, struct dhcpv6_session *, dhcpv6_finished ),
};

/** DHCPv6 job control interface descriptor */
static struct interface_descriptor dhcpv6_job_desc =
	INTF_DESC ( struct dhcpv6_session, job, dhcpv6_job_op );

/** DHCPv6 data transfer interface operations */
static struct interface_operation dhcpv6_xfer_op[] = {
	INTF_OP ( xfer_deliver, struct dhcpv6_session *, dhcpv6_rx ),
};

/** DHCPv6 data transfer interface descriptor */
static struct interface_descriptor dhcpv6_xfer_desc =
	INTF_DESC ( struct dhcpv6_session, xfer, dhcpv6_xfer_op );

/**
 * Start DHCPv6
 *
 * @v job		Job control interface
 * @v netdev		Network device
 * @v stateful		Perform stateful address autoconfiguration
 * @ret rc		Return status code
 */
int start_dhcpv6 ( struct interface *job, struct net_device *netdev,
		   int stateful ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	struct dhcpv6_session *dhcpv6;
	struct {
		union {
			struct sockaddr_in6 sin6;
			struct sockaddr sa;
		} client;
		union {
			struct sockaddr_in6 sin6;
			struct sockaddr sa;
		} server;
	} addresses;
	uint32_t xid;
	int len;
	int rc;

	/* Allocate and initialise structure */
	dhcpv6 = zalloc ( sizeof ( *dhcpv6 ) );
	if ( ! dhcpv6 )
		return -ENOMEM;
	ref_init ( &dhcpv6->refcnt, dhcpv6_free );
	intf_init ( &dhcpv6->job, &dhcpv6_job_desc, &dhcpv6->refcnt );
	intf_init ( &dhcpv6->xfer, &dhcpv6_xfer_desc, &dhcpv6->refcnt );
	dhcpv6->netdev = netdev_get ( netdev );
	xid = random();
	memcpy ( dhcpv6->xid, &xid, sizeof ( dhcpv6->xid ) );
	dhcpv6->start = currticks();
	timer_init ( &dhcpv6->timer, dhcpv6_timer_expired, &dhcpv6->refcnt );

	/* Construct client and server addresses */
	memset ( &addresses, 0, sizeof ( addresses ) );
	addresses.client.sin6.sin6_family = AF_INET6;
	addresses.client.sin6.sin6_port = htons ( DHCPV6_CLIENT_PORT );
	addresses.server.sin6.sin6_family = AF_INET6;
	ipv6_all_dhcp_relay_and_servers ( &addresses.server.sin6.sin6_addr );
	addresses.server.sin6.sin6_scope_id = netdev->index;
	addresses.server.sin6.sin6_port = htons ( DHCPV6_SERVER_PORT );

	/* Construct client DUID from system UUID */
	dhcpv6->client_duid.type = htons ( DHCPV6_DUID_UUID );
	if ( ( len = fetch_uuid_setting ( NULL, &uuid_setting,
					  &dhcpv6->client_duid.uuid ) ) < 0 ) {
		rc = len;
		DBGC ( dhcpv6, "DHCPv6 %s could not create DUID-UUID: %s\n",
		       dhcpv6->netdev->name, strerror ( rc ) );
		goto err_client_duid;
	}

	/* Construct IAID from link-layer address */
	dhcpv6->iaid = crc32_le ( 0, netdev->ll_addr, ll_protocol->ll_addr_len);
	DBGC ( dhcpv6, "DHCPv6 %s has XID %02x%02x%02x\n", dhcpv6->netdev->name,
	       dhcpv6->xid[0], dhcpv6->xid[1], dhcpv6->xid[2] );

	/* Enter initial state */
	dhcpv6_set_state ( dhcpv6, ( stateful ? &dhcpv6_solicit :
				     &dhcpv6_information_request ) );

	/* Open socket */
	if ( ( rc = xfer_open_socket ( &dhcpv6->xfer, SOCK_DGRAM,
				       &addresses.server.sa,
				       &addresses.client.sa ) ) != 0 ) {
		DBGC ( dhcpv6, "DHCPv6 %s could not open socket: %s\n",
		       dhcpv6->netdev->name, strerror ( rc ) );
		goto err_open_socket;
	}

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &dhcpv6->job, job );
	ref_put ( &dhcpv6->refcnt );
	return 0;

 err_open_socket:
	dhcpv6_finished ( dhcpv6, rc );
 err_client_duid:
	ref_put ( &dhcpv6->refcnt );
	return rc;
}

/** Boot filename setting */
const struct setting filename6_setting __setting ( SETTING_BOOT, filename ) = {
	.name = "filename",
	.description = "Boot filename",
	.tag = DHCPV6_BOOTFILE_URL,
	.type = &setting_type_string,
	.scope = &ipv6_scope,
};

/** DNS search list setting */
const struct setting dnssl6_setting __setting ( SETTING_IP_EXTRA, dnssl ) = {
	.name = "dnssl",
	.description = "DNS search list",
	.tag = DHCPV6_DOMAIN_LIST,
	.type = &setting_type_dnssl,
	.scope = &ipv6_scope,
};
