/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/device.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/job.h>
#include <ipxe/retry.h>
#include <ipxe/tcpip.h>
#include <ipxe/ip.h>
#include <ipxe/uuid.h>
#include <ipxe/timer.h>
#include <ipxe/settings.h>
#include <ipxe/dhcp.h>
#include <ipxe/dhcpopts.h>
#include <ipxe/dhcppkt.h>
#include <ipxe/dhcp_arch.h>
#include <ipxe/features.h>
#include <config/dhcp.h>

/** @file
 *
 * Dynamic Host Configuration Protocol
 *
 */

struct dhcp_session;
static int dhcp_tx ( struct dhcp_session *dhcp );

/**
 * DHCP operation types
 *
 * This table maps from DHCP message types (i.e. values of the @c
 * DHCP_MESSAGE_TYPE option) to values of the "op" field within a DHCP
 * packet.
 */
static const uint8_t dhcp_op[] = {
	[DHCPDISCOVER]	= BOOTP_REQUEST,
	[DHCPOFFER]	= BOOTP_REPLY,
	[DHCPREQUEST]	= BOOTP_REQUEST,
	[DHCPDECLINE]	= BOOTP_REQUEST,
	[DHCPACK]	= BOOTP_REPLY,
	[DHCPNAK]	= BOOTP_REPLY,
	[DHCPRELEASE]	= BOOTP_REQUEST,
	[DHCPINFORM]	= BOOTP_REQUEST,
};

/** Raw option data for options common to all DHCP requests */
static uint8_t dhcp_request_options_data[] = {
	DHCP_MESSAGE_TYPE, DHCP_BYTE ( 0 ),
	DHCP_MAX_MESSAGE_SIZE,
	DHCP_WORD ( ETH_MAX_MTU - 20 /* IP header */ - 8 /* UDP header */ ),
	DHCP_CLIENT_ARCHITECTURE, DHCP_ARCH_CLIENT_ARCHITECTURE,
	DHCP_CLIENT_NDI, DHCP_ARCH_CLIENT_NDI,
	DHCP_VENDOR_CLASS_ID, DHCP_ARCH_VENDOR_CLASS_ID,
	DHCP_USER_CLASS_ID, DHCP_STRING ( 'i', 'P', 'X', 'E' ),
	DHCP_PARAMETER_REQUEST_LIST,
	DHCP_OPTION ( DHCP_SUBNET_MASK, DHCP_ROUTERS, DHCP_DNS_SERVERS,
		      DHCP_LOG_SERVERS, DHCP_HOST_NAME, DHCP_DOMAIN_NAME,
		      DHCP_ROOT_PATH, DHCP_VENDOR_ENCAP, DHCP_VENDOR_CLASS_ID,
		      DHCP_TFTP_SERVER_NAME, DHCP_BOOTFILE_NAME,
		      DHCP_DOMAIN_SEARCH,
		      128, 129, 130, 131, 132, 133, 134, 135, /* for PXE */
		      DHCP_EB_ENCAP, DHCP_ISCSI_INITIATOR_IQN ),
	DHCP_END
};

/** DHCP server address setting */
const struct setting dhcp_server_setting __setting ( SETTING_MISC,
						     dhcp-server ) = {
	.name = "dhcp-server",
	.description = "DHCP server",
	.tag = DHCP_SERVER_IDENTIFIER,
	.type = &setting_type_ipv4,
};

/**
 * Most recent DHCP transaction ID
 *
 * This is exposed for use by the fakedhcp code when reconstructing
 * DHCP packets for PXE NBPs.
 */
uint32_t dhcp_last_xid;

/**
 * Name a DHCP packet type
 *
 * @v msgtype		DHCP message type
 * @ret string		DHCP mesasge type name
 */
static inline const char * dhcp_msgtype_name ( unsigned int msgtype ) {
	switch ( msgtype ) {
	case DHCPNONE:		return "BOOTP"; /* Non-DHCP packet */
	case DHCPDISCOVER:	return "DHCPDISCOVER";
	case DHCPOFFER:		return "DHCPOFFER";
	case DHCPREQUEST:	return "DHCPREQUEST";
	case DHCPDECLINE:	return "DHCPDECLINE";
	case DHCPACK:		return "DHCPACK";
	case DHCPNAK:		return "DHCPNAK";
	case DHCPRELEASE:	return "DHCPRELEASE";
	case DHCPINFORM:	return "DHCPINFORM";
	default:		return "DHCP<invalid>";
	}
}

/****************************************************************************
 *
 * DHCP session
 *
 */

struct dhcp_session;

/** DHCP session state operations */
struct dhcp_session_state {
	/** State name */
	const char *name;
	/**
	 * Construct transmitted packet
	 *
	 * @v dhcp		DHCP session
	 * @v dhcppkt		DHCP packet
	 * @v peer		Destination address
	 */
	int ( * tx ) ( struct dhcp_session *dhcp, struct dhcp_packet *dhcppkt,
		       struct sockaddr_in *peer );
	/**
	 * Handle received packet
	 *
	 * @v dhcp		DHCP session
	 * @v dhcppkt		DHCP packet
	 * @v peer		DHCP server address
	 * @v msgtype		DHCP message type
	 * @v server_id		DHCP server ID
	 * @v pseudo_id		DHCP server pseudo-ID
	 */
	void ( * rx ) ( struct dhcp_session *dhcp, struct dhcp_packet *dhcppkt,
			struct sockaddr_in *peer, uint8_t msgtype,
			struct in_addr server_id, struct in_addr pseudo_id );
	/**
	 * Handle timer expiry
	 *
	 * @v dhcp		DHCP session
	 */
	void ( * expired ) ( struct dhcp_session *dhcp );
	/** Transmitted message type */
	uint8_t tx_msgtype;
	/** Timeout parameters */
	uint8_t min_timeout_sec;
	uint8_t max_timeout_sec;
};

static struct dhcp_session_state dhcp_state_discover;
static struct dhcp_session_state dhcp_state_request;
static struct dhcp_session_state dhcp_state_proxy;
static struct dhcp_session_state dhcp_state_pxebs;

/** A DHCP session */
struct dhcp_session {
	/** Reference counter */
	struct refcnt refcnt;
	/** Job control interface */
	struct interface job;
	/** Data transfer interface */
	struct interface xfer;

	/** Network device being configured */
	struct net_device *netdev;
	/** Local socket address */
	struct sockaddr_in local;
	/** State of the session */
	struct dhcp_session_state *state;
	/** Transaction ID (in network-endian order) */
	uint32_t xid;

	/** Offered IP address */
	struct in_addr offer;
	/** DHCP server */
	struct in_addr server;
	/** DHCP offer priority */
	int priority;

	/** ProxyDHCP protocol extensions should be ignored */
	int no_pxedhcp;
	/** ProxyDHCP server */
	struct in_addr proxy_server;
	/** ProxyDHCP offer */
	struct dhcp_packet *proxy_offer;
	/** ProxyDHCP offer priority */
	int proxy_priority;

	/** PXE Boot Server type */
	uint16_t pxe_type;
	/** List of PXE Boot Servers to attempt */
	struct in_addr *pxe_attempt;
	/** List of PXE Boot Servers to accept */
	struct in_addr *pxe_accept;

	/** Retransmission timer */
	struct retry_timer timer;
	/** Transmission counter */
	unsigned int count;
	/** Start time of the current state (in ticks) */
	unsigned long start;
};

/**
 * Free DHCP session
 *
 * @v refcnt		Reference counter
 */
static void dhcp_free ( struct refcnt *refcnt ) {
	struct dhcp_session *dhcp =
		container_of ( refcnt, struct dhcp_session, refcnt );

	netdev_put ( dhcp->netdev );
	dhcppkt_put ( dhcp->proxy_offer );
	free ( dhcp );
}

/**
 * Mark DHCP session as complete
 *
 * @v dhcp		DHCP session
 * @v rc		Return status code
 */
static void dhcp_finished ( struct dhcp_session *dhcp, int rc ) {

	/* Stop retry timer */
	stop_timer ( &dhcp->timer );

	/* Shut down interfaces */
	intf_shutdown ( &dhcp->xfer, rc );
	intf_shutdown ( &dhcp->job, rc );
}

/**
 * Transition to new DHCP session state
 *
 * @v dhcp		DHCP session
 * @v state		New session state
 */
static void dhcp_set_state ( struct dhcp_session *dhcp,
			     struct dhcp_session_state *state ) {

	DBGC ( dhcp, "DHCP %p entering %s state\n", dhcp, state->name );
	dhcp->state = state;
	dhcp->start = currticks();
	stop_timer ( &dhcp->timer );
	set_timer_limits ( &dhcp->timer,
			   ( state->min_timeout_sec * TICKS_PER_SEC ),
			   ( state->max_timeout_sec * TICKS_PER_SEC ) );
	start_timer_nodelay ( &dhcp->timer );
}

/**
 * Check if DHCP packet contains PXE options
 *
 * @v dhcppkt		DHCP packet
 * @ret has_pxeopts	DHCP packet contains PXE options
 *
 * It is assumed that the packet is already known to contain option 60
 * set to "PXEClient".
 */
static int dhcp_has_pxeopts ( struct dhcp_packet *dhcppkt ) {

	/* Check for a boot filename */
	if ( dhcppkt_fetch ( dhcppkt, DHCP_BOOTFILE_NAME, NULL, 0 ) > 0 )
		return 1;

	/* Check for a PXE boot menu */
	if ( dhcppkt_fetch ( dhcppkt, DHCP_PXE_BOOT_MENU, NULL, 0 ) > 0 )
		return 1;

	return 0;
}

/****************************************************************************
 *
 * DHCP state machine
 *
 */

/**
 * Construct transmitted packet for DHCP discovery
 *
 * @v dhcp		DHCP session
 * @v dhcppkt		DHCP packet
 * @v peer		Destination address
 */
static int dhcp_discovery_tx ( struct dhcp_session *dhcp,
			       struct dhcp_packet *dhcppkt __unused,
			       struct sockaddr_in *peer ) {

	DBGC ( dhcp, "DHCP %p DHCPDISCOVER\n", dhcp );

	/* Set server address */
	peer->sin_addr.s_addr = INADDR_BROADCAST;
	peer->sin_port = htons ( BOOTPS_PORT );

	return 0;
}

/**
 * Handle received packet during DHCP discovery
 *
 * @v dhcp		DHCP session
 * @v dhcppkt		DHCP packet
 * @v peer		DHCP server address
 * @v msgtype		DHCP message type
 * @v server_id		DHCP server ID
 * @v pseudo_id		DHCP server pseudo-ID
 */
static void dhcp_discovery_rx ( struct dhcp_session *dhcp,
				struct dhcp_packet *dhcppkt,
				struct sockaddr_in *peer, uint8_t msgtype,
				struct in_addr server_id,
				struct in_addr pseudo_id ) {
	struct in_addr ip;
	char vci[9]; /* "PXEClient" */
	int vci_len;
	int has_pxeclient;
	int8_t priority = 0;
	uint8_t no_pxedhcp = 0;
	unsigned long elapsed;

	DBGC ( dhcp, "DHCP %p %s from %s:%d", dhcp,
	       dhcp_msgtype_name ( msgtype ), inet_ntoa ( peer->sin_addr ),
	       ntohs ( peer->sin_port ) );
	if ( ( server_id.s_addr != peer->sin_addr.s_addr ) ||
	     ( pseudo_id.s_addr != peer->sin_addr.s_addr ) ) {
		DBGC ( dhcp, " (%s/", inet_ntoa ( server_id ) );
		DBGC ( dhcp, "%s)", inet_ntoa ( pseudo_id ) );
	}

	/* Identify offered IP address */
	ip = dhcppkt->dhcphdr->yiaddr;
	if ( ip.s_addr )
		DBGC ( dhcp, " for %s", inet_ntoa ( ip ) );

	/* Identify "PXEClient" vendor class */
	vci_len = dhcppkt_fetch ( dhcppkt, DHCP_VENDOR_CLASS_ID,
				  vci, sizeof ( vci ) );
	has_pxeclient = ( ( vci_len >= ( int ) sizeof ( vci ) ) &&
			  ( strncmp ( "PXEClient", vci, sizeof (vci) ) == 0 ));
	if ( has_pxeclient ) {
		DBGC ( dhcp, "%s",
		       ( dhcp_has_pxeopts ( dhcppkt ) ? " pxe" : " proxy" ) );
	}

	/* Identify priority */
	dhcppkt_fetch ( dhcppkt, DHCP_EB_PRIORITY, &priority,
			sizeof ( priority ) );
	if ( priority )
		DBGC ( dhcp, " pri %d", priority );

	/* Identify ignore-PXE flag */
	dhcppkt_fetch ( dhcppkt, DHCP_EB_NO_PXEDHCP, &no_pxedhcp,
			sizeof ( no_pxedhcp ) );
	if ( no_pxedhcp )
		DBGC ( dhcp, " nopxe" );
	DBGC ( dhcp, "\n" );

	/* Select as DHCP offer, if applicable */
	if ( ip.s_addr && ( peer->sin_port == htons ( BOOTPS_PORT ) ) &&
	     ( ( msgtype == DHCPOFFER ) || ( ! msgtype /* BOOTP */ ) ) &&
	     ( priority >= dhcp->priority ) ) {
		dhcp->offer = ip;
		dhcp->server = server_id;
		dhcp->priority = priority;
		dhcp->no_pxedhcp = no_pxedhcp;
	}

	/* Select as ProxyDHCP offer, if applicable */
	if ( pseudo_id.s_addr && has_pxeclient &&
	     ( priority >= dhcp->proxy_priority ) ) {
		dhcppkt_put ( dhcp->proxy_offer );
		dhcp->proxy_server = pseudo_id;
		dhcp->proxy_offer = dhcppkt_get ( dhcppkt );
		dhcp->proxy_priority = priority;
	}

	/* We can exit the discovery state when we have a valid
	 * DHCPOFFER, and either:
	 *
	 *  o  The DHCPOFFER instructs us to ignore ProxyDHCPOFFERs, or
	 *  o  We have a valid ProxyDHCPOFFER, or
	 *  o  We have allowed sufficient time for ProxyDHCPOFFERs.
	 */

	/* If we don't yet have a DHCPOFFER, do nothing */
	if ( ! dhcp->offer.s_addr )
		return;

	/* If we can't yet transition to DHCPREQUEST, do nothing */
	elapsed = ( currticks() - dhcp->start );
	if ( ! ( dhcp->no_pxedhcp || dhcp->proxy_offer ||
		 ( elapsed > DHCP_DISC_PROXY_TIMEOUT_SEC * TICKS_PER_SEC ) ) )
		return;

	/* Transition to DHCPREQUEST */
	dhcp_set_state ( dhcp, &dhcp_state_request );
}

/**
 * Handle timer expiry during DHCP discovery
 *
 * @v dhcp		DHCP session
 */
static void dhcp_discovery_expired ( struct dhcp_session *dhcp ) {
	unsigned long elapsed = ( currticks() - dhcp->start );

	/* If link is blocked, defer DHCP discovery (and reset timeout) */
	if ( netdev_link_blocked ( dhcp->netdev ) ) {
		DBGC ( dhcp, "DHCP %p deferring discovery\n", dhcp );
		start_timer_fixed ( &dhcp->timer,
				    ( DHCP_DISC_START_TIMEOUT_SEC *
				      TICKS_PER_SEC ) );
		return;
	}

	/* Give up waiting for ProxyDHCP before we reach the failure point */
	if ( dhcp->offer.s_addr &&
	     ( elapsed > DHCP_DISC_PROXY_TIMEOUT_SEC * TICKS_PER_SEC ) ) {
		dhcp_set_state ( dhcp, &dhcp_state_request );
		return;
	}

	/* Otherwise, retransmit current packet */
	dhcp_tx ( dhcp );
}

/** DHCP discovery state operations */
static struct dhcp_session_state dhcp_state_discover = {
	.name			= "discovery",
	.tx			= dhcp_discovery_tx,
	.rx			= dhcp_discovery_rx,
	.expired		= dhcp_discovery_expired,
	.tx_msgtype		= DHCPDISCOVER,
	.min_timeout_sec	= DHCP_DISC_START_TIMEOUT_SEC,
	.max_timeout_sec	= DHCP_DISC_END_TIMEOUT_SEC,
};

/**
 * Construct transmitted packet for DHCP request
 *
 * @v dhcp		DHCP session
 * @v dhcppkt		DHCP packet
 * @v peer		Destination address
 */
static int dhcp_request_tx ( struct dhcp_session *dhcp,
			     struct dhcp_packet *dhcppkt,
			     struct sockaddr_in *peer ) {
	int rc;

	DBGC ( dhcp, "DHCP %p DHCPREQUEST to %s:%d",
	       dhcp, inet_ntoa ( dhcp->server ), BOOTPS_PORT );
	DBGC ( dhcp, " for %s\n", inet_ntoa ( dhcp->offer ) );

	/* Set server ID */
	if ( ( rc = dhcppkt_store ( dhcppkt, DHCP_SERVER_IDENTIFIER,
				    &dhcp->server,
				    sizeof ( dhcp->server ) ) ) != 0 )
		return rc;

	/* Set requested IP address */
	if ( ( rc = dhcppkt_store ( dhcppkt, DHCP_REQUESTED_ADDRESS,
				    &dhcp->offer,
				    sizeof ( dhcp->offer ) ) ) != 0 )
		return rc;

	/* Set server address */
	peer->sin_addr.s_addr = INADDR_BROADCAST;
	peer->sin_port = htons ( BOOTPS_PORT );

	return 0;
}

/**
 * Handle received packet during DHCP request
 *
 * @v dhcp		DHCP session
 * @v dhcppkt		DHCP packet
 * @v peer		DHCP server address
 * @v msgtype		DHCP message type
 * @v server_id		DHCP server ID
 * @v pseudo_id		DHCP server pseudo-ID
 */
static void dhcp_request_rx ( struct dhcp_session *dhcp,
			      struct dhcp_packet *dhcppkt,
			      struct sockaddr_in *peer, uint8_t msgtype,
			      struct in_addr server_id,
			      struct in_addr pseudo_id ) {
	struct in_addr ip;
	struct settings *parent;
	struct settings *settings;
	int rc;

	DBGC ( dhcp, "DHCP %p %s from %s:%d", dhcp,
	       dhcp_msgtype_name ( msgtype ), inet_ntoa ( peer->sin_addr ),
	       ntohs ( peer->sin_port ) );
	if ( ( server_id.s_addr != peer->sin_addr.s_addr ) ||
	     ( pseudo_id.s_addr != peer->sin_addr.s_addr ) ) {
		DBGC ( dhcp, " (%s/", inet_ntoa ( server_id ) );
		DBGC ( dhcp, "%s)", inet_ntoa ( pseudo_id ) );
	}

	/* Identify leased IP address */
	ip = dhcppkt->dhcphdr->yiaddr;
	if ( ip.s_addr )
		DBGC ( dhcp, " for %s", inet_ntoa ( ip ) );
	DBGC ( dhcp, "\n" );

	/* Filter out unacceptable responses */
	if ( peer->sin_port != htons ( BOOTPS_PORT ) )
		return;
	if ( msgtype /* BOOTP */ && ( msgtype != DHCPACK ) )
		return;
	if ( server_id.s_addr != dhcp->server.s_addr )
		return;
	if ( ip.s_addr != dhcp->offer.s_addr )
		return;

	/* Record assigned address */
	dhcp->local.sin_addr = ip;

	/* Register settings */
	parent = netdev_settings ( dhcp->netdev );
	settings = &dhcppkt->settings;
	if ( ( rc = register_settings ( settings, parent,
					DHCP_SETTINGS_NAME ) ) != 0 ) {
		DBGC ( dhcp, "DHCP %p could not register settings: %s\n",
		       dhcp, strerror ( rc ) );
		dhcp_finished ( dhcp, rc );
		return;
	}

	/* Perform ProxyDHCP if applicable */
	if ( dhcp->proxy_offer /* Have ProxyDHCP offer */ &&
	     ( ! dhcp->no_pxedhcp ) /* ProxyDHCP not disabled */ ) {
		if ( dhcp_has_pxeopts ( dhcp->proxy_offer ) ) {
			/* PXE options already present; register settings
			 * without performing a ProxyDHCPREQUEST
			 */
			settings = &dhcp->proxy_offer->settings;
			if ( ( rc = register_settings ( settings, NULL,
					   PROXYDHCP_SETTINGS_NAME ) ) != 0 ) {
				DBGC ( dhcp, "DHCP %p could not register "
				       "proxy settings: %s\n",
				       dhcp, strerror ( rc ) );
				dhcp_finished ( dhcp, rc );
				return;
			}
		} else {
			/* PXE options not present; use a ProxyDHCPREQUEST */
			dhcp_set_state ( dhcp, &dhcp_state_proxy );
			return;
		}
	}

	/* Terminate DHCP */
	dhcp_finished ( dhcp, 0 );
}

/**
 * Handle timer expiry during DHCP discovery
 *
 * @v dhcp		DHCP session
 */
static void dhcp_request_expired ( struct dhcp_session *dhcp ) {

	/* Retransmit current packet */
	dhcp_tx ( dhcp );
}

/** DHCP request state operations */
static struct dhcp_session_state dhcp_state_request = {
	.name			= "request",
	.tx			= dhcp_request_tx,
	.rx			= dhcp_request_rx,
	.expired		= dhcp_request_expired,
	.tx_msgtype		= DHCPREQUEST,
	.min_timeout_sec	= DHCP_REQ_START_TIMEOUT_SEC,
	.max_timeout_sec	= DHCP_REQ_END_TIMEOUT_SEC,
};

/**
 * Construct transmitted packet for ProxyDHCP request
 *
 * @v dhcp		DHCP session
 * @v dhcppkt		DHCP packet
 * @v peer		Destination address
 */
static int dhcp_proxy_tx ( struct dhcp_session *dhcp,
			   struct dhcp_packet *dhcppkt,
			   struct sockaddr_in *peer ) {
	int rc;

	DBGC ( dhcp, "DHCP %p ProxyDHCP REQUEST to %s\n", dhcp,
	       inet_ntoa ( dhcp->proxy_server ) );

	/* Set server ID */
	if ( ( rc = dhcppkt_store ( dhcppkt, DHCP_SERVER_IDENTIFIER,
				    &dhcp->proxy_server,
				    sizeof ( dhcp->proxy_server ) ) ) != 0 )
		return rc;

	/* Set server address */
	peer->sin_addr = dhcp->proxy_server;
	peer->sin_port = htons ( PXE_PORT );

	return 0;
}

/**
 * Handle received packet during ProxyDHCP request
 *
 * @v dhcp		DHCP session
 * @v dhcppkt		DHCP packet
 * @v peer		DHCP server address
 * @v msgtype		DHCP message type
 * @v server_id		DHCP server ID
 * @v pseudo_id		DHCP server pseudo-ID
 */
static void dhcp_proxy_rx ( struct dhcp_session *dhcp,
			    struct dhcp_packet *dhcppkt,
			    struct sockaddr_in *peer, uint8_t msgtype,
			    struct in_addr server_id,
			    struct in_addr pseudo_id ) {
	struct settings *settings = &dhcppkt->settings;
	int rc;

	DBGC ( dhcp, "DHCP %p %s from %s:%d", dhcp,
	       dhcp_msgtype_name ( msgtype ), inet_ntoa ( peer->sin_addr ),
	       ntohs ( peer->sin_port ) );
	if ( ( server_id.s_addr != peer->sin_addr.s_addr ) ||
	     ( pseudo_id.s_addr != peer->sin_addr.s_addr ) ) {
		DBGC ( dhcp, " (%s/", inet_ntoa ( server_id ) );
		DBGC ( dhcp, "%s)", inet_ntoa ( pseudo_id ) );
	}
	if ( dhcp_has_pxeopts ( dhcppkt ) )
		DBGC ( dhcp, " pxe" );
	DBGC ( dhcp, "\n" );

	/* Filter out unacceptable responses */
	if ( peer->sin_port != ntohs ( PXE_PORT ) )
		return;
	if ( ( msgtype != DHCPOFFER ) && ( msgtype != DHCPACK ) )
		return;
	if ( ( pseudo_id.s_addr != dhcp->proxy_server.s_addr ) )
		return;
	if ( ! dhcp_has_pxeopts ( dhcppkt ) )
		return;

	/* Register settings */
	if ( ( rc = register_settings ( settings, NULL,
					PROXYDHCP_SETTINGS_NAME ) ) != 0 ) {
		DBGC ( dhcp, "DHCP %p could not register proxy settings: %s\n",
		       dhcp, strerror ( rc ) );
		dhcp_finished ( dhcp, rc );
		return;
	}

	/* Terminate DHCP */
	dhcp_finished ( dhcp, 0 );
}

/**
 * Handle timer expiry during ProxyDHCP request
 *
 * @v dhcp		DHCP session
 */
static void dhcp_proxy_expired ( struct dhcp_session *dhcp ) {
	unsigned long elapsed = ( currticks() - dhcp->start );

	/* Give up waiting for ProxyDHCP before we reach the failure point */
	if ( elapsed > DHCP_REQ_PROXY_TIMEOUT_SEC * TICKS_PER_SEC ) {
		dhcp_finished ( dhcp, 0 );
		return;
	}

	/* Retransmit current packet */
	dhcp_tx ( dhcp );
}

/** ProxyDHCP request state operations */
static struct dhcp_session_state dhcp_state_proxy = {
	.name			= "ProxyDHCP",
	.tx			= dhcp_proxy_tx,
	.rx			= dhcp_proxy_rx,
	.expired		= dhcp_proxy_expired,
	.tx_msgtype		= DHCPREQUEST,
	.min_timeout_sec	= DHCP_PROXY_START_TIMEOUT_SEC,
	.max_timeout_sec	= DHCP_PROXY_END_TIMEOUT_SEC,
};

/**
 * Construct transmitted packet for PXE Boot Server Discovery
 *
 * @v dhcp		DHCP session
 * @v dhcppkt		DHCP packet
 * @v peer		Destination address
 */
static int dhcp_pxebs_tx ( struct dhcp_session *dhcp,
			   struct dhcp_packet *dhcppkt,
			   struct sockaddr_in *peer ) {
	struct dhcp_pxe_boot_menu_item menu_item = { 0, 0 };
	int rc;

	/* Set server address */
	peer->sin_addr = *(dhcp->pxe_attempt);
	peer->sin_port = ( ( peer->sin_addr.s_addr == INADDR_BROADCAST ) ?
			   htons ( BOOTPS_PORT ) : htons ( PXE_PORT ) );

	DBGC ( dhcp, "DHCP %p PXEBS REQUEST to %s:%d for type %d\n",
	       dhcp, inet_ntoa ( peer->sin_addr ), ntohs ( peer->sin_port ),
	       le16_to_cpu ( dhcp->pxe_type ) );

	/* Set boot menu item */
	menu_item.type = dhcp->pxe_type;
	if ( ( rc = dhcppkt_store ( dhcppkt, DHCP_PXE_BOOT_MENU_ITEM,
				    &menu_item, sizeof ( menu_item ) ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Check to see if PXE Boot Server address is acceptable
 *
 * @v dhcp		DHCP session
 * @v bs		Boot Server address
 * @ret accept		Boot Server is acceptable
 */
static int dhcp_pxebs_accept ( struct dhcp_session *dhcp,
			       struct in_addr bs ) {
	struct in_addr *accept;

	/* Accept if we have no acceptance filter */
	if ( ! dhcp->pxe_accept )
		return 1;

	/* Scan through acceptance list */
	for ( accept = dhcp->pxe_accept ; accept->s_addr ; accept++ ) {
		if ( accept->s_addr == bs.s_addr )
			return 1;
	}

	DBGC ( dhcp, "DHCP %p rejecting server %s\n",
	       dhcp, inet_ntoa ( bs ) );
	return 0;
}

/**
 * Handle received packet during PXE Boot Server Discovery
 *
 * @v dhcp		DHCP session
 * @v dhcppkt		DHCP packet
 * @v peer		DHCP server address
 * @v msgtype		DHCP message type
 * @v server_id		DHCP server ID
 * @v pseudo_id		DHCP server pseudo-ID
 */
static void dhcp_pxebs_rx ( struct dhcp_session *dhcp,
			    struct dhcp_packet *dhcppkt,
			    struct sockaddr_in *peer, uint8_t msgtype,
			    struct in_addr server_id,
			    struct in_addr pseudo_id ) {
	struct dhcp_pxe_boot_menu_item menu_item = { 0, 0 };
	int rc;

	DBGC ( dhcp, "DHCP %p %s from %s:%d", dhcp,
	       dhcp_msgtype_name ( msgtype ), inet_ntoa ( peer->sin_addr ),
	       ntohs ( peer->sin_port ) );
	if ( ( server_id.s_addr != peer->sin_addr.s_addr ) ||
	     ( pseudo_id.s_addr != peer->sin_addr.s_addr ) ) {
		DBGC ( dhcp, " (%s/", inet_ntoa ( server_id ) );
		DBGC ( dhcp, "%s)", inet_ntoa ( pseudo_id ) );
	}

	/* Identify boot menu item */
	dhcppkt_fetch ( dhcppkt, DHCP_PXE_BOOT_MENU_ITEM,
			&menu_item, sizeof ( menu_item ) );
	if ( menu_item.type )
		DBGC ( dhcp, " for type %d", ntohs ( menu_item.type ) );
	DBGC ( dhcp, "\n" );

	/* Filter out unacceptable responses */
	if ( ( peer->sin_port != htons ( BOOTPS_PORT ) ) &&
	     ( peer->sin_port != htons ( PXE_PORT ) ) )
		return;
	if ( msgtype != DHCPACK )
		return;
	if ( menu_item.type != dhcp->pxe_type )
		return;
	if ( ! dhcp_pxebs_accept ( dhcp, pseudo_id ) )
		return;

	/* Register settings */
	if ( ( rc = register_settings ( &dhcppkt->settings, NULL,
					PXEBS_SETTINGS_NAME ) ) != 0 ) {
		DBGC ( dhcp, "DHCP %p could not register settings: %s\n",
		       dhcp, strerror ( rc ) );
		dhcp_finished ( dhcp, rc );
		return;
	}

	/* Terminate DHCP */
	dhcp_finished ( dhcp, 0 );
}

/**
 * Handle timer expiry during PXE Boot Server Discovery
 *
 * @v dhcp		DHCP session
 */
static void dhcp_pxebs_expired ( struct dhcp_session *dhcp ) {
	unsigned long elapsed = ( currticks() - dhcp->start );

	/* Give up waiting before we reach the failure point, and fail
	 * over to the next server in the attempt list
	 */
	if ( elapsed > PXEBS_MAX_TIMEOUT_SEC * TICKS_PER_SEC ) {
		dhcp->pxe_attempt++;
		if ( dhcp->pxe_attempt->s_addr ) {
			dhcp_set_state ( dhcp, &dhcp_state_pxebs );
			return;
		} else {
			dhcp_finished ( dhcp, -ETIMEDOUT );
			return;
		}
	}

	/* Retransmit current packet */
	dhcp_tx ( dhcp );
}

/** PXE Boot Server Discovery state operations */
static struct dhcp_session_state dhcp_state_pxebs = {
	.name			= "PXEBS",
	.tx			= dhcp_pxebs_tx,
	.rx			= dhcp_pxebs_rx,
	.expired		= dhcp_pxebs_expired,
	.tx_msgtype		= DHCPREQUEST,
	.min_timeout_sec	= PXEBS_START_TIMEOUT_SEC,
	.max_timeout_sec	= PXEBS_END_TIMEOUT_SEC,
};

/****************************************************************************
 *
 * Packet construction
 *
 */

/**
 * Create a DHCP packet
 *
 * @v dhcppkt		DHCP packet structure to fill in
 * @v netdev		Network device
 * @v msgtype		DHCP message type
 * @v xid		Transaction ID (in network-endian order)
 * @v options		Initial options to include (or NULL)
 * @v options_len	Length of initial options
 * @v data		Buffer for DHCP packet
 * @v max_len		Size of DHCP packet buffer
 * @ret rc		Return status code
 *
 * Creates a DHCP packet in the specified buffer, and initialise a
 * DHCP packet structure.
 */
int dhcp_create_packet ( struct dhcp_packet *dhcppkt,
			 struct net_device *netdev, uint8_t msgtype,
			 uint32_t xid, const void *options, size_t options_len,
			 void *data, size_t max_len ) {
	struct dhcphdr *dhcphdr = data;
	int rc;

	/* Sanity check */
	if ( max_len < ( sizeof ( *dhcphdr ) + options_len ) )
		return -ENOSPC;

	/* Initialise DHCP packet content */
	memset ( dhcphdr, 0, max_len );
	dhcphdr->xid = xid;
	dhcphdr->magic = htonl ( DHCP_MAGIC_COOKIE );
	dhcphdr->htype = ntohs ( netdev->ll_protocol->ll_proto );
	dhcphdr->op = dhcp_op[msgtype];
	dhcphdr->hlen = netdev->ll_protocol->ll_addr_len;
	memcpy ( dhcphdr->chaddr, netdev->ll_addr,
		 netdev->ll_protocol->ll_addr_len );
	memcpy ( dhcphdr->options, options, options_len );

	/* If the local link-layer address functions only as a name
	 * (i.e. cannot be used as a destination address), then
	 * request broadcast responses.
	 */
	if ( netdev->ll_protocol->flags & LL_NAME_ONLY )
		dhcphdr->flags |= htons ( BOOTP_FL_BROADCAST );

	/* If the network device already has an IPv4 address then
	 * unicast responses from the DHCP server may be rejected, so
	 * request broadcast responses.
	 */
	if ( ipv4_has_any_addr ( netdev ) )
		dhcphdr->flags |= htons ( BOOTP_FL_BROADCAST );

	/* Initialise DHCP packet structure */
	memset ( dhcppkt, 0, sizeof ( *dhcppkt ) );
	dhcppkt_init ( dhcppkt, data, max_len );
	
	/* Set DHCP_MESSAGE_TYPE option */
	if ( ( rc = dhcppkt_store ( dhcppkt, DHCP_MESSAGE_TYPE,
				    &msgtype, sizeof ( msgtype ) ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Create DHCP request packet
 *
 * @v dhcppkt		DHCP packet structure to fill in
 * @v netdev		Network device
 * @v msgtype		DHCP message type
 * @v xid		Transaction ID (in network-endian order)
 * @v ciaddr		Client IP address
 * @v data		Buffer for DHCP packet
 * @v max_len		Size of DHCP packet buffer
 * @ret rc		Return status code
 *
 * Creates a DHCP request packet in the specified buffer, and
 * initialise a DHCP packet structure.
 */
int dhcp_create_request ( struct dhcp_packet *dhcppkt,
			  struct net_device *netdev, unsigned int msgtype,
			  uint32_t xid, struct in_addr ciaddr,
			  void *data, size_t max_len ) {
	struct dhcp_netdev_desc dhcp_desc;
	struct dhcp_client_id client_id;
	struct dhcp_client_uuid client_uuid;
	uint8_t *dhcp_features;
	size_t dhcp_features_len;
	size_t ll_addr_len;
	void *user_class;
	ssize_t len;
	int rc;

	/* Create DHCP packet */
	if ( ( rc = dhcp_create_packet ( dhcppkt, netdev, msgtype, xid,
					 dhcp_request_options_data,
					 sizeof ( dhcp_request_options_data ),
					 data, max_len ) ) != 0 ) {
		DBG ( "DHCP could not create DHCP packet: %s\n",
		      strerror ( rc ) );
		goto err_create_packet;
	}

	/* Set client IP address */
	dhcppkt->dhcphdr->ciaddr = ciaddr;

	/* Add options to identify the feature list */
	dhcp_features = table_start ( DHCP_FEATURES );
	dhcp_features_len = table_num_entries ( DHCP_FEATURES );
	if ( ( rc = dhcppkt_store ( dhcppkt, DHCP_EB_ENCAP, dhcp_features,
				    dhcp_features_len ) ) != 0 ) {
		DBG ( "DHCP could not set features list option: %s\n",
		      strerror ( rc ) );
		goto err_store_features;
	}

	/* Add options to identify the network device */
	fetch_raw_setting ( netdev_settings ( netdev ), &busid_setting,
			    &dhcp_desc, sizeof ( dhcp_desc ) );
	if ( ( rc = dhcppkt_store ( dhcppkt, DHCP_EB_BUS_ID, &dhcp_desc,
				    sizeof ( dhcp_desc ) ) ) != 0 ) {
		DBG ( "DHCP could not set bus ID option: %s\n",
		      strerror ( rc ) );
		goto err_store_busid;
	}

	/* Add DHCP client identifier.  Required for Infiniband, and
	 * doesn't hurt other link layers.
	 */
	client_id.ll_proto = ntohs ( netdev->ll_protocol->ll_proto );
	ll_addr_len = netdev->ll_protocol->ll_addr_len;
	assert ( ll_addr_len <= sizeof ( client_id.ll_addr ) );
	memcpy ( client_id.ll_addr, netdev->ll_addr, ll_addr_len );
	if ( ( rc = dhcppkt_store ( dhcppkt, DHCP_CLIENT_ID, &client_id,
				    ( ll_addr_len + 1 ) ) ) != 0 ) {
		DBG ( "DHCP could not set client ID: %s\n",
		      strerror ( rc ) );
		goto err_store_client_id;
	}

	/* Add client UUID, if we have one.  Required for PXE.  The
	 * PXE spec does not specify a byte ordering for UUIDs, but
	 * RFC4578 suggests that it follows the EFI spec, in which the
	 * first three fields are little-endian.
	 */
	client_uuid.type = DHCP_CLIENT_UUID_TYPE;
	if ( ( len = fetch_uuid_setting ( NULL, &uuid_setting,
					  &client_uuid.uuid ) ) >= 0 ) {
		uuid_mangle ( &client_uuid.uuid );
		if ( ( rc = dhcppkt_store ( dhcppkt, DHCP_CLIENT_UUID,
					    &client_uuid,
					    sizeof ( client_uuid ) ) ) != 0 ) {
			DBG ( "DHCP could not set client UUID: %s\n",
			      strerror ( rc ) );
			goto err_store_client_uuid;
		}
	}

	/* Add user class, if we have one. */
	if ( ( len = fetch_raw_setting_copy ( NULL, &user_class_setting,
					      &user_class ) ) >= 0 ) {
		if ( ( rc = dhcppkt_store ( dhcppkt, DHCP_USER_CLASS_ID,
					    user_class, len ) ) != 0 ) {
			DBG ( "DHCP could not set user class: %s\n",
			      strerror ( rc ) );
			goto err_store_user_class;
		}
	}

 err_store_user_class:
	free ( user_class );
 err_store_client_uuid:
 err_store_client_id:
 err_store_busid:
 err_store_features:
 err_create_packet:
	return rc;
}

/****************************************************************************
 *
 * Data transfer interface
 *
 */

/**
 * Transmit DHCP request
 *
 * @v dhcp		DHCP session
 * @ret rc		Return status code
 */
static int dhcp_tx ( struct dhcp_session *dhcp ) {
	static struct sockaddr_in peer = {
		.sin_family = AF_INET,
	};
	struct xfer_metadata meta = {
		.netdev = dhcp->netdev,
		.src = ( struct sockaddr * ) &dhcp->local,
		.dest = ( struct sockaddr * ) &peer,
	};
	struct io_buffer *iobuf;
	uint8_t msgtype = dhcp->state->tx_msgtype;
	struct dhcp_packet dhcppkt;
	int rc;

	/* Start retry timer.  Do this first so that failures to
	 * transmit will be retried.
	 */
	start_timer ( &dhcp->timer );

	/* Allocate buffer for packet */
	iobuf = xfer_alloc_iob ( &dhcp->xfer, DHCP_MIN_LEN );
	if ( ! iobuf )
		return -ENOMEM;

	/* Create basic DHCP packet in temporary buffer */
	if ( ( rc = dhcp_create_request ( &dhcppkt, dhcp->netdev, msgtype,
					  dhcp->xid, dhcp->local.sin_addr,
					  iobuf->data,
					  iob_tailroom ( iobuf ) ) ) != 0 ) {
		DBGC ( dhcp, "DHCP %p could not construct DHCP request: %s\n",
		       dhcp, strerror ( rc ) );
		goto done;
	}

	/* (Ab)use the "secs" field to convey metadata about the DHCP
	 * session state into packet traces.  Useful for extracting
	 * debug information from non-debug builds.
	 */
	dhcppkt.dhcphdr->secs = htons ( ( ++(dhcp->count) << 2 ) |
					( dhcp->offer.s_addr ? 0x02 : 0 ) |
					( dhcp->proxy_offer ? 0x01 : 0 ) );

	/* Fill in packet based on current state */
	if ( ( rc = dhcp->state->tx ( dhcp, &dhcppkt, &peer ) ) != 0 ) {
		DBGC ( dhcp, "DHCP %p could not fill DHCP request: %s\n",
		       dhcp, strerror ( rc ) );
		goto done;
	}

	/* Transmit the packet */
	iob_put ( iobuf, dhcppkt_len ( &dhcppkt ) );
	if ( ( rc = xfer_deliver ( &dhcp->xfer, iob_disown ( iobuf ),
				   &meta ) ) != 0 ) {
		DBGC ( dhcp, "DHCP %p could not transmit UDP packet: %s\n",
		       dhcp, strerror ( rc ) );
		goto done;
	}

 done:
	free_iob ( iobuf );
	return rc;
}

/**
 * Receive new data
 *
 * @v dhcp		DHCP session
 * @v iobuf		I/O buffer
 * @v meta		Transfer metadata
 * @ret rc		Return status code
 */
static int dhcp_deliver ( struct dhcp_session *dhcp,
			  struct io_buffer *iobuf,
			  struct xfer_metadata *meta ) {
	struct net_device *netdev = dhcp->netdev;
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	struct sockaddr_in *peer;
	size_t data_len;
	struct dhcp_packet *dhcppkt;
	struct dhcphdr *dhcphdr;
	uint8_t msgtype = 0;
	struct in_addr server_id = { 0 };
	struct in_addr pseudo_id;
	int rc = 0;

	/* Sanity checks */
	if ( ! meta->src ) {
		DBGC ( dhcp, "DHCP %p received packet without source port\n",
		       dhcp );
		rc = -EINVAL;
		goto err_no_src;
	}
	peer = ( struct sockaddr_in * ) meta->src;

	/* Create a DHCP packet containing the I/O buffer contents.
	 * Whilst we could just use the original buffer in situ, that
	 * would waste the unused space in the packet buffer, and also
	 * waste a relatively scarce fully-aligned I/O buffer.
	 */
	data_len = iob_len ( iobuf );
	dhcppkt = zalloc ( sizeof ( *dhcppkt ) + data_len );
	if ( ! dhcppkt ) {
		rc = -ENOMEM;
		goto err_alloc_dhcppkt;
	}
	dhcphdr = ( ( ( void * ) dhcppkt ) + sizeof ( *dhcppkt ) );
	memcpy ( dhcphdr, iobuf->data, data_len );
	dhcppkt_init ( dhcppkt, dhcphdr, data_len );

	/* Identify message type */
	dhcppkt_fetch ( dhcppkt, DHCP_MESSAGE_TYPE, &msgtype,
			sizeof ( msgtype ) );

	/* Identify server ID */
	dhcppkt_fetch ( dhcppkt, DHCP_SERVER_IDENTIFIER,
			&server_id, sizeof ( server_id ) );

	/* Identify server pseudo-ID */
	pseudo_id = server_id;
	if ( ! pseudo_id.s_addr )
		pseudo_id = dhcppkt->dhcphdr->siaddr;
	if ( ! pseudo_id.s_addr )
		pseudo_id = peer->sin_addr;

	/* Check for matching transaction ID */
	if ( dhcphdr->xid != dhcp->xid ) {
		DBGC ( dhcp, "DHCP %p %s from %s:%d has bad transaction "
		       "ID\n", dhcp, dhcp_msgtype_name ( msgtype ),
		       inet_ntoa ( peer->sin_addr ),
		       ntohs ( peer->sin_port ) );
		rc = -EINVAL;
		goto err_xid;
	};

	/* Check for matching client hardware address */
	if ( memcmp ( dhcphdr->chaddr, netdev->ll_addr,
		      ll_protocol->ll_addr_len ) != 0 ) {
		DBGC ( dhcp, "DHCP %p %s from %s:%d has bad chaddr %s\n",
		       dhcp, dhcp_msgtype_name ( msgtype ),
		       inet_ntoa ( peer->sin_addr ), ntohs ( peer->sin_port ),
		       ll_protocol->ntoa ( dhcphdr->chaddr ) );
		rc = -EINVAL;
		goto err_chaddr;
	}

	/* Handle packet based on current state */
	dhcp->state->rx ( dhcp, dhcppkt, peer, msgtype, server_id, pseudo_id );

 err_chaddr:
 err_xid:
	dhcppkt_put ( dhcppkt );
 err_alloc_dhcppkt:
 err_no_src:
	free_iob ( iobuf );
	return rc;
}

/** DHCP data transfer interface operations */
static struct interface_operation dhcp_xfer_operations[] = {
	INTF_OP ( xfer_deliver, struct dhcp_session *, dhcp_deliver ),
};

/** DHCP data transfer interface descriptor */
static struct interface_descriptor dhcp_xfer_desc =
	INTF_DESC ( struct dhcp_session, xfer, dhcp_xfer_operations );

/**
 * Handle DHCP retry timer expiry
 *
 * @v timer		DHCP retry timer
 * @v fail		Failure indicator
 */
static void dhcp_timer_expired ( struct retry_timer *timer, int fail ) {
	struct dhcp_session *dhcp =
		container_of ( timer, struct dhcp_session, timer );

	/* If we have failed, terminate DHCP */
	if ( fail ) {
		dhcp_finished ( dhcp, -ETIMEDOUT );
		return;
	}

	/* Handle timer expiry based on current state */
	dhcp->state->expired ( dhcp );
}

/****************************************************************************
 *
 * Job control interface
 *
 */

/** DHCP job control interface operations */
static struct interface_operation dhcp_job_op[] = {
	INTF_OP ( intf_close, struct dhcp_session *, dhcp_finished ),
};

/** DHCP job control interface descriptor */
static struct interface_descriptor dhcp_job_desc =
	INTF_DESC ( struct dhcp_session, job, dhcp_job_op );

/****************************************************************************
 *
 * Instantiators
 *
 */

/**
 * DHCP peer address for socket opening
 *
 * This is a dummy address; the only useful portion is the socket
 * family (so that we get a UDP connection).  The DHCP client will set
 * the IP address and source port explicitly on each transmission.
 */
static struct sockaddr dhcp_peer = {
	.sa_family = AF_INET,
};

/**
 * Start DHCP state machine on a network device
 *
 * @v job		Job control interface
 * @v netdev		Network device
 * @ret rc		Return status code
 *
 * Starts DHCP on the specified network device.  If successful, the
 * DHCPACK (and ProxyDHCPACK, if applicable) will be registered as
 * option sources.
 */
int start_dhcp ( struct interface *job, struct net_device *netdev ) {
	struct dhcp_session *dhcp;
	int rc;

	/* Allocate and initialise structure */
	dhcp = zalloc ( sizeof ( *dhcp ) );
	if ( ! dhcp )
		return -ENOMEM;
	ref_init ( &dhcp->refcnt, dhcp_free );
	intf_init ( &dhcp->job, &dhcp_job_desc, &dhcp->refcnt );
	intf_init ( &dhcp->xfer, &dhcp_xfer_desc, &dhcp->refcnt );
	timer_init ( &dhcp->timer, dhcp_timer_expired, &dhcp->refcnt );
	dhcp->netdev = netdev_get ( netdev );
	dhcp->local.sin_family = AF_INET;
	dhcp->local.sin_port = htons ( BOOTPC_PORT );
	dhcp->xid = random();

	/* Store DHCP transaction ID for fakedhcp code */
	dhcp_last_xid = dhcp->xid;

	/* Instantiate child objects and attach to our interfaces */
	if ( ( rc = xfer_open_socket ( &dhcp->xfer, SOCK_DGRAM, &dhcp_peer,
				  ( struct sockaddr * ) &dhcp->local ) ) != 0 )
		goto err;

	/* Enter DHCPDISCOVER state */
	dhcp_set_state ( dhcp, &dhcp_state_discover );

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &dhcp->job, job );
	ref_put ( &dhcp->refcnt );
	return 0;

 err:
	dhcp_finished ( dhcp, rc );
	ref_put ( &dhcp->refcnt );
	return rc;
}

/**
 * Retrieve list of PXE boot servers for a given server type
 *
 * @v dhcp		DHCP session
 * @v raw		DHCP PXE boot server list
 * @v raw_len		Length of DHCP PXE boot server list
 * @v ip		IP address list to fill in
 *
 * The caller must ensure that the IP address list has sufficient
 * space.
 */
static void pxebs_list ( struct dhcp_session *dhcp, void *raw,
			 size_t raw_len, struct in_addr *ip ) {
	struct dhcp_pxe_boot_server *server = raw;
	size_t server_len;
	unsigned int i;

	while ( raw_len ) {
		if ( raw_len < sizeof ( *server ) ) {
			DBGC ( dhcp, "DHCP %p malformed PXE server list\n",
			       dhcp );
			break;
		}
		server_len = offsetof ( typeof ( *server ),
					ip[ server->num_ip ] );
		if ( raw_len < server_len ) {
			DBGC ( dhcp, "DHCP %p malformed PXE server list\n",
			       dhcp );
			break;
		}
		if ( server->type == dhcp->pxe_type ) {
			for ( i = 0 ; i < server->num_ip ; i++ )
				*(ip++) = server->ip[i];
		}
		server = ( ( ( void * ) server ) + server_len );
		raw_len -= server_len;
	}
}

/**
 * Start PXE Boot Server Discovery on a network device
 *
 * @v job		Job control interface
 * @v netdev		Network device
 * @v pxe_type		PXE server type
 * @ret rc		Return status code
 *
 * Starts PXE Boot Server Discovery on the specified network device.
 * If successful, the Boot Server ACK will be registered as an option
 * source.
 */
int start_pxebs ( struct interface *job, struct net_device *netdev,
		  unsigned int pxe_type ) {
	struct setting pxe_discovery_control_setting =
		{ .tag = DHCP_PXE_DISCOVERY_CONTROL };
	struct setting pxe_boot_servers_setting =
		{ .tag = DHCP_PXE_BOOT_SERVERS };
	struct setting pxe_boot_server_mcast_setting =
		{ .tag = DHCP_PXE_BOOT_SERVER_MCAST };
	ssize_t pxebs_list_len;
	struct dhcp_session *dhcp;
	struct in_addr *ip;
	unsigned int pxe_discovery_control;
	int rc;

	/* Get upper bound for PXE boot server IP address list */
	pxebs_list_len = fetch_raw_setting ( NULL, &pxe_boot_servers_setting,
					     NULL, 0 );
	if ( pxebs_list_len < 0 )
		pxebs_list_len = 0;

	/* Allocate and initialise structure */
	dhcp = zalloc ( sizeof ( *dhcp ) + sizeof ( *ip ) /* mcast */ +
			sizeof ( *ip ) /* bcast */ + pxebs_list_len +
			sizeof ( *ip ) /* terminator */ );
	if ( ! dhcp )
		return -ENOMEM;
	ref_init ( &dhcp->refcnt, dhcp_free );
	intf_init ( &dhcp->job, &dhcp_job_desc, &dhcp->refcnt );
	intf_init ( &dhcp->xfer, &dhcp_xfer_desc, &dhcp->refcnt );
	timer_init ( &dhcp->timer, dhcp_timer_expired, &dhcp->refcnt );
	dhcp->netdev = netdev_get ( netdev );
	dhcp->local.sin_family = AF_INET;
	fetch_ipv4_setting ( netdev_settings ( netdev ), &ip_setting,
			     &dhcp->local.sin_addr );
	dhcp->local.sin_port = htons ( BOOTPC_PORT );
	dhcp->pxe_type = cpu_to_le16 ( pxe_type );

	/* Construct PXE boot server IP address lists */
	pxe_discovery_control =
		fetch_uintz_setting ( NULL, &pxe_discovery_control_setting );
	ip = ( ( ( void * ) dhcp ) + sizeof ( *dhcp ) );
	dhcp->pxe_attempt = ip;
	if ( ! ( pxe_discovery_control & PXEBS_NO_MULTICAST ) ) {
		fetch_ipv4_setting ( NULL, &pxe_boot_server_mcast_setting, ip);
		if ( ip->s_addr )
			ip++;
	}
	if ( ! ( pxe_discovery_control & PXEBS_NO_BROADCAST ) )
		(ip++)->s_addr = INADDR_BROADCAST;
	if ( pxe_discovery_control & PXEBS_NO_UNKNOWN_SERVERS )
		dhcp->pxe_accept = ip;
	if ( pxebs_list_len ) {
		uint8_t buf[pxebs_list_len];

		fetch_raw_setting ( NULL, &pxe_boot_servers_setting,
				    buf, sizeof ( buf ) );
		pxebs_list ( dhcp, buf, sizeof ( buf ), ip );
	}
	if ( ! dhcp->pxe_attempt->s_addr ) {
		DBGC ( dhcp, "DHCP %p has no PXE boot servers for type %04x\n",
		       dhcp, pxe_type );
		rc = -EINVAL;
		goto err;
	}

	/* Dump out PXE server lists */
	DBGC ( dhcp, "DHCP %p attempting", dhcp );
	for ( ip = dhcp->pxe_attempt ; ip->s_addr ; ip++ )
		DBGC ( dhcp, " %s", inet_ntoa ( *ip ) );
	DBGC ( dhcp, "\n" );
	if ( dhcp->pxe_accept ) {
		DBGC ( dhcp, "DHCP %p accepting", dhcp );
		for ( ip = dhcp->pxe_accept ; ip->s_addr ; ip++ )
			DBGC ( dhcp, " %s", inet_ntoa ( *ip ) );
		DBGC ( dhcp, "\n" );
	}

	/* Instantiate child objects and attach to our interfaces */
	if ( ( rc = xfer_open_socket ( &dhcp->xfer, SOCK_DGRAM, &dhcp_peer,
				  ( struct sockaddr * ) &dhcp->local ) ) != 0 )
		goto err;

	/* Enter PXEBS state */
	dhcp_set_state ( dhcp, &dhcp_state_pxebs );

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &dhcp->job, job );
	ref_put ( &dhcp->refcnt );
	return 0;

 err:
	dhcp_finished ( dhcp, rc );
	ref_put ( &dhcp->refcnt );
	return rc;
}

/** DHCP network device configurator */
struct net_device_configurator dhcp_configurator __net_device_configurator = {
	.name = "dhcp",
	.start = start_dhcp,
};
