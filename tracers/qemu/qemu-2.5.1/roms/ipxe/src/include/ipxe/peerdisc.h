#ifndef _IPXE_PEERDISC_H
#define _IPXE_PEERDISC_H

/** @file
 *
 * Peer Content Caching and Retrieval (PeerDist) protocol peer discovery
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/refcnt.h>
#include <ipxe/list.h>
#include <ipxe/tables.h>
#include <ipxe/retry.h>
#include <ipxe/socket.h>
#include <ipxe/interface.h>
#include <ipxe/pccrc.h>

/** A PeerDist discovery socket */
struct peerdisc_socket {
	/** Name */
	const char *name;
	/** Data transfer interface */
	struct interface xfer;
	/** Socket address */
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} address;
};

/** PeerDist discovery socket table */
#define PEERDISC_SOCKETS __table ( struct peerdisc_socket, "peerdisc_sockets" )

/** Declare a PeerDist discovery socket */
#define __peerdisc_socket __table_entry ( PEERDISC_SOCKETS, 01 )

/** A PeerDist discovery segment */
struct peerdisc_segment {
	/** Reference count */
	struct refcnt refcnt;
	/** List of segments */
	struct list_head list;
	/** Segment identifier string
	 *
	 * This is MS-PCCRC's "HoHoDk", transcribed as an upper-case
	 * Base16-encoded string.
	 */
	const char *id;
	/** Message UUID string */
	const char *uuid;
	/** List of discovered peers
	 *
	 * The list of peers may be appended to during the lifetime of
	 * the discovery segment.  Discovered peers will not be
	 * removed from the list until the last discovery has been
	 * closed; this allows users to safely maintain a pointer to a
	 * current position within the list.
	 */
	struct list_head peers;
	/** List of active clients */
	struct list_head clients;
	/** Transmission timer */
	struct retry_timer timer;
};

/** A PeerDist discovery peer */
struct peerdisc_peer {
	/** List of peers */
	struct list_head list;
	/** Peer location */
	char location[0];
};

/** A PeerDist discovery client */
struct peerdisc_client {
	/** Discovery segment */
	struct peerdisc_segment *segment;
	/** List of clients */
	struct list_head list;
	/** Operations */
	struct peerdisc_client_operations *op;
};

/** PeerDist discovery client operations */
struct peerdisc_client_operations {
	/** New peers have been discovered
	 *
	 * @v peerdisc		PeerDist discovery client
	 */
	void ( * discovered ) ( struct peerdisc_client *peerdisc );
};

/**
 * Initialise PeerDist discovery
 *
 * @v peerdisc		PeerDist discovery client
 * @v op		Discovery operations
 */
static inline __attribute__ (( always_inline )) void
peerdisc_init ( struct peerdisc_client *peerdisc,
		struct peerdisc_client_operations *op ) {

	peerdisc->op = op;
}

extern unsigned int peerdisc_timeout_secs;

extern int peerdisc_open ( struct peerdisc_client *peerdisc, const void *id,
			   size_t len );
extern void peerdisc_close ( struct peerdisc_client *peerdisc );

#endif /* _IPXE_PEERDISC_H */
