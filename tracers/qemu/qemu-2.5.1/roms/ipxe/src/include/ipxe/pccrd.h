#ifndef _IPXE_PCCRD_H
#define _IPXE_PCCRD_H

/** @file
 *
 * Peer Content Caching and Retrieval: Discovery Protocol [MS-PCCRD]
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** PeerDist discovery port */
#define PEERDIST_DISCOVERY_PORT 3702

/** PeerDist discovery IPv4 address (239.255.255.250) */
#define PEERDIST_DISCOVERY_IPV4 \
	( ( 239 << 24 ) | ( 255 << 16 ) | ( 255 << 8 ) | ( 250 << 0 ) )

/** PeerDist discovery IPv6 address (ff02::c) */
#define PEERDIST_DISCOVERY_IPV6 \
	{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc }

/** A PeerDist discovery reply block count */
struct peerdist_discovery_block_count {
	/** Count (as an eight-digit hex value) */
	char hex[8];
} __attribute__ (( packed ));

/** A PeerDist discovery reply */
struct peerdist_discovery_reply {
	/** List of segment ID strings
	 *
	 * The list is terminated with a zero-length string.
	 */
	char *ids;
	/** List of peer locations
	 *
	 * The list is terminated with a zero-length string.
	 */
	char *locations;
};

extern char * peerdist_discovery_request ( const char *uuid, const char *id );
extern int peerdist_discovery_reply ( char *data, size_t len,
				      struct peerdist_discovery_reply *reply );

#endif /* _IPXE_PCCRD_H */
