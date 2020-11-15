#ifndef _IPXE_IPOIB_H
#define _IPXE_IPOIB_H

/** @file
 *
 * IP over Infiniband
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/if_arp.h>
#include <ipxe/infiniband.h>

/** IPoIB MAC address length */
#define IPOIB_ALEN 20

/** An IPoIB MAC address */
struct ipoib_mac {
	/** Queue pair number
	 *
	 * MSB indicates support for IPoIB "connected mode".  Lower 24
	 * bits are the QPN.
	 */
	uint32_t flags__qpn;
	/** Port GID */
	union ib_gid gid;
} __attribute__ (( packed ));

/** IPoIB link-layer header length */
#define IPOIB_HLEN 4

/** IPoIB link-layer header */
struct ipoib_hdr {
	/** Network-layer protocol */
	uint16_t proto;
	/** Reserved, must be zero */
	uint16_t reserved;
} __attribute__ (( packed ));

/** GUID mask used for constructing eIPoIB Local Ethernet MAC address (LEMAC) */
#define IPOIB_GUID_MASK 0xe7

/** eIPoIB Remote Ethernet MAC address
 *
 * An eIPoIB REMAC address is an Ethernet-like (6 byte) link-layer
 * pseudo-address used to look up a full IPoIB link-layer address.
 */
struct ipoib_remac {
	/** Remote QPN
	 *
	 * Must be ORed with EIPOIB_QPN_LA so that eIPoIB REMAC
	 * addresses are considered as locally-assigned Ethernet MAC
	 * addreses.
	 */
	uint32_t qpn;
	/** Remote LID */
	uint16_t lid;
} __attribute__ (( packed ));

/** eIPoIB REMAC locally-assigned address indicator */
#define EIPOIB_QPN_LA 0x02000000UL

extern const char * ipoib_ntoa ( const void *ll_addr );
extern struct net_device * alloc_ipoibdev ( size_t priv_size );

#endif /* _IPXE_IPOIB_H */
