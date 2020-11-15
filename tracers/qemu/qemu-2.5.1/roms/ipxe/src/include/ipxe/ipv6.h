#ifndef _IPXE_IPV6_H
#define _IPXE_IPV6_H

/** @file
 *
 * IPv6 protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <ipxe/in.h>
#include <ipxe/list.h>
#include <ipxe/netdevice.h>

/** IPv6 version */
#define IPV6_VER 0x60000000UL

/** IPv6 version mask */
#define IPV6_MASK_VER 0xf0000000UL

/** IPv6 maximum hop limit */
#define IPV6_HOP_LIMIT 0xff

/** IPv6 header */
struct ipv6_header {
	/** Version (4 bits), Traffic class (8 bits), Flow label (20 bits) */
	uint32_t ver_tc_label;
	/** Payload length, including any extension headers */
	uint16_t len;
	/** Next header type */
	uint8_t next_header;
	/** Hop limit */
	uint8_t hop_limit;
	/** Source address */
	struct in6_addr src;
	/** Destination address */
	struct in6_addr dest;
} __attribute__ (( packed ));

/** IPv6 extension header common fields */
struct ipv6_extension_header_common {
	/** Next header type */
	uint8_t next_header;
	/** Header extension length (excluding first 8 bytes) */
	uint8_t len;
} __attribute__ (( packed ));

/** IPv6 type-length-value options */
struct ipv6_option {
	/** Type */
	uint8_t type;
	/** Length */
	uint8_t len;
	/** Value */
	uint8_t value[0];
} __attribute__ (( packed ));

/** IPv6 option types */
enum ipv6_option_type {
	/** Pad1 */
	IPV6_OPT_PAD1 = 0x00,
	/** PadN */
	IPV6_OPT_PADN = 0x01,
};

/** Test if IPv6 option can be safely ignored */
#define IPV6_CAN_IGNORE_OPT( type ) ( ( (type) & 0xc0 ) == 0x00 )

/** IPv6 option-based extension header */
struct ipv6_options_header {
	/** Extension header common fields */
	struct ipv6_extension_header_common common;
	/** Options */
	struct ipv6_option options[0];
} __attribute__ (( packed ));

/** IPv6 routing header */
struct ipv6_routing_header {
	/** Extension header common fields */
	struct ipv6_extension_header_common common;
	/** Routing type */
	uint8_t type;
	/** Segments left */
	uint8_t remaining;
	/** Type-specific data */
	uint8_t data[0];
} __attribute__ (( packed ));

/** IPv6 fragment header */
struct ipv6_fragment_header {
	/** Extension header common fields */
	struct ipv6_extension_header_common common;
	/** Fragment offset (13 bits), reserved, more fragments (1 bit) */
	uint16_t offset_more;
	/** Identification */
	uint32_t ident;
} __attribute__ (( packed ));

/** Fragment offset mask */
#define IPV6_MASK_OFFSET 0xfff8

/** More fragments */
#define IPV6_MASK_MOREFRAGS 0x0001

/** IPv6 extension header */
union ipv6_extension_header {
	/** Extension header common fields */
	struct ipv6_extension_header_common common;
	/** Minimum size padding */
	uint8_t pad[8];
	/** Generic options header */
	struct ipv6_options_header options;
	/** Hop-by-hop options header */
	struct ipv6_options_header hopbyhop;
	/** Routing header */
	struct ipv6_routing_header routing;
	/** Fragment header */
	struct ipv6_fragment_header fragment;
	/** Destination options header */
	struct ipv6_options_header destination;
};

/** IPv6 header types */
enum ipv6_header_type {
	/** IPv6 hop-by-hop options header type */
	IPV6_HOPBYHOP = 0,
	/** IPv6 routing header type */
	IPV6_ROUTING = 43,
	/** IPv6 fragment header type */
	IPV6_FRAGMENT = 44,
	/** IPv6 no next header type */
	IPV6_NO_HEADER = 59,
	/** IPv6 destination options header type */
	IPV6_DESTINATION = 60,
};

/** IPv6 pseudo-header */
struct ipv6_pseudo_header {
	/** Source address */
	struct in6_addr src;
	/** Destination address */
	struct in6_addr dest;
	/** Upper-layer packet length */
	uint32_t len;
	/** Zero padding */
	uint8_t zero[3];
	/** Next header */
	uint8_t next_header;
} __attribute__ (( packed ));

/** An IPv6 address/routing table entry */
struct ipv6_miniroute {
	/** List of miniroutes */
	struct list_head list;

	/** Network device */
	struct net_device *netdev;

	/** IPv6 address (or prefix if no address is defined) */
	struct in6_addr address;
	/** Prefix length */
	unsigned int prefix_len;
	/** IPv6 prefix mask (derived from prefix length) */
	struct in6_addr prefix_mask;
	/** Router address */
	struct in6_addr router;
	/** Flags */
	unsigned int flags;
};

/** IPv6 address/routing table entry flags */
enum ipv6_miniroute_flags {
	/** Routing table entry address is valid */
	IPV6_HAS_ADDRESS = 0x0001,
	/** Routing table entry router address is valid */
	IPV6_HAS_ROUTER = 0x0002,
};

/**
 * Construct local IPv6 address via EUI-64
 *
 * @v addr		Prefix to be completed
 * @v netdev		Network device
 * @ret prefix_len	Prefix length, or negative error
 */
static inline int ipv6_eui64 ( struct in6_addr *addr,
			       struct net_device *netdev ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	const void *ll_addr = netdev->ll_addr;
	int rc;

	if ( ( rc = ll_protocol->eui64 ( ll_addr, &addr->s6_addr[8] ) ) != 0 )
		return rc;
	addr->s6_addr[8] ^= 0x02;
	return 64;
}

/**
 * Construct link-local address via EUI-64
 *
 * @v addr		Zeroed address to construct
 * @v netdev		Network device
 * @ret prefix_len	Prefix length, or negative error
 */
static inline int ipv6_link_local ( struct in6_addr *addr,
				    struct net_device *netdev ) {

	addr->s6_addr16[0] = htons ( 0xfe80 );
	return ipv6_eui64 ( addr, netdev );
}

/**
 * Construct solicited-node multicast address
 *
 * @v addr		Zeroed address to construct
 * @v unicast		Unicast address
 */
static inline void ipv6_solicited_node ( struct in6_addr *addr,
					 const struct in6_addr *unicast ) {

	addr->s6_addr16[0] = htons ( 0xff02 );
	addr->s6_addr[11] = 1;
	addr->s6_addr[12] = 0xff;
	memcpy ( &addr->s6_addr[13], &unicast->s6_addr[13], 3 );
}

/**
 * Construct all-routers multicast address
 *
 * @v addr		Zeroed address to construct
 */
static inline void ipv6_all_routers ( struct in6_addr *addr ) {
	addr->s6_addr16[0] = htons ( 0xff02 );
	addr->s6_addr[15] = 2;
}

extern struct list_head ipv6_miniroutes;

extern struct net_protocol ipv6_protocol __net_protocol;

extern int ipv6_has_addr ( struct net_device *netdev, struct in6_addr *addr );
extern int ipv6_set_prefix ( struct net_device *netdev, struct in6_addr *prefix,
			     unsigned int prefix_len, struct in6_addr *router );
extern int ipv6_set_address ( struct net_device *netdev,
			      struct in6_addr *address );
extern int parse_ipv6_setting ( const struct setting_type *type,
				const char *value, void *buf, size_t len );
extern int format_ipv6_setting ( const struct setting_type *type,
				 const void *raw, size_t raw_len, char *buf,
				 size_t len );

#endif /* _IPXE_IPV6_H */
