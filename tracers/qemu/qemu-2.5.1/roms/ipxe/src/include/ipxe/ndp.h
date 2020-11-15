#ifndef _IPXE_NDP_H
#define _IPXE_NDP_H

/** @file
 *
 * Neighbour discovery protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/in.h>
#include <ipxe/ipv6.h>
#include <ipxe/icmpv6.h>
#include <ipxe/neighbour.h>

/** An NDP option header */
struct ndp_option_header {
	/** Type */
	uint8_t type;
	/** Length (in blocks of 8 bytes) */
	uint8_t blocks;
} __attribute__ (( packed ));

/** NDP option block size */
#define NDP_OPTION_BLKSZ 8U

/** NDP source link-layer address option */
#define NDP_OPT_LL_SOURCE 1

/** NDP target link-layer address option */
#define NDP_OPT_LL_TARGET 2

/** NDP source or target link-layer address option */
struct ndp_ll_addr_option {
	/** NDP option header */
	struct ndp_option_header header;
	/** Link-layer address */
	uint8_t ll_addr[0];
} __attribute__ (( packed ));

/** NDP prefix information option */
#define NDP_OPT_PREFIX 3

/** NDP prefix information */
struct ndp_prefix_information_option {
	/** NDP option header */
	struct ndp_option_header header;
	/** Prefix length */
	uint8_t prefix_len;
	/** Flags */
	uint8_t flags;
	/** Valid lifetime */
	uint32_t valid;
	/** Preferred lifetime */
	uint32_t preferred;
	/** Reserved */
	uint32_t reserved;
	/** Prefix */
	struct in6_addr prefix;
} __attribute__ (( packed ));

/** NDP on-link flag */
#define NDP_PREFIX_ON_LINK 0x80

/** NDP autonomous address configuration flag */
#define NDP_PREFIX_AUTONOMOUS 0x40

/** NDP recursive DNS server option */
#define NDP_OPT_RDNSS 25

/** NDP recursive DNS server */
struct ndp_rdnss_option {
	/** NDP option header */
	struct ndp_option_header header;
	/** Reserved */
	uint16_t reserved;
	/** Lifetime */
	uint32_t lifetime;
	/** Addresses */
	struct in6_addr addresses[0];
} __attribute__ (( packed ));

/** NDP DNS search list option */
#define NDP_OPT_DNSSL 31

/** NDP DNS search list */
struct ndp_dnssl_option {
	/** NDP option header */
	struct ndp_option_header header;
	/** Reserved */
	uint16_t reserved;
	/** Lifetime */
	uint32_t lifetime;
	/** Domain names */
	uint8_t names[0];
} __attribute__ (( packed ));

/** An NDP option */
union ndp_option {
	/** Option header */
	struct ndp_option_header header;
	/** Source or target link-layer address option */
	struct ndp_ll_addr_option ll_addr;
	/** Prefix information option */
	struct ndp_prefix_information_option prefix;
	/** Recursive DNS server option */
	struct ndp_rdnss_option rdnss;
	/** DNS search list option */
	struct ndp_dnssl_option dnssl;
} __attribute__ (( packed ));

/** An NDP neighbour solicitation or advertisement header */
struct ndp_neighbour_header {
	/** ICMPv6 header */
	struct icmp_header icmp;
	/** Flags */
	uint8_t flags;
	/** Reserved */
	uint8_t reserved[3];
	/** Target address */
	struct in6_addr target;
	/** Options */
	union ndp_option option[0];
} __attribute__ (( packed ));

/** NDP router flag */
#define NDP_NEIGHBOUR_ROUTER 0x80

/** NDP solicited flag */
#define NDP_NEIGHBOUR_SOLICITED 0x40

/** NDP override flag */
#define NDP_NEIGHBOUR_OVERRIDE 0x20

/** An NDP router advertisement header */
struct ndp_router_advertisement_header {
	/** ICMPv6 header */
	struct icmp_header icmp;
	/** Current hop limit */
	uint8_t hop_limit;
	/** Flags */
	uint8_t flags;
	/** Router lifetime */
	uint16_t lifetime;
	/** Reachable time */
	uint32_t reachable;
	/** Retransmission timer */
	uint32_t retransmit;
	/** Options */
	union ndp_option option[0];
} __attribute__ (( packed ));

/** NDP managed address configuration */
#define NDP_ROUTER_MANAGED 0x80

/** NDP other configuration */
#define NDP_ROUTER_OTHER 0x40

/** An NDP router solicitation header */
struct ndp_router_solicitation_header {
	/** ICMPv6 header */
	struct icmp_header icmp;
	/** Reserved */
	uint32_t reserved;
	/** Options */
	union ndp_option option[0];
} __attribute__ (( packed ));

/** An NDP header */
union ndp_header {
	/** ICMPv6 header */
	struct icmp_header icmp;
	/** Neighbour solicitation or advertisement header */
	struct ndp_neighbour_header neigh;
	/** Router solicitation header */
	struct ndp_router_solicitation_header rsol;
	/** Router advertisement header */
	struct ndp_router_advertisement_header radv;
} __attribute__ (( packed ));

extern struct neighbour_discovery ndp_discovery;

/**
 * Transmit packet, determining link-layer address via NDP
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v net_dest		Destination network-layer address
 * @v net_source	Source network-layer address
 * @v ll_source		Source link-layer address
 * @ret rc		Return status code
 */
static inline int ndp_tx ( struct io_buffer *iobuf, struct net_device *netdev,
			   const void *net_dest, const void *net_source,
			   const void *ll_source ) {

	return neighbour_tx ( iobuf, netdev, &ipv6_protocol, net_dest,
			      &ndp_discovery, net_source, ll_source );
}

/** NDP settings block name */
#define NDP_SETTINGS_NAME "ndp"

#endif /* _IPXE_NDP_H */
