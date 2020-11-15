/******************************************************************************
 * Copyright (c) 2013 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef _ICMPV6_H_
#define _ICMPV6_H_

#include <stdint.h>
#include <netlib/ethernet.h>
#include <netlib/ipv6.h>

#define __ICMPV6_DEBUG__

#ifdef __ICMPV6_DEBUG__
#define ICMPV6_DEBUG_PRINT(format, ...) printf(format, ## __VA_ARGS__)
#else
#define ICMPV6_DEBUG_PRINT(format, ...)
#endif

#define ICMPv6_HEADER_SIZE		4	/* Size of common fields */
#define IPTYPE_ICMPV6		     0x3a

/* Error message types */
#define ICMPV6_DEST_UNREACHABLE		1	/* Destination unreachable */
#define ICMPV6_PACKET_TOO_BIG		2	/* Packet too big */
#define ICMPV6_TIME_EXCEEDED		3	/* Time exceeded */
#define ICMPV6_PARAM_PROBLEM		4	/* Parameter problem */

/* Informational message types */
#define ICMPV6_ECHO_REQUEST		128	/* Echo request */
#define ICMPV6_ECHO_REPLY		129	/* Echo reply */
#define ICMPV6_MCAST_LISTENER_QUERY	130	/* Multicast listener query */
#define ICMPV6_MCAST_LISTENER_REPORT	131	/* Multicast listener report */
#define ICMPv6 MCAST_LISTENER_DONE	132	/* Multicast listener done */
#define ICMPV6_ROUTER_SOLICITATION	133	/* Router solicitation */
#define ICMPV6_ROUTER_ADVERTISEMENT	134	/* Router advertisement */
#define ICMPV6_NEIGHBOUR_SOLICITATION	135	/* Neighbor solicitation */
#define ICMPV6_NEIGHBOUR_ADVERTISEMENT	136	/* Neighbor advertisement */
#define ICMPV6_REDIRECT_MSG		137	/* Redirect message */

/******** Functions *******************/
int8_t handle_icmpv6 (int fd, struct ethhdr *etherhdr, uint8_t  *ip6_packet);
void   send_neighbour_solicitation(int fd, ip6_addr_t *target_ip6);
void   send_router_solicitation(int fd);
int    is_ra_received(void);

/* Prefix information */
struct option_prefix {
	uint8_t  type;
	uint8_t  length;
	uint8_t  prefix_length;
	uint8_t  onlink:1,
		 autom:1,
		 not_router:1,
		 not_site_prefix:1,
		 reserved:4;
	uint32_t valid_lifetime;
	uint32_t preferred_lifetime;
	uint32_t reserved2;
	ip6_addr_t prefix;
} __attribute((packed));

/* Neighbour advertisement/solicitation flags */
struct na_flags {
    uint8_t is_router:1,	/* sender (we) is a router */
	    na_is_solicited:1,	/* this NA was solicited (asked for) */
	    override:1,		/* receiver shall override its cache entries */
	    unused:5;
}__attribute((packed));

/* Source/Target Link-layer address */
struct option_ll_address{
        uint8_t  type;
        uint8_t  length;
        uint8_t  mac[ETH_ALEN];
} __attribute((packed));

struct neighbour_solicitation {
	uint32_t router:1,
		 solicited:1,
		 override:1,
		 reserved:29;
	ip6_addr_t target;
	struct option_ll_address lladdr;
} __attribute((packed));

struct neighbour_advertisement {
	uint32_t router:1,
		 solicited:1,
		 override:1,
		 reserved:29;
	ip6_addr_t target;
	struct option_ll_address lladdr;
} __attribute((packed));

struct router_solicitation {
	uint32_t reserved;
	struct option_ll_address lladdr;
} __attribute((packed));

struct router_advertisement {
	uint8_t curr_hop_limit;
	struct raflags {
		uint8_t managed:1,
			other:1,
			reserved:6;
	} flags;
	uint16_t router_lifetime;
	uint32_t reachable_time;
	uint32_t retrans_timer;
	struct option_prefix prefix;
	struct option_ll_address ll_addr;
} __attribute((packed));

struct icmp6hdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union {
		struct neighbour_solicitation nghb_solicit;
		struct neighbour_advertisement nghb_adv;
		struct router_solicitation router_solicit;
		struct router_advertisement ra;
	} icmp6body;
} __attribute((packed));

#endif
