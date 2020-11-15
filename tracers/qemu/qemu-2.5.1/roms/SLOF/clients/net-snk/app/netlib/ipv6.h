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

#ifndef _IPV6_H_
#define _IPV6_H_

#include <stdint.h>
#include <netlib/ethernet.h>

#define __IPV6_DEBUG__

#ifdef __IPV6_DEBUG__
#define IPV6_DEBUG_PRINT(format, ...) do { printf(format, ## __VA_ARGS__); } while (0)
#else
#define IPV6_DEBUG_PRINT(format, ...)
#endif

#define IPV6_ADDR_LENGTH	 16 /* Size of IPv6 adress in bytes */
#define IPV6_LL_PREFIX		 0xFE80000000000000ULL
#define IPV6_SOLIC_NODE_PREFIX   0xFF02000000000000ULL
#define IPV6_SOLIC_NODE_IFACE_ID 0x00000001FF000000ULL

/**
 *  An IPv6 Address
 */
typedef union {
	uint8_t addr[IPV6_ADDR_LENGTH];
	struct {
		uint64_t prefix;
		uint64_t interface_id;
	} part;
} ip6_addr_t;

typedef struct {
	uint8_t type;
	uint8_t pad[7];
	union {
		ip6_addr_t  v6;
		char        v4[4];
	} addr;
} netaddr_t;

/** \struct prefix_info
 *
 * List of Prefixes we have adresses from
 * Used for internal purposes, information derived from prefix option
 * in Router Advertisements
 * See RFC 4861 section 4.6.2
 */
struct prefix_info {
	uint64_t prefix;
	uint8_t  on_link:1,         /* When set prefix can be used for on-link
                                     * determination */
		 autoconf:1,        /* Prefix can be used for stateless address
                                     * configuration */
		 reserved1:6;
	uint32_t valid_lifetime;     /* Time until prefix expires */
	uint32_t preferred_lifetime; /* Time until prefix becomes deprecated */
	uint32_t start_time;         /* Time when received */
	uint32_t reserved2;
	struct   prefix_info *next;
};


/* List of IPv6 addresses */
struct ip6addr_list_entry {
	ip6_addr_t addr;
	struct prefix_info prfx_info;
	struct ip6addr_list_entry *next;
};

/** \struct ip6hdr
 *  A header for IPv6 packets.
 *  For more information see RFC 2460
 */
struct ip6hdr {
	uint32_t ver_tc_fl;	/**< Version, Traffic class, Flow label	*/
	uint16_t pl;		/**< Payload length			*/
	uint8_t  nh;		/**< Next header			*/
	uint8_t  hl;		/**< Hop limit				*/
	ip6_addr_t src;		/**< IPv6 source address		*/
	ip6_addr_t dst;		/**< IPv6 destination address		*/
} __attribute((packed));

/** \struct packeth
 * Struct with pointers to headers within a packet
 */
struct packeth {
	struct ethhdr  *ethh;
	struct ip6hdr  *ip6h;
	struct icmp6hdr  *icmp6h;
	struct udphdr  *udph;
	/* ... */
};

/** \struct parseip6_state
 * Stores information about state of IPv6 address parser
 */
struct parseip6_state {
	char *lookahead;
	char *ptr;
	const char *addr;
	int state;
	int s1ctr;
	int s2ctr;
	int blocknr;
	int zeroblocks;
	int i;
	int done;
	int errorcode;
};

/** \struct ip6_config
 * Stores flags wheter we use Stateless- or Stateful Autoconfiguration or DHCPv6
 */
struct ip6_config {
	uint8_t managed_mode:1,
		other_config:1,
		reserved:6;
} ip6_state;

/******************** VARIABLES **********************************************/
/* Function pointer send_ip. Points either to send_ipv4() or send_ipv6() */
extern int   (*send_ip) (int fd, void *, int);

/* IPv6 link-local multicast addresses */
struct ip6addr_list_entry all_routers_ll; // Routers
struct ip6addr_list_entry all_dhcpv6_ll;  // DHCPv6 servers
struct ip6addr_list_entry all_nodes_ll;   // All IPv6 nodes

/* List of Ipv6 Addresses */
struct ip6addr_list_entry *first_ip6;
struct ip6addr_list_entry *last_ip6;

/* Neighbor cache */
struct neighbor *first_neighbor;
struct neighbor *last_neighbor;

/* Router list */
struct router *first_router;
struct router *last_router;

/******************** FUNCTIONS *********************************************/
/* Handles IPv6-packets that are detected by receive_ether. */
int8_t handle_ipv6(int fd, uint8_t * ip6_packet, int32_t packetsize);

/* Fill IPv6 header */
void fill_ip6hdr(uint8_t * packet, uint16_t packetsize,
	         uint8_t ip_proto, ip6_addr_t *ip6_src, ip6_addr_t *ip6_dst);

/* Set own IPv6 address */
void set_ipv6_address(int fd, ip6_addr_t *own_ip6);

/* Get own IPv6 address */
ip6_addr_t *get_ipv6_address(void);

/* Create link-local address from a given Mac Address */
ip6_addr_t * ip6_create_ll_address (const uint8_t *own_mac);

/* For a given MAC calculates EUI64-Identifier.*/
uint64_t mac2eui64 (const uint8_t *mac);

/* Create empty element for prefix list and return a pointer to it */
struct prefix_info * ip6_create_prefix_info(void);

/* Create a new IPv6 address with a given network prefix
 *	and add it to our IPv6 address list */
void * ip6_prefix2addr (ip6_addr_t prefix);

/* Compare IPv6 adresses */
int8_t ip6_cmp( ip6_addr_t *ip_1, ip6_addr_t *ip_2 );

/* Check if prefix is already in our list */
int8_t unknown_prefix (ip6_addr_t *ip);

/* Send IPv6 packet */
int send_ipv6 (int fd, void* buffer, int len);

/* Add IPv6 address to list */
int8_t ip6addr_add (struct ip6addr_list_entry *new_address);

/* Parse an IPv6 address */
int parseip6(const char *addr, uint8_t *parsedaddr);
int str_to_ipv6(const char *str, uint8_t *ip);
void ipv6_to_str(const uint8_t *ip, char *str);

#endif
