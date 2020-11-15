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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netlib/ethernet.h>
#include <netlib/ipv6.h>
#include <netlib/icmpv6.h>
#include <netlib/ndp.h>
#include <netlib/dhcpv6.h>

static int ra_received = 0;

/**
 * NET:
 * @param  fd           socket fd
 */
void
send_router_solicitation (int fd)
{
	ip6_addr_t dest_addr;
	uint8_t ether_packet[ETH_MTU_SIZE];
	struct packeth headers;

	headers.ip6h   = (struct ip6hdr *) (ether_packet + sizeof(struct ethhdr));
	headers.icmp6h = (struct icmp6hdr *) (ether_packet +
			  sizeof(struct ethhdr) +
			  sizeof(struct ip6hdr));

	/* Destination is "All routers multicast address" (link-local) */
	dest_addr.part.prefix       = all_routers_ll.addr.part.prefix;
	dest_addr.part.interface_id = all_routers_ll.addr.part.interface_id;


	/* Fill IPv6 header */
	fill_ip6hdr (ether_packet + sizeof(struct ethhdr),
		     ICMPv6_HEADER_SIZE + sizeof(struct router_solicitation),
		     0x3a, //ICMPV6
		     get_ipv6_address(), &dest_addr);

	/* Fill ICMPv6 message */
	headers.icmp6h->type = ICMPV6_ROUTER_SOLICITATION;
	headers.icmp6h->code = 0;
	headers.icmp6h->icmp6body.router_solicit.lladdr.type    = 1;
	headers.icmp6h->icmp6body.router_solicit.lladdr.length  = 1;
	memcpy( &(headers.icmp6h->icmp6body.router_solicit.lladdr.mac),
		get_mac_address(), 6);

	send_ip (fd, headers.ip6h, sizeof(struct ip6hdr) +
		   ICMPv6_HEADER_SIZE + sizeof(struct router_solicitation));
}

/**
 * NET: Process prefix option in Router Advertisements
 *
 * @param  ip6_packet	pointer to an IPv6 packet
 */
static void
handle_prefixoption (uint8_t *option)
{
	ip6_addr_t prefix;
	struct ip6addr_list_entry *new_address;
	struct option_prefix *prefix_option;
	struct prefix_info *prfx_info;

	prefix_option = (struct option_prefix *) option;
	memcpy( &(prefix.addr), &(prefix_option->prefix.addr), IPV6_ADDR_LENGTH);

	/* Link-local adresses in RAs are nonsense                  */
	if ( (IPV6_LL_PREFIX & (prefix_option->prefix.part.prefix)) == IPV6_LL_PREFIX )
		return;

	if (prefix_option->preferred_lifetime > prefix_option->valid_lifetime)
		return;

	/* Add address created from prefix to IPv6 address list */
	new_address = ip6_prefix2addr (prefix);
	if (!new_address)
		return;

	/* Process only prefixes we don't already have an adress from */
	if (!unknown_prefix (&new_address->addr)) {
		return;
	}

	/* Fill struct prefix_info from data in RA and store it in new_address */
	prfx_info = ip6_create_prefix_info();
	if (!prfx_info)
		return;
	memcpy (&(new_address->prfx_info), prfx_info, sizeof(struct prefix_info));

	/* Add prefix received in RA to list of known prefixes */
	ip6addr_add (new_address);
}

/**
 * NET: Process source link layer addresses in Router Advertisements
 *
 * @param  ip6_packet	pointer to an IPv6 packet
 */
static void
handle_source_lladdr ( struct option_ll_address *option, struct router *rtr)
{
	memcpy (&(rtr->mac), &(option->mac), 6);
}

/**
 * NET: Process ICMPv6 options in Router Advertisements
 *
 * @param  ip6_packet	pointer to an IPv6 packet
 */
static void
process_ra_options (uint8_t *option, int32_t option_length, struct router *r)
{
	while (option_length > 0) {
		switch (*option) {
			case ND_OPTION_SOURCE_LL_ADDR:
				handle_source_lladdr ((struct option_ll_address *) option, r);
				break;
			case ND_OPTION_PREFIX_INFO:
				handle_prefixoption(option);
				break;
			default:
				break;
		}
		//option+1 is the length field. length is in units of 8 bytes
		option_length = option_length - (*(option+1) * 8);
		option = option + (*(option+1) * 8);
	}

	return;
}

/**
 * NET: Process Router Advertisements
 *
 * @param  ip6_packet	pointer to an IPv6 packet
 */
static void
handle_ra (struct icmp6hdr *icmp6h, uint8_t *ip6_packet)
{
	uint8_t  *first_option;
	int32_t option_length;
	struct ip6hdr *ip6h;
	struct router_advertisement *ra;
	struct router *rtr;
	ip6_addr_t *rtr_ip;
	uint8_t rtr_mac[] = {0, 0, 0, 0, 0, 0};

	ip6h = (struct ip6hdr *) ip6_packet;
	ra = (struct router_advertisement *) &icmp6h->icmp6body.ra;
	rtr_ip = (ip6_addr_t *) &ip6h->src;

	rtr = find_router (&(ip6h->src));
	if (!rtr) {
		rtr = router_create (rtr_mac, rtr_ip);
		router_add (rtr);
	}

	/* store info from router advertisement in router struct */
	rtr->lifetime = ra->router_lifetime;
	rtr->reachable_time = ra->reachable_time;
	rtr->retrans_timer = ra->retrans_timer;

	/* save flags concerning address (auto-) configuration */
	ip6_state.managed_mode = ra->flags.managed;
	ip6_state.other_config = ra->flags.other;

	/* Process ICMPv6 options in Router Advertisement */
	first_option = (uint8_t *) icmp6h + ICMPv6_HEADER_SIZE + 12;
	option_length =  (uint8_t *) icmp6h + ip6h->pl - first_option;
	process_ra_options( (uint8_t *) first_option, option_length, rtr);

	ra_received = 1;
}

int is_ra_received(void)
{
	return ra_received;
}

/**
 * NET:
 *
 * @param  fd         socket fd
 * @param  ip6_addr_t *dest_ip6
 */
void
send_neighbour_solicitation (int fd, ip6_addr_t *dest_ip6)
{
	ip6_addr_t snma;

	uint8_t ether_packet[ETH_MTU_SIZE];
	struct  packeth headers;

	memset(ether_packet, 0, ETH_MTU_SIZE);
	headers.ethh   = (struct ethhdr *) ether_packet;
	headers.ip6h   = (struct ip6hdr *) (ether_packet + sizeof(struct ethhdr));
	headers.icmp6h = (struct icmp6hdr *) (ether_packet +
			  sizeof(struct ethhdr) +
			  sizeof(struct ip6hdr));

	/* Fill IPv6 header */
	snma.part.prefix       = IPV6_SOLIC_NODE_PREFIX;
	snma.part.interface_id = IPV6_SOLIC_NODE_IFACE_ID;
	snma.addr[13]          = dest_ip6->addr[13];
	snma.addr[14]          = dest_ip6->addr[14];
	snma.addr[15]          = dest_ip6->addr[15];
        fill_ip6hdr((uint8_t *) headers.ip6h,
                   ICMPv6_HEADER_SIZE +
		   sizeof(struct neighbour_solicitation),
		   0x3a, //ICMPv6
                   get_ipv6_address(), &snma);

	/* Fill ICMPv6 message */
	headers.icmp6h->type = ICMPV6_NEIGHBOUR_SOLICITATION;
	headers.icmp6h->code = 0;
	memcpy( &(headers.icmp6h->icmp6body.nghb_solicit.target),
		dest_ip6, IPV6_ADDR_LENGTH );
	headers.icmp6h->icmp6body.nghb_solicit.lladdr.type    = 1;
	headers.icmp6h->icmp6body.nghb_solicit.lladdr.length  = 1;
	memcpy( &(headers.icmp6h->icmp6body.nghb_solicit.lladdr.mac),
		get_mac_address(), 6);

	send_ip (fd, ether_packet + sizeof(struct ethhdr),
		   sizeof(struct ip6hdr) + ICMPv6_HEADER_SIZE +
		   sizeof(struct neighbour_solicitation));
}

/**
 * NET:
 *
 * @param  fd           socket fd
 * @param  ip6_packet	pointer to an IPv6 packet
 * @param  icmp6hdr	pointer to the icmp6 header in ip6_packet
 * @param  na_flags	Neighbour advertisment flags
 */
static void
send_neighbour_advertisement (int fd, struct neighbor *target)
{
	struct na_flags na_adv_flags;
	uint8_t ether_packet[ETH_MTU_SIZE];
	struct  packeth headers;


	headers.ip6h   = (struct ip6hdr *) (ether_packet + sizeof(struct ethhdr));
	headers.icmp6h = (struct icmp6hdr *) (ether_packet +
			  sizeof(struct ethhdr) +
			  sizeof(struct ip6hdr));

	/* Fill IPv6 header */
        fill_ip6hdr(ether_packet + sizeof(struct ethhdr),
                   ICMPv6_HEADER_SIZE +
		   sizeof(struct neighbour_advertisement),
		   0x3a, //ICMPv6
                   get_ipv6_address(), (ip6_addr_t *) &(target->ip.addr));

	/* Fill ICMPv6 message */
	memcpy( &(headers.icmp6h->icmp6body.nghb_adv.target),
		&(target->ip.addr), IPV6_ADDR_LENGTH );
	headers.icmp6h->icmp6body.nghb_adv.lladdr.type    = 1;
	headers.icmp6h->icmp6body.nghb_adv.lladdr.length  = 1;
	memcpy( &(headers.icmp6h->icmp6body.nghb_adv.lladdr.mac),
		get_mac_address(), 6);

	na_adv_flags.is_router = 0;
	na_adv_flags.na_is_solicited = 1;
	na_adv_flags.override = 1;

	headers.icmp6h->type = ICMPV6_NEIGHBOUR_ADVERTISEMENT;
	headers.icmp6h->code = 0;
	headers.icmp6h->icmp6body.nghb_adv.router    = na_adv_flags.is_router;

	headers.icmp6h->icmp6body.nghb_adv.solicited = na_adv_flags.na_is_solicited;
	headers.icmp6h->icmp6body.nghb_adv.override  = na_adv_flags.override;
	headers.icmp6h->icmp6body.nghb_adv.lladdr.type	    = 2;
	headers.icmp6h->icmp6body.nghb_adv.lladdr.length    = 1;

	memset( &(headers.icmp6h->icmp6body.nghb_adv.target), 0,
		IPV6_ADDR_LENGTH );

	if( na_adv_flags.na_is_solicited ) {
		memcpy( &(headers.icmp6h->icmp6body.nghb_adv.target),
			get_ipv6_address(), IPV6_ADDR_LENGTH);
	}

	memcpy( &(headers.icmp6h->icmp6body.nghb_adv.lladdr.mac),
		get_mac_address(), 6);

	send_ip (fd, ether_packet + sizeof(struct ethhdr),
		   sizeof(struct ip6hdr) + ICMPv6_HEADER_SIZE +
		   sizeof(struct neighbour_advertisement));
}

/**
 * NET:
 *
 * @param  fd           socket fd
 * @param  ip6_packet	pointer to an IPv6 packet
 */
static int8_t
handle_na (int fd, uint8_t *packet)
{
	struct neighbor *n = NULL;
	struct packeth headers;
	ip6_addr_t ip;

	headers.ethh = (struct ethhdr *) packet;
	headers.ip6h = (struct ip6hdr *) ((unsigned char *) headers.ethh +
		                                        sizeof(struct ethhdr));
        headers.icmp6h = (struct icmp6hdr *) (packet +
					      sizeof(struct ethhdr) +
					      sizeof(struct ip6hdr));

	memcpy(&(ip.addr), &(headers.ip6h->src), IPV6_ADDR_LENGTH);

	n = find_neighbor (&ip);

	if (!n) {
		n= (struct neighbor *)
			neighbor_create( packet, &headers );
		if (!n)
			return 0;
		if (!neighbor_add(n))
			return 0;
	} else {
		memcpy (&(n->mac), &(headers.ethh->src_mac[0]), 6);

		if (n->eth_len > 0) {
			struct ethhdr * ethh = (struct ethhdr *) &(n->eth_frame);
			memcpy(ethh->dest_mac, &(n->mac), 6);
			send_ether (fd, &(n->eth_frame), n->eth_len + sizeof(struct ethhdr));
			n->eth_len = 0;
		}
	}

	return 1;
}

/**
 * NET: Handles ICMPv6 messages
 *
 * @param  fd           socket fd
 * @param  ip6_packet	pointer to an IPv6 packet
 * @param  packetsize	size of ipv6_packet
 */
int8_t
handle_icmpv6 (int fd, struct ethhdr *etherhdr,
	      uint8_t  *ip6_packet)
{

	struct icmp6hdr *received_icmp6 = NULL;
	struct ip6hdr *received_ip6	= NULL;
	struct neighbor target;

	received_ip6 =   (struct ip6hdr *) ip6_packet;
	received_icmp6 = (struct icmp6hdr *) (ip6_packet +
			  sizeof(struct ip6hdr));
	memcpy( &(target.ip.addr), &(received_ip6->src),
		IPV6_ADDR_LENGTH );
	memcpy( &(target.mac), etherhdr->src_mac, 6);

	/* process ICMPv6 types */
	switch(received_icmp6->type) {
		case ICMPV6_NEIGHBOUR_SOLICITATION:
			send_neighbour_advertisement(fd, &target);
			break;
		case ICMPV6_NEIGHBOUR_ADVERTISEMENT:
			handle_na(fd, (uint8_t *) ip6_packet - sizeof(struct ethhdr));
			break;
		case ICMPV6_ROUTER_ADVERTISEMENT:
			handle_ra(received_icmp6, (uint8_t *) received_ip6);
			break;
		default:
			return -1;
	}

	return 1;
}
