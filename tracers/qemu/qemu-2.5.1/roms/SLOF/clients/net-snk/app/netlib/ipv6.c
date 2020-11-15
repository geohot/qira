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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netlib/ethernet.h>
#include <netlib/ipv6.h>
#include <netlib/icmpv6.h>
#include <netlib/ndp.h>
#include <netlib/udp.h>

#undef IPV6_DEBUG
//#define IPV6_DEBUG
#ifdef IPV6_DEBUG
#define dprintf(_x ...) do { printf(_x); } while (0)
#else
#define dprintf(_x ...)
#endif

/****************************** PROTOTYPES *******************************/
int8_t ip6addr_add (struct ip6addr_list_entry *new_address);
static void ipv6_init(int fd);
static int ip6_is_multicast (ip6_addr_t * ip);

/****************************** LOCAL VARIABLES **************************/

/* Own IPv6 address */
static struct ip6addr_list_entry *own_ip6;

/* Null IPv6 address */
static ip6_addr_t null_ip6;

/* helper variables */
static uint8_t null_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


/****************************** IMPLEMENTATION ***************************/

/**
 * IPv6: Set the own IPv6 address.
 *
 * @param  fd            Socket descriptor
 * @param  _own_ip       client IPv6 address (e.g. ::1)
 */
void
set_ipv6_address (int fd, ip6_addr_t *_own_ip6)
{
	own_ip6 = malloc (sizeof(struct ip6addr_list_entry));

	/* If no address was passed as a parameter generate a link-local
	 * address from our MAC address.*/
	if (_own_ip6 == NULL)
		memcpy(&(own_ip6->addr.addr),
			ip6_create_ll_address(get_mac_address()),
		       IPV6_ADDR_LENGTH);
	else
		memcpy (&(own_ip6->addr.addr), _own_ip6, 16);

	/* Add to our list of IPv6 addresses */
	ip6addr_add (own_ip6);

	ipv6_init(fd);
}

/**
 * IPv6: Get pointer to own IPv6 address.
 *
 * @return pointer to client IPv6 address (e.g. ::1)
 */
ip6_addr_t *
get_ipv6_address (void)
{
	return (ip6_addr_t *) &(own_ip6->addr);
}

/**
 * IPv6: Search for IPv6 address in list
 *
 * @return 0 - IPv6 address is not in list
 *         1 - IPv6 address is in list
 */
static int8_t
find_ip6addr (ip6_addr_t *ip)
{
	struct ip6addr_list_entry *n = NULL;

	if (ip == NULL)
	    return 0;

	for (n = first_ip6; n != NULL ; n=n->next)
		if (ip6_cmp (&(n->addr), ip))
			return 1; /* IPv6 address is in  our list*/

	return 0; /* not one of our IPv6 addresses*/
}

/**
 * NET: Handles IPv6-packets
 *
 * @param  fd         - Socket descriptor
 * @param  ip6_packet - Pointer to IPv6 header
 * @param  packetsize - Size of Ipv6 packet
 * @return ERROR      - -1 if packet is too small or unknown protocol
 *			return value of handle_udp
 *
 * @see handle_udp
 * @see ip6hdr
 */
int8_t
handle_ipv6 (int fd, uint8_t * ip6_packet, int32_t packetsize)
{

	struct ip6hdr *ip6 = NULL;
	ip6 = (struct ip6hdr *) ip6_packet;

	/* Only handle packets which are for us */
	if (! find_ip6addr(&(ip6->dst)))
		return -1;

	if (packetsize < sizeof(struct ip6hdr))
		return -1; // packet is too small

	switch (ip6->nh) {
		case IPTYPE_UDP:
			return handle_udp (fd, ip6_packet + sizeof (struct ip6hdr),
					ip6->pl);
		case IPTYPE_ICMPV6:
			return handle_icmpv6 (fd, (struct ethhdr *) ip6_packet - sizeof(struct ethhdr),
					      ip6_packet);
	}

	return -1; // unknown protocol
}

 /**
 * NET: Creates IPv6-packet. Places IPv6-header in a packet and fills it
 *      with corresponding information.
 *      <p>
 *      Use this function with similar functions for other network layers
 *      (fill_ethhdr, fill_udphdr, fill_dnshdr, fill_btphdr).
 *
 * @param  packet      Points to the place where IPv6-header must be placed.
 * @param  packetsize  Size of payload (i.e. excluding ethhdr and ip6hdr)
 * @param  ip_proto    Type of the next level protocol (e.g. UDP).
 * @param  ip6_src     Sender IPv6 address
 * @param  ip6_dst     Receiver IPv6 address
 * @see                ip6hdr
 * @see                fill_iphdr
 * @see                fill_ethhdr
 * @see                fill_udphdr
 * @see                fill_dnshdr
 * @see                fill_btphdr
 */
void
fill_ip6hdr (uint8_t * packet, uint16_t packetsize,
             uint8_t ip_proto, ip6_addr_t *ip6_src, ip6_addr_t *ip6_dst)
{

	struct ip6hdr * ip6h = (struct ip6hdr *) packet;

	ip6h->ver_tc_fl = 6 << 28;	// set version to 6
	ip6h->pl = packetsize;		// IPv6 payload size
	ip6h->nh = ip_proto;
	ip6h->hl = 255;
	memcpy (&(ip6h->src), ip6_src, IPV6_ADDR_LENGTH);
	memcpy (&(ip6h->dst), ip6_dst, IPV6_ADDR_LENGTH);
}

/**
 * NET: For a given MAC calculates EUI64-Identifier.
 *      See RFC 4291 "IP Version 6 Addressing Architecture"
 *
 */
uint64_t
mac2eui64 (const uint8_t *mac)
{
	uint8_t eui64id[8];
	uint64_t retid;

	memcpy (eui64id, mac, 3);
	memcpy (eui64id + 5, mac + 3, 3);
	eui64id[3] = 0xff;
	eui64id[4] = 0xfe;

	memcpy(&retid, eui64id, 8);
	return retid;
}

/**
 * NET: create link-local IPv6 address
 *
 * @param  own_mac    MAC of NIC
 * @return ll_addr    pointer to newly created link-local address
 */
ip6_addr_t *
ip6_create_ll_address (const uint8_t *own_mac)
{
	ip6_addr_t *ll_addr;

	ll_addr = malloc (sizeof (struct ip6addr_list_entry));
	memset (ll_addr, 0, IPV6_ADDR_LENGTH);
	ll_addr->part.prefix       |= IPV6_LL_PREFIX;
	ll_addr->part.interface_id |= mac2eui64((uint8_t *) own_mac);

	return ll_addr;
}

/*
 * NET: check if we already have an address with the same prefix.
 * @param  struct ip6_addr_list_entry *ip6
 * @return true or false
 */
int8_t
unknown_prefix (ip6_addr_t *ip)
{
	struct ip6addr_list_entry *node;

	for( node = first_ip6; node != NULL; node=node->next )
		if( node->addr.part.prefix == ip->part.prefix )
			return 0; /* address is one of ours */

	return 1; /* prefix not yet in our list */
}

/*
 * NET: Create empty element for prefix list and return a pointer to it;
 * @return NULL - malloc failed
 *	   ! NULL - pointer to new prefix_info
 */
struct prefix_info *
ip6_create_prefix_info ()
{
	struct prefix_info *prfx_info;

	prfx_info = malloc (sizeof(struct prefix_info));
	if (!prfx_info)
		return NULL;

	return prfx_info;
}

/*
 * NET: create a new IPv6 address with a given network prefix
 *	and add it to our IPv6 address list
 *
 * @param  ip6_addr prefix (as received in RA)
 * @return NULL - pointer to new ip6addr_list entry
 */
void *
ip6_prefix2addr (ip6_addr_t prefix)
{
	struct ip6addr_list_entry *new_address;
	uint64_t interface_id;

	new_address = malloc (sizeof(struct ip6addr_list_entry));
	if( !new_address )
		return NULL;

	/* fill new addr struct */
	/* extract prefix from Router Advertisement */
	memcpy (&(new_address->addr.part.prefix), &prefix, 8 );

	/* interface id is generated from MAC address */
	interface_id = mac2eui64 (get_mac_address());
	memcpy (&(new_address->addr.part.interface_id), &interface_id, 8);

	return new_address;
}

/**
 * NET: add new IPv6 adress to list
 *
 * @param   ip6_addr *new_address
 * @return  0 - passed pointer = NULL;
 *	    1 - ok
 */
int8_t
ip6addr_add (struct ip6addr_list_entry *new_address)
{
	struct ip6addr_list_entry *solicited_node;


	if (new_address == NULL)
		return 0;

	 /* Don't add the same address twice */
	if (find_ip6addr (&(new_address->addr)))
		return 0;

	/* If address is a unicast address, we also have to process packets
	 * for its solicited-node multicast address.
	 * See RFC 2373 - IP Version 6 Adressing Architecture */
	if (! ip6_is_multicast(&(new_address->addr))) {


		solicited_node = malloc(sizeof(struct ip6addr_list_entry));
		if (! solicited_node)
			return 0;

		solicited_node->addr.part.prefix       = IPV6_SOLIC_NODE_PREFIX;
		solicited_node->addr.part.interface_id = IPV6_SOLIC_NODE_IFACE_ID;
		solicited_node->addr.addr[13] = new_address->addr.addr[13];
		solicited_node->addr.addr[14] = new_address->addr.addr[14];
		solicited_node->addr.addr[15] = new_address->addr.addr[15];
		ip6addr_add (solicited_node);
	}

        if (NULL == first_ip6)
                first_ip6 = new_address;
        last_ip6->next = new_address;
        last_ip6 = new_address;
        last_ip6->next = NULL;

        return 1; /* no error */
}

/**
 * NET: Initialize IPv6
 *
 * @param  fd            socket fd
 */
static void
ipv6_init (int fd)
{
	int i = 0;

	send_ip = &send_ipv6;

	/* Address configuration parameters */
	ip6_state.managed_mode = 0;

	/* Null IPv6 address */
	null_ip6.part.prefix       = 0;
	null_ip6.part.interface_id = 0;

	/* Multicast addresses */
	all_nodes_ll.addr.part.prefix         = 0xff02000000000000;
	all_nodes_ll.addr.part.interface_id   = 1;
	all_dhcpv6_ll.addr.part.prefix        = 0xff02000000000000ULL;
	all_dhcpv6_ll.addr.part.interface_id  = 0x10002ULL;
	all_routers_ll.addr.part.prefix       = 0xff02000000000000;
	all_routers_ll.addr.part.interface_id      = 2;

	ip6addr_add(&all_nodes_ll);
	/* ... */

	/* Router list */
	first_router = NULL;
	last_router = first_router;

	/* Init Neighbour cache */
	first_neighbor = NULL;
	last_neighbor  = first_neighbor;

	send_router_solicitation (fd);
	for(i=0; i < 4 && !is_ra_received(); i++) {
		set_timer(TICKS_SEC);
		do {
			receive_ether(fd);
			if (is_ra_received())
				break;
		} while (get_timer() > 0);
	}
}

/**
 * NET: compare IPv6 adresses
 *
 * @param  ip6_addr ip_1
 * @param  ip6_addr ip_2
 */
int8_t
ip6_cmp (ip6_addr_t *ip_1, ip6_addr_t *ip_2)
{
	return ((int8_t) !memcmp( &(ip_1->addr[0]), &(ip_2->addr[0]),
		IPV6_ADDR_LENGTH ));
}

/**
 * NET: Calculate checksum over IPv6 header and upper-layer protocol
 *      (e.g. UDP or ICMPv6)
 *
 * @param  *ip    - pointer to IPv6 address
 * @return true or false
 */
int
ip6_is_multicast (ip6_addr_t * ip)
{
	uint8_t mc = 0xFF;
	return ! memcmp(&ip->addr[0], &mc, 1);
}

/**
 * NET: Generate multicast MAC address from IPv6 address
 *      (e.g. UDP or ICMPv6)
 *
 * @param  *ip    - pointer to IPv6 address
 * @return pointer to Multicast MAC address
 */
static uint8_t *
ip6_to_multicast_mac (ip6_addr_t * ip)
{
	uint8_t *mc_mac;

	mc_mac = malloc(ETH_ALEN);
	if (!mc_mac)
		return NULL;

	mc_mac[0] = 0x33;
	mc_mac[1] = 0x33;
	memcpy (mc_mac+2, (uint8_t *) &(ip->addr)+12, 4);

	return mc_mac;
}

/**
 * NET: calculate checksum over IPv6 header and upper-layer protocol
 *      (e.g. UDP or ICMPv6)
 *
 * @param  struct ip6hdr *ip6h    - pointer to IPv6 header
 * @param  unsigned short *packet - pointer to header of upper-layer
 *				    protocol
 * @param  int words              - number of words (as in 2 bytes)
 *				    starting from *packet
 * @return checksum
 */
static unsigned short
ip6_checksum (struct ip6hdr *ip6h, unsigned short *packet, int words)
{
	int i=0;
	unsigned long checksum;
	struct ip6hdr pseudo_ip6h;
	unsigned short *pip6h;

	memcpy (&pseudo_ip6h, ip6h, sizeof(struct ip6hdr));
	pseudo_ip6h.hl	      = ip6h->nh;
	pseudo_ip6h.ver_tc_fl = 0;
	pseudo_ip6h.nh	      = 0;
	pip6h = (unsigned short *) &pseudo_ip6h;

	for (checksum = 0; words > 0; words--) {
		checksum += *packet++;
		i++;
	}

	for (i = 0; i < 20; i++) {
		checksum += *pip6h++;
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	return ~checksum;
}

/**
 * NET: Handles IPv6-packets
 *
 * @param fd          socket fd
 * @param ip6_packet  Pointer to IPv6 header in packet
 * @param packetsize  Size of IPv6 packet
 * @return -1 == ERRROR
 *	   return of handle_udp() or handle_icmp6()
 *
 * @see receive_ether
 * @see ip6hdr
 */
int
send_ipv6 (int fd, void* buffer, int len)
{
	struct neighbor *n;
	struct ip6hdr *ip6h;
	struct udphdr *udph;
	struct icmp6hdr *icmp6h;
	ip6_addr_t ip_dst;
	uint8_t *mac_addr, mac[6];

	mac_addr = mac;

	ip6h    = (struct ip6hdr *) buffer;
	udph   = (struct udphdr *)   ((uint8_t *) ip6h + sizeof (struct ip6hdr));
	icmp6h = (struct icmp6hdr *) ((uint8_t *) ip6h + sizeof (struct ip6hdr));

	memcpy(&ip_dst, &ip6h->dst, 16);

	if(len + sizeof(struct ethhdr) > 1500)
		return -1;

	if ( ip6_cmp (&ip6h->src, &null_ip6))
		memcpy (&(ip6h->src), get_ipv6_address(), IPV6_ADDR_LENGTH);

	if (ip6h->nh == 17) {//UDP
		udph->uh_sum = ip6_checksum (ip6h, (unsigned short *) udph ,
					     ip6h->pl >> 1);
		/* As per RFC 768, if the computed  checksum  is zero,
		 * it is transmitted as all ones (the equivalent in
		 * one's complement arithmetic).
		 */
		if (udph->uh_sum == 0)
			udph->uh_sum = ~udph->uh_sum;
	}
	else if (ip6h->nh == 0x3a) //ICMPv6
		icmp6h->checksum = ip6_checksum (ip6h,
						 (unsigned short *) icmp6h,
						 ip6h->pl >> 1);

	n = find_neighbor (&ip_dst);

	// If packet is a neighbor solicitation
	if (icmp6h->type == ICMPV6_NEIGHBOUR_SOLICITATION) {
		mac_addr = ip6_to_multicast_mac (&ip_dst);
		fill_ethhdr( buffer-sizeof(struct ethhdr), htons(ETHERTYPE_IPv6),
			     get_mac_address(),
			     mac_addr);
	}

	// If address is a multicast address, create a proper mac address
	else if (ip6_is_multicast (&ip_dst)) {
		mac_addr = ip6_to_multicast_mac (&ip_dst);
	}
	else {
		// Check if the MAC address is already cached
		if (n) {
			if (memcmp(n->mac, null_mac, ETH_ALEN) != 0)
				memcpy (mac_addr, &(n->mac), ETH_ALEN); /* found it */
		} else {
			mac_addr = null_mac;
			n = malloc(sizeof(struct neighbor));
			memcpy(&(n->ip.addr[0]), &ip_dst, 16);
			n->status = NB_PROBE;
			n->times_asked += 1;
			neighbor_add(n);
		}

		if (! memcmp (mac_addr, &null_mac, 6)) {
			if (n->eth_len == 0) {
				send_neighbour_solicitation (fd, &ip_dst);

				// Store the packet until we know the MAC address
				memset(n->eth_frame, 0, 1500);
				fill_ethhdr (n->eth_frame,
					     htons(ETHERTYPE_IPv6),
					     get_mac_address(),
					     mac_addr);
				memcpy (&(n->eth_frame[sizeof(struct ethhdr)]),
				       buffer, len);
				n->eth_len = len;
				set_timer(TICKS_SEC);
				do {
					receive_ether(fd);
				} while (get_timer() > 0);
			}
		}
	}

	fill_ethhdr (n->eth_frame, htons(ETHERTYPE_IPv6), get_mac_address(),
		     mac_addr);
	memcpy (&(n->eth_frame[sizeof(struct ethhdr)]), buffer, len);
	return send_ether (fd, n->eth_frame, len + sizeof(struct ethhdr));
}

static int
check_colons(const char *str)
{
	char *pch, *prv;
	int col = 0;
	int dcol = 0;

	dprintf("str : %s\n",str);
	pch = strchr(str, ':');
	while(pch != NULL){
		prv = pch;
		pch = strchr(pch+1, ':');
		if((pch-prv) != 1) {
			col++;
		} else {
			col--; /* Its part of double colon */
			dcol++;
		}
	}

	dprintf("The number of  col : %d \n",col);
	dprintf("The number of dcol : %d \n",dcol);

	if((dcol > 1) ||                      /* Cannot have 2 "::" */ 
	   ((dcol == 1) && (col > 5)) ||      /* Too many ':'s */
	   ((dcol == 0) && (col != 7)) ) {    /* Too few ':'s */
		dprintf(" exiting for check_colons \n");
		return 0;
	}

	return (col+dcol);
}

static int
ipv6str_to_bytes(const char *str, char *ip)
{
	char block[5];
	int res;
	char *pos;
	uint32_t cnt = 0, len;

	dprintf("str : %s \n",str);

	while (*str != 0) {
		if (cnt > 15 || !isxdigit(*str)){
			return 0;
		}
		if ((pos = strchr(str, ':')) != NULL) {
			len = (int16_t) (pos - str);
			dprintf("\t len  is : %d \n",len);
			if (len > 4)
				return 0;
			strncpy(block, str, len);
			block[len] = 0;
			dprintf("\t str   : %s \n",str);
			dprintf("\t block : %s \n",block);
			str += len;
		} else {
			strncpy(block, str, 4);
			block[4] = 0;
			dprintf("\t str   : %s \n",str);
			dprintf("\t block : %s \n",block);
			str += strlen(block);
		}
		res = strtol(block, NULL, 16);
		dprintf("\t res : %x \n",res);
		if ((res > 0xFFFF) || (res < 0))
			return 0;
		ip[cnt++] = (res & 0xFF00) >> 8;
		ip[cnt++] = (res & 0x00FF);
		if (*str == ':'){
			str++;
		}
	}

	dprintf("cnt : %d\n",cnt);
	return cnt;
}

int str_to_ipv6(const char *str, uint8_t *ip)
{
	int i, k;
	uint16_t len;
	char *ptr;
	char tmp[30], buf[16];

	memset(ip,0,16);

	if(!check_colons(str))
		return 0;

	if ((ptr = strstr(str, "::")) != NULL) {
		/* Handle the ::1 IPv6 loopback */
		if(!strcmp(str,"::1")) {
			ip[15] = 1;
			return 16;
		}
		len = (ptr-str);
		dprintf(" len : %d \n",len);
		if (len >= sizeof(tmp))
			return 0;
		strncpy(tmp, str, len);
		tmp[len] = 0;
		ptr += 2;

		i = ipv6str_to_bytes(ptr, buf);
		if(i == 0)
		return i;

		#if defined(ARGS_DEBUG)
		int j;
		dprintf("=========== bottom part i : %d \n",i);
		for(j=0; j<i; j++)
			dprintf("%02x \t",buf[j]);
		#endif

		/* Copy the bottom part i.e bytes following "::" */
		memcpy(ip+(16-i), buf, i);

		k = ipv6str_to_bytes(tmp, buf);
		if(k == 0)
			return k;

		#if defined(ARGS_DEBUG)
		dprintf("=========== top part k : %d \n",k);
		for(j=0; j<k; j++)
			printf("%02x \t",buf[j]);
		#endif

		/* Copy the top part i.e bytes before "::"  */
		memcpy(ip, buf, k);
		#if defined(ARGS_DEBUG)
		dprintf("\n");
		for(j=0; j<16; j++)
			dprintf("%02x \t",ip[j]);
		#endif

	} else {
		i = ipv6str_to_bytes(str, (char *)ip);
	}
	return i;
}

void ipv6_to_str(const uint8_t *ip, char *str)
{
	int i, len;
	uint8_t byte_even, byte_odd;
	char *consec_zero, *strptr;

	*str = 0;
	for (i = 0; i < 16; i+=2) {
		byte_even = ip[i];
		byte_odd = ip[i+1];
		if (byte_even)
			sprintf(str, "%s%x%02x", str, byte_even, byte_odd);
		else if (byte_odd)
			sprintf(str, "%s%x", str, byte_odd);
		else
			strcat(str, "0");
		if (i != 14)
			strcat(str, ":");
	}
	strptr = str;
	do {
		consec_zero = strstr(strptr, "0:0:");
		if (consec_zero) {
			len = consec_zero - strptr;
			if (!len)
				break;
			else if (strptr[len-1] == ':')
				break;
			else
				strptr = consec_zero + 2;
		}
	} while (consec_zero);
	if (consec_zero) {
		len = consec_zero - str;
		str[len] = 0;
		if (len)
			strcat(str, ":");
		else
			strcat(str, "::");
		strptr = consec_zero + 4;
		while (*strptr) {
			if (!strncmp(strptr, "0:", 2))
				strptr += 2;
			else
				break;
		}
		strcat(str, strptr);
		if (!strcmp(str, "::0"))
			strcpy(str, "::");
	}
}
