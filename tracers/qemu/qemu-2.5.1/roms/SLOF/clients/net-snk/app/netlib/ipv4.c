/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/


/*>>>>>>>>>>>>>>>>>>>>> DEFINITIONS & DECLARATIONS <<<<<<<<<<<<<<<<<<<<<<*/

#include <ipv4.h>
#include <udp.h>
#include <tcp.h>
#include <ethernet.h>
#include <time.h>
#include <sys/socket.h>
#include <string.h>

/* ARP Message types */
#define ARP_REQUEST            1
#define ARP_REPLY              2

/* ARP talbe size (+1) */
#define ARP_ENTRIES 10

/* ICMP Message types */
#define ICMP_ECHO_REPLY            0
#define ICMP_DST_UNREACHABLE       3
#define ICMP_SRC_QUENCH            4
#define ICMP_REDIRECT              5
#define ICMP_ECHO_REQUEST          8
#define ICMP_TIME_EXCEEDED        11
#define ICMP_PARAMETER_PROBLEM    12
#define ICMP_TIMESTAMP_REQUEST    13
#define ICMP_TIMESTAMP_REPLY      14
#define ICMP_INFORMATION_REQUEST  15
#define ICMP_INFORMATION_REPLY    16

/** \struct arp_entry
 *  A entry that describes a mapping between IPv4- and MAC-address.
 */
typedef struct arp_entry arp_entry_t;
struct arp_entry {
	uint32_t ipv4_addr;
	uint8_t  mac_addr[6];
	uint8_t  eth_frame[ETH_MTU_SIZE];
	int      eth_len;
	int	 pkt_pending;
};

/** \struct icmphdr
 *  ICMP packet
 */
struct icmphdr {
	unsigned char type;
	unsigned char code;
	unsigned short int checksum;
	union {
		/* for type 3 "Destination Unreachable" */
		unsigned int unused;
		/* for type 0 and 8 */
		struct echo {
			unsigned short int id;
			unsigned short int seq;
		} echo;
	} options;
	union {
		/* payload for destination unreachable */
		struct dun {
			unsigned char iphdr[20];
			unsigned char data[64];
		} dun;
		/* payload for echo or echo reply */
		/* maximum size supported is 84 */
		unsigned char data[84];
	} payload;
};

/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>> PROTOTYPES <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/

static unsigned short
checksum(unsigned short *packet, int words);

static void
arp_send_request(int fd, uint32_t dest_ip);

static void
arp_send_reply(int fd, uint32_t src_ip, uint8_t * src_mac);

static void
fill_arphdr(uint8_t * packet, uint8_t opcode,
            const uint8_t * src_mac, uint32_t src_ip,
            const uint8_t * dest_mac, uint32_t dest_ip);

static arp_entry_t*
lookup_mac_addr(uint32_t ipv4_addr);

static void
fill_udp_checksum(struct iphdr *ipv4_hdr);

static int8_t
handle_icmp(int fd, struct iphdr * iph, uint8_t * packet, int32_t packetsize);

/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>> LOCAL VARIABLES <<<<<<<<<<<<<<<<<<<<<<<<<*/

/* Routing parameters */
static uint32_t own_ip       = 0;
static uint32_t multicast_ip = 0;
static uint32_t router_ip    = 0;
static uint32_t subnet_mask  = 0;

/* helper variables */
static uint32_t ping_dst_ip;
static const uint8_t null_mac_addr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t broadcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static       uint8_t multicast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* There are only (ARP_ENTRIES-1) effective entries because
 * the entry that is pointed by arp_producer is never used.
 */
static unsigned int arp_consumer = 0;
static unsigned int arp_producer = 0;
static arp_entry_t  arp_table[ARP_ENTRIES];
static arp_entry_t  pending_pkt;

/* Function pointer send_ip. Points either to send_ipv4() or send_ipv6() */
int   (*send_ip) (int fd, void *, int);

/*>>>>>>>>>>>>>>>>>>>>>>>>>>>> IMPLEMENTATION <<<<<<<<<<<<<<<<<<<<<<<<<<<*/

/**
 * IPv4: Initialize the environment for the IPv4 layer.
 */
static void
ipv4_init(void)
{
	int i;

	ping_dst_ip = 0;

	// clear ARP table
	arp_consumer = 0;
	arp_producer = 0;
	for(i=0; i<ARP_ENTRIES; ++i) {
		arp_table[i].ipv4_addr = 0;
		memset(arp_table[i].mac_addr, 0, 6);
		arp_table[i].eth_len = 0;
		arp_table[i].pkt_pending = 0;
	}

	/* Set IP send function to send_ipv4() */ 
	send_ip = &send_ipv4;
}

/**
 * IPv4: Set the own IPv4 address.
 *
 * @param  _own_ip  client IPv4 address (e.g. 127.0.0.1)
 */
void
set_ipv4_address(uint32_t _own_ip)
{
	own_ip = _own_ip;
	ipv4_init();
}

/**
 * IPv4: Get the own IPv4 address.
 *
 * @return client IPv4 address (e.g. 127.0.0.1)
 */
uint32_t
get_ipv4_address(void)
{
	return own_ip;
}

/**
 * IPv4: Set the IPv4 multicast address.
 *
 * @param  _own_ip  multicast IPv4 address (224.0.0.0 - 239.255.255.255)
 */
void
set_ipv4_multicast(uint32_t _multicast_ip)
{
	// is this IP Multicast out of range (224.0.0.0 - 239.255.255.255)
	if((htonl(_multicast_ip) < 0xE0000000)
	|| (htonl(_multicast_ip) > 0xEFFFFFFF)) {
		multicast_ip = 0;
		memset(multicast_mac, 0xFF, 6);
		return;
	}

	multicast_ip = _multicast_ip;
	multicast_mac[0] = 0x01;
	multicast_mac[1] = 0x00;
	multicast_mac[2] = 0x5E;
	multicast_mac[3] = (uint8_t) 0x7F & (multicast_ip >> 16);
	multicast_mac[4] = (uint8_t) 0xFF & (multicast_ip >>  8);
	multicast_mac[5] = (uint8_t) 0xFF & (multicast_ip >>  0);
}

/**
 * IPv4: Get the IPv4 multicast address.
 *
 * @return multicast IPv4 address (224.0.0.0 - 239.255.255.255 or 0 if not set)
 */
uint32_t
get_ipv4_multicast(void)
{
	return multicast_ip;
}

/**
 * IPv4: Set the routers IPv4 address.
 *
 * @param  _router_ip   router IPv4 address
 */
void
set_ipv4_router(uint32_t _router_ip)
{
	router_ip = _router_ip;
	ipv4_init();
}

/**
 * IPv4: Get the routers IPv4 address.
 *
 * @return router IPv4 address
 */
uint32_t
get_ipv4_router(void)
{
	return router_ip;
}

/**
 * IPv4: Set the subnet mask.
 *
 * @param  _subnet_mask   netmask of the own IPv4 address
 */
void
set_ipv4_netmask(uint32_t _subnet_mask)
{
	subnet_mask = _subnet_mask;
	ipv4_init();
}

/**
 * IPv4: Get the subnet mask.
 *
 * @return netmask of the own IPv4 address
 */
uint32_t
get_ipv4_netmask(void)
{
	return subnet_mask;
}

/**
 * IPv4: Creates IP-packet. Places IP-header in a packet and fills it
 *       with corresponding information.
 *       <p>
 *       Use this function with similar functions for other network layers
 *       (fill_ethhdr, fill_udphdr, fill_dnshdr, fill_btphdr).
 *
 * @param  packet      Points to the place where IP-header must be placed.
 * @param  packetsize  Size of the packet in bytes incl. this hdr and data.
 * @param  ip_proto    Type of the next level protocol (e.g. UDP).
 * @param  ip_src      Sender IP address
 * @param  ip_dst      Receiver IP address
 * @see                iphdr
 * @see                fill_ethhdr
 * @see                fill_udphdr
 * @see                fill_dnshdr
 * @see                fill_btphdr
 */
void
fill_iphdr(uint8_t * packet, uint16_t packetsize,
           uint8_t ip_proto, uint32_t ip_src, uint32_t ip_dst) {
	struct iphdr * iph = (struct iphdr *) packet;

	iph -> ip_hlv = 0x45;
	iph -> ip_tos = 0x10;
	iph -> ip_len = htons(packetsize);
	iph -> ip_id = htons(0);
	iph -> ip_off = 0;
	iph -> ip_ttl = 0xFF;
	iph -> ip_p = ip_proto;
	iph -> ip_src = htonl(ip_src);
	iph -> ip_dst = htonl(ip_dst);
	iph -> ip_sum = 0;
}

/**
 * IPv4: Handles IPv4-packets according to Receive-handle diagram.
 *
 * @param  fd         socket fd
 * @param  ip_packet  IP-packet to be handled
 * @param  packetsize Length of the packet
 * @return            ZERO - packet handled successfully;
 *                    NON ZERO - packet was not handled (e.g. bad format)
 * @see               receive_ether
 * @see               iphdr
 */
int8_t
handle_ipv4(int fd, uint8_t * ip_packet, int32_t packetsize)
{
	struct iphdr * iph;
	int32_t old_sum;
	static uint8_t ip_heap[65536 + ETH_MTU_SIZE];

	if (packetsize < sizeof(struct iphdr))
		return -1; // packet is too small

	iph = (struct iphdr * ) ip_packet;

	/* Drop it if destination IPv4 address is no IPv4 Broadcast, no
	 * registered IPv4 Multicast and not our Unicast address
	 */
	if((multicast_ip == 0 && iph->ip_dst >= 0xE0000000 && iph->ip_dst <= 0xEFFFFFFF)
	|| (multicast_ip != iph->ip_dst && iph->ip_dst != 0xFFFFFFFF &&
	    own_ip != 0 && iph->ip_dst != own_ip)) {
		return -1;
	}

	old_sum = iph -> ip_sum;
	iph -> ip_sum = 0;
	if (old_sum != checksum((uint16_t *) iph, sizeof (struct iphdr) >> 1))
		return -1; // Wrong IP checksum

	// is it the first fragment in a packet?
	if (((iph -> ip_off) & 0x1FFF) == 0) {
		// is it part of more fragments?
		if (((iph -> ip_off) & 0x2000) == 0x2000) {
			memcpy(ip_heap, ip_packet, iph->ip_len);
			return 0;
		}
	}
	// it's not the first fragment
	else {
		// get the first fragment
		struct iphdr * iph_first = (struct iphdr * ) ip_heap;

		// is this fragment not part of the first one, then exit
		if ((iph_first->ip_id  != iph->ip_id ) ||
		    (iph_first->ip_p   != iph->ip_p  ) ||
		    (iph_first->ip_src != iph->ip_src) ||
		    (iph_first->ip_dst != iph->ip_dst)) {
			return 0;
		}

		// this fragment is part of the first one!
		memcpy(ip_heap + sizeof(struct iphdr) +
		       ((iph -> ip_off) & 0x1FFF) * 8,
		       ip_packet + sizeof(struct iphdr),
		       iph -> ip_len - sizeof(struct iphdr));

		// is it part of more fragments? Then return.
		if (((iph -> ip_off) & 0x2000) == 0x2000) {
			return 0;
		}

		// packet is completly reassambled now!

		// recalculate ip_len and set iph and ip_packet to the
		iph_first->ip_len = iph->ip_len + ((iph->ip_off) & 0x1FFF) * 8;

		// set iph and ip_packet to the resulting packet.
		ip_packet = ip_heap;
		iph = (struct iphdr * ) ip_packet;
	}

	switch (iph -> ip_p) {
	case IPTYPE_ICMP:
		return handle_icmp(fd, iph, ip_packet + sizeof(struct iphdr),
		                   iph -> ip_len - sizeof(struct iphdr));
	case IPTYPE_UDP:
		return handle_udp(fd, ip_packet + sizeof(struct iphdr),
		                  iph -> ip_len - sizeof(struct iphdr));
	case IPTYPE_TCP:
		return handle_tcp(ip_packet + sizeof(struct iphdr),
		                  iph -> ip_len - sizeof(struct iphdr));
	default:
		break;
	}
	return -1; // Unknown protocol
}

/**
 * IPv4: Send IPv4-packets.
 *
 *       Before the packet is sent there are some patcches performed:
 *       - IPv4 source address is replaced by our unicast IPV4 address
 *         if it is set to 0 or 1
 *       - IPv4 destination address is replaced by our multicast IPV4 address
 *         if it is set to 1
 *       - IPv4 checksum is calculaded.
 *       - If payload type is UDP, then the UDP checksum is calculated also.
 *
 *       We send an ARP request first, if this is the first packet sent to
 *       the declared IPv4 destination address. In this case we store the
 *       the packet and send it later if we receive the ARP response.
 *       If the MAC address is known already, then we send the packet immediately.
 *       If there is already an ARP request pending, then we drop this packet
 *       and send again an ARP request.
 *
 * @param  fd         socket fd
 * @param  ip_packet  IP-packet to be handled
 * @param  packetsize Length of the packet
 * @return            -2 - packet dropped (MAC address not resolved - ARP request pending)
 *                    -1 - packet dropped (bad format)
 *                     0 - packet stored  (ARP request sent - packet will be sent if
 *                                         ARP response is received)
 *                    >0 - packet send    (number of transmitted bytes is returned)
 *
 * @see               receive_ether
 * @see               iphdr
 */
int
send_ipv4(int fd, void* buffer, int len)
{
	arp_entry_t *arp_entry = 0;
	struct iphdr *ip;
	const uint8_t *mac_addr = 0;
	uint32_t ip_dst = 0;

	if(len + sizeof(struct ethhdr) > ETH_MTU_SIZE)
		return -1;

	ip = (struct iphdr  *) buffer;

	/* Replace source IPv4 address with our own unicast IPv4 address
	 * if it's 0 (= own unicast source address not specified).
	 */
	if(ip->ip_src == 0) {
		ip->ip_src = htonl( own_ip );
	}
	/* Replace source IPv4 address with our unicast IPv4 address and
	 * replace destination IPv4 address with our multicast IPv4 address
	 * if source address is set to 1.
	 */
	else if(ip->ip_src == 1) {
		ip->ip_src = htonl( own_ip );
		ip->ip_dst = htonl( multicast_ip );
	}

	// Calculate the IPv4 checksum
	ip->ip_sum = 0;
	ip->ip_sum = checksum((uint16_t *) ip, sizeof (struct iphdr) >> 1);

	// if payload type is UDP, then we need to calculate the
	// UDP checksum that depends on the IP header
	if(ip->ip_p == IPTYPE_UDP) {
		fill_udp_checksum(ip);
	}

	ip_dst = ip->ip_dst;
	// Check if the MAC address is already cached
	if(~ip->ip_dst == 0
	|| ( ((~subnet_mask) & ip->ip_dst) == ~subnet_mask &&
	     (  subnet_mask  & ip->ip_dst) == (subnet_mask & own_ip)))  {
		arp_entry = &arp_table[arp_producer];
		mac_addr = broadcast_mac;
	}
	else if(ip->ip_dst == multicast_ip) {
		arp_entry = &arp_table[arp_producer];
		mac_addr = multicast_mac;
	}
	else {
		// Check if IP address is in the same subnet as we are
		if((subnet_mask & own_ip) == (subnet_mask & ip->ip_dst))
			arp_entry = lookup_mac_addr(ip->ip_dst);
		// if not then we need to know the router's IP address
		else {
			ip_dst = router_ip;
			arp_entry = lookup_mac_addr(router_ip);
		}
		if(arp_entry && memcmp(arp_entry->mac_addr, null_mac_addr, 6) != 0)
			mac_addr = arp_entry->mac_addr;
	}

	// If we could not resolv the MAC address by our own...
	if(!mac_addr) {
		// send the ARP request
		arp_send_request(fd, ip_dst);

		// drop the current packet if there is already a ARP request pending
		if(arp_entry)
			return -2;

		// take the next entry in the ARP table to prepare a the new ARP entry.
		arp_entry = &arp_table[arp_producer];
		arp_producer = (arp_producer+1)%ARP_ENTRIES;

		// if ARP table is full then we must drop the oldes entry.
		if(arp_consumer == arp_producer)
			arp_consumer = (arp_consumer+1)%ARP_ENTRIES;

		// store the packet to be send if the ARP reply is received
		arp_entry->pkt_pending = 1;
		arp_entry->ipv4_addr = ip_dst;
		memset(arp_entry->mac_addr, 0, 6);
		pending_pkt.ipv4_addr = ip_dst;
		memset(pending_pkt.mac_addr, 0, 6);
		fill_ethhdr (pending_pkt.eth_frame, htons(ETHERTYPE_IP),
		             get_mac_address(), null_mac_addr);
		memcpy(&pending_pkt.eth_frame[sizeof(struct ethhdr)],
		       buffer, len);
		pending_pkt.eth_len = len + sizeof(struct ethhdr);

		set_timer(TICKS_SEC);
		do {
			receive_ether(fd);
			if (!arp_entry->eth_len)
				break;
		} while (get_timer() > 0);

		return 0;
	}

	// Send the packet with the known MAC address
	fill_ethhdr(arp_entry->eth_frame, htons(ETHERTYPE_IP),
	            get_mac_address(), mac_addr);
	memcpy(&arp_entry->eth_frame[sizeof(struct ethhdr)], buffer, len);
	return send_ether(fd, arp_entry->eth_frame, len + sizeof(struct ethhdr));
}

/**
 * IPv4: Calculate UDP checksum. Places the result into the UDP-header.
 *      <p>
 *      Use this function after filling the UDP payload.
 *
 * @param  ipv4_hdr    Points to the place where IPv4-header starts.
 */

static void
fill_udp_checksum(struct iphdr *ipv4_hdr)
{
	int i;
	unsigned long checksum = 0;
	struct iphdr ip_hdr;
	char *ptr;
	udp_hdr_t *udp_hdr;

	udp_hdr = (udp_hdr_t *) (ipv4_hdr + 1);
	udp_hdr->uh_sum = 0;

	memset(&ip_hdr, 0, sizeof(struct iphdr));
	ip_hdr.ip_src    = ipv4_hdr->ip_src;
	ip_hdr.ip_dst    = ipv4_hdr->ip_dst;
	ip_hdr.ip_len    = udp_hdr->uh_ulen;
	ip_hdr.ip_p      = ipv4_hdr->ip_p;

	ptr = (char*) udp_hdr;
	for (i = 0; i < udp_hdr->uh_ulen; i+=2)
		checksum += *((uint16_t*) &ptr[i]);

	ptr = (char*) &ip_hdr;
	for (i = 0; i < sizeof(struct iphdr); i+=2)
		checksum += *((uint16_t*) &ptr[i]);

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	udp_hdr->uh_sum = ~checksum;

	/* As per RFC 768, if the computed  checksum  is zero,
	 * it is transmitted as all ones (the equivalent in
	 * one's complement arithmetic).
	 */
	if (udp_hdr->uh_sum == 0)
		udp_hdr->uh_sum = ~udp_hdr->uh_sum;
}

/**
 * IPv4: Calculates checksum for IP header.
 *
 * @param  packet     Points to the IP-header
 * @param  words      Size of the packet in words incl. IP-header and data.
 * @return            Checksum
 * @see               iphdr
 */
static unsigned short
checksum(unsigned short * packet, int words)
{
	unsigned long checksum;

	for (checksum = 0; words > 0; words--)
		checksum += *packet++;
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	return ~checksum;
}

static arp_entry_t*
lookup_mac_addr(uint32_t ipv4_addr)
{
	unsigned int i;

	for(i=arp_consumer; i != arp_producer; i = ((i+1)%ARP_ENTRIES) ) {
		if(arp_table[i].ipv4_addr == ipv4_addr)
			return &arp_table[i];
	}
	return 0;
}


/**
 * ARP: Sends an ARP-request package.
 *      For given IPv4 retrieves MAC via ARP (makes several attempts)
 *
 * @param  fd        socket fd
 * @param  dest_ip   IP of the host which MAC should be obtained
 */
static void
arp_send_request(int fd, uint32_t dest_ip)
{
	arp_entry_t *arp_entry = &arp_table[arp_producer];

	memset(arp_entry->eth_frame, 0, sizeof(struct ethhdr) + sizeof(struct arphdr));
	fill_arphdr(&arp_entry->eth_frame[sizeof(struct ethhdr)], ARP_REQUEST,
	            get_mac_address(), own_ip, broadcast_mac, dest_ip);
	fill_ethhdr(arp_entry->eth_frame, ETHERTYPE_ARP,
	            get_mac_address(), broadcast_mac);

	send_ether(fd, arp_entry->eth_frame,
	     sizeof(struct ethhdr) + sizeof(struct arphdr));
}

/**
 * ARP: Sends an ARP-reply package.
 *      This package is used to serve foreign requests (in case IP in
 *      foreign request matches our host IP).
 *
 * @param  fd        socket fd
 * @param  src_ip    requester IP address (foreign IP)
 * @param  src_mac   requester MAC address (foreign MAC)
 */
static void
arp_send_reply(int fd, uint32_t src_ip, uint8_t * src_mac)
{
	arp_entry_t *arp_entry = &arp_table[arp_producer];

	memset(arp_entry->eth_frame, 0, sizeof(struct ethhdr) + sizeof(struct arphdr));
	fill_ethhdr(arp_entry->eth_frame, ETHERTYPE_ARP,
	            get_mac_address(), src_mac);
	fill_arphdr(&arp_entry->eth_frame[sizeof(struct ethhdr)], ARP_REPLY,
	            get_mac_address(), own_ip, src_mac, src_ip);

	send_ether(fd, arp_entry->eth_frame,
	     sizeof(struct ethhdr) + sizeof(struct arphdr));
}

/**
 * ARP: Creates ARP package. Places ARP-header in a packet and fills it
 *      with corresponding information.
 *      <p>
 *      Use this function with similar functions for other network layers
 *      (fill_ethhdr).
 *
 * @param  packet      Points to the place where ARP-header must be placed.
 * @param  opcode      Identifies is it request (ARP_REQUEST)
 *                     or reply (ARP_REPLY) package.
 * @param  src_mac     sender MAC address
 * @param  src_ip      sender IP address
 * @param  dest_mac    receiver MAC address
 * @param  dest_ip     receiver IP address
 * @see                arphdr
 * @see                fill_ethhdr
 */
static void
fill_arphdr(uint8_t * packet, uint8_t opcode,
	    const uint8_t * src_mac, uint32_t src_ip,
	    const uint8_t * dest_mac, uint32_t dest_ip)
{
	struct arphdr * arph = (struct arphdr *) packet;

	arph -> hw_type = htons(1);
	arph -> proto_type = htons(ETHERTYPE_IP);
	arph -> hw_len = 6;
	arph -> proto_len = 4;
	arph -> opcode = htons(opcode);

	memcpy(arph->src_mac, src_mac, 6);
	arph->src_ip = htonl(src_ip);
	memcpy(arph->dest_mac, dest_mac, 6);
	arph->dest_ip = htonl(dest_ip);
}

/**
 * ARP: Handles ARP-messages according to Receive-handle diagram.
 *      Updates arp_table for outstanding ARP requests (see arp_getmac).
 *
 * @param  fd         socket fd
 * @param  packet     ARP-packet to be handled
 * @param  packetsize length of the packet
 * @return            ZERO - packet handled successfully;
 *                    NON ZERO - packet was not handled (e.g. bad format)
 * @see               arp_getmac
 * @see               receive_ether
 * @see               arphdr
 */
int8_t
handle_arp(int fd, uint8_t * packet, int32_t packetsize)
{
	struct arphdr * arph = (struct arphdr *) packet;

	if (packetsize < sizeof(struct arphdr))
		return -1; // Packet is too small

	if (arph -> hw_type != htons(1) || arph -> proto_type != htons(ETHERTYPE_IP))
		return -1; // Unknown hardware or unsupported protocol

	if (arph -> dest_ip != htonl(own_ip))
		return -1; // receiver IP doesn't match our IP

	switch(htons(arph -> opcode)) {
	case ARP_REQUEST:
		// foreign request
		if(own_ip != 0)
			arp_send_reply(fd, htonl(arph->src_ip), arph -> src_mac);
		return 0; // no error
	case ARP_REPLY: {
		unsigned int i;
		// if it is not for us -> return immediately
		if(memcmp(get_mac_address(), arph->dest_mac, 6)) {
			return 0; // no error
		}

		if(arph->src_ip == 0) {
			// we are not interested for a MAC address if
			// the IPv4 address is 0.0.0.0 or ff.ff.ff.ff
			return -1;
		}

		// now let's find the corresponding entry in the ARP table

		for(i=arp_consumer; i != arp_producer; i = ((i+1)%ARP_ENTRIES) ) {
			if(arp_table[i].ipv4_addr == arph->src_ip)
				break;
		}
		if(i == arp_producer || memcmp(arp_table[i].mac_addr, null_mac_addr, 6) != 0) {
			// we have not asked to resolve this IPv4 address !
			return -1;
		}

		memcpy(arp_table[i].mac_addr, arph->src_mac, 6);

		// do we have something to send
		if (arp_table[i].pkt_pending) {
			struct ethhdr * ethh = (struct ethhdr *) pending_pkt.eth_frame;
			memcpy(ethh -> dest_mac, arp_table[i].mac_addr, 6);

			send_ether(fd, pending_pkt.eth_frame, pending_pkt.eth_len);
			pending_pkt.pkt_pending = 0;
			arp_table[i].eth_len = 0;
		}
		return 0; // no error
	}
	default:
		break;
	}
	return -1; // Invalid message type
}

/**
 * ICMP: Send an ICMP Echo request to destination IPv4 address.
 *       This function does also set a global variable to the
 *       destination IPv4 address. If there is an ICMP Echo Reply
 *       received later then the variable is set back to 0.
 *       In other words, reading a value of 0 form this variable
 *       means that an answer to the request has been arrived.
 *
 * @param  fd            socket descriptor
 * @param  _ping_dst_ip  destination IPv4 address
 */
void
ping_ipv4(int fd, uint32_t _ping_dst_ip)
{
	unsigned char packet[sizeof(struct iphdr) + sizeof(struct icmphdr)];
	struct icmphdr *icmp;

	ping_dst_ip = _ping_dst_ip;

	if(ping_dst_ip == 0)
		return;

	fill_iphdr(packet, sizeof(struct iphdr) + sizeof(struct icmphdr), IPTYPE_ICMP,
	           0, ping_dst_ip);
	icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));
	icmp->type = ICMP_ECHO_REQUEST;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->options.echo.id = 0xd476;
	icmp->options.echo.seq = 1;

	memset(icmp->payload.data, '*', sizeof(icmp->payload.data));

	icmp->checksum =
	    checksum((unsigned short *) icmp, sizeof(struct icmphdr) >> 1);
	send_ipv4(fd, packet, sizeof(struct iphdr) + sizeof(struct icmphdr));
}

/**
 * ICMP: Return host IPv4 address that we are waiting for a
 *       ICMP Echo reply message. If this value is 0 then we have
 *       received an reply.
 *
 * @return  ping_dst_ip  host IPv4 address
 */
uint32_t
pong_ipv4(void)
{
	return ping_dst_ip;
}

/**
 * ICMP: Handles ICMP-packets according to Receive-handle diagram.
 *
 * @param  fd         socket fd
 * @param  icmp_packet  ICMP-packet to be handled
 * @param  packetsize   Length of the packet
 * @return              ZERO - packet handled successfully;
 *                      NON ZERO - packet was not handled (e.g. bad format)
 * @see                 handle_ipv4
 */
static int8_t
handle_icmp(int fd, struct iphdr * iph, uint8_t * packet, int32_t packetsize)
{
	struct icmphdr *icmp = (struct icmphdr *) packet;

	switch(icmp->type) {
	case ICMP_ECHO_REPLY:
		if (icmp->options.echo.id != 0xd476)
			return -1;
		if (icmp->options.echo.seq != 1)
			return -1;
		if(ping_dst_ip != iph->ip_src
		|| ping_dst_ip == 0)
			return -1;
		ping_dst_ip = 0;
		break;
	case ICMP_DST_UNREACHABLE: {
		// We've got Destination Unreachable msg
		// Inform corresponding upper network layers
		struct iphdr * bad_iph = (struct iphdr * ) &icmp->payload;

		switch(bad_iph->ip_p) {
		case IPTYPE_TCP:
			handle_tcp_dun((uint8_t *) (bad_iph + 1), packetsize
			               - sizeof(struct icmphdr)
			               - sizeof(struct iphdr), icmp->code);
			break;
		case IPTYPE_UDP:
			handle_udp_dun((uint8_t *) (bad_iph + 1), packetsize
			               - sizeof(struct icmphdr)
			               - sizeof(struct iphdr), icmp->code);
			break;
		}
		break;
	}
	case ICMP_SRC_QUENCH:
		break;
	case ICMP_REDIRECT:
		break;
	case ICMP_ECHO_REQUEST: {
		// We've got an Echo Request - answer with Echo Replay msg
		unsigned char reply_packet[sizeof(struct iphdr) + packetsize];
		struct icmphdr *reply_icmph;

		fill_iphdr(reply_packet, sizeof(struct iphdr) + packetsize,
		           IPTYPE_ICMP, 0, iph->ip_src);

		reply_icmph = (struct icmphdr *) &reply_packet[sizeof(struct iphdr)];
		memcpy(reply_icmph, packet, packetsize);
		reply_icmph -> type = ICMP_ECHO_REPLY;
		reply_icmph -> checksum = 0;
		reply_icmph->checksum = checksum((unsigned short *) reply_icmph,
		                                 sizeof(struct icmphdr) >> 1);

		send_ipv4(fd, reply_packet, sizeof(struct iphdr) + packetsize);
		break;
	}
	case ICMP_TIME_EXCEEDED:
		break;
	case ICMP_PARAMETER_PROBLEM:
		break;
	case ICMP_TIMESTAMP_REQUEST:
		break;
	case ICMP_TIMESTAMP_REPLY:
		break;
	case ICMP_INFORMATION_REQUEST:
		break;
	case ICMP_INFORMATION_REPLY:
		break;
	}
	return 0;
}
