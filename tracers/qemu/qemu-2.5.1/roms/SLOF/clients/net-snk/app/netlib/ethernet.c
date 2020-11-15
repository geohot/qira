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


/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ALGORITHMS <<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/

/** \file netbase.c <pre>
 * *********************** Receive-handle diagram *************************
 *
 * Note: Every layer calls out required upper layer
 *
 * lower
 *  | MAC/LLC     Receive packet (receive_ether)
 *  |                           |
 *  | NETWORK       +-----------+---------+
 *  |               |                     |
 *  |           IPv4 (handle_ipv4)    IPv6 (handle_ipv4)
 *  |           ARP  (handle_arp)     ICMP & NDP
 *  |           ICMP                      |
 *  |                 |                   |
 *  |                 +---------+---------+
 *  |                           |
 *  | TRANSPORT       +---------+---------+
 *  |                 |                   |
 *  |              TCP (handle_tcp)    UDP (handle_udp)
 *  |                                     |
 *  | APPLICATION        +----------------+-----------+
 *  V                    |                            |
 * upper               DNS (handle_dns)      BootP / DHCP (handle_bootp_client)
 * 
 * ************************************************************************
 * </pre> */


/*>>>>>>>>>>>>>>>>>>>>>>> DEFINITIONS & DECLARATIONS <<<<<<<<<<<<<<<<<<<<*/

#include <ethernet.h>
#include <string.h>
#include <sys/socket.h>
#include <ipv4.h>
#include <ipv6.h>


/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>> LOCAL VARIABLES <<<<<<<<<<<<<<<<<<<<<<<<<*/

static uint8_t ether_packet[ETH_MTU_SIZE];
static uint8_t own_mac[6] = {0, 0, 0, 0, 0, 0};
static uint8_t multicast_mac[] = {0x01, 0x00, 0x5E};
static const uint8_t broadcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>> IMPLEMENTATION <<<<<<<<<<<<<<<<<<<<<<<<<<*/

/**
 * Ethernet: Set the own MAC address to initializes ethernet layer.
 *
 * @param  own_mac  own hardware-address (MAC)
 */
void
set_mac_address(const uint8_t * _own_mac) {
	if (_own_mac)
		memcpy(own_mac, _own_mac, 6);
	else
		memset(own_mac, 0, 6);
}

/**
 * Ethernet: Set the own MAC address to initializes ethernet layer.
 *
 * @return  own hardware-address (MAC)
 */
const uint8_t *
get_mac_address(void) {
	return own_mac;
}

/**
 * Ethernet: Check if given multicast address is a multicast MAC address
 *           starting with 0x3333 
 *
 * @return  true or false 
 */
static uint8_t
is_multicast_mac(uint8_t * mac) {

    	uint16_t mc = 0x3333;
    	if (memcmp(mac, &mc, 2) == 0)
	       return 1;

	return 0;
}


/**
 * Ethernet: Receives an ethernet-packet and handles it according to
 *      Receive-handle diagram.
 *
 * @param  fd        socket fd
 * @return  ZERO - packet was handled or no packets received;
 *          NON ZERO - error condition occurs.
 */
int32_t
receive_ether(int fd) {
	int32_t bytes_received;
	struct ethhdr * ethh;

	memset(ether_packet, 0, ETH_MTU_SIZE);
	bytes_received = recv(fd, ether_packet, ETH_MTU_SIZE, 0);

	if (!bytes_received) // No messages
		return 0;

	if (bytes_received < sizeof(struct ethhdr))
		return -1; // packet is too small

	ethh = (struct ethhdr *) ether_packet;

	if(memcmp(ethh->dest_mac, broadcast_mac, 6) != 0
	&& memcmp(ethh->dest_mac, multicast_mac, 3) != 0
	&& memcmp(ethh->dest_mac, own_mac, 6      ) != 0
	&& !is_multicast_mac(ethh->dest_mac))
		return -1; // packet is too small

	switch (htons(ethh -> type)) {
	case ETHERTYPE_IP:
		return handle_ipv4(fd, (uint8_t*) (ethh + 1),
		                   bytes_received - sizeof(struct ethhdr));

	case ETHERTYPE_IPv6:
		return handle_ipv6(fd, ether_packet + sizeof(struct ethhdr),
				bytes_received - sizeof(struct ethhdr));

	case ETHERTYPE_ARP:
		return handle_arp(fd, (uint8_t*) (ethh + 1),
		           bytes_received - sizeof(struct ethhdr));
	default:
		break;
	}
	return -1; // unknown protocol
}

/**
 * Ethernet: Sends an ethernet frame via the initialized file descriptor.
 *
 * @return number of transmitted bytes
 */
int
send_ether(int fd, void* buffer, int len)
{
	return send(fd, buffer, len, 0);
}

/**
 * Ethernet: Creates Ethernet-packet. Places Ethernet-header in a packet and
 *           fills it with corresponding information.
 *           <p>
 *           Use this function with similar functions for other network layers
 *           (fill_arphdr, fill_iphdr, fill_udphdr, fill_dnshdr, fill_btphdr).
 *
 * @param  packet      Points to the place where eth-header must be placed.
 * @param  eth_type    Type of the next level protocol (e.g. IP or ARP).
 * @param  src_mac     Sender MAC address
 * @param  dest_mac    Receiver MAC address
 * @see                ethhdr
 * @see                fill_arphdr
 * @see                fill_iphdr
 * @see                fill_udphdr
 * @see                fill_dnshdr
 * @see                fill_btphdr
 */
void
fill_ethhdr(uint8_t * packet, uint16_t eth_type,
            const uint8_t * src_mac, const uint8_t * dest_mac) {
	struct ethhdr * ethh = (struct ethhdr *) packet;

	ethh -> type = htons(eth_type);
	memcpy(ethh -> src_mac, src_mac, 6);
	memcpy(ethh -> dest_mac, dest_mac, 6);
}
