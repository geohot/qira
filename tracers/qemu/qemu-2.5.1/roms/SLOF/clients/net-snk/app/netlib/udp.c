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

/*>>>>>>>>>>>>>>>>>>>>>>> DEFINITIONS & DECLARATIONS <<<<<<<<<<<<<<<<<<<<*/

#include <udp.h>
#include <sys/socket.h>
#include <dhcp.h>
#include <dhcpv6.h>
#include <dns.h>
#ifdef USE_MTFTP
#include <mtftp.h>
#else
#include <tftp.h>
#endif



/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>> LOCAL VARIABLES <<<<<<<<<<<<<<<<<<<<<<<<<*/


#ifdef USE_MTFTP

uint16_t net_tftp_uport;
uint16_t net_mtftp_uport;

void net_set_tftp_port(uint16_t tftp_port) {
	net_tftp_uport = tftp_port;
}

void net_set_mtftp_port(uint16_t tftp_port) {
	net_mtftp_uport = tftp_port;
}

#endif

/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>> IMPLEMENTATION <<<<<<<<<<<<<<<<<<<<<<<<<<*/


/**
 * NET: Handles UDP-packets according to Receive-handle diagram.
 *
 * @param  udp_packet UDP-packet to be handled
 * @param  packetsize Length of the packet
 * @return            ZERO - packet handled successfully;
 *                    NON ZERO - packet was not handled (e.g. bad format)
 * @see               receive_ether
 * @see               udphdr
 */
int8_t
handle_udp(int fd, uint8_t * udp_packet, int32_t packetsize) {
	struct udphdr * udph = (struct udphdr *) udp_packet;

	if (packetsize < sizeof(struct udphdr))
		return -1; // packet is too small

	switch (htons(udph -> uh_dport)) {
	case UDPPORT_BOOTPC:
		if (udph -> uh_sport == htons(UDPPORT_BOOTPS))
			return handle_dhcp(fd, udp_packet + sizeof(struct udphdr),
			                    packetsize - sizeof(struct udphdr));
		else
			return -1;
	case UDPPORT_DNSC:
		if (udph -> uh_sport == htons(UDPPORT_DNSS))
			return handle_dns(udp_packet + sizeof(struct udphdr),
			                  packetsize - sizeof(struct udphdr));
		else
			return -1;
        case UDPPORT_DHCPV6C:
                return handle_dhcpv6(udp_packet+sizeof(struct udphdr),
                                     packetsize - sizeof(struct udphdr));
	case UDPPORT_TFTPC:
#ifdef USE_MTFTP
		return handle_tftp(fd, udp_packet + sizeof(struct udphdr),
			               packetsize - sizeof(struct udphdr));
#else
		return handle_tftp(fd, udp_packet, packetsize);
#endif
	default:
#ifdef USE_MTFTP
		if (htons(udph -> uh_dport) == net_tftp_uport)
			return handle_tftp(fd, udp_packet + sizeof(struct udphdr),
                       packetsize - sizeof(struct udphdr));
		else if (htons(udph -> uh_dport) == net_mtftp_uport)
			return handle_tftp(fd, udp_packet + sizeof(struct udphdr),
                       packetsize - sizeof(struct udphdr));
#endif
		return -1;
	}
}

/**
 * NET: This function handles situation when "Destination unreachable"
 *      ICMP-error occurs during sending UDP-packet.
 *
 * @param  err_code   Error Code (e.g. "Host unreachable")
 * @param  packet     original UDP-packet
 * @param  packetsize length of the packet
 * @see               handle_icmp
 */
void
handle_udp_dun(uint8_t * udp_packet, uint32_t packetsize, uint8_t err_code) {
	struct udphdr * udph = (struct udphdr *) udp_packet;

	if (packetsize < sizeof(struct udphdr))
		return; // packet is too small

	switch (htons(udph -> uh_sport)) {
	case UDPPORT_TFTPC:
		handle_tftp_dun(err_code);
		break;
	}
}

/**
 * NET: Creates UDP-packet. Places UDP-header in a packet and fills it
 *      with corresponding information.
 *      <p>
 *      Use this function with similar functions for other network layers
 *      (fill_ethhdr, fill_iphdr, fill_dnshdr, fill_btphdr).
 *
 * @param  packet      Points to the place where UDP-header must be placed.
 * @param  packetsize  Size of the packet in bytes incl. this hdr and data.
 * @param  src_port    UDP source port
 * @param  dest_port   UDP destination port
 * @see                udphdr
 * @see                fill_ethhdr
 * @see                fill_iphdr
 * @see                fill_dnshdr
 * @see                fill_btphdr
 */
void
fill_udphdr(uint8_t * packet, uint16_t packetsize,
            uint16_t src_port, uint16_t dest_port) {
	struct udphdr * udph = (struct udphdr *) packet;

	udph -> uh_sport = htons(src_port);
	udph -> uh_dport = htons(dest_port);
	udph -> uh_ulen = htons(packetsize);
	udph -> uh_sum = htons(0);
}
