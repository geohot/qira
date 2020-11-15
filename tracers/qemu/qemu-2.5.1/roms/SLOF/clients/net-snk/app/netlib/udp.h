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

#ifndef _UDP_H
#define _UDP_H

#include <stdint.h>

#define IPTYPE_UDP         17

#define UDPPORT_BOOTPS     67   /**< UDP port of BootP/DHCP-server */
#define UDPPORT_BOOTPC     68   /**< UDP port of BootP/DHCP-client */
#define UDPPORT_DNSS       53   /**< UDP port of DNS-server        */
#define UDPPORT_DNSC    32769   /**< UDP port of DNS-client        */
#define UDPPORT_TFTPC    2001   /**< UDP port of TFTP-client	   */
#define UDPPORT_DHCPV6C   546   /**< UDP port of DHCPv6-client     */

/** \struct udphdr
 *  A header for UDP-packets.
 *  For more information see RFC 768.
 */
struct udphdr {
	uint16_t uh_sport;   /**< Source port                                  */
	uint16_t uh_dport;   /**< Destinantion port                            */
	uint16_t uh_ulen;    /**< Length in octets, incl. this header and data */
	uint16_t uh_sum;     /**< Checksum                                     */
};
typedef struct udphdr udp_hdr_t;

typedef int32_t *(*handle_upper_udp_t)(uint8_t *, int32_t);
typedef void    *(*handle_upper_udp_dun_t)(uint8_t);

/* Handles UDP-packets that are detected by any network layer. */
extern int8_t handle_udp(int fd, uint8_t * udp_packet, int32_t packetsize);

/* Handles UDP related ICMP-Dest.Unreachable packets that are detected by
 * the network layers. */
extern void handle_udp_dun(uint8_t * udp_packet, uint32_t packetsize, uint8_t err_code);

/* fills udp header */
extern void fill_udphdr(uint8_t *packet, uint16_t packetsize,
                        uint16_t src_port, uint16_t dest_port);

#ifdef USE_MTFTP
extern void net_set_tftp_port(uint16_t tftp_port);
extern void net_set_mtftp_port(uint16_t tftp_port);
#endif

#endif
