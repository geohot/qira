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


#ifndef _IPV4_H_
#define _IPV4_H_

#include <stdint.h>

#define IPTYPE_ICMP         1

/** \struct iphdr
 *  A header for IP-packets.
 *  For more information see RFC 791.
 */
struct iphdr {
	uint8_t ip_hlv;      /**< Header length and version of the header      */
	uint8_t ip_tos;      /**< Type of Service                              */
	uint16_t ip_len;     /**< Length in octets, inlc. this header and data */
	uint16_t ip_id;      /**< ID is used to aid in assembling framents     */
	uint16_t ip_off;     /**< Info about fragmentation (control, offset)   */
	uint8_t ip_ttl;      /**< Time to Live                                 */
	uint8_t ip_p;        /**< Next level protocol type                     */
	uint16_t ip_sum;     /**< Header checksum                              */
	uint32_t ip_src;     /**< Source IP address                            */
	uint32_t ip_dst;     /**< Destination IP address                       */
};
typedef struct iphdr ipv4_hdr_t;

/* ICMP Error Codes */
#define ICMP_NET_UNREACHABLE 0
#define ICMP_HOST_UNREACHABLE 1
#define ICMP_PROTOCOL_UNREACHABLE 2
#define ICMP_PORT_UNREACHABLE 3
#define ICMP_FRAGMENTATION_NEEDED 4
#define ICMP_SOURCE_ROUTE_FAILED 5

/** \struct arphdr
 *  A header for ARP-messages, retains info about HW and proto addresses.
 *  For more information see RFC 826.
 */
struct arphdr {
	uint16_t hw_type;    /**< HW address space (1 for Ethernet)            */
	uint16_t proto_type; /**< Protocol address space                       */
	uint8_t hw_len;      /**< Byte length of each HW address               */
	uint8_t proto_len;   /**< Byte length of each proto address            */
	uint16_t opcode;     /**< Identifies is it request (1) or reply (2)    */
	uint8_t src_mac[6];  /**< HW address of sender of this packet          */
	uint32_t src_ip;     /**< Proto address of sender of this packet       */
	uint8_t dest_mac[6]; /**< HW address of target of this packet          */
	uint32_t dest_ip;    /**< Proto address of target of this packet       */
} __attribute((packed));

/*>>>>>>>>>>>>> Initialization of the IPv4 network layer. <<<<<<<<<<<<<*/
extern void     set_ipv4_address(uint32_t own_ip);
extern uint32_t get_ipv4_address(void);
extern void     set_ipv4_multicast(uint32_t multicast_ip);
extern uint32_t get_ipv4_multicast(void);
extern void     set_ipv4_router(uint32_t router_ip);
extern uint32_t get_ipv4_router(void);
extern void     set_ipv4_netmask(uint32_t subnet_mask);
extern uint32_t get_ipv4_netmask(void);

extern int   (*send_ip) (int fd, void *, int);

/* fills ip header */
extern void fill_iphdr(uint8_t * packet, uint16_t packetsize,
                       uint8_t ip_proto, uint32_t ip_src, uint32_t ip_dst);

/* Send a IPv4 packet. Adding the Ethernet-Header and resolving the
 * MAC address is done transparent in the background if necessary.
 */
extern int send_ipv4(int fd, void* buffer, int len);

/* Sends an ICMP Echo request to destination IPv4 address */
extern void ping_ipv4(int fd, uint32_t _ping_dst_ip);

/* Returns host IPv4 address that we are waiting for a response */
extern uint32_t pong_ipv4(void);

/* Handles IPv4-packets that are detected by receive_ether. */
extern int8_t handle_ipv4(int fd, uint8_t * packet, int32_t packetsize);

/* Handles ARP-packets that are detected by receive_ether. */
extern int8_t handle_arp(int fd, uint8_t * packet, int32_t packetsize);

#endif
