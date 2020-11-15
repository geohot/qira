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

#ifndef _ETHERNET_H
#define _ETHERNET_H

#include <stdint.h>

#define ETH_MTU_SIZE     1518   /**< Maximum Transfer Unit         */
#define ETH_ALEN            6   /**< HW address length             */
#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_IPv6 0x86DD
#define ETHERTYPE_ARP  0x0806

/** \struct ethhdr
 *  A header for Ethernet-packets.
 */
struct ethhdr {
	uint8_t dest_mac[ETH_ALEN];   /**< Destination HW address        */
	uint8_t src_mac[ETH_ALEN];    /**< Source HW address             */
	uint16_t type;                /**< Next level protocol type      */
};

/* Initializes ethernet layer */
extern void set_mac_address(const uint8_t * own_mac);
extern const uint8_t * get_mac_address(void);

/* Receives and handles packets, according to Receive-handle diagram */
extern int32_t receive_ether(int fd);

/* Sends an ethernet frame. */
extern int send_ether(int fd, void* buffer, int len);

/* fills ethernet header */
extern void fill_ethhdr(uint8_t * packet, uint16_t eth_type,
                        const uint8_t * src_mac, const uint8_t * dest_mac);

#endif
