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

#ifndef _NDP_H_
#define _NDP_H_

#include <netlib/ipv6.h>

#define __NDP_DEBUG__

#ifdef __NDP_DEBUG__
#define NDP_DEBUG_PRINT(format, ...) do { printf(format, ## __VA_ARGS__); } while (0)
#else
#define NDP_DEBUG_PRINT(format, ...)
#endif

#define ND_OPTION_SOURCE_LL_ADDR  1
#define ND_OPTION_TARGET_LL_ADDR  2
#define ND_OPTION_PREFIX_INFO     3
#define ND_OPTION_REDIRECT_HDR    4
#define ND_OPTION_MTU             5

/* Default Router List */
struct router {
	uint8_t  mac[6];
	ip6_addr_t ip;
	uint32_t lifetime;
	uint32_t reachable_time;
	uint32_t retrans_timer;
	struct router *next;
};

/* Neighbor cache */
struct neighbor {
	uint8_t mac[6];
	ip6_addr_t ip;
	uint8_t is_router;
	uint8_t status;
	uint8_t times_asked;
	/* ... */
	struct neighbor *next;
	uint8_t eth_frame[1500]; //FIXME
	uint32_t eth_len;

#define NB_INCOMPLETE 1
#define NB_REACHABLE  2
#define NB_STALE      3
#define NB_DELAY      4
#define NB_PROBE      5
};

/******************** FUNCTIONS *********************************************/
int8_t neighbor_add (struct neighbor *);
void * neighbor_create (uint8_t *packet, struct packeth *headers);
struct neighbor * find_neighbor (ip6_addr_t *);

int8_t router_add(struct router*);
void * router_create(uint8_t *mac, ip6_addr_t *ip);
struct router * find_router(ip6_addr_t *);

#endif //_NDP_H_
