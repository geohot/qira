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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netlib/ipv6.h>
#include <netlib/icmpv6.h>
#include <netlib/ndp.h>

/*
 * NET: add new router to list
 * @param  struct router nghb  - new router
 * @return true or false
 */
int8_t
router_add (struct router *nghb )
{
	if (nghb == NULL)
		return -1;

	if (first_router == NULL) {
		first_router= nghb;
		last_router = first_router;
		last_router->next = NULL;
	} else {
		last_router->next = nghb;
		last_router = nghb;
		last_router->next = NULL;
	}
	return 1; /* no error */
}

/*
 * NET: create a new router
 * @param  uint8_t *packet - received packet (Ethernet/IPv6/ICMPv6/ND_NghSlct)
 * @param  struct packeth  - pointers to headers in packet
 * @return pointer to new router
 */
void *
router_create (uint8_t *mac, ip6_addr_t *ip)
{
	struct router *new_router;

	new_router = malloc (sizeof(struct router));
	if( !new_router) {
		return 0;
	}
	memset (new_router, 0, sizeof(struct router));

	/* fill neighbor struct */
	memcpy (new_router->mac, mac, 6);
	memcpy (&(new_router->ip.addr[0]), &(ip->addr[0]), IPV6_ADDR_LENGTH);

	return new_router;
}

struct router *
find_router( ip6_addr_t *ip )
{
	struct router *n = NULL;

	for (n = first_router; n != NULL ; n=n->next)
		if (ip6_cmp (&(n->ip), ip))
			return n; /* router is already in list*/

	return NULL; /* router is unknown */
}

/*
 * NET: add new neighbor to list
 * @param  struct neighbor nghb  - new neighbor
 * @return true or false
 */
int8_t
neighbor_add (struct neighbor *nghb)
{
	if (nghb == NULL)
		return -1;

	if (first_neighbor == NULL) {
		first_neighbor = nghb;
		last_neighbor = first_neighbor;
		last_neighbor->next = NULL;
	} else {
		last_neighbor->next = nghb;
		last_neighbor = nghb;
		last_neighbor->next = NULL;
	}

	return 1; /* no error */
}

/*
 * NET: create a new neighbor
 * @param  uint8_t *packet - received packet (Ethernet/IPv6/ICMPv6/ND_NghSlct)
 * @param  struct packeth  - pointers to headers in packet
 * @return pointer         - pointer to new neighbor
 *         NULL            - malloc failed
 */
void *
neighbor_create (uint8_t *packet, struct packeth *headers)
{
	struct neighbor *new_neighbor;

	new_neighbor = malloc (sizeof(struct neighbor));
	if( !new_neighbor )
		return NULL;

	/* fill neighbor struct */
	memcpy (&(new_neighbor->mac),
		&(headers->ethh->src_mac[0]), 6);
	memcpy (&(new_neighbor->ip.addr), &(headers->ip6h->src), IPV6_ADDR_LENGTH);
	new_neighbor->status = NB_INCOMPLETE;

	return new_neighbor;
}

/**
 * NET: Find neighbor with given IPv6 address in Neighbor Cache
 *
 * @param  ip - Pointer to IPv6 address
 * @return pointer - pointer to client IPv6 address (e.g. ::1)
 *         NULL    - Neighbor not found
 */
struct neighbor *
find_neighbor (ip6_addr_t *ip)
{
	struct neighbor *n = NULL;

	for (n = first_neighbor; n != NULL ; n=n->next) {
		if (ip6_cmp (&(n->ip), ip)) {
			return n; /* neighbor is already in cache */
		}
	}

	return NULL; /* neighbor is unknown */
}
