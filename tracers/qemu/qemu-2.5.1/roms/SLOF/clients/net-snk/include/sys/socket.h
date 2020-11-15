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


#ifndef _SOCKET_H
#define _SOCKET_H
#include <stdint.h>

#define AF_PACKET 0
#define AF_INET   1
#define AF_INET6  2

#define SOCK_RAW    0
#define SOCK_PACKET 1
#define SOCK_DGRAM  2
#define SOCK_STREAM 3

#define INADDR_ANY 0xFFFFFFFF

#define IPPROTO_UDP 1

#define ETH_ALEN 6   /**< HW address length             */

struct sockaddr {
	uint16_t tra_port;

	uint16_t ipv4_proto;
	uint32_t ipv4_addr;

	// protocol field is only used by "connect"-handler
	uint16_t llc_proto;
	uint8_t  mac_addr[ETH_ALEN];
};

int socket(int, int, int, char *);
int sendto(int, const void *, int, int, const void *, int);
int send(int, const void *, int, int);
int recv(int, void *, int, int);

#define htonl(x) x
#define htons(x) x

#endif

