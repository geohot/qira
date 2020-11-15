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

#ifndef _TCP_H
#define _TCP_H

#include <stdint.h>

#define IPTYPE_TCP          6

/* Handles TCP-packets that are detected by any network layer. */
extern int8_t handle_tcp(uint8_t * udp_packet, int32_t packetsize);

/* Handles TCP related ICMP-Dest.Unreachable packets that are detected by
 * the network layers. */
extern void handle_tcp_dun(uint8_t * tcp_packet, uint32_t packetsize, uint8_t err_code);

#endif
