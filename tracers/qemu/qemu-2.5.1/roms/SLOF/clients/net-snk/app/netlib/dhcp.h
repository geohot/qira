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

#ifndef _DHCP_H_
#define _DHCP_H_

#include <stdint.h>

#ifdef USE_MTFTP
#include <netlib/mtftp.h>
#else
#include <netlib/tftp.h>
#endif

/** \struct btphdr
 *  A header for BootP/DHCP-messages.
 *  For more information see RFC 951 / RFC 2131.
 */
struct btphdr {
	uint8_t op;          /**< Identifies is it request (1) or reply (2)    */
	uint8_t htype;       /**< HW address type (ethernet usually)           */
	uint8_t hlen;        /**< HW address length                            */
	uint8_t hops;        /**< This info used by relay agents (not used)    */
	uint32_t xid;        /**< This ID is used to match queries and replies */
	uint16_t secs;       /**< Unused                                       */
	uint16_t unused;     /**< Unused                                       */
	uint32_t ciaddr;     /**< Client IP address (if client knows it)       */
	uint32_t yiaddr;     /**< "Your" (client) IP address                   */
	uint32_t siaddr;     /**< Next server IP address (TFTP server IP)      */
	uint32_t giaddr;     /**< Gateway IP address (used by relay agents)    */
	uint8_t chaddr[16];  /**< Client HW address                            */
	uint8_t sname[64];   /**< Server host name (TFTP server name)          */
	uint8_t file[128];   /**< Boot file name                               */
	uint8_t vend[64];    /**< Optional parameters field (DHCP-options)     */
};

int bootp(char *ret_buffer, filename_ip_t *, unsigned int);
int dhcpv4(char *ret_buffer, filename_ip_t *);
void dhcp_send_release(int fd);

/* Handles DHCP-packets, which are detected by receive_ether. */
extern int8_t handle_dhcp(int fd, uint8_t * packet, int32_t packetsize);

#endif
