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

#ifndef _DHCPV6_H_
#define _DHCPV6_H_

#include <stdint.h>
#include <netlib/ethernet.h>

#define DHCPV6_STATELESS 0
#define DHCPV6_STATEFUL  1

/* DHCP port numbers */
#define DHCP_CLIENT_PORT	546
#define DHCP_SERVER_PORT	547

/* DHCPv6 message types	 */
#define DHCP_SOLICIT		  1
#define DHCP_ADVERTISE		  2
#define DHCP_REQUEST		  3
#define DHCP_CONFIRM		  4
#define DHCP_RENEW		  5
#define DHCP_REBIND		  6
#define DHCP_REPLY		  7
#define DHCP_RELEASE		  8
#define DHCP_DECLINE		  9
#define DHCP_RECONFIGURE	 10
#define DHCP_INFORMATION_REQUEST 11
#define RELAY_FORW		 12
#define RELAY_REPL		 13

/* DHCPv6 option types	*/
#define DHCPV6_OPTION_CLIENTID	0x0001
#define DHCPV6_OPTION_SERVERID	0x0002
#define DHCPV6_OPTION_IA_NA	3
#define DHCPV6_OPTION_IA_TA	4
#define DHCPV6_OPTION_IAADDR	5
#define DHCPV6_OPTION_ORO	6
#define DHCPV6_OPTION_PREFEREN	7
#define DHCPV6_OPTION_ELAPSED_TIME	8
#define DHCPV6_OPTION_RELAY_MS	9
#define DHCPV6_OPTION_AUTH	11
#define DHCPV6_OPTION_UNICAST	12
#define DHCPV6_OPTION_STATUS_C	13
#define DHCPV6_OPTION_RAPID_CO	14
#define DHCPV6_OPTION_USER_CLA	15
#define DHCPV6_OPTION_VENDOR_C	16
#define DHCPV6_OPTION_VENDOR_O	17
#define DHCPV6_OPTION_INTERFAC	18
#define DHCPV6_OPTION_RECONF_M	19
#define DHCPV6_OPTION_RECONF_A	20
#define DHCPV6_OPTION_DNS_SERVERS	23
#define DHCPV6_OPTION_DOMAIN_LIST	24
#define DHCPV6_OPTION_BOOT_URL	59

/* DHCPv6 status codes	*/
#define DHCP_STATUSCODE_SUCCESS		0
#define DHCP_STATUSCODE_UNSPECFAIL	1
#define DHCP_STATUSCODE_NOADDRAVAIL	2
#define DHCP_STATUSCODE_NOBINDING	3
#define DHCP_STATUSCODE_NOTONLINK	4
#define DHCP_STATUSCODE_USEMULTICAST	5
#define DHCPV6_STATE_SELECT		6

/* DUID types	*/
#define DUID_LLT	1 /* DUID based on Link-layer Address Plus Time */
#define DUID_EN		2 /* DUID based on Assigned by Vendor Based on Enterprise Number */
#define DUID_LL		3 /* DUID based on Link-layer Address */

/* Prototypes */
int32_t dhcpv6 ( char *ret_buffer, void *fn_ip);
uint32_t handle_dhcpv6(uint8_t * , int32_t);

struct dhcp6_gen_option {
	uint16_t code;
	uint16_t length;
};

struct client_identifier {
	uint16_t code;
	uint16_t length;
	uint16_t duid_type;
	uint16_t hardware_type;
	uint8_t mac[6];
};

struct server_identifier {
	uint16_t code;
	uint16_t length;
	uint16_t duid_type;
	uint16_t hardware_type;
	uint32_t time;
	uint8_t mac[6];
};

struct dhcp_info_request {
	struct client_identifier client_id;
	struct elapsed_time {
		uint16_t code;
		uint16_t length;
		uint16_t time;
	} el_time;
	struct option_request {
		uint16_t code;
		uint16_t length;
		uint16_t option_code[5];
	} option_request_option;
};

struct dhcp_message_header {
	uint8_t type;		   /* Message type   */
	uint8_t transaction_id[3]; /* Transaction id */
	struct dhcp_info_request option;
};

struct dhcp_dns {
	uint16_t code;
	uint16_t length;
	uint8_t p_ip6[16];
	uint8_t s_ip6[16];
}__attribute((packed));

struct dhcp_dns_list {
	uint16_t code;
	uint16_t length;
	uint8_t domain[256];
}__attribute((packed));

struct dhcp_boot_url {
	uint16_t type;
	uint16_t length;
	uint8_t url[256];
};

struct dhcp6_received_options {
	uint8_t filename;
	uint8_t ip;
	uint8_t client_id;
	uint8_t server_id;
};
struct dhcp_message_reply {
	uint8_t type;			    /* Message type   */
	uint8_t transaction_id[3];          /* Transaction id */
	struct client_identifier client_id;
	struct server_identifier server_id;
};

#endif
