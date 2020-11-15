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


/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ALGORITHMS <<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/

/** \file dhcp.c <pre>
 * **************** State-transition diagram for DHCP client  *************
 *
 *   +---------+                  Note: DHCP-server msg / DHCP-client msg
 *   |  INIT   |
 *   +---------+
 *        |
 *        |  - / Discover
 *        V
 *   +---------+
 *   | SELECT  |                     Timeout
 *   +---------+                        |
 *        |                             |
 *        |  Offer / Request            |
 *        |                             |
 *        V                             V
 *   +---------+     NACK / -      ***********
 *   | REQUEST | ----------------> *  FAULT  *
 *   +---------+                   ***********
 *        |
 *        |          ACK / -       ***********
 *        +----------------------> * SUCCESS *
 *                                 ***********
 *
 * ************************************************************************
 * </pre> */


/*>>>>>>>>>>>>>>>>>>>>> DEFINITIONS & DECLARATIONS <<<<<<<<<<<<<<<<<<<<<<*/

#include <dhcp.h>
#include <ethernet.h>
#include <ipv4.h>
#include <udp.h>
#include <dns.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <ctype.h>
#include <stdlib.h>

/* DHCP Message Types */
#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK	        5
#define DHCPNACK        6
#define DHCPRELEASE     7
#define DHCPINFORM      8

/* DHCP Option Codes */
#define DHCP_MASK              1
#define DHCP_ROUTER            3
#define DHCP_DNS               6
#define DHCP_REQUESTED_IP     50
#define DHCP_OVERLOAD         52
#define DHCP_MSG_TYPE         53
#define DHCP_SERVER_ID        54
#define DHCP_REQUEST_LIST     55
#define DHCP_TFTP_SERVER      66
#define DHCP_BOOTFILE         67
#define DHCP_CLIENT_ARCH      93
#define DHCP_ENDOPT         0xFF
#define DHCP_PADOPT         0x00

/* "file/sname" overload option values */
#define DHCP_OVERLOAD_FILE     1
#define DHCP_OVERLOAD_SNAME    2
#define DHCP_OVERLOAD_BOTH     3

/* DHCP states codes */
#define DHCP_STATE_SELECT      1
#define DHCP_STATE_REQUEST     2
#define DHCP_STATE_SUCCESS     3
#define DHCP_STATE_FAULT       4

/* DHCP Client Architecture */
#ifndef DHCPARCH
#define USE_DHCPARCH 0
#define DHCPARCH 0
#else
#define USE_DHCPARCH 1
#endif

static uint8_t dhcp_magic[] = {0x63, 0x82, 0x53, 0x63};
/**< DHCP_magic is a cookie, that identifies DHCP options (see RFC 2132) */

/** \struct dhcp_options_t
 *  This structure is used to fill options in DHCP-msg during transmitting
 *  or to retrieve options from DHCP-msg during receiving.
 *  <p>
 *  If flag[i] == TRUE then field for i-th option retains valid value and
 *  information from this field may retrived (in case of receiving) or will
 *  be transmitted (in case of transmitting).
 *  
 */
typedef struct {
	uint8_t    flag[256];         /**< Show if corresponding opt. is valid */
	uint8_t    request_list[256]; /**< o.55 If i-th member is TRUE, then i-th  
	                                  option will be requested from server */
	uint32_t   server_ID;         /**< o.54 Identifies DHCP-server         */
	uint32_t   requested_IP;      /**< o.50 Must be filled in DHCP-Request */
	uint32_t   dns_IP;            /**< o. 6 DNS IP                         */
	uint32_t   router_IP;         /**< o. 3 Router IP                      */
	uint32_t   subnet_mask;       /**< o. 1 Subnet mask                    */
	uint8_t    msg_type;          /**< o.53 DHCP-message type              */
	uint8_t    overload;          /**< o.52 Overload sname/file fields     */
	int8_t     tftp_server[256];  /**< o.66 TFTP server name               */
	int8_t     bootfile[256];     /**< o.67 Boot file name                 */
	uint16_t   client_arch;       /**< o.93 Client architecture type       */
} dhcp_options_t;

/** Stores state of DHCP-client (refer to State-transition diagram) */
static uint8_t dhcp_state;


/*>>>>>>>>>>>>>>>>>>>>>>>>>>>> PROTOTYPES <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/

static int32_t
dhcp_attempt(int fd);

static int32_t
dhcp_encode_options(uint8_t * opt_field, dhcp_options_t * opt_struct);

static int32_t
dhcp_decode_options(uint8_t opt_field[], uint32_t opt_len,
                    dhcp_options_t * opt_struct);

static int8_t
dhcp_merge_options(uint8_t dst_options[], uint32_t * dst_len,
                   uint8_t src_options[], uint32_t src_len);

static int8_t
dhcp_find_option(uint8_t options[], uint32_t len,
                 uint8_t op_code, uint32_t * op_offset);

static void
dhcp_append_option(uint8_t dst_options[], uint32_t * dst_len,
                   uint8_t * new_option);

static void
dhcp_combine_option(uint8_t dst_options[], uint32_t * dst_len,
                    uint32_t dst_offset, uint8_t * new_option);

static void
dhcp_send_discover(int fd);

static void
dhcp_send_request(int fd);

static uint8_t
strtoip(int8_t * str, uint32_t * ip);


/*>>>>>>>>>>>>>>>>>>>>>>>>>>>> LOCAL VARIABLES <<<<<<<<<<<<<<<<<<<<<<<<<<*/

static uint8_t  ether_packet[ETH_MTU_SIZE];
static uint32_t dhcp_own_ip        = 0;
static uint32_t dhcp_server_ip     = 0;
static uint32_t dhcp_siaddr_ip     = 0;
static int8_t   dhcp_filename[256];
static int8_t   dhcp_tftp_name[256];

static char   * response_buffer;

/*>>>>>>>>>>>>>>>>>>>>>>>>>>>> IMPLEMENTATION <<<<<<<<<<<<<<<<<<<<<<<<<<<*/

int32_t
dhcpv4(char *ret_buffer, filename_ip_t * fn_ip) {

	uint32_t dhcp_tftp_ip     = 0;
	int fd = fn_ip->fd;

	strcpy((char *) dhcp_filename, "");
	strcpy((char *) dhcp_tftp_name, "");

	response_buffer = ret_buffer;

	if (dhcp_attempt(fd) == 0)
		return -1;

	if (fn_ip->own_ip) {
		dhcp_own_ip = fn_ip->own_ip;
	}
	if (fn_ip->server_ip) {
		dhcp_siaddr_ip = fn_ip->server_ip;
	}
	if(fn_ip->filename[0] != 0) {
		strcpy((char *) dhcp_filename, (char *) fn_ip->filename);
	}

	// TFTP SERVER
	if (!strlen((char *) dhcp_tftp_name)) {
		if (!dhcp_siaddr_ip) {
			// ERROR: TFTP name is not presented
			return -3;
		}

		// take TFTP-ip from siaddr field
		dhcp_tftp_ip = dhcp_siaddr_ip;
	}
	else {
		// TFTP server defined by its name
		if (!strtoip(dhcp_tftp_name, &(dhcp_tftp_ip))) {
			if (!dns_get_ip(fd, dhcp_tftp_name, (uint8_t *)&(dhcp_tftp_ip), 4)) {
				// DNS error - can't obtain TFTP-server name  
				// Use TFTP-ip from siaddr field, if presented
				if (dhcp_siaddr_ip) {
					dhcp_tftp_ip = dhcp_siaddr_ip;
				}
				else {
					// ERROR: Can't obtain TFTP server IP
					return -4;
				}
			}
		}
	}

	// Store configuration info into filename_ip strucutre
	fn_ip -> own_ip = dhcp_own_ip;
	fn_ip -> server_ip = dhcp_tftp_ip;
	strcpy((char *) fn_ip -> filename, (char *) dhcp_filename);

	return 0;
}

/**
 * DHCP: Tries o obtain DHCP parameters, refer to state-transition diagram
 */
static int32_t
dhcp_attempt(int fd) {
	int sec;

	// Send DISCOVER message and switch DHCP-client to SELECT state
	dhcp_send_discover(fd);

	dhcp_state = DHCP_STATE_SELECT;

	// setting up a timer with a timeout of two seconds
	for (sec = 0; sec < 2; sec++) {
		set_timer(TICKS_SEC);
		do {
			receive_ether(fd);

			// Wait until client will switch to Final state or Timeout occurs
			switch (dhcp_state) {
			case DHCP_STATE_SUCCESS :
				return 1;
			case DHCP_STATE_FAULT :
				return 0;
			}
		} while (get_timer() > 0);
	}

	// timeout 
	return 0;
}

/**
 * DHCP: Supplements DHCP-message with options stored in structure.
 *       For more information about option coding see dhcp_options_t.
 *
 * @param  opt_field     Points to the "vend" field of DHCP-message  
 *                       (destination)
 * @param  opt_struct    this structure stores info about the options which
 *                       will be added to DHCP-message (source)
 * @return               TRUE - options packed;
 *                       FALSE - error condition occurs.
 * @see                  dhcp_options_t
 */
static int32_t
dhcp_encode_options(uint8_t * opt_field, dhcp_options_t * opt_struct) {
	uint8_t * options = opt_field;
	uint16_t i, sum; // used to define is any options set

	// magic
	memcpy(options, dhcp_magic, 4);
	options += 4;

	// fill message type
	switch (opt_struct -> msg_type) {
	case DHCPDISCOVER :
	case DHCPREQUEST :
	case DHCPDECLINE :
	case DHCPINFORM :
	case DHCPRELEASE :
		options[0] = DHCP_MSG_TYPE;
		options[1] = 1;
		options[2] = opt_struct -> msg_type;
		options += 3;
		break;
	default :
		return 0; // Unsupported DHCP-message
	}

	if (opt_struct -> overload) {
		options[0] = DHCP_OVERLOAD;
		options[1] = 0x01;
		options[2] = opt_struct -> overload;
		options +=3;
	}

	if (opt_struct -> flag[DHCP_REQUESTED_IP]) {
		options[0] = DHCP_REQUESTED_IP;
		options[1] = 0x04;
		* (uint32_t *) (options + 2) = htonl (opt_struct -> requested_IP);
		options +=6;
	}

	if (opt_struct -> flag[DHCP_SERVER_ID]) {
		options[0] = DHCP_SERVER_ID;
		options[1] = 0x04;
		* (uint32_t *) (options + 2) = htonl (opt_struct -> server_ID);
		options +=6;
	}

	sum = 0;
	for (i = 0; i < 256; i++)
		sum += opt_struct -> request_list[i];

	if (sum) {
		options[0] = DHCP_REQUEST_LIST;
		options[1] = sum;
		options += 2;
		for (i = 0; i < 256; i++) {
			if (opt_struct -> request_list[i]) {
				options[0] = i; options++;
			}
		}
	}

	if (opt_struct -> flag[DHCP_TFTP_SERVER]) {
		options[0] = DHCP_TFTP_SERVER;
		options[1] = strlen((char *) opt_struct -> tftp_server) + 1;
		memcpy(options + 2, opt_struct -> tftp_server, options[1]);
		options += options[1] + 2;
	}

	if (opt_struct -> flag[DHCP_BOOTFILE]) {
		options[0] = DHCP_BOOTFILE;
		options[1] = strlen((char *) opt_struct -> bootfile) + 1;
		memcpy(options + 2, opt_struct -> bootfile, options[1]);
		options += options[1] + 2;
	}

	if (opt_struct -> flag[DHCP_CLIENT_ARCH]) {
		options[0] = DHCP_CLIENT_ARCH;
		options[1] = 2;
		options[2] = (DHCPARCH >> 8);
		options[3] = DHCPARCH & 0xff;
		options += 4;
	}

	// end options
	options[0] = 0xFF;
	options++;

	return 1;
}

/**
 * DHCP: Extracts encoded options from DHCP-message into the structure.
 *       For more information about option coding see dhcp_options_t.
 *
 * @param  opt_field     Points to the "options" field of DHCP-message  
 *                       (source).
 * @param  opt_len       Length of "options" field.
 * @param  opt_struct    this structure stores info about the options which
 *                       was extracted from DHCP-message (destination).
 * @return               TRUE - options extracted;
 *                       FALSE - error condition occurs.
 * @see                  dhcp_options_t
 */
static int32_t
dhcp_decode_options(uint8_t opt_field[], uint32_t opt_len,
                    dhcp_options_t * opt_struct) {
	int32_t offset = 0;

	memset(opt_struct, 0, sizeof(dhcp_options_t));

	// magic
	if (memcmp(opt_field, dhcp_magic, 4)) {
		return 0;
	}

	offset += 4;
	while (offset < opt_len) {
		opt_struct -> flag[opt_field[offset]] = 1;
		switch(opt_field[offset]) {
		case DHCP_OVERLOAD :
			opt_struct -> overload = opt_field[offset + 2];
			offset += 2 + opt_field[offset + 1]; 
			break;

		case DHCP_REQUESTED_IP :
			opt_struct -> requested_IP = htonl(* (uint32_t *) (opt_field + offset + 2));
			offset += 2 + opt_field[offset + 1]; 
			break;

		case DHCP_MASK :
			opt_struct -> flag[DHCP_MASK] = 1;
			opt_struct -> subnet_mask = htonl(* (uint32_t *) (opt_field + offset + 2));
			offset += 2 + opt_field[offset + 1]; 
			break;

		case DHCP_DNS :
			opt_struct -> flag[DHCP_DNS] = 1;
			opt_struct -> dns_IP = htonl(* (uint32_t *) (opt_field + offset + 2));
			offset += 2 + opt_field[offset + 1]; 
			break;

		case DHCP_ROUTER :
			opt_struct -> flag[DHCP_ROUTER] = 1;
			opt_struct -> router_IP = htonl(* (uint32_t *) (opt_field + offset + 2));
			offset += 2 + opt_field[offset + 1]; 
			break;

		case DHCP_MSG_TYPE :
			if ((opt_field[offset + 2] > 0) && (opt_field[offset + 2] < 9))
				opt_struct -> msg_type = opt_field[offset + 2];
			else
				return 0;
			offset += 2 + opt_field[offset + 1];
			break;

		case DHCP_SERVER_ID :
			opt_struct -> server_ID = htonl(* (uint32_t *) (opt_field + offset + 2));
			offset += 2 + opt_field[offset + 1];
			break;

		case DHCP_TFTP_SERVER	:
			memcpy(opt_struct -> tftp_server, opt_field + offset + 2, opt_field[offset + 1]);
			(opt_struct -> tftp_server)[opt_field[offset + 1]] = 0;
			offset += 2 + opt_field[offset + 1];
			break;

		case DHCP_BOOTFILE :
			memcpy(opt_struct ->  bootfile, opt_field + offset + 2, opt_field[offset + 1]);
			(opt_struct -> bootfile)[opt_field[offset + 1]] = 0;
			offset += 2 + opt_field[offset + 1];
			break;

		case DHCP_CLIENT_ARCH :
			opt_struct -> client_arch = ((opt_field[offset + 2] << 8) & 0xFF00) | (opt_field[offset + 3] & 0xFF);
			offset += 4;
			break;

		case DHCP_PADOPT :
			offset++;
			break;

		case DHCP_ENDOPT :  // End of options
			return 1;

		default :
			offset += 2 + opt_field[offset + 1]; // Unsupported opt. - do nothing
		}
	}
	if (offset == opt_len)
		return 1; // options finished without 0xFF

	return 0;
}

/**
 * DHCP: Appends information from source "options" into dest "options".
 *       This function is used to support "file/sname" overloading.
 *
 * @param  dst_options   destanation "options" field
 * @param  dst_len       size of dst_options (modified by this function)
 * @param  src_options   source "options" field
 * @param  src_len       size of src_options
 * @return               TRUE - options merged;
 *                       FALSE - error condition occurs.
 */
static int8_t dhcp_merge_options(uint8_t dst_options[], uint32_t * dst_len,
                                 uint8_t src_options[], uint32_t src_len) {
	int32_t dst_offset, src_offset = 0;

	// remove ENDOPT if presented
	if (dhcp_find_option(dst_options, * dst_len, DHCP_ENDOPT, (uint32_t *) &dst_offset))
		* dst_len = dst_offset;

	while (src_offset < src_len) {
		switch(src_options[src_offset]) {
		case DHCP_PADOPT:
			src_offset++;
			break;
		case DHCP_ENDOPT:
			return 1;
		default:
			if (dhcp_find_option(dst_options, * dst_len,
			                     src_options[src_offset],
			                     (uint32_t *) &dst_offset)) {
				dhcp_combine_option(dst_options, dst_len,
				                    dst_offset,
				                    (uint8_t *) src_options +
				                    src_offset);
			}
			else {
				dhcp_append_option(dst_options, dst_len, src_options + src_offset);
			}
			src_offset += 2 + src_options[src_offset + 1];
		}
	}

	if (src_offset == src_len) 
		return 1;
	return 0;
}

/**
 * DHCP: Finds given occurrence of the option with the given code (op_code)
 *       in "options" field of DHCP-message.
 *
 * @param  options       "options" field of DHCP-message
 * @param  len           length of the "options" field
 * @param  op_code       code of the option to find
 * @param  op_offset     SUCCESS - offset to an option occurrence;
 *                       FAULT - offset is set to zero.
 * @return               TRUE - option was find;
 *                       FALSE - option wasn't find.
 */
static int8_t dhcp_find_option(uint8_t options[], uint32_t len,
                               uint8_t op_code, uint32_t * op_offset) {
	uint32_t srch_offset = 0;
	* op_offset = 0;

	while (srch_offset < len) {
		if (options[srch_offset] == op_code) {
			* op_offset = srch_offset;
			return 1;
		}
		if (options[srch_offset] == DHCP_ENDOPT)
			return 0;

		if (options[srch_offset] == DHCP_PADOPT)
			srch_offset++;
		else
			srch_offset += 2 + options[srch_offset + 1];
	}
	return 0;
}

/**
 * DHCP: Appends new option from one list (src) into the tail
 *       of another option list (dst)
 *
 * @param  dst_options   "options" field of DHCP-message
 * @param  dst_len       length of the "options" field (modified)
 * @param  new_option    points to an option in another list (src)
 */
static void
dhcp_append_option(uint8_t dst_options[], uint32_t * dst_len,
                   uint8_t * new_option) {
	memcpy(dst_options + ( * dst_len), new_option, 2 + (* (new_option + 1)));
	* dst_len += 2 + *(new_option + 1);
}

/**
 * DHCP: This function is used when options with the same code are
 *       presented in both merged lists. In this case information
 *       about the option from one list (src) is combined (complemented)
 *       with information about the option in another list (dst).
 *
 * @param  dst_options  "options" field of DHCP-message
 * @param  dst_len       length of the "options" field (modified)
 * @param  dst_offset    offset of the option from beginning of the list
 * @param  new_option    points to an option in another list (src)
 */
static void
dhcp_combine_option(uint8_t dst_options[], uint32_t * dst_len,
                    uint32_t dst_offset, uint8_t * new_option) {

	uint8_t tmp_buffer[1024]; // use to provide safe memcpy
	uint32_t tail_len;

	// move all subsequent options (allocate size for additional info)
	tail_len = (* dst_len) - dst_offset - 2 - dst_options[dst_offset + 1];

	memcpy(tmp_buffer, dst_options + (* dst_len) - tail_len, tail_len);
	memcpy(dst_options + (* dst_len) - tail_len + (* (new_option + 1)),
	       tmp_buffer, tail_len);

	// add new_content to option
	memcpy(dst_options + (* dst_len) - tail_len, new_option + 2,
	       * (new_option + 1));
	dst_options[dst_offset + 1] += * (new_option + 1);

	// correct dst_len
	* dst_len += * (new_option + 1);
}

/**
 * DHCP: Sends DHCP-Discover message. Looks for DHCP servers.
 */
static void
dhcp_send_discover(int fd) {
	uint32_t packetsize = sizeof(struct iphdr) +
	                      sizeof(struct udphdr) + sizeof(struct btphdr);
	struct btphdr *btph;
	dhcp_options_t opt;

	memset(ether_packet, 0, packetsize);

	btph = (struct btphdr *) (&ether_packet[
	       sizeof(struct iphdr) + sizeof(struct udphdr)]);

	btph -> op = 1;
	btph -> htype = 1;
	btph -> hlen = 6;
	memcpy(btph -> chaddr, get_mac_address(), 6);

	memset(&opt, 0, sizeof(dhcp_options_t));

	opt.msg_type = DHCPDISCOVER;

	opt.request_list[DHCP_MASK] = 1;
	opt.request_list[DHCP_DNS] = 1;
	opt.request_list[DHCP_ROUTER] = 1;
	opt.request_list[DHCP_TFTP_SERVER] = 1;
	opt.request_list[DHCP_BOOTFILE] = 1;
	opt.request_list[DHCP_CLIENT_ARCH] = USE_DHCPARCH;

	dhcp_encode_options(btph -> vend, &opt);

	fill_udphdr(&ether_packet[sizeof(struct iphdr)],
	            sizeof(struct btphdr) + sizeof(struct udphdr),
	            UDPPORT_BOOTPC, UDPPORT_BOOTPS);
	fill_iphdr(ether_packet, sizeof(struct btphdr) +
	           sizeof(struct udphdr) + sizeof(struct iphdr),
	           IPTYPE_UDP, dhcp_own_ip, 0xFFFFFFFF);

	send_ipv4(fd, ether_packet, packetsize);
}

/**
 * DHCP: Sends DHCP-Request message. Asks for acknowledgment to occupy IP.
 */
static void
dhcp_send_request(int fd) {
	uint32_t packetsize = sizeof(struct iphdr) +
	                      sizeof(struct udphdr) + sizeof(struct btphdr);
	struct btphdr *btph;
	dhcp_options_t opt;

	memset(ether_packet, 0, packetsize);

	btph = (struct btphdr *) (&ether_packet[
	       sizeof(struct iphdr) + sizeof(struct udphdr)]);

	btph -> op = 1;
	btph -> htype = 1;
	btph -> hlen = 6;
	memcpy(btph -> chaddr, get_mac_address(), 6);

	memset(&opt, 0, sizeof(dhcp_options_t));

	opt.msg_type = DHCPREQUEST;
	memcpy(&(opt.requested_IP), &dhcp_own_ip, 4);
	opt.flag[DHCP_REQUESTED_IP] = 1;
	memcpy(&(opt.server_ID), &dhcp_server_ip, 4);
	opt.flag[DHCP_SERVER_ID] = 1;

	opt.request_list[DHCP_MASK] = 1;
	opt.request_list[DHCP_DNS] = 1;
	opt.request_list[DHCP_ROUTER] = 1;
	opt.request_list[DHCP_TFTP_SERVER] = 1;
	opt.request_list[DHCP_BOOTFILE] = 1;
	opt.request_list[DHCP_CLIENT_ARCH] = USE_DHCPARCH;
	opt.flag[DHCP_CLIENT_ARCH] = USE_DHCPARCH;

	dhcp_encode_options(btph -> vend, &opt);

	fill_udphdr(&ether_packet[sizeof(struct iphdr)],
	            sizeof(struct btphdr) + sizeof(struct udphdr),
	            UDPPORT_BOOTPC, UDPPORT_BOOTPS);
	fill_iphdr(ether_packet, sizeof(struct btphdr) +
	           sizeof(struct udphdr) + sizeof(struct iphdr),
	           IPTYPE_UDP, 0, 0xFFFFFFFF);

	send_ipv4(fd, ether_packet, packetsize);
}


/**
 * DHCP: Sends DHCP-Release message. Releases occupied IP.
 */
void dhcp_send_release(int fd) {
	uint32_t packetsize = sizeof(struct iphdr) +
	                      sizeof(struct udphdr) + sizeof(struct btphdr);
	struct btphdr *btph;
	dhcp_options_t opt;

	btph = (struct btphdr *) (&ether_packet[
	       sizeof(struct iphdr) + sizeof(struct udphdr)]);

	memset(ether_packet, 0, packetsize);

	btph -> op = 1;
	btph -> htype = 1;
	btph -> hlen = 6;
	strcpy((char *) btph -> file, "");
	memcpy(btph -> chaddr, get_mac_address(), 6);
	btph -> ciaddr = htonl(dhcp_own_ip);

	memset(&opt, 0, sizeof(dhcp_options_t));

	opt.msg_type = DHCPRELEASE;
	opt.server_ID = dhcp_server_ip;
	opt.flag[DHCP_SERVER_ID] = 1;

	dhcp_encode_options(btph -> vend, &opt);

	fill_udphdr(&ether_packet[sizeof(struct iphdr)], 
	            sizeof(struct btphdr) + sizeof(struct udphdr),
	            UDPPORT_BOOTPC, UDPPORT_BOOTPS);
	fill_iphdr(ether_packet, sizeof(struct btphdr) +
	           sizeof(struct udphdr) + sizeof(struct iphdr), IPTYPE_UDP,
	           dhcp_own_ip, dhcp_server_ip);

	send_ipv4(fd, ether_packet, packetsize);
}

/**
 * DHCP: Handles DHCP-messages according to Receive-handle diagram.
 *       Changes the state of DHCP-client.
 *
 * @param  fd         socket descriptor
 * @param  packet     BootP/DHCP-packet to be handled
 * @param  packetsize length of the packet
 * @return            ZERO - packet handled successfully;
 *                    NON ZERO - packet was not handled (e.g. bad format)
 * @see               receive_ether
 * @see               btphdr
 */

int8_t
handle_dhcp(int fd, uint8_t * packet, int32_t packetsize) {
	struct btphdr * btph;
	struct iphdr * iph;
	dhcp_options_t opt;

	memset(&opt, 0, sizeof(dhcp_options_t));  
	btph = (struct btphdr *) packet;
	iph = (struct iphdr *) packet - sizeof(struct udphdr) -
	      sizeof(struct iphdr);
	if (btph -> op != 2)
		return -1; // it is not Boot Reply

	if (memcmp(btph -> vend, dhcp_magic, 4)) {
		// It is BootP - RFC 951
		dhcp_own_ip    = htonl(btph -> yiaddr);
		dhcp_siaddr_ip = htonl(btph -> siaddr);
		dhcp_server_ip = htonl(iph -> ip_src);

		if (strlen((char *) btph -> sname) && !dhcp_siaddr_ip) {
			strncpy((char *) dhcp_tftp_name, (char *) btph -> sname,
			        sizeof(btph -> sname));
			dhcp_tftp_name[sizeof(btph -> sname)] = 0;
		}

		if (strlen((char *) btph -> file)) {
			strncpy((char *) dhcp_filename, (char *) btph -> file, sizeof(btph -> file));
			dhcp_filename[sizeof(btph -> file)] = 0;
		}

		dhcp_state = DHCP_STATE_SUCCESS;
		return 0;
	}


	// decode options  
	if (!dhcp_decode_options(btph -> vend, packetsize -
	                         sizeof(struct btphdr) + sizeof(btph -> vend),
	                         &opt)) {
		return -1;  // can't decode options
	}

	if (opt.overload) {
		int16_t decode_res = 0;
		uint8_t options[1024]; // buffer for merged options
		uint32_t opt_len;

		// move 1-st part of options from vend field into buffer
		opt_len = packetsize - sizeof(struct btphdr) +
		          sizeof(btph -> vend) - 4;
		memcpy(options, btph -> vend, opt_len + 4);

		// add other parts
		switch (opt.overload) {
		case DHCP_OVERLOAD_FILE:
			decode_res = dhcp_merge_options(options + 4, &opt_len,
			                                btph -> file,
			                                sizeof(btph -> file));
			break;
		case DHCP_OVERLOAD_SNAME:
			decode_res = dhcp_merge_options(options + 4, &opt_len,
			                                btph -> sname,
			                                sizeof(btph -> sname));
			break;
		case DHCP_OVERLOAD_BOTH:
			decode_res = dhcp_merge_options(options + 4, &opt_len,
			                                btph -> file,
			                                sizeof(btph -> file));
			if (!decode_res)
				break;
			decode_res = dhcp_merge_options(options + 4, &opt_len,
			                                btph -> sname,
			                                sizeof(btph -> sname));
			break;
		}

		if (!decode_res)
			return -1; // bad options in sname/file fields

		// decode merged options
		if (!dhcp_decode_options(options, opt_len + 4, &opt)) {
			return -1; // can't decode options
		}
	}

	if (!opt.msg_type) {
		// It is BootP with Extensions - RFC 1497
		// retrieve conf. settings from BootP - reply
		dhcp_own_ip = htonl(btph -> yiaddr);
		dhcp_siaddr_ip = htonl(btph -> siaddr);
		if (strlen((char *) btph -> sname) && !dhcp_siaddr_ip) {
			strncpy((char *) dhcp_tftp_name, (char *) btph -> sname, sizeof(btph -> sname));
			dhcp_tftp_name[sizeof(btph -> sname)] = 0;
		}

		if (strlen((char *) btph -> file)) {
			strncpy((char *) dhcp_filename, (char *) btph -> file, sizeof(btph -> file));
			dhcp_filename[sizeof(btph -> file)] = 0;
		}

		// retrieve DHCP-server IP from IP-header
		dhcp_server_ip = iph -> htonl(ip_src);

		dhcp_state = DHCP_STATE_SUCCESS;
	}
	else {
		// It is DHCP - RFC 2131 & RFC 2132
		// opt contains parameters from server
		switch (dhcp_state) {
		case DHCP_STATE_SELECT :
			if (opt.msg_type == DHCPOFFER) {
				dhcp_own_ip = htonl(btph -> yiaddr);
				dhcp_server_ip = opt.server_ID;
				dhcp_send_request(fd);
				dhcp_state = DHCP_STATE_REQUEST;
			}
			return 0;
		case DHCP_STATE_REQUEST :
			switch (opt.msg_type) {
			case DHCPNACK :
				dhcp_own_ip = 0;
				dhcp_server_ip = 0;
				dhcp_state = DHCP_STATE_FAULT;
				break;
			case DHCPACK :
				dhcp_own_ip = htonl(btph -> yiaddr);
				dhcp_server_ip = opt.server_ID;
				dhcp_siaddr_ip = htonl(btph -> siaddr);
				if (opt.flag[DHCP_TFTP_SERVER]) {
					strcpy((char *) dhcp_tftp_name, (char *) opt.tftp_server);
				}
				else {
					strcpy((char *) dhcp_tftp_name, "");
					if ((opt.overload != DHCP_OVERLOAD_SNAME &&
					     opt.overload != DHCP_OVERLOAD_BOTH) &&
					     !dhcp_siaddr_ip) {
						strncpy((char *) dhcp_tftp_name,
						        (char *) btph->sname,
						        sizeof(btph -> sname));
						dhcp_tftp_name[sizeof(btph->sname)] = 0;
					}
				}

				if (opt.flag[DHCP_BOOTFILE]) {
					strcpy((char *) dhcp_filename, (char *) opt.bootfile);
				}
				else {
					strcpy((char *) dhcp_filename, "");
					if (opt.overload != DHCP_OVERLOAD_FILE &&
						opt.overload != DHCP_OVERLOAD_BOTH && 
						strlen((char *) btph -> file)) {
						strncpy((char *) dhcp_filename,
						        (char *) btph->file,
						        sizeof(btph->file));
						dhcp_filename[sizeof(btph -> file)] = 0;
					}
				}

				dhcp_state = DHCP_STATE_SUCCESS;
				break;
			default:
				break; // Unused DHCP-message - do nothing
			}
			break;
		default :
			return -1; // Illegal DHCP-client state
		}
	}

	if (dhcp_state == DHCP_STATE_SUCCESS) {

		// initialize network entity with real own_ip
		// to be able to answer for foreign requests
		set_ipv4_address(dhcp_own_ip);

		if(response_buffer) {
			if(packetsize <= 1720)
				memcpy(response_buffer, packet, packetsize);
			else
				memcpy(response_buffer, packet, 1720);
		}

		/* Subnet mask */
		if (opt.flag[DHCP_MASK]) {
			/* Router */
			if (opt.flag[DHCP_ROUTER]) {
				set_ipv4_router(opt.router_IP);
				set_ipv4_netmask(opt.subnet_mask);
			}
		}

		/* DNS-server */
		if (opt.flag[DHCP_DNS]) {
			dns_init(opt.dns_IP, 0, 4);
		}
	}

	return 0;
}

/**
 * DHCP: Converts "255.255.255.255" -> 32-bit long IP
 *
 * @param  str        string to be converted
 * @param  ip         in case of SUCCESS - 32-bit long IP
                      in case of FAULT - zero
 * @return            TRUE - IP converted successfully;
 *                    FALSE - error condition occurs (e.g. bad format)
 */
static uint8_t
strtoip(int8_t * str, uint32_t * ip) {
	int8_t ** ptr = &str;
	int16_t i = 0, res, len;
	char octet[256];

	* ip = 0;

	while (**ptr != 0) {
		if (i > 3 || !isdigit(**ptr))
			return 0;
		if (strstr((char *) * ptr, ".") != NULL) {
			len = (int16_t) ((int8_t *) strstr((char *) * ptr, ".") - 
			      (int8_t *) (* ptr));
			strncpy(octet, (char *) * ptr, len); octet[len] = 0;
			* ptr += len;
		}
		else {
			strcpy(octet, (char *) * ptr);
			* ptr += strlen(octet);
		}
		res = strtol(octet, NULL, 10);
		if ((res > 255) || (res < 0))
			return 0;
		* ip = ((* ip) << 8) + res;
		i++;
		if (** ptr == '.')
			(*ptr)++;
	}

	if (i != 4)
		return 0;
	return 1;
}
