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

#include <tftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>

#include <ethernet.h>
#include <ipv4.h>
#include <ipv6.h>
#include <udp.h>

//#define __DEBUG__

#define MAX_BLOCKSIZE 1428
#define BUFFER_LEN 256

#define ENOTFOUND 1
#define EACCESS   2
#define EBADOP    4
#define EBADID    5
#define ENOUSER   7
//#define EUNDEF 0
//#define ENOSPACE 3
//#define EEXISTS 6

#define RRQ   1
#define WRQ   2
#define DATA  3
#define ACK   4
#define ERROR 5
#define OACK  6

/* Local variables */
static unsigned char packet[BUFFER_LEN];
static unsigned char  *buffer = NULL;
static unsigned short block = 0;
static unsigned short blocksize;
static char blocksize_str[6];    /* Blocksize string for read request */
static int received_len = 0;
static int retries = 0;
static int huge_load;
static int len;
static int tftp_finished = 0;
static int lost_packets = 0;
static int tftp_errno = 0; 
static int ip_version = 0; 
static short port_number = -1;
static tftp_err_t *tftp_err;
static filename_ip_t  *fn_ip;

/**
 * dump_package - Prints a package.
 *
 * @package: package which is to print
 * @len:     length of the package
 */
#ifdef __DEBUG__

static void
dump_package(unsigned char *buffer, unsigned int len)
{
	int i;

	for (i = 1; i <= len; i++) {
		printf("%02x%02x ", buffer[i - 1], buffer[i]);
		i++;
		if ((i % 16) == 0)
			printf("\n");
	}
	printf("\n");
}
#endif

/**
 * send_rrq - Sends a read request package.
 *
 * @fd:          Socket Descriptor
 */
static void
send_rrq(int fd)
{
	int ip_len = 0;
	int ip6_payload_len    = 0;
	unsigned short udp_len = 0;
	unsigned char mode[] = "octet";
	char *ptr	     = NULL;
	struct iphdr *ip     = NULL;
	struct ip6hdr *ip6   = NULL;
	struct udphdr *udph  = NULL;
	struct tftphdr *tftp = NULL;

	memset(packet, 0, BUFFER_LEN);

	if (4 == ip_version) {
		ip = (struct iphdr *) packet;
		udph = (struct udphdr *) (ip + 1);
		ip_len = sizeof(struct iphdr) + sizeof(struct udphdr)
			+ strlen((char *) fn_ip->filename) + strlen((char *) mode) + 4
			+ strlen("blksize") + strlen(blocksize_str) + 2;
		fill_iphdr ((uint8_t *) ip, ip_len, IPTYPE_UDP, 0,
			    fn_ip->server_ip);
	}
	else if (6 == ip_version) {
		ip6 = (struct ip6hdr *) packet;
		udph = (struct udphdr *) (ip6 + 1);
		ip6_payload_len = sizeof(struct udphdr)
			+ strlen((char *) fn_ip->filename) + strlen((char *) mode) + 4
			+ strlen("blksize") + strlen(blocksize_str) + 2;
		ip_len = sizeof(struct ip6hdr) + ip6_payload_len;
		fill_ip6hdr ((uint8_t *) ip6, ip6_payload_len, IPTYPE_UDP, get_ipv6_address(),
			     &(fn_ip->server_ip6)); 

	}
	udp_len = htons(sizeof(struct udphdr)
			      + strlen((char *) fn_ip->filename) + strlen((char *) mode) + 4
			      + strlen("blksize") + strlen(blocksize_str) + 2);
	fill_udphdr ((uint8_t *) udph, udp_len, htons(2001), htons(69));

	tftp = (struct tftphdr *) (udph + 1);
	tftp->th_opcode = htons(RRQ);

	ptr = (char *) &tftp->th_data;
	memcpy(ptr, fn_ip->filename, strlen((char *) fn_ip->filename) + 1);

	ptr += strlen((char *) fn_ip->filename) + 1;
	memcpy(ptr, mode, strlen((char *) mode) + 1);

	ptr += strlen((char *) mode) + 1;
	memcpy(ptr, "blksize", strlen("blksize") + 1);

	ptr += strlen("blksize") + 1;
	memcpy(ptr, blocksize_str, strlen(blocksize_str) + 1);

	send_ip (fd, packet, ip_len);

#ifdef __DEBUG__
	printf("tftp RRQ with %d bytes transmitted.\n", ip_len);
#endif
	return;
}

/**
 * send_ack - Sends a acknowlege package.
 *
 * @blckno: block number
 * @dport:  UDP destination port
 */
static void
send_ack(int fd, int blckno, unsigned short dport)
{
	int ip_len 	       = 0;
	int ip6_payload_len    = 0;
	unsigned short udp_len = 0;
	struct iphdr *ip     = NULL;
	struct ip6hdr *ip6   = NULL;
	struct udphdr *udph  = NULL;
	struct tftphdr *tftp = NULL;

	memset(packet, 0, BUFFER_LEN);

	if (4 == ip_version) {
		ip = (struct iphdr *) packet;
		udph = (struct udphdr *) (ip + 1);
		ip_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 4;
		fill_iphdr ((uint8_t *) ip, ip_len, IPTYPE_UDP, 0,
			    fn_ip->server_ip);
	}
	else if (6 == ip_version) {
		ip6 = (struct ip6hdr *) packet;
		udph = (struct udphdr *) (ip6 + 1);
		ip6_payload_len = sizeof(struct udphdr) + 4;
		ip_len = sizeof(struct ethhdr) + sizeof(struct ip6hdr) +
		    	 ip6_payload_len;
		fill_ip6hdr ((uint8_t *) ip6, ip6_payload_len, IPTYPE_UDP, get_ipv6_address(),
			     &(fn_ip->server_ip6));
	}
	udp_len = htons(sizeof(struct udphdr) + 4);
	fill_udphdr ((uint8_t *) udph, udp_len, htons(2001), htons(dport));

	tftp = (struct tftphdr *) (udph + 1);
	tftp->th_opcode = htons(ACK);
	tftp->th_data = htons(blckno);

	send_ip(fd, packet, ip_len);

#ifdef __DEBUG__
	printf("tftp ACK %d bytes transmitted.\n", ip_len);
#endif

	return;
}

/**
 * send_error - Sends an error package.
 *
 * @fd:          Socket Descriptor
 * @error_code:  Used sub code for error packet
 * @dport:       UDP destination port
 */
static void
send_error(int fd, int error_code, unsigned short dport)
{
	int ip_len 	       = 0;
	int ip6_payload_len    = 0;
	unsigned short udp_len = 0;
	struct ip6hdr *ip6   = NULL;
	struct iphdr *ip     = NULL;
	struct udphdr *udph  = NULL;
	struct tftphdr *tftp = NULL;

	memset(packet, 0, BUFFER_LEN);

	if (4 == ip_version) {
		ip = (struct iphdr *) packet;
		udph = (struct udphdr *) (ip + 1);
		ip_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 5;
		fill_iphdr ((uint8_t *) ip, ip_len, IPTYPE_UDP, 0,
			    fn_ip->server_ip);
	}
	else if (6 == ip_version) {
		ip6 = (struct ip6hdr *) packet;
		udph = (struct udphdr *) (ip6 + 1);
		ip6_payload_len = sizeof(struct udphdr) + 5;
		ip_len = sizeof(struct ethhdr) + sizeof(struct ip6hdr) +
		         ip6_payload_len; 
		fill_ip6hdr ((uint8_t *) ip6, ip6_payload_len, IPTYPE_UDP, get_ipv6_address(),
			    &(fn_ip->server_ip6));
	}
	udp_len = htons(sizeof(struct udphdr) + 5);
	fill_udphdr ((uint8_t *) udph, udp_len, htons(2001), htons(dport));

	tftp = (struct tftphdr *) (udph + 1);
	tftp->th_opcode = htons(ERROR);
	tftp->th_data = htons(error_code);
	((char *) &tftp->th_data)[2] = 0;

	send_ip(fd, packet, ip_len);

#ifdef __DEBUG__
	printf("tftp ERROR %d bytes transmitted.\n", ip_len);
#endif

	return;
}

static void
print_progress(int urgent, int received_bytes)
{
	static unsigned int i = 1;
	static int first = -1;
	static int last_bytes = 0;
	char buffer[100];
	char *ptr;

	// 1MB steps or 0x400 times or urgent 
	if(((received_bytes - last_bytes) >> 20) > 0
	|| (i & 0x3FF) == 0 || urgent) {
		if(!first) {
			sprintf(buffer, "%d KBytes", (last_bytes >> 10));
			for(ptr = buffer; *ptr != 0; ++ptr)
				*ptr = '\b';
			printf(buffer);
		}
		printf("%d KBytes", (received_bytes >> 10));
		i = 1;
		first = 0;
		last_bytes = received_bytes;
	}
	++i;
}

/**
 * get_blksize tries to extract the blksize from the OACK package
 * the TFTP returned. From RFC 1782
 * The OACK packet has the following format:
 *
 *   +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
 *   |  opc  |  opt1  | 0 | value1 | 0 |  optN  | 0 | valueN | 0 |
 *   +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
 *
 * @param buffer  the network packet
 * @param len  the length of the network packet
 * @return  the blocksize the server supports or 0 for error
 */
static int
get_blksize(unsigned char *buffer, unsigned int len)
{
	unsigned char *orig = buffer;
	/* skip all headers until tftp has been reached */
	buffer += sizeof(struct udphdr);
	/* skip opc */
	buffer += 2;
	while (buffer < orig + len) {
		if (!memcmp(buffer, "blksize", strlen("blksize") + 1))
			return (unsigned short) strtoul((char *) (buffer +
							strlen("blksize") + 1),
							(char **) NULL, 10);
		else {
			/* skip the option name */
			buffer = (unsigned char *) strchr((char *) buffer, 0);
			if (!buffer)
				return 0;
			buffer++;
			/* skip the option value */
			buffer = (unsigned char *) strchr((char *) buffer, 0);
			if (!buffer)
				return 0;
			buffer++;
		}
	}
	return 0;
}

/**
 * Handle incoming tftp packets after read request was sent 
 *
 * this function also prints out some status characters
 * \|-/ for each packet received
 * A for an arp packet
 * I for an ICMP packet
 * #+* for different unexpected TFTP packets (not very good)
 *
 * @param fd     socket descriptor
 * @param packet points to the UDP header of the packet 
 * @param len    the length of the network packet
 * @return       ZERO if packet was handled successfully
 *               ERRORCODE if error occurred 
 */
int32_t
handle_tftp(int fd, uint8_t *pkt, int32_t packetsize) 
{
	struct udphdr *udph;
	struct tftphdr *tftp;

	/* buffer is only set if we are handling TFTP */
	if (buffer == NULL )
		return 0;

#ifndef __DEBUG__
	print_progress(0, received_len);
#endif
	udph = (struct udphdr *) pkt;
	tftp = (struct tftphdr *) ((void *) udph + sizeof(struct udphdr));
	set_timer(TICKS_SEC);

#ifdef __DEBUG__
	dump_package(pkt, packetsize);
#endif

	port_number = udph->uh_sport;
	if (tftp->th_opcode == htons(OACK)) {
		/* an OACK means that the server answers our blocksize request */
		blocksize = get_blksize(pkt, packetsize);
		if (!blocksize || blocksize > MAX_BLOCKSIZE) {
			send_error(fd, 8, port_number);
			tftp_errno = -8;
			goto error;
		}
		send_ack(fd, 0, port_number);
	} else if (tftp->th_opcode == htons(ACK)) {
		/* an ACK means that the server did not answers
		 * our blocksize request, therefore we will set the blocksize
		 * to the default value of 512 */
		blocksize = 512;
		send_ack(fd, 0, port_number);
	} else if ((unsigned char) tftp->th_opcode == ERROR) {
#ifdef __DEBUG__
		printf("tftp->th_opcode : %x\n", tftp->th_opcode);
		printf("tftp->th_data   : %x\n", tftp->th_data);
#endif
		switch ( (uint8_t) tftp->th_data) {
		case ENOTFOUND:
			tftp_errno = -3;	// ERROR: file not found
			break;
		case EACCESS:
			tftp_errno = -4;	// ERROR: access violation
			break;
		case EBADOP:
			tftp_errno = -5;	// ERROR: illegal TFTP operation
			break;
		case EBADID:
			tftp_errno = -6;	// ERROR: unknown transfer ID
			break;
		case ENOUSER:
			tftp_errno = -7;	// ERROR: no such user
			break;
		default:	
			tftp_errno = -1;	// ERROR: unknown error
		}
		goto error;
	} else if (tftp->th_opcode == DATA) {
		/* DATA PACKAGE */
		if (block + 1 == tftp->th_data) {
			++block;
		}
		else if( block == 0xffff && huge_load != 0
		     &&  (tftp->th_data == 0 || tftp->th_data == 1) ) {
			block = tftp->th_data;
		}
		else if (tftp->th_data == block) {
#ifdef __DEBUG__
			printf
			    ("\nTFTP: Received block %x, expected block was %x\n",
			     tftp->th_data, block + 1);
			printf("\b+ ");
#endif
			send_ack(fd, tftp->th_data, port_number);
			lost_packets++;
			tftp_err->bad_tftp_packets++;
			return 0;
		} else if (tftp->th_data < block) {
#ifdef __DEBUG__
			printf
			    ("\nTFTP: Received block %x, expected block was %x\n",
			     tftp->th_data, block + 1);
			printf("\b* ");
#endif
			/* This means that an old data packet appears (again);
			 * this happens sometimes if we don't answer fast enough
			 * and a timeout is generated on the server side;
			 * as we already have this packet we just ignore it */
			tftp_err->bad_tftp_packets++;
			return 0;
		} else {
			tftp_err->blocks_missed = block + 1;
			tftp_err->blocks_received = tftp->th_data;
			tftp_errno = -42;
			goto error;
		}
		tftp_err->bad_tftp_packets = 0;
		/* check if our buffer is large enough */
		if (received_len + udph->uh_ulen - 12 > len) {
			tftp_errno = -2;
			goto error;
		}
		memcpy(buffer + received_len, &tftp->th_data + 1,
		       udph->uh_ulen - 12);
		send_ack(fd, tftp->th_data, port_number);
		received_len += udph->uh_ulen - 12;
		/* Last packet reached if the payload of the UDP packet
		 * is smaller than blocksize + 12
		 * 12 = UDP header (8) + 4 bytes TFTP payload */
		if (udph->uh_ulen < blocksize + 12) {
			tftp_finished = 1;
			return 0;
		}
		/* 0xffff is the highest block number possible
		 * see the TFTP RFCs */

		if (block >= 0xffff && huge_load == 0) {
			tftp_errno = -9;
			goto error;
		}
	} else {
#ifdef __DEBUG__
		printf("Unknown packet %x\n", tftp->th_opcode);
		printf("\b# ");
#endif
		tftp_err->bad_tftp_packets++;
		return 0;
	}

	return 0;

error:
#ifdef __DEBUG__
	printf("\nTFTP errno: %d\n", tftp_errno);
#endif
	tftp_finished = 1;
	return tftp_errno;
}

/**
 * TFTP: This function handles situation when "Destination unreachable"
 *       ICMP-error occurs during sending TFTP-packet.
 *
 * @param  err_code   Error Code (e.g. "Host unreachable")
 */
void
handle_tftp_dun(uint8_t err_code)
{
	tftp_errno = - err_code - 10;
	tftp_finished = 1;
}

/**
 * TFTP: Interface function to load files via TFTP.
 *
 * @param  _fn_ip        contains the following configuration information:
 *                       client IP, TFTP-server IP, filename to be loaded
 * @param  _buffer       destination buffer for the file
 * @param  _len          size of destination buffer
 * @param  _retries      max number of retries
 * @param  _tftp_err     contains info about TFTP-errors (e.g. lost packets)
 * @param  _mode         NON ZERO - multicast, ZERO - unicast
 * @param  _blocksize    blocksize for DATA-packets
 * @return               ZERO - error condition occurs
 *                       NON ZERO - size of received file
 */
int
tftp(filename_ip_t * _fn_ip, unsigned char *_buffer, int _len,
     unsigned int _retries, tftp_err_t * _tftp_err,
     int32_t _mode, int32_t _blocksize, int _ip_version)
{
	retries     = _retries;
	fn_ip       = _fn_ip;
	len         = _len;
	huge_load   = _mode;
	ip_version  = _ip_version;
	tftp_errno  = 0;
	tftp_err    = _tftp_err;
	tftp_err->bad_tftp_packets = 0;
	tftp_err->no_packets = 0;

	/* Default blocksize must be 512 for TFTP servers
	 * which do not support the RRQ blocksize option */
	blocksize = 512;

	/* Preferred blocksize - used as option for the read request */
	if (_blocksize < 8)
		_blocksize = 8;
	else if (_blocksize > MAX_BLOCKSIZE)
		_blocksize = MAX_BLOCKSIZE;
	sprintf(blocksize_str, "%d", _blocksize);

	printf("  Receiving data:  ");
	print_progress(-1, 0);

	// Setting buffer to a non-zero address enabled handling of received TFTP packets.
	buffer = _buffer;

	set_timer(TICKS_SEC);
	send_rrq(fn_ip->fd);

	while (! tftp_finished) {
		/* if timeout (no packet received) */
		if(get_timer() <= 0) {
			/* the server doesn't seem to retry let's help out a bit */
			if (tftp_err->no_packets > 4 && port_number != -1
			    && block > 1) {
				send_ack(fn_ip->fd, block, port_number);
			}
			else if (port_number == -1 && block == 0
				 && (tftp_err->no_packets&3) == 3) {
				printf("\nRepeating TFTP read request...\n");
				send_rrq(fn_ip->fd);
			}
			tftp_err->no_packets++;
			set_timer(TICKS_SEC);
		}

		/* handle received packets */
		receive_ether(fn_ip->fd);

		/* bad_tftp_packets are counted whenever we receive a TFTP packet
			* which was not expected; if this gets larger than 'retries'
			* we just exit */
		if (tftp_err->bad_tftp_packets > retries) {
			tftp_errno = -40;
			break;
		}

		/* no_packets counts the times we have returned from receive_ether()
			* without any packet received; if this gets larger than 'retries'
			* we also just exit */
		if (tftp_err->no_packets > retries) {
			tftp_errno = -41;
			break;
		}
	}

	// Setting buffer to NULL disables handling of received TFTP packets.
	buffer = NULL;

	if (tftp_errno)
		return tftp_errno;

	print_progress(-1, received_len);
	printf("\n");
	if (lost_packets)
		printf("Lost ACK packets: %d\n", lost_packets);
		
	return received_len;
}
