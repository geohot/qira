#ifndef _IPXE_ICMP_H
#define _IPXE_ICMP_H

/** @file
 *
 * ICMP protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/iobuf.h>
#include <ipxe/socket.h>
#include <ipxe/tcpip.h>
#include <ipxe/tables.h>

/** An ICMP header */
struct icmp_header {
	/** Type */
	uint8_t type;
	/** Code */
	uint8_t code;
	/** Checksum */
	uint16_t chksum;
} __attribute__ (( packed ));

/** An ICMP echo request/reply */
struct icmp_echo {
	/** ICMPv6 header */
	struct icmp_header icmp;
	/** Identifier */
	uint16_t ident;
	/** Sequence number */
	uint16_t sequence;
	/** Data */
	uint8_t data[0];
} __attribute__ (( packed ));

/** An ICMP echo protocol */
struct icmp_echo_protocol {
	/** Address family */
	sa_family_t family;
	/** Request type */
	uint8_t request;
	/** Reply type */
	uint8_t reply;
	/** TCP/IP protocol */
	struct tcpip_protocol *tcpip_protocol;
	/** Include network-layer checksum within packet */
	int net_checksum;
};

/** ICMP echo protocol table */
#define ICMP_ECHO_PROTOCOLS \
	__table ( struct icmp_echo_protocol, "icmp_echo_protocols" )

/** Declare an ICMP echo protocol */
#define __icmp_echo_protocol __table_entry ( ICMP_ECHO_PROTOCOLS, 01 )

#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8

extern int icmp_tx_echo_request ( struct io_buffer *iobuf,
				  struct sockaddr_tcpip *st_dest );

extern int icmp_rx_echo_request ( struct io_buffer *iobuf,
				  struct sockaddr_tcpip *st_src,
				  struct icmp_echo_protocol *echo_protocol );
extern int icmp_rx_echo_reply ( struct io_buffer *iobuf,
				struct sockaddr_tcpip *st_src );

#endif /* _IPXE_ICMP_H */
