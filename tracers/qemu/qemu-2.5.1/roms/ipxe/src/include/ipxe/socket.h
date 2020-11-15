#ifndef _IPXE_SOCKET_H
#define _IPXE_SOCKET_H

/** @file
 *
 * Socket addresses
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/tables.h>

/**
 * @defgroup commtypes Communication semantics
 *
 * @{
 */

/** Connection-based, reliable streams */
extern int tcp_sock_stream;
#define TCP_SOCK_STREAM 0x1
#define SOCK_STREAM tcp_sock_stream

/** Connectionless, unreliable streams */
extern int udp_sock_dgram;
#define UDP_SOCK_DGRAM 0x2
#define SOCK_DGRAM udp_sock_dgram

/** Echo testing streams */
extern int ping_sock_echo;
#define PING_SOCK_ECHO 0x3
#define SOCK_ECHO ping_sock_echo

/** @} */

/**
 * Name communication semantics
 *
 * @v semantics		Communication semantics (e.g. SOCK_STREAM)
 * @ret name		Name of communication semantics
 */
static inline __attribute__ (( always_inline )) const char *
socket_semantics_name ( int semantics ) {
	/* Cannot use a switch() because of the {TCP_UDP}_SOCK_XXX hack */
	if ( semantics == SOCK_STREAM ) {
		return "SOCK_STREAM";
	} else if ( semantics == SOCK_DGRAM ) {
		return "SOCK_DGRAM";
	} else if ( semantics == SOCK_ECHO ) {
		return "SOCK_ECHO";
	} else {
		return "SOCK_UNKNOWN";
	}
}

/**
 * @defgroup addrfam Address families
 *
 * @{
 */
#define AF_INET		1	/**< IPv4 Internet addresses */
#define AF_INET6	2	/**< IPv6 Internet addresses */
#define AF_FC		3	/**< Fibre Channel addresses */
/** @} */

/**
 * Name address family
 *
 * @v family		Address family (e.g. AF_INET)
 * @ret name		Name of address family
 */
static inline __attribute__ (( always_inline )) const char *
socket_family_name ( int family ) {
	switch ( family ) {
	case AF_INET:		return "AF_INET";
	case AF_INET6:		return "AF_INET6";
	case AF_FC:		return "AF_FC";
	default:		return "AF_UNKNOWN";
	}
}

/** A socket address family */
typedef uint16_t sa_family_t;

/** Length of a @c struct @c sockaddr */
#define SA_LEN 32

/**
 * Generalized socket address structure
 *
 * This contains the fields common to socket addresses for all address
 * families.
 */
struct sockaddr {
	/** Socket address family
	 *
	 * This is an AF_XXX constant.
	 */
        sa_family_t sa_family;
	/** Padding
	 *
	 * This ensures that a struct @c sockaddr_tcpip is large
	 * enough to hold a socket address for any TCP/IP address
	 * family.
	 */
	char pad[ SA_LEN - sizeof ( sa_family_t ) ];
} __attribute__ (( packed, may_alias ));

/**
 * Socket address converter
 *
 */
struct sockaddr_converter {
	/** Socket address family
	 *
	 * This is an AF_XXX constant.
	 */
        sa_family_t family;
	/** Transcribe socket address
	 *
	 * @v sa		Socket address
	 * @ret string		Socket address string
	 */
	const char * ( * ntoa ) ( struct sockaddr *sa );
	/** Parse socket address
	 *
	 * @v string		Socket address stringh
	 * @v sa		Socket address to fill in
	 * @ret rc		Return status code
	 */
	int ( * aton ) ( const char *string, struct sockaddr *sa );
};

/** Socket address converter table */
#define SOCKADDR_CONVERTERS \
	__table ( struct sockaddr_converter, "sockaddr_converters" )

/** Declare a socket address converter */
#define __sockaddr_converter __table_entry ( SOCKADDR_CONVERTERS, 01 )

extern const char * sock_ntoa ( struct sockaddr *sa );
extern int sock_aton ( const char *string, struct sockaddr *sa );

#endif /* _IPXE_SOCKET_H */
