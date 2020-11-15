#ifndef	_IPXE_IN_H
#define	_IPXE_IN_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <byteswap.h>
#include <ipxe/socket.h>

/* Protocol numbers */

#define IP_ICMP		1
#define IP_TCP		6
#define IP_UDP		17
#define IP_ICMP6	58

/* IP address constants */

#define INADDR_NONE		htonl ( 0xffffffff )

#define INADDR_BROADCAST	htonl ( 0xffffffff )

#define	INADDR_NET_CLASSA	htonl ( 0xff000000 )
#define	INADDR_NET_CLASSB	htonl ( 0xffff0000 )
#define	INADDR_NET_CLASSC	htonl ( 0xffffff00 )

#define	IN_IS_CLASSA( addr ) \
	( ( (addr) & htonl ( 0x80000000 ) ) == htonl ( 0x00000000 ) )
#define	IN_IS_CLASSB( addr ) \
	( ( (addr) & htonl ( 0xc0000000 ) ) == htonl ( 0x80000000 ) )
#define	IN_IS_CLASSC( addr ) \
	( ( (addr) & htonl ( 0xe0000000 ) ) == htonl ( 0xc0000000 ) )
#define IN_IS_MULTICAST( addr ) \
	( ( (addr) & htonl ( 0xf0000000 ) ) == htonl ( 0xe0000000 ) )

/**
 * IP address structure
 */
struct in_addr {
	uint32_t	s_addr;
};

typedef struct in_addr in_addr;

/**
 * IP6 address structure
 */
struct in6_addr {
        union {
                uint8_t u6_addr8[16];
                uint16_t u6_addr16[8];
                uint32_t u6_addr32[4];
        } in6_u;
#define s6_addr         in6_u.u6_addr8
#define s6_addr16       in6_u.u6_addr16
#define s6_addr32       in6_u.u6_addr32
};

#define IN6_IS_ADDR_UNSPECIFIED( addr )					\
	( ( ( ( ( const uint32_t * ) (addr) )[0] ) |			\
	    ( ( ( const uint32_t * ) (addr) )[1] ) |			\
	    ( ( ( const uint32_t * ) (addr) )[2] ) |			\
	    ( ( ( const uint32_t * ) (addr) )[3] ) ) == 0 )

#define IN6_IS_ADDR_MULTICAST( addr )					\
	( *( ( const uint8_t * ) (addr) ) == 0xff )

#define IN6_IS_ADDR_LINKLOCAL( addr )					\
	( ( *( ( const uint16_t * ) (addr) ) & htons ( 0xffc0 ) ) ==	\
	  htons ( 0xfe80 ) )

#define IN6_IS_ADDR_NONGLOBAL( addr )					\
	( IN6_IS_ADDR_LINKLOCAL (addr) || IN6_IS_ADDR_MULTICAST (addr) )

/**
 * IPv4 socket address
 */
struct sockaddr_in {
	/** Socket address family (part of struct @c sockaddr)
	 *
	 * Always set to @c AF_INET for IPv4 addresses
	 */
	sa_family_t sin_family;
	/** Flags (part of struct @c sockaddr_tcpip) */
	uint16_t sin_flags;
	/** TCP/IP port (part of struct @c sockaddr_tcpip) */
	uint16_t sin_port;
	/** Scope ID (part of struct @c sockaddr_tcpip)
	 *
	 * For multicast addresses, this is the network device index.
	 */
        uint16_t sin_scope_id;
	/** IPv4 address */
	struct in_addr sin_addr;
	/** Padding
	 *
	 * This ensures that a struct @c sockaddr_in is large enough
	 * to hold a socket address for any TCP/IP address family.
	 */
	char pad[ sizeof ( struct sockaddr ) -
		  ( sizeof ( sa_family_t ) /* sin_family */ +
		    sizeof ( uint16_t ) /* sin_flags */ +
		    sizeof ( uint16_t ) /* sin_port */ +
		    sizeof ( uint16_t ) /* sin_scope_id */ +
		    sizeof ( struct in_addr ) /* sin_addr */ ) ];
} __attribute__ (( packed, may_alias ));

/**
 * IPv6 socket address
 */
struct sockaddr_in6 {
	/** Socket address family (part of struct @c sockaddr)
	 *
	 * Always set to @c AF_INET6 for IPv6 addresses
	 */
	sa_family_t sin6_family;
	/** Flags (part of struct @c sockaddr_tcpip) */
	uint16_t sin6_flags;
	/** TCP/IP port (part of struct @c sockaddr_tcpip) */
	uint16_t sin6_port;
	/** Scope ID (part of struct @c sockaddr_tcpip)
	 *
	 * For link-local or multicast addresses, this is the network
	 * device index.
	 */
        uint16_t sin6_scope_id;
	/** IPv6 address */
        struct in6_addr sin6_addr;
	/** Padding
	 *
	 * This ensures that a struct @c sockaddr_in6 is large
	 * enough to hold a socket address for any TCP/IP address
	 * family.
	 */
	char pad[ sizeof ( struct sockaddr ) -
		  ( sizeof ( sa_family_t ) /* sin6_family */ +
		    sizeof ( uint16_t ) /* sin6_flags */ +
		    sizeof ( uint16_t ) /* sin6_port */ +
		    sizeof ( uint16_t ) /* sin6_scope_id */ +
		    sizeof ( struct in6_addr ) /* sin6_addr */ ) ];
} __attribute__ (( packed, may_alias ));

extern int inet_aton ( const char *cp, struct in_addr *inp );
extern char * inet_ntoa ( struct in_addr in );
extern int inet6_aton ( const char *string, struct in6_addr *in );
extern char * inet6_ntoa ( const struct in6_addr *in );

#endif	/* _IPXE_IN_H */
