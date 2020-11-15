#ifndef _IPXE_DHCPV6_H
#define _IPXE_DHCPV6_H

/** @file
 *
 * Dynamic Host Configuration Protocol for IPv6
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/in.h>
#include <ipxe/uuid.h>

/** DHCPv6 server port */
#define DHCPV6_SERVER_PORT 547

/** DHCPv6 client port */
#define DHCPV6_CLIENT_PORT 546

/**
 * A DHCPv6 option
 *
 */
struct dhcpv6_option {
	/** Code */
	uint16_t code;
	/** Length of the data field */
	uint16_t len;
	/** Data */
	uint8_t data[0];
} __attribute__ (( packed ));

/** DHCP unique identifier based on UUID (DUID-UUID) */
struct dhcpv6_duid_uuid {
	/** Type */
	uint16_t type;
	/** UUID */
	union uuid uuid;
} __attribute__ (( packed ));

/** DHCP unique identifier based on UUID (DUID-UUID) */
#define DHCPV6_DUID_UUID 4

/** DHCPv6 client or server identifier option */
struct dhcpv6_duid_option {
	/** Option header */
	struct dhcpv6_option header;
	/** DHCP unique identifier (DUID) */
	uint8_t duid[0];
} __attribute__ (( packed ));

/** DHCPv6 client identifier option */
#define DHCPV6_CLIENT_ID 1

/** DHCPv6 server identifier option */
#define DHCPV6_SERVER_ID 2

/** DHCPv6 identity association for non-temporary address (IA_NA) option */
struct dhcpv6_ia_na_option {
	/** Option header */
	struct dhcpv6_option header;
	/** Identity association identifier (IAID) */
	uint32_t iaid;
	/** Renew time (in seconds) */
	uint32_t renew;
	/** Rebind time (in seconds) */
	uint32_t rebind;
	/** IA_NA options */
	struct dhcpv6_option options[0];
} __attribute__ (( packed ));

/** DHCPv6 identity association for non-temporary address (IA_NA) option */
#define DHCPV6_IA_NA 3

/** DHCPv6 identity association address (IAADDR) option */
struct dhcpv6_iaaddr_option {
	/** Option header */
	struct dhcpv6_option header;
	/** IPv6 address */
	struct in6_addr address;
	/** Preferred lifetime (in seconds) */
	uint32_t preferred;
	/** Valid lifetime (in seconds) */
	uint32_t valid;
	/** IAADDR options */
	struct dhcpv6_option options[0];
} __attribute__ (( packed ));

/** DHCPv6 identity association address (IAADDR) option */
#define DHCPV6_IAADDR 5

/** DHCPv6 option request option */
struct dhcpv6_option_request_option {
	/** Option header */
	struct dhcpv6_option header;
	/** Requested options */
	uint16_t requested[0];
} __attribute__ (( packed ));

/** DHCPv6 option request option */
#define DHCPV6_OPTION_REQUEST 6

/** DHCPv6 elapsed time option */
struct dhcpv6_elapsed_time_option {
	/** Option header */
	struct dhcpv6_option header;
	/** Elapsed time, in centiseconds */
	uint16_t elapsed;
} __attribute__ (( packed ));

/** DHCPv6 elapsed time option */
#define DHCPV6_ELAPSED_TIME 8

/** DHCPv6 status code option */
struct dhcpv6_status_code_option {
	/** Option header */
	struct dhcpv6_option header;
	/** Status code */
	uint16_t status;
	/** Status message */
	char message[0];
} __attribute__ (( packed ));

/** DHCPv6 status code option */
#define DHCPV6_STATUS_CODE 13

/** DHCPv6 user class */
struct dhcpv6_user_class {
	/** Length */
	uint16_t len;
	/** User class string */
	char string[0];
} __attribute__ (( packed ));

/** DHCPv6 user class option */
struct dhcpv6_user_class_option {
	/** Option header */
	struct dhcpv6_option header;
	/** User class */
	struct dhcpv6_user_class user_class[0];
} __attribute__ (( packed ));

/** DHCPv6 user class option */
#define DHCPV6_USER_CLASS 15

/** DHCPv6 DNS recursive name server option */
#define DHCPV6_DNS_SERVERS 23

/** DHCPv6 domain search list option */
#define DHCPV6_DOMAIN_LIST 24

/** DHCPv6 bootfile URI option */
#define DHCPV6_BOOTFILE_URL 59

/** DHCPv6 bootfile parameters option */
#define DHCPV6_BOOTFILE_PARAM 60

/** DHCPv6 syslog server option
 *
 * This option code has not yet been assigned by IANA.  Please update
 * this definition once an option code has been assigned.
 */
#define DHCPV6_LOG_SERVERS 0xffffffffUL

/**
 * Any DHCPv6 option
 *
 */
union dhcpv6_any_option {
	struct dhcpv6_option header;
	struct dhcpv6_duid_option duid;
	struct dhcpv6_ia_na_option ia_na;
	struct dhcpv6_iaaddr_option iaaddr;
	struct dhcpv6_option_request_option option_request;
	struct dhcpv6_elapsed_time_option elapsed_time;
	struct dhcpv6_status_code_option status_code;
	struct dhcpv6_user_class_option user_class;
};

/**
 * A DHCPv6 header
 *
 */
struct dhcpv6_header {
	/** Message type */
	uint8_t type;
	/** Transaction ID */
	uint8_t xid[3];
	/** Options */
	struct dhcpv6_option options[0];
} __attribute__ (( packed ));

/** DHCPv6 solicitation */
#define DHCPV6_SOLICIT 1

/** DHCPv6 advertisement */
#define DHCPV6_ADVERTISE 2

/** DHCPv6 request */
#define DHCPV6_REQUEST 3

/** DHCPv6 reply */
#define DHCPV6_REPLY 7

/** DHCPv6 information request */
#define DHCPV6_INFORMATION_REQUEST 11

/** DHCPv6 settings block name */
#define DHCPV6_SETTINGS_NAME "dhcpv6"

/**
 * Construct all-DHCP-relay-agents-and-servers multicast address
 *
 * @v addr		Zeroed address to construct
 */
static inline void ipv6_all_dhcp_relay_and_servers ( struct in6_addr *addr ) {
	addr->s6_addr16[0] = htons ( 0xff02 );
	addr->s6_addr[13] = 1;
	addr->s6_addr[15] = 2;
}

extern int start_dhcpv6 ( struct interface *job, struct net_device *netdev,
			  int stateful );

#endif /* _IPXE_DHCPV6_H */
