#ifndef _IPXE_DHCP_H
#define _IPXE_DHCP_H

/** @file
 *
 * Dynamic Host Configuration Protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stdarg.h>
#include <ipxe/in.h>
#include <ipxe/list.h>
#include <ipxe/refcnt.h>
#include <ipxe/tables.h>
#include <ipxe/uuid.h>
#include <ipxe/netdevice.h>
#include <ipxe/uaccess.h>

struct interface;
struct dhcp_options;
struct dhcp_packet;

/** BOOTP/DHCP server port */
#define BOOTPS_PORT 67

/** BOOTP/DHCP client port */
#define BOOTPC_PORT 68

/** PXE server port */
#define PXE_PORT 4011

/** Construct a tag value for an encapsulated option
 *
 * This tag value can be passed to Etherboot functions when searching
 * for DHCP options in order to search for a tag within an
 * encapsulated options block.
 */
#define DHCP_ENCAP_OPT( encapsulator, encapsulated ) \
	( ( (encapsulator) << 8 ) | (encapsulated) )
/** Extract encapsulating option block tag from encapsulated tag value */
#define DHCP_ENCAPSULATOR( encap_opt ) ( (encap_opt) >> 8 )
/** Extract encapsulated option tag from encapsulated tag value */
#define DHCP_ENCAPSULATED( encap_opt ) ( (encap_opt) & 0xff )
/** Option is encapsulated */
#define DHCP_IS_ENCAP_OPT( opt ) DHCP_ENCAPSULATOR( opt )

/**
 * @defgroup dhcpopts DHCP option tags
 * @{
 */

/** Padding
 *
 * This tag does not have a length field; it is always only a single
 * byte in length.
 */
#define DHCP_PAD 0

/** Minimum normal DHCP option */
#define DHCP_MIN_OPTION 1

/** Subnet mask */
#define DHCP_SUBNET_MASK 1

/** Routers */
#define DHCP_ROUTERS 3

/** DNS servers */
#define DHCP_DNS_SERVERS 6

/** Syslog servers */
#define DHCP_LOG_SERVERS 7

/** Host name */
#define DHCP_HOST_NAME 12

/** Domain name */
#define DHCP_DOMAIN_NAME 15

/** Root path */
#define DHCP_ROOT_PATH 17

/** Vendor encapsulated options */
#define DHCP_VENDOR_ENCAP 43

/** PXE boot server discovery control */
#define DHCP_PXE_DISCOVERY_CONTROL DHCP_ENCAP_OPT ( DHCP_VENDOR_ENCAP, 6 )

/** PXE boot server discovery control bits */
enum dhcp_pxe_discovery_control {
	/** Inhibit broadcast discovery */
	PXEBS_NO_BROADCAST = 1,
	/** Inhibit multicast discovery */
	PXEBS_NO_MULTICAST = 2,
	/** Accept only servers in DHCP_PXE_BOOT_SERVERS list */
	PXEBS_NO_UNKNOWN_SERVERS = 4,
	/** Skip discovery if filename present */
	PXEBS_SKIP = 8,
};

/** PXE boot server multicast address */
#define DHCP_PXE_BOOT_SERVER_MCAST DHCP_ENCAP_OPT ( DHCP_VENDOR_ENCAP, 7 )

/** PXE boot servers */
#define DHCP_PXE_BOOT_SERVERS DHCP_ENCAP_OPT ( DHCP_VENDOR_ENCAP, 8 )

/** PXE boot server */
struct dhcp_pxe_boot_server {
	/** "Type" */
	uint16_t type;
	/** Number of IPv4 addresses */
	uint8_t num_ip;
	/** IPv4 addresses */
	struct in_addr ip[0];
} __attribute__ (( packed ));

/** PXE boot menu */
#define DHCP_PXE_BOOT_MENU DHCP_ENCAP_OPT ( DHCP_VENDOR_ENCAP, 9 )

/** PXE boot menu */
struct dhcp_pxe_boot_menu {
	/** "Type" */
	uint16_t type;
	/** Description length */
	uint8_t desc_len;
	/** Description */
	char desc[0];
} __attribute__ (( packed ));

/** PXE boot menu prompt */
#define DHCP_PXE_BOOT_MENU_PROMPT DHCP_ENCAP_OPT ( DHCP_VENDOR_ENCAP, 10 )

/** PXE boot menu prompt */
struct dhcp_pxe_boot_menu_prompt {
	/** Timeout
	 *
	 * A value of 0 means "time out immediately and select first
	 * boot item, without displaying the prompt".  A value of 255
	 * means "display menu immediately with no timeout".  Any
	 * other value means "display prompt, wait this many seconds
	 * for keypress, if key is F8, display menu, otherwise select
	 * first boot item".
	 */
	uint8_t timeout;
	/** Prompt to press F8 */
	char prompt[0];
} __attribute__ (( packed ));

/** PXE boot menu item */
#define DHCP_PXE_BOOT_MENU_ITEM DHCP_ENCAP_OPT ( DHCP_VENDOR_ENCAP, 71 )

/** PXE boot menu item */
struct dhcp_pxe_boot_menu_item {
	/** "Type"
	 *
	 * This field actually identifies the specific boot server (or
	 * cluster of boot servers offering identical boot files).
	 */
	uint16_t type;
	/** "Layer"
	 *
	 * Just don't ask.
	 */
	uint16_t layer;
} __attribute__ (( packed ));

/** Requested IP address */
#define DHCP_REQUESTED_ADDRESS 50

/** Lease time */
#define DHCP_LEASE_TIME 51

/** Option overloading
 *
 * The value of this option is the bitwise-OR of zero or more
 * DHCP_OPTION_OVERLOAD_XXX constants.
 */
#define DHCP_OPTION_OVERLOAD 52

/** The "file" field is overloaded to contain extra DHCP options */
#define DHCP_OPTION_OVERLOAD_FILE 1

/** The "sname" field is overloaded to contain extra DHCP options */
#define DHCP_OPTION_OVERLOAD_SNAME 2

/** DHCP message type */
#define DHCP_MESSAGE_TYPE 53
#define DHCPNONE 0
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

/** DHCP server identifier */
#define DHCP_SERVER_IDENTIFIER 54

/** Parameter request list */
#define DHCP_PARAMETER_REQUEST_LIST 55

/** Maximum DHCP message size */
#define DHCP_MAX_MESSAGE_SIZE 57

/** Vendor class identifier */
#define DHCP_VENDOR_CLASS_ID 60

/** Client identifier */
#define DHCP_CLIENT_ID 61

/** Client identifier */
struct dhcp_client_id {
	/** Link-layer protocol */
	uint8_t ll_proto;
	/** Link-layer address */
	uint8_t ll_addr[MAX_LL_ADDR_LEN];
} __attribute__ (( packed ));

/** TFTP server name
 *
 * This option replaces the fixed "sname" field, when that field is
 * used to contain overloaded options.
 */
#define DHCP_TFTP_SERVER_NAME 66

/** Bootfile name
 *
 * This option replaces the fixed "file" field, when that field is
 * used to contain overloaded options.
 */
#define DHCP_BOOTFILE_NAME 67

/** User class identifier */
#define DHCP_USER_CLASS_ID 77

/** Client system architecture */
#define DHCP_CLIENT_ARCHITECTURE 93

/** DHCP client architecture */
struct dhcp_client_architecture {
	uint16_t arch;
} __attribute__ (( packed ));

/** DHCP client architecture values
 *
 * These are defined by the PXE specification and redefined by
 * RFC4578.
 */
enum dhcp_client_architecture_values {
	/** Intel x86 PC */
	DHCP_CLIENT_ARCHITECTURE_X86 = 0x0000,
	/** NEC/PC98 */
	DHCP_CLIENT_ARCHITECTURE_PC98 = 0x0001,
	/** EFI Itanium */
	DHCP_CLIENT_ARCHITECTURE_IA64 = 0x0002,
	/** DEC Alpha */
	DHCP_CLIENT_ARCHITECTURE_ALPHA = 0x0003,
	/** Arc x86 */
	DHCP_CLIENT_ARCHITECTURE_ARCX86 = 0x0004,
	/** Intel Lean Client */
	DHCP_CLIENT_ARCHITECTURE_LC = 0x0005,
	/** EFI IA32 */
	DHCP_CLIENT_ARCHITECTURE_IA32 = 0x0006,
	/** EFI BC */
	DHCP_CLIENT_ARCHITECTURE_EFI = 0x0007,
	/** EFI Xscale */
	DHCP_CLIENT_ARCHITECTURE_XSCALE = 0x0008,
	/** EFI x86-64 */
	DHCP_CLIENT_ARCHITECTURE_X86_64 = 0x0009,
};

/** Client network device interface */
#define DHCP_CLIENT_NDI 94

/** UUID client identifier */
#define DHCP_CLIENT_UUID 97

/** UUID client identifier */
struct dhcp_client_uuid {
	/** Identifier type */
	uint8_t type;
	/** UUID */
	union uuid uuid;
} __attribute__ (( packed ));

#define DHCP_CLIENT_UUID_TYPE 0

/** DNS domain search list */
#define DHCP_DOMAIN_SEARCH 119

/** Etherboot-specific encapsulated options
 *
 * This encapsulated options field is used to contain all options
 * specific to Etherboot (i.e. not assigned by IANA or other standards
 * bodies).
 */
#define DHCP_EB_ENCAP 175

/** Priority of this options block
 *
 * This is a signed 8-bit integer field indicating the priority of
 * this block of options.  It can be used to specify the relative
 * priority of multiple option blocks (e.g. options from non-volatile
 * storage versus options from a DHCP server).
 */
#define DHCP_EB_PRIORITY DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x01 )

/** "Your" IP address
 *
 * This option is used internally to contain the value of the "yiaddr"
 * field, in order to provide a consistent approach to storing and
 * processing options.  It should never be present in a DHCP packet.
 */
#define DHCP_EB_YIADDR DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x02 )

/** "Server" IP address
 *
 * This option is used internally to contain the value of the "siaddr"
 * field, in order to provide a consistent approach to storing and
 * processing options.  It should never be present in a DHCP packet.
 */
#define DHCP_EB_SIADDR DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x03 )

/** Keep SAN drive registered
 *
 * If set to a non-zero value, iPXE will not detach any SAN drive
 * after failing to boot from it.  (This option is required in order
 * to perform an installation direct to an iSCSI target.)
 */
#define DHCP_EB_KEEP_SAN DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x08 )

/** Skip booting from SAN drive
 *
 * If set to a non-zero value, iPXE will skip booting from any SAN
 * drive.  (This option is sometimes required in conjunction with @c
 * DHCP_EB_KEEP_SAN in order to perform an installation direct to an
 * iSCSI target.)
 */
#define DHCP_EB_SKIP_SAN_BOOT DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x09 )

/*
 * Tags in the range 0x10-0x4f are reserved for feature markers
 *
 */

/** Scriptlet
 *
 * If a scriptlet exists, it will be executed in place of the usual
 * call to autoboot()
 */
#define DHCP_EB_SCRIPTLET DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x51 )

/** Encrypted syslog server */
#define DHCP_EB_SYSLOGS_SERVER DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x55 )

/** Trusted root certficate fingerprints */
#define DHCP_EB_TRUST DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x5a )

/** Client certficate */
#define DHCP_EB_CERT DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x5b )

/** Client private key */
#define DHCP_EB_KEY DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x5c )

/** Cross-signed certificate source */
#define DHCP_EB_CROSS_CERT DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0x5d )

/** Skip PXE DHCP protocol extensions such as ProxyDHCP
 *
 * If set to a non-zero value, iPXE will not wait for ProxyDHCP offers
 * and will ignore any PXE-specific DHCP options that it receives.
 */
#define DHCP_EB_NO_PXEDHCP DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xb0 )

/** Network device descriptor
 *
 * Byte 0 is the bus type ID; remaining bytes depend on the bus type.
 *
 * PCI devices:
 * Byte 0 : 1 (PCI)
 * Byte 1 : PCI vendor ID MSB
 * Byte 2 : PCI vendor ID LSB
 * Byte 3 : PCI device ID MSB
 * Byte 4 : PCI device ID LSB
 */
#define DHCP_EB_BUS_ID DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xb1 )

/** Network device descriptor */
struct dhcp_netdev_desc {
	/** Bus type ID */
	uint8_t type;
	/** Vendor ID */
	uint16_t vendor;
	/** Device ID */
	uint16_t device;
} __attribute__ (( packed ));

/** Use cached network settings (obsolete; do not reuse this value) */
#define DHCP_EB_USE_CACHED DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xb2 )

/** BIOS drive number
 *
 * This is the drive number for a drive emulated via INT 13.  0x80 is
 * the first hard disk, 0x81 is the second hard disk, etc.
 */
#define DHCP_EB_BIOS_DRIVE DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xbd )

/** Username
 *
 * This will be used as the username for any required authentication.
 * It is expected that this option's value will be held in
 * non-volatile storage, rather than transmitted as part of a DHCP
 * packet.
 */
#define DHCP_EB_USERNAME DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xbe )

/** Password
 *
 * This will be used as the password for any required authentication.
 * It is expected that this option's value will be held in
 * non-volatile storage, rather than transmitted as part of a DHCP
 * packet.
 */
#define DHCP_EB_PASSWORD DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xbf )

/** Reverse username
 *
 * This will be used as the reverse username (i.e. the username
 * provided by the server) for any required authentication.  It is
 * expected that this option's value will be held in non-volatile
 * storage, rather than transmitted as part of a DHCP packet.
 */
#define DHCP_EB_REVERSE_USERNAME DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xc0 )

/** Reverse password
 *
 * This will be used as the reverse password (i.e. the password
 * provided by the server) for any required authentication.  It is
 * expected that this option's value will be held in non-volatile
 * storage, rather than transmitted as part of a DHCP packet.
 */
#define DHCP_EB_REVERSE_PASSWORD DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xc1 )

/** User ID
 *
 * This will be used as the user id for AUTH_SYS based authentication in NFS.
 */
#define DHCP_EB_UID DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xc2 )

/** Group ID
 *
 * This will be used as the group id for AUTH_SYS based authentication in NFS.
 */
#define DHCP_EB_GID DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xc3 )

/** iPXE version number */
#define DHCP_EB_VERSION DHCP_ENCAP_OPT ( DHCP_EB_ENCAP, 0xeb )

/** iSCSI primary target IQN */
#define DHCP_ISCSI_PRIMARY_TARGET_IQN 201

/** iSCSI secondary target IQN */
#define DHCP_ISCSI_SECONDARY_TARGET_IQN 202

/** iSCSI initiator IQN */
#define DHCP_ISCSI_INITIATOR_IQN 203

/** Maximum normal DHCP option */
#define DHCP_MAX_OPTION 254

/** End of options
 *
 * This tag does not have a length field; it is always only a single
 * byte in length.
 */
#define DHCP_END 255

/** @} */

/** Construct a DHCP option from a list of bytes */
#define DHCP_OPTION( ... ) VA_ARG_COUNT ( __VA_ARGS__ ), __VA_ARGS__

/** Construct a DHCP option from a list of characters */
#define DHCP_STRING( ... ) DHCP_OPTION ( __VA_ARGS__ )

/** Construct a byte-valued DHCP option */
#define DHCP_BYTE( value ) DHCP_OPTION ( value )

/** Construct a word-valued DHCP option */
#define DHCP_WORD( value ) DHCP_OPTION ( ( ( (value) >> 8 ) & 0xff ),   \
					 ( ( (value) >> 0 ) & 0xff ) )

/** Construct a dword-valued DHCP option */
#define DHCP_DWORD( value ) DHCP_OPTION ( ( ( (value) >> 24 ) & 0xff ), \
					  ( ( (value) >> 16 ) & 0xff ), \
					  ( ( (value) >> 8  ) & 0xff ), \
					  ( ( (value) >> 0  ) & 0xff ) )

/** Construct a DHCP encapsulated options field */
#define DHCP_ENCAP( ... ) DHCP_OPTION ( __VA_ARGS__, DHCP_END )

/**
 * A DHCP option
 *
 * DHCP options consist of a mandatory tag, a length field that is
 * mandatory for all options except @c DHCP_PAD and @c DHCP_END, and a
 * payload.  
 */
struct dhcp_option {
	/** Tag
	 *
	 * Must be a @c DHCP_XXX value.
	 */
	uint8_t tag;
	/** Length
	 *
	 * This is the length of the data field (i.e. excluding the
	 * tag and length fields).  For the two tags @c DHCP_PAD and
	 * @c DHCP_END, the length field is implicitly zero and is
	 * also missing, i.e. these DHCP options are only a single
	 * byte in length.
	 */
	uint8_t len;
	/** Option data */
	uint8_t data[0];
} __attribute__ (( packed ));

/**
 * Length of a DHCP option header
 *
 * The header is the portion excluding the data, i.e. the tag and the
 * length.
 */
#define DHCP_OPTION_HEADER_LEN ( offsetof ( struct dhcp_option, data ) )

/** Maximum length for a single DHCP option */
#define DHCP_MAX_LEN 0xff

/**
 * A DHCP header
 *
 */
struct dhcphdr {
	/** Operation
	 *
	 * This must be either @c BOOTP_REQUEST or @c BOOTP_REPLY.
	 */
	uint8_t op;
	/** Hardware address type
	 *
	 * This is an ARPHRD_XXX constant.  Note that ARPHRD_XXX
	 * constants are nominally 16 bits wide; this could be
	 * considered to be a bug in the BOOTP/DHCP specification.
	 */
	uint8_t htype;
	/** Hardware address length */
	uint8_t hlen;
	/** Number of hops from server */
	uint8_t hops;
	/** Transaction ID */
	uint32_t xid;
	/** Seconds since start of acquisition */
	uint16_t secs;
	/** Flags */
	uint16_t flags;
	/** "Client" IP address
	 *
	 * This is filled in if the client already has an IP address
	 * assigned and can respond to ARP requests.
	 */
	struct in_addr ciaddr;
	/** "Your" IP address
	 *
	 * This is the IP address assigned by the server to the client.
	 */
	struct in_addr yiaddr;
	/** "Server" IP address
	 *
	 * This is the IP address of the next server to be used in the
	 * boot process.
	 */
	struct in_addr siaddr;
	/** "Gateway" IP address
	 *
	 * This is the IP address of the DHCP relay agent, if any.
	 */
	struct in_addr giaddr;
	/** Client hardware address */
	uint8_t chaddr[16];
	/** Server host name (null terminated)
	 *
	 * This field may be overridden and contain DHCP options
	 */
	char sname[64];
	/** Boot file name (null terminated)
	 *
	 * This field may be overridden and contain DHCP options
	 */
	char file[128];
	/** DHCP magic cookie
	 *
	 * Must have the value @c DHCP_MAGIC_COOKIE.
	 */
	uint32_t magic;
	/** DHCP options
	 *
	 * Variable length; extends to the end of the packet.  Minimum
	 * length (for the sake of sanity) is 1, to allow for a single
	 * @c DHCP_END tag.
	 */
	uint8_t options[0];
};

/** Opcode for a request from client to server */
#define BOOTP_REQUEST 1

/** Opcode for a reply from server to client */
#define BOOTP_REPLY 2

/** BOOTP reply must be broadcast
 *
 * Clients that cannot accept unicast BOOTP replies must set this
 * flag.
 */
#define BOOTP_FL_BROADCAST 0x8000

/** DHCP magic cookie */
#define DHCP_MAGIC_COOKIE 0x63825363UL

/** DHCP minimum packet length
 *
 * This is the mandated minimum packet length that a DHCP participant
 * must be prepared to receive.
 */
#define DHCP_MIN_LEN 552

/** Settings block name used for DHCP responses */
#define DHCP_SETTINGS_NAME "dhcp"

/** Settings block name used for ProxyDHCP responses */
#define PROXYDHCP_SETTINGS_NAME "proxydhcp"

/** Setting block name used for BootServerDHCP responses */
#define PXEBS_SETTINGS_NAME "pxebs"

extern uint32_t dhcp_last_xid;
extern int dhcp_create_packet ( struct dhcp_packet *dhcppkt,
				struct net_device *netdev, uint8_t msgtype,
				uint32_t xid, const void *options,
				size_t options_len, void *data,
				size_t max_len );
extern int dhcp_create_request ( struct dhcp_packet *dhcppkt,
				 struct net_device *netdev,
				 unsigned int msgtype, uint32_t xid,
				 struct in_addr ciaddr,
				 void *data, size_t max_len );
extern int start_dhcp ( struct interface *job, struct net_device *netdev );
extern int start_pxebs ( struct interface *job, struct net_device *netdev,
			 unsigned int pxe_type );

#endif /* _IPXE_DHCP_H */
