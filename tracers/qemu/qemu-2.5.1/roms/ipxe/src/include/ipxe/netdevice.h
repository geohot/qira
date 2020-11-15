#ifndef _IPXE_NETDEVICE_H
#define _IPXE_NETDEVICE_H

/** @file
 *
 * Network device management
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/list.h>
#include <ipxe/tables.h>
#include <ipxe/refcnt.h>
#include <ipxe/settings.h>
#include <ipxe/interface.h>
#include <ipxe/retry.h>

struct io_buffer;
struct net_device;
struct net_protocol;
struct ll_protocol;
struct device;

/** Maximum length of a hardware address
 *
 * The longest currently-supported link-layer address is for IPoIB.
 */
#define MAX_HW_ADDR_LEN 8

/** Maximum length of a link-layer address
 *
 * The longest currently-supported link-layer address is for IPoIB.
 */
#define MAX_LL_ADDR_LEN 20

/** Maximum length of a link-layer header
 *
 * The longest currently-supported link-layer header is for RNDIS: an
 * 8-byte RNDIS header, a 32-byte RNDIS packet message header, a
 * 14-byte Ethernet header and a possible 4-byte VLAN header.  Round
 * up to 64 bytes.
 */
#define MAX_LL_HEADER_LEN 64

/** Maximum length of a network-layer address */
#define MAX_NET_ADDR_LEN 16

/** Maximum length of a network-layer header
 *
 * The longest currently-supported network-layer header is for IPv6 at
 * 40 bytes.
 */
#define MAX_NET_HEADER_LEN 40

/** Maximum combined length of a link-layer and network-layer header */
#define MAX_LL_NET_HEADER_LEN ( MAX_LL_HEADER_LEN + MAX_NET_HEADER_LEN )

/**
 * A network-layer protocol
 *
 */
struct net_protocol {
	/** Protocol name */
	const char *name;
	/**
	 * Process received packet
	 *
	 * @v iobuf		I/O buffer
	 * @v netdev		Network device
	 * @v ll_dest		Link-layer destination address
	 * @v ll_source		Link-layer source address
	 * @v flags		Packet flags
	 * @ret rc		Return status code
	 *
	 * This method takes ownership of the I/O buffer.
	 */
	int ( * rx ) ( struct io_buffer *iobuf, struct net_device *netdev,
		       const void *ll_dest, const void *ll_source,
		       unsigned int flags );
	/**
	 * Transcribe network-layer address
	 *
	 * @v net_addr		Network-layer address
	 * @ret string		Human-readable transcription of address
	 *
	 * This method should convert the network-layer address into a
	 * human-readable format (e.g. dotted quad notation for IPv4).
	 *
	 * The buffer used to hold the transcription is statically
	 * allocated.
	 */
	const char * ( *ntoa ) ( const void * net_addr );
	/** Network-layer protocol
	 *
	 * This is an ETH_P_XXX constant, in network-byte order
	 */
	uint16_t net_proto;
	/** Network-layer address length */
	uint8_t net_addr_len;
};

/** Packet is a multicast (including broadcast) packet */
#define LL_MULTICAST 0x0001

/** Packet is a broadcast packet */
#define LL_BROADCAST 0x0002

/**
 * A link-layer protocol
 *
 */
struct ll_protocol {
	/** Protocol name */
	const char *name;
	/**
	 * Add link-layer header
	 *
	 * @v netdev		Network device
	 * @v iobuf		I/O buffer
	 * @v ll_dest		Link-layer destination address
	 * @v ll_source		Source link-layer address
	 * @v net_proto		Network-layer protocol, in network-byte order
	 * @ret rc		Return status code
	 */
	int ( * push ) ( struct net_device *netdev, struct io_buffer *iobuf,
			 const void *ll_dest, const void *ll_source,
			 uint16_t net_proto );
	/**
	 * Remove link-layer header
	 *
	 * @v netdev		Network device
	 * @v iobuf		I/O buffer
	 * @ret ll_dest		Link-layer destination address
	 * @ret ll_source	Source link-layer address
	 * @ret net_proto	Network-layer protocol, in network-byte order
	 * @ret flags		Packet flags
	 * @ret rc		Return status code
	 */
	int ( * pull ) ( struct net_device *netdev, struct io_buffer *iobuf,
			 const void **ll_dest, const void **ll_source,
			 uint16_t *net_proto, unsigned int *flags );
	/**
	 * Initialise link-layer address
	 *
	 * @v hw_addr		Hardware address
	 * @v ll_addr		Link-layer address to fill in
	 */
	void ( * init_addr ) ( const void *hw_addr, void *ll_addr );
	/**
	 * Transcribe link-layer address
	 *
	 * @v ll_addr		Link-layer address
	 * @ret string		Human-readable transcription of address
	 *
	 * This method should convert the link-layer address into a
	 * human-readable format.
	 *
	 * The buffer used to hold the transcription is statically
	 * allocated.
	 */
	const char * ( * ntoa ) ( const void *ll_addr );
	/**
	 * Hash multicast address
	 *
	 * @v af		Address family
	 * @v net_addr		Network-layer address
	 * @v ll_addr		Link-layer address to fill in
	 * @ret rc		Return status code
	 */
	int ( * mc_hash ) ( unsigned int af, const void *net_addr,
			    void *ll_addr );
	/**
	 * Generate Ethernet-compatible compressed link-layer address
	 *
	 * @v ll_addr		Link-layer address
	 * @v eth_addr		Ethernet-compatible address to fill in
	 * @ret rc		Return status code
	 */
	int ( * eth_addr ) ( const void *ll_addr, void *eth_addr );
	/**
	 * Generate EUI-64 address
	 *
	 * @v ll_addr		Link-layer address
	 * @v eui64		EUI-64 address to fill in
	 * @ret rc		Return status code
	 */
	int ( * eui64 ) ( const void *ll_addr, void *eui64 );
	/** Link-layer protocol
	 *
	 * This is an ARPHRD_XXX constant, in network byte order.
	 */
	uint16_t ll_proto;
	/** Hardware address length */
	uint8_t hw_addr_len;
	/** Link-layer address length */
	uint8_t ll_addr_len;
	/** Link-layer header length */
	uint8_t ll_header_len;
	/** Flags */
	unsigned int flags;
};

/** Local link-layer address functions only as a name
 *
 * This flag indicates that the local link-layer address cannot
 * directly be used as a destination address by a remote node.
 */
#define LL_NAME_ONLY 0x0001

/** Network device operations */
struct net_device_operations {
	/** Open network device
	 *
	 * @v netdev	Network device
	 * @ret rc	Return status code
	 *
	 * This method should allocate RX I/O buffers and enable
	 * the hardware to start transmitting and receiving packets.
	 */
	int ( * open ) ( struct net_device *netdev );
	/** Close network device
	 *
	 * @v netdev	Network device
	 *
	 * This method should stop the flow of packets, and free up
	 * any packets that are currently in the device's TX queue.
	 */
	void ( * close ) ( struct net_device *netdev );
	/** Transmit packet
	 *
	 * @v netdev	Network device
	 * @v iobuf	I/O buffer
	 * @ret rc	Return status code
	 *
	 * This method should cause the hardware to initiate
	 * transmission of the I/O buffer.
	 *
	 * If this method returns success, the I/O buffer remains
	 * owned by the net device's TX queue, and the net device must
	 * eventually call netdev_tx_complete() to free the buffer.
	 * If this method returns failure, the I/O buffer is
	 * immediately released; the failure is interpreted as
	 * "failure to enqueue buffer".
	 *
	 * This method is guaranteed to be called only when the device
	 * is open.
	 */
	int ( * transmit ) ( struct net_device *netdev,
			     struct io_buffer *iobuf );
	/** Poll for completed and received packets
	 *
	 * @v netdev	Network device
	 *
	 * This method should cause the hardware to check for
	 * completed transmissions and received packets.  Any received
	 * packets should be delivered via netdev_rx().
	 *
	 * This method is guaranteed to be called only when the device
	 * is open.
	 */
	void ( * poll ) ( struct net_device *netdev );
	/** Enable or disable interrupts
	 *
	 * @v netdev	Network device
	 * @v enable	Interrupts should be enabled
	 *
	 * This method may be NULL to indicate that interrupts are not
	 * supported.
	 */
	void ( * irq ) ( struct net_device *netdev, int enable );
};

/** Network device error */
struct net_device_error {
	/** Error status code */
	int rc;
	/** Error count */
	unsigned int count;
};

/** Maximum number of unique errors that we will keep track of */
#define NETDEV_MAX_UNIQUE_ERRORS 4

/** Network device statistics */
struct net_device_stats {
	/** Count of successful completions */
	unsigned int good;
	/** Count of error completions */
	unsigned int bad;
	/** Error breakdowns */
	struct net_device_error errors[NETDEV_MAX_UNIQUE_ERRORS];
};

/** A network device configuration */
struct net_device_configuration {
	/** Network device */
	struct net_device *netdev;
	/** Network device configurator */
	struct net_device_configurator *configurator;
	/** Configuration status */
	int rc;
	/** Job control interface */
	struct interface job;
};

/** A network device configurator */
struct net_device_configurator {
	/** Name */
	const char *name;
	/** Check applicability of configurator
	 *
	 * @v netdev		Network device
	 * @ret applies		Configurator applies to this network device
	 */
	int ( * applies ) ( struct net_device *netdev );
	/** Start configuring network device
	 *
	 * @v job		Job control interface
	 * @v netdev		Network device
	 * @ret rc		Return status code
	 */
	int ( * start ) ( struct interface *job, struct net_device *netdev );
};

/** Network device configurator table */
#define NET_DEVICE_CONFIGURATORS \
	__table ( struct net_device_configurator, "net_device_configurators" )

/** Declare a network device configurator */
#define __net_device_configurator \
	__table_entry ( NET_DEVICE_CONFIGURATORS, 01 )

/** Maximum length of a network device name */
#define NETDEV_NAME_LEN 12

/**
 * A network device
 *
 * This structure represents a piece of networking hardware.  It has
 * properties such as a link-layer address and methods for
 * transmitting and receiving raw packets.
 *
 * Note that this structure must represent a generic network device,
 * not just an Ethernet device.
 */
struct net_device {
	/** Reference counter */
	struct refcnt refcnt;
	/** List of network devices */
	struct list_head list;
	/** List of open network devices */
	struct list_head open_list;
	/** Index of this network device */
	unsigned int index;
	/** Name of this network device */
	char name[NETDEV_NAME_LEN];
	/** Underlying hardware device */
	struct device *dev;

	/** Network device operations */
	struct net_device_operations *op;

	/** Link-layer protocol */
	struct ll_protocol *ll_protocol;
	/** Hardware address
	 *
	 * This is an address which is an intrinsic property of the
	 * hardware, e.g. an address held in EEPROM.
	 *
	 * Note that the hardware address may not be the same length
	 * as the link-layer address.
	 */
	uint8_t hw_addr[MAX_HW_ADDR_LEN];
	/** Link-layer address
	 *
	 * This is the current link-layer address assigned to the
	 * device.  It can be changed at runtime.
	 */
	uint8_t ll_addr[MAX_LL_ADDR_LEN];
	/** Link-layer broadcast address */
	const uint8_t *ll_broadcast;

	/** Current device state
	 *
	 * This is the bitwise-OR of zero or more NETDEV_XXX constants.
	 */
	unsigned int state;
	/** Link status code
	 *
	 * Zero indicates that the link is up; any other value
	 * indicates the error preventing link-up.
	 */
	int link_rc;
	/** Link block timer */
	struct retry_timer link_block;
	/** Maximum packet length
	 *
	 * This length includes any link-layer headers.
	 */
	size_t max_pkt_len;
	/** TX packet queue */
	struct list_head tx_queue;
	/** Deferred TX packet queue */
	struct list_head tx_deferred;
	/** RX packet queue */
	struct list_head rx_queue;
	/** TX statistics */
	struct net_device_stats tx_stats;
	/** RX statistics */
	struct net_device_stats rx_stats;

	/** Configuration settings applicable to this device */
	struct generic_settings settings;

	/** Driver private data */
	void *priv;

	/** Network device configurations (variable length) */
	struct net_device_configuration configs[0];
};

/** Network device is open */
#define NETDEV_OPEN 0x0001

/** Network device interrupts are enabled */
#define NETDEV_IRQ_ENABLED 0x0002

/** Network device receive queue processing is frozen */
#define NETDEV_RX_FROZEN 0x0004

/** Network device interrupts are unsupported
 *
 * This flag can be used by a network device to indicate that
 * interrupts are not supported despite the presence of an irq()
 * method.
 */
#define NETDEV_IRQ_UNSUPPORTED 0x0008

/** Link-layer protocol table */
#define LL_PROTOCOLS __table ( struct ll_protocol, "ll_protocols" )

/** Declare a link-layer protocol */
#define __ll_protocol  __table_entry ( LL_PROTOCOLS, 01 )

/** Network-layer protocol table */
#define NET_PROTOCOLS __table ( struct net_protocol, "net_protocols" )

/** Declare a network-layer protocol */
#define __net_protocol __table_entry ( NET_PROTOCOLS, 01 )

/** A network upper-layer driver */
struct net_driver {
	/** Name */
	const char *name;
	/** Probe device
	 *
	 * @v netdev		Network device
	 * @ret rc		Return status code
	 */
	int ( * probe ) ( struct net_device *netdev );
	/** Notify of device or link state change
	 *
	 * @v netdev		Network device
	 */
	void ( * notify ) ( struct net_device *netdev );
	/** Remove device
	 *
	 * @v netdev		Network device
	 */
	void ( * remove ) ( struct net_device *netdev );
};

/** Network driver table */
#define NET_DRIVERS __table ( struct net_driver, "net_drivers" )

/** Declare a network driver */
#define __net_driver __table_entry ( NET_DRIVERS, 01 )

extern struct list_head net_devices;
extern struct net_device_operations null_netdev_operations;
extern struct settings_operations netdev_settings_operations;

/**
 * Initialise a network device
 *
 * @v netdev		Network device
 * @v op		Network device operations
 */
static inline void netdev_init ( struct net_device *netdev,
				 struct net_device_operations *op ) {
	netdev->op = op;
}

/**
 * Stop using a network device
 *
 * @v netdev		Network device
 *
 * Drivers should call this method immediately before the final call
 * to netdev_put().
 */
static inline void netdev_nullify ( struct net_device *netdev ) {
	netdev->op = &null_netdev_operations;
}

/**
 * Get printable network device link-layer address
 *
 * @v netdev		Network device
 * @ret name		Link-layer address
 */
static inline const char * netdev_addr ( struct net_device *netdev ) {
	return netdev->ll_protocol->ntoa ( netdev->ll_addr );
}

/** Iterate over all network devices */
#define for_each_netdev( netdev ) \
	list_for_each_entry ( (netdev), &net_devices, list )

/** There exist some network devices
 *
 * @ret existence	Existence of network devices
 */
static inline int have_netdevs ( void ) {
	return ( ! list_empty ( &net_devices ) );
}

/**
 * Get reference to network device
 *
 * @v netdev		Network device
 * @ret netdev		Network device
 */
static inline __attribute__ (( always_inline )) struct net_device *
netdev_get ( struct net_device *netdev ) {
	ref_get ( &netdev->refcnt );
	return netdev;
}

/**
 * Drop reference to network device
 *
 * @v netdev		Network device
 */
static inline __attribute__ (( always_inline )) void
netdev_put ( struct net_device *netdev ) {
	ref_put ( &netdev->refcnt );
}

/**
 * Get driver private area for this network device
 *
 * @v netdev		Network device
 * @ret priv		Driver private area for this network device
 */
static inline __attribute__ (( always_inline )) void *
netdev_priv ( struct net_device *netdev ) {
        return netdev->priv;
}

/**
 * Get per-netdevice configuration settings block
 *
 * @v netdev		Network device
 * @ret settings	Settings block
 */
static inline __attribute__ (( always_inline )) struct settings *
netdev_settings ( struct net_device *netdev ) {
	return &netdev->settings.settings;
}

/**
 * Initialise a per-netdevice configuration settings block
 *
 * @v generics		Generic settings block
 * @v refcnt		Containing object reference counter, or NULL
 * @v name		Settings block name
 */
static inline __attribute__ (( always_inline )) void
netdev_settings_init ( struct net_device *netdev ) {
	generic_settings_init ( &netdev->settings, &netdev->refcnt );
	netdev->settings.settings.op = &netdev_settings_operations;
}

/**
 * Get network device configuration
 *
 * @v netdev		Network device
 * @v configurator	Network device configurator
 * @ret config		Network device configuration
 */
static inline struct net_device_configuration *
netdev_configuration ( struct net_device *netdev,
		       struct net_device_configurator *configurator ) {

	return &netdev->configs[ table_index ( NET_DEVICE_CONFIGURATORS,
					       configurator ) ];
}

/**
 * Check if configurator applies to network device
 *
 * @v netdev		Network device
 * @v configurator	Network device configurator
 * @ret applies		Configurator applies to network device
 */
static inline int
netdev_configurator_applies ( struct net_device *netdev,
			      struct net_device_configurator *configurator ) {
	return ( ( configurator->applies == NULL ) ||
		 configurator->applies ( netdev ) );
}

/**
 * Check link state of network device
 *
 * @v netdev		Network device
 * @ret link_up		Link is up
 */
static inline __attribute__ (( always_inline )) int
netdev_link_ok ( struct net_device *netdev ) {
	return ( netdev->link_rc == 0 );
}

/**
 * Check link block state of network device
 *
 * @v netdev		Network device
 * @ret link_blocked	Link is blocked
 */
static inline __attribute__ (( always_inline )) int
netdev_link_blocked ( struct net_device *netdev ) {
	return ( timer_running ( &netdev->link_block ) );
}

/**
 * Check whether or not network device is open
 *
 * @v netdev		Network device
 * @ret is_open		Network device is open
 */
static inline __attribute__ (( always_inline )) int
netdev_is_open ( struct net_device *netdev ) {
	return ( netdev->state & NETDEV_OPEN );
}

/**
 * Check whether or not network device supports interrupts
 *
 * @v netdev		Network device
 * @ret irq_supported	Network device supports interrupts
 */
static inline __attribute__ (( always_inline )) int
netdev_irq_supported ( struct net_device *netdev ) {
	return ( ( netdev->op->irq != NULL ) &&
		 ! ( netdev->state & NETDEV_IRQ_UNSUPPORTED ) );
}

/**
 * Check whether or not network device interrupts are currently enabled
 *
 * @v netdev		Network device
 * @ret irq_enabled	Network device interrupts are enabled
 */
static inline __attribute__ (( always_inline )) int
netdev_irq_enabled ( struct net_device *netdev ) {
	return ( netdev->state & NETDEV_IRQ_ENABLED );
}

/**
 * Check whether or not network device receive queue processing is frozen
 *
 * @v netdev		Network device
 * @ret rx_frozen	Network device receive queue processing is frozen
 */
static inline __attribute__ (( always_inline )) int
netdev_rx_frozen ( struct net_device *netdev ) {
	return ( netdev->state & NETDEV_RX_FROZEN );
}

extern void netdev_rx_freeze ( struct net_device *netdev );
extern void netdev_rx_unfreeze ( struct net_device *netdev );
extern void netdev_link_err ( struct net_device *netdev, int rc );
extern void netdev_link_down ( struct net_device *netdev );
extern void netdev_link_block ( struct net_device *netdev,
				unsigned long timeout );
extern void netdev_link_unblock ( struct net_device *netdev );
extern int netdev_tx ( struct net_device *netdev, struct io_buffer *iobuf );
extern void netdev_tx_defer ( struct net_device *netdev,
			      struct io_buffer *iobuf );
extern void netdev_tx_err ( struct net_device *netdev,
			    struct io_buffer *iobuf, int rc );
extern void netdev_tx_complete_err ( struct net_device *netdev,
				 struct io_buffer *iobuf, int rc );
extern void netdev_tx_complete_next_err ( struct net_device *netdev, int rc );
extern void netdev_rx ( struct net_device *netdev, struct io_buffer *iobuf );
extern void netdev_rx_err ( struct net_device *netdev,
			    struct io_buffer *iobuf, int rc );
extern void netdev_poll ( struct net_device *netdev );
extern struct io_buffer * netdev_rx_dequeue ( struct net_device *netdev );
extern struct net_device * alloc_netdev ( size_t priv_size );
extern int register_netdev ( struct net_device *netdev );
extern int netdev_open ( struct net_device *netdev );
extern void netdev_close ( struct net_device *netdev );
extern void unregister_netdev ( struct net_device *netdev );
extern void netdev_irq ( struct net_device *netdev, int enable );
extern struct net_device * find_netdev ( const char *name );
extern struct net_device * find_netdev_by_index ( unsigned int index );
extern struct net_device * find_netdev_by_location ( unsigned int bus_type,
						     unsigned int location );
extern struct net_device *
find_netdev_by_ll_addr ( struct ll_protocol *ll_protocol, const void *ll_addr );
extern struct net_device * last_opened_netdev ( void );
extern int net_tx ( struct io_buffer *iobuf, struct net_device *netdev,
		    struct net_protocol *net_protocol, const void *ll_dest,
		    const void *ll_source );
extern int net_rx ( struct io_buffer *iobuf, struct net_device *netdev,
		    uint16_t net_proto, const void *ll_dest,
		    const void *ll_source, unsigned int flags );
extern void net_poll ( void );
extern struct net_device_configurator *
find_netdev_configurator ( const char *name );
extern int netdev_configure ( struct net_device *netdev,
			      struct net_device_configurator *configurator );
extern int netdev_configure_all ( struct net_device *netdev );
extern int netdev_configuration_in_progress ( struct net_device *netdev );
extern int netdev_configuration_ok ( struct net_device *netdev );

/**
 * Complete network transmission
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 *
 * The packet must currently be in the network device's TX queue.
 */
static inline void netdev_tx_complete ( struct net_device *netdev,
					struct io_buffer *iobuf ) {
	netdev_tx_complete_err ( netdev, iobuf, 0 );
}

/**
 * Complete network transmission
 *
 * @v netdev		Network device
 *
 * Completes the oldest outstanding packet in the TX queue.
 */
static inline void netdev_tx_complete_next ( struct net_device *netdev ) {
	netdev_tx_complete_next_err ( netdev, 0 );
}

/**
 * Mark network device as having link up
 *
 * @v netdev		Network device
 */
static inline __attribute__ (( always_inline )) void
netdev_link_up ( struct net_device *netdev ) {
	netdev_link_err ( netdev, 0 );
}

#endif /* _IPXE_NETDEVICE_H */
