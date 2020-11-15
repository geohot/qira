#ifndef _ECM_H
#define _ECM_H

/** @file
 *
 * CDC-ECM USB Ethernet driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/usb.h>
#include <ipxe/usbnet.h>
#include <ipxe/cdc.h>

/** CDC-ECM subclass */
#define USB_SUBCLASS_CDC_ECM 0x06

/** Set Ethernet packet filter */
#define ECM_SET_ETHERNET_PACKET_FILTER					\
	( USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE |		\
	  USB_REQUEST_TYPE ( 0x43 ) )

/** Ethernet packet types */
enum ecm_ethernet_packet_filter {
	/** Promiscuous mode */
	ECM_PACKET_TYPE_PROMISCUOUS = 0x0001,
	/** All multicast packets */
	ECM_PACKET_TYPE_ALL_MULTICAST = 0x0002,
	/** Unicast packets */
	ECM_PACKET_TYPE_DIRECTED = 0x0004,
	/** Broadcast packets */
	ECM_PACKET_TYPE_BROADCAST = 0x0008,
	/** Specified multicast packets */
	ECM_PACKET_TYPE_MULTICAST = 0x0010,
};

/** An Ethernet Functional Descriptor */
struct ecm_ethernet_descriptor {
	/** Descriptor header */
	struct usb_descriptor_header header;
	/** Descriptor subtype */
	uint8_t subtype;
	/** MAC address string */
	uint8_t mac;
	/** Ethernet statistics bitmap */
	uint32_t statistics;
	/** Maximum segment size */
	uint16_t mtu;
	/** Multicast filter configuration */
	uint16_t mcast;
	/** Number of wake-on-LAN filters */
	uint8_t wol;
} __attribute__ (( packed ));

/** A CDC-ECM network device */
struct ecm_device {
	/** USB device */
	struct usb_device *usb;
	/** USB bus */
	struct usb_bus *bus;
	/** Network device */
	struct net_device *netdev;
	/** USB network device */
	struct usbnet_device usbnet;
};

/** Interrupt maximum fill level
 *
 * This is a policy decision.
 */
#define ECM_INTR_MAX_FILL 2

/** Bulk IN maximum fill level
 *
 * This is a policy decision.
 */
#define ECM_IN_MAX_FILL 8

/** Bulk IN buffer size
 *
 * This is a policy decision.
 */
#define ECM_IN_MTU ( ETH_FRAME_LEN + 4 /* possible VLAN header */ )

extern struct ecm_ethernet_descriptor *
ecm_ethernet_descriptor ( struct usb_configuration_descriptor *config,
			  struct usb_interface_descriptor *interface );
extern int ecm_fetch_mac ( struct usb_device *usb,
			   struct ecm_ethernet_descriptor *desc,
			   uint8_t *hw_addr );

#endif /* _ECM_H */
