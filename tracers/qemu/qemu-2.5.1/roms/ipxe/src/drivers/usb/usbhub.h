#ifndef _USBHUB_H
#define _USBHUB_H

/** @file
 *
 * USB hubs
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/usb.h>
#include <ipxe/list.h>
#include <ipxe/process.h>

/** Request recipient is a port */
#define USB_HUB_RECIP_PORT ( 3 << 0 )

/** A basic USB hub descriptor */
struct usb_hub_descriptor_basic {
	/** Descriptor header */
	struct usb_descriptor_header header;
	/** Number of ports */
	uint8_t ports;
	/** Characteristics */
	uint16_t characteristics;
	/** Power-on delay (in 2ms intervals */
	uint8_t delay;
	/** Controller current (in mA) */
	uint8_t current;
} __attribute__ (( packed ));

/** A basic USB hub descriptor */
#define USB_HUB_DESCRIPTOR 41

/** An enhanced USB hub descriptor */
struct usb_hub_descriptor_enhanced {
	/** Basic USB hub descriptor */
	struct usb_hub_descriptor_basic basic;
	/** Header decode latency */
	uint8_t latency;
	/** Maximum delay */
	uint16_t delay;
	/** Removable device bitmask */
	uint16_t removable;
} __attribute__ (( packed ));

/** An enhanced USB hub descriptor */
#define USB_HUB_DESCRIPTOR_ENHANCED 42

/** A USB hub descriptor */
union usb_hub_descriptor {
	/** Descriptor header */
	struct usb_descriptor_header header;
	/** Basic hub descriptor */
	struct usb_hub_descriptor_basic basic;
	/** Enhanced hub descriptor */
	struct usb_hub_descriptor_enhanced enhanced;
} __attribute__ (( packed ));

/** Port status */
struct usb_hub_port_status {
	/** Current status */
	uint16_t current;
	/** Changed status */
	uint16_t changed;
} __attribute__ (( packed ));

/** Current connect status feature */
#define USB_HUB_PORT_CONNECTION 0

/** Port enabled/disabled feature */
#define USB_HUB_PORT_ENABLE 1

/** Port reset feature */
#define USB_HUB_PORT_RESET 4

/** Port power feature */
#define USB_HUB_PORT_POWER 8

/** Low-speed device attached */
#define USB_HUB_PORT_LOW_SPEED 9

/** High-speed device attached */
#define USB_HUB_PORT_HIGH_SPEED 10

/** Connect status changed */
#define USB_HUB_C_PORT_CONNECTION 16

/** Port enable/disable changed */
#define	USB_HUB_C_PORT_ENABLE 17

/** Suspend changed */
#define USB_HUB_C_PORT_SUSPEND 18

/** Over-current indicator changed */
#define USB_HUB_C_PORT_OVER_CURRENT 19

/** Reset changed */
#define USB_HUB_C_PORT_RESET 20

/** Link state changed */
#define USB_HUB_C_PORT_LINK_STATE 25

/** Configuration error */
#define USB_HUB_C_PORT_CONFIG_ERROR 26

/** Calculate feature from change bit number */
#define USB_HUB_C_FEATURE( bit ) ( 16 + (bit) )

/** USB features */
#define USB_HUB_FEATURES						\
	( ( 1 << USB_HUB_C_PORT_CONNECTION ) |				\
	  ( 1 << USB_HUB_C_PORT_ENABLE ) |				\
	  ( 1 << USB_HUB_C_PORT_SUSPEND ) |				\
	  ( 1 << USB_HUB_C_PORT_OVER_CURRENT ) |			\
	  ( 1 << USB_HUB_C_PORT_RESET ) )

/** USB features for enhanced hubs */
#define USB_HUB_FEATURES_ENHANCED					\
	( ( 1 << USB_HUB_C_PORT_CONNECTION ) |				\
	  ( 1 << USB_HUB_C_PORT_OVER_CURRENT ) |			\
	  ( 1 << USB_HUB_C_PORT_RESET ) |				\
	  ( 1 << USB_HUB_C_PORT_LINK_STATE ) |				\
	  ( 1 << USB_HUB_C_PORT_CONFIG_ERROR ) )

/** Set hub depth */
#define USB_HUB_SET_HUB_DEPTH						\
	( USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_DEVICE |		\
	  USB_REQUEST_TYPE ( 12 ) )

/** Clear transaction translator buffer */
#define USB_HUB_CLEAR_TT_BUFFER						\
	( USB_DIR_OUT | USB_TYPE_CLASS | USB_HUB_RECIP_PORT |		\
	  USB_REQUEST_TYPE ( 8 ) )

/**
 * Get hub descriptor
 *
 * @v usb		USB device
 * @v enhanced		Hub is an enhanced hub
 * @v data		Hub descriptor to fill in
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_hub_get_descriptor ( struct usb_device *usb, int enhanced,
			 union usb_hub_descriptor *data ) {
	unsigned int desc;
	size_t len;

	/* Determine descriptor type and length */
	desc = ( enhanced ? USB_HUB_DESCRIPTOR_ENHANCED : USB_HUB_DESCRIPTOR );
	len = ( enhanced ? sizeof ( data->enhanced ) : sizeof ( data->basic ) );

	return usb_get_descriptor ( usb, USB_TYPE_CLASS, desc, 0, 0,
				    &data->header, len );
}

/**
 * Get port status
 *
 * @v usb		USB device
 * @v port		Port address
 * @v status		Port status descriptor to fill in
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_hub_get_port_status ( struct usb_device *usb, unsigned int port,
			  struct usb_hub_port_status *status ) {

	return usb_get_status ( usb, ( USB_TYPE_CLASS | USB_HUB_RECIP_PORT ),
				port, status, sizeof ( *status ) );
}

/**
 * Clear port feature
 *
 * @v usb		USB device
 * @v port		Port address
 * @v feature		Feature to clear
 * @v index		Index (when clearing a port indicator)
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_hub_clear_port_feature ( struct usb_device *usb, unsigned int port,
			     unsigned int feature, unsigned int index ) {

	return usb_clear_feature ( usb, ( USB_TYPE_CLASS | USB_HUB_RECIP_PORT ),
				   feature, ( ( index << 8 ) | port ) );
}

/**
 * Set port feature
 *
 * @v usb		USB device
 * @v port		Port address
 * @v feature		Feature to clear
 * @v index		Index (when clearing a port indicator)
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_hub_set_port_feature ( struct usb_device *usb, unsigned int port,
			   unsigned int feature, unsigned int index ) {

	return usb_set_feature ( usb, ( USB_TYPE_CLASS | USB_HUB_RECIP_PORT ),
				 feature, ( ( index << 8 ) | port ) );
}

/**
 * Set hub depth
 *
 * @v usb		USB device
 * @v depth		Hub depth
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_hub_set_hub_depth ( struct usb_device *usb, unsigned int depth ) {

	return usb_control ( usb, USB_HUB_SET_HUB_DEPTH, depth, 0, NULL, 0 );
}

/**
 * Clear transaction translator buffer
 *
 * @v usb		USB device
 * @v device		Device address
 * @v endpoint		Endpoint address
 * @v attributes	Endpoint attributes
 * @v tt_port		Transaction translator port (or 1 for single-TT hubs)
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_hub_clear_tt_buffer ( struct usb_device *usb, unsigned int device,
			  unsigned int endpoint, unsigned int attributes,
			  unsigned int tt_port ) {
	unsigned int value;

	/* Calculate value */
	value = ( ( ( endpoint & USB_ENDPOINT_MAX ) << 0 ) | ( device << 4 ) |
		  ( ( attributes & USB_ENDPOINT_ATTR_TYPE_MASK ) << 11 ) |
		  ( ( endpoint & USB_ENDPOINT_IN ) << 8 ) );

	return usb_control ( usb, USB_HUB_CLEAR_TT_BUFFER, value,
			     tt_port, NULL, 0 );
}

/** Transaction translator port value for single-TT hubs */
#define USB_HUB_TT_SINGLE 1

/** A USB hub device */
struct usb_hub_device {
	/** Name */
	const char *name;
	/** USB device */
	struct usb_device *usb;
	/** USB hub */
	struct usb_hub *hub;
	/** Features */
	unsigned int features;

	/** Interrupt endpoint */
	struct usb_endpoint intr;
	/** Interrupt endpoint refill process */
	struct process refill;
};

/** Interrupt ring fill level
 *
 * This is a policy decision.
 */
#define USB_HUB_INTR_FILL 4

/** Maximum time to wait for port to become enabled
 *
 * This is a policy decision.
 */
#define USB_HUB_ENABLE_MAX_WAIT_MS 100

#endif /* _USBHUB_H */
