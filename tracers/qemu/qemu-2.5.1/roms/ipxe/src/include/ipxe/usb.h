#ifndef _IPXE_USB_H
#define _IPXE_USB_H

/** @file
 *
 * Universal Serial Bus (USB)
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <byteswap.h>
#include <ipxe/list.h>
#include <ipxe/device.h>
#include <ipxe/process.h>
#include <ipxe/iobuf.h>
#include <ipxe/tables.h>

/** USB protocols */
enum usb_protocol {
	/** USB 2.0 */
	USB_PROTO_2_0 = 0x0200,
	/** USB 3.0 */
	USB_PROTO_3_0 = 0x0300,
	/** USB 3.1 */
	USB_PROTO_3_1 = 0x0301,
};

/** Define a USB speed
 *
 * @v mantissa		Mantissa
 * @v exponent		Exponent (in engineering terms: 1=k, 2=M, 3=G)
 * @ret speed		USB speed
 */
#define USB_SPEED( mantissa, exponent ) ( (exponent << 16) | (mantissa) )

/** Extract USB speed mantissa */
#define USB_SPEED_MANTISSA(speed) ( (speed) & 0xffff )

/** Extract USB speed exponent */
#define USB_SPEED_EXPONENT(speed) ( ( (speed) >> 16 ) & 0x3 )

/** USB device speeds */
enum usb_speed {
	/** Not connected */
	USB_SPEED_NONE = 0,
	/** Low speed (1.5Mbps) */
	USB_SPEED_LOW = USB_SPEED ( 1500, 1 ),
	/** Full speed (12Mbps) */
	USB_SPEED_FULL = USB_SPEED ( 12, 2 ),
	/** High speed (480Mbps) */
	USB_SPEED_HIGH = USB_SPEED ( 480, 2 ),
	/** Super speed (5Gbps) */
	USB_SPEED_SUPER = USB_SPEED ( 5, 3 ),
};

/** USB packet IDs */
enum usb_pid {
	/** IN PID */
	USB_PID_IN = 0x69,
	/** OUT PID */
	USB_PID_OUT = 0xe1,
	/** SETUP PID */
	USB_PID_SETUP = 0x2d,
};

/** A USB setup data packet */
struct usb_setup_packet {
	/** Request */
	uint16_t request;
	/** Value paramer */
	uint16_t value;
	/** Index parameter */
	uint16_t index;
	/** Length of data stage */
	uint16_t len;
} __attribute__ (( packed ));

/** Data transfer is from host to device */
#define USB_DIR_OUT ( 0 << 7 )

/** Data transfer is from device to host */
#define USB_DIR_IN ( 1 << 7 )

/** Standard request type */
#define USB_TYPE_STANDARD ( 0 << 5 )

/** Class-specific request type */
#define USB_TYPE_CLASS ( 1 << 5 )

/** Vendor-specific request type */
#define USB_TYPE_VENDOR ( 2 << 5 )

/** Request recipient is the device */
#define USB_RECIP_DEVICE ( 0 << 0 )

/** Request recipient is an interface */
#define USB_RECIP_INTERFACE ( 1 << 0 )

/** Request recipient is an endpoint */
#define USB_RECIP_ENDPOINT ( 2 << 0 )

/** Construct USB request type */
#define USB_REQUEST_TYPE(type) ( (type) << 8 )

/** Get status */
#define USB_GET_STATUS ( USB_DIR_IN | USB_REQUEST_TYPE ( 0 ) )

/** Clear feature */
#define USB_CLEAR_FEATURE ( USB_DIR_OUT | USB_REQUEST_TYPE ( 1 ) )

/** Set feature */
#define USB_SET_FEATURE ( USB_DIR_OUT | USB_REQUEST_TYPE ( 3 ) )

/** Set address */
#define USB_SET_ADDRESS ( USB_DIR_OUT | USB_REQUEST_TYPE ( 5 ) )

/** Get descriptor */
#define USB_GET_DESCRIPTOR ( USB_DIR_IN | USB_REQUEST_TYPE ( 6 ) )

/** Set descriptor */
#define USB_SET_DESCRIPTOR ( USB_DIR_OUT | USB_REQUEST_TYPE ( 7 ) )

/** Get configuration */
#define USB_GET_CONFIGURATION ( USB_DIR_IN | USB_REQUEST_TYPE ( 8 ) )

/** Set configuration */
#define USB_SET_CONFIGURATION ( USB_DIR_OUT | USB_REQUEST_TYPE ( 9 ) )

/** Get interface */
#define USB_GET_INTERFACE \
	( USB_DIR_IN | USB_RECIP_INTERFACE | USB_REQUEST_TYPE ( 10 ) )

/** Set interface */
#define USB_SET_INTERFACE \
	( USB_DIR_OUT | USB_RECIP_INTERFACE | USB_REQUEST_TYPE ( 11 ) )

/** Endpoint halt feature */
#define USB_ENDPOINT_HALT 0

/** A USB class code tuple */
struct usb_class {
	/** Class code */
	uint8_t class;
	/** Subclass code */
	uint8_t subclass;
	/** Protocol code */
	uint8_t protocol;
} __attribute__ (( packed ));

/** Class code for USB hubs */
#define USB_CLASS_HUB 9

/** A USB descriptor header */
struct usb_descriptor_header {
	/** Length of descriptor */
	uint8_t len;
	/** Descriptor type */
	uint8_t type;
} __attribute__ (( packed ));

/** A USB device descriptor */
struct usb_device_descriptor {
	/** Descriptor header */
	struct usb_descriptor_header header;
	/** USB specification release number in BCD */
	uint16_t protocol;
	/** Device class */
	struct usb_class class;
	/** Maximum packet size for endpoint zero */
	uint8_t mtu;
	/** Vendor ID */
	uint16_t vendor;
	/** Product ID */
	uint16_t product;
	/** Device release number in BCD */
	uint16_t release;
	/** Manufacturer string */
	uint8_t manufacturer;
	/** Product string */
	uint8_t name;
	/** Serial number string */
	uint8_t serial;
	/** Number of possible configurations */
	uint8_t configurations;
} __attribute__ (( packed ));

/** A USB device descriptor */
#define USB_DEVICE_DESCRIPTOR 1

/** A USB configuration descriptor */
struct usb_configuration_descriptor {
	/** Descriptor header */
	struct usb_descriptor_header header;
	/** Total length */
	uint16_t len;
	/** Number of interfaces */
	uint8_t interfaces;
	/** Configuration value */
	uint8_t config;
	/** Configuration string */
	uint8_t name;
	/** Attributes */
	uint8_t attributes;
	/** Maximum power consumption */
	uint8_t power;
} __attribute__ (( packed ));

/** A USB configuration descriptor */
#define USB_CONFIGURATION_DESCRIPTOR 2

/** A USB string descriptor */
struct usb_string_descriptor {
	/** Descriptor header */
	struct usb_descriptor_header header;
	/** String */
	char string[0];
} __attribute__ (( packed ));

/** A USB string descriptor */
#define USB_STRING_DESCRIPTOR 3

/** A USB interface descriptor */
struct usb_interface_descriptor {
	/** Descriptor header */
	struct usb_descriptor_header header;
	/** Interface number */
	uint8_t interface;
	/** Alternate setting */
	uint8_t alternate;
	/** Number of endpoints */
	uint8_t endpoints;
	/** Interface class */
	struct usb_class class;
	/** Interface name */
	uint8_t name;
} __attribute__ (( packed ));

/** A USB interface descriptor */
#define USB_INTERFACE_DESCRIPTOR 4

/** A USB endpoint descriptor */
struct usb_endpoint_descriptor {
	/** Descriptor header */
	struct usb_descriptor_header header;
	/** Endpoint address */
	uint8_t endpoint;
	/** Attributes */
	uint8_t attributes;
	/** Maximum packet size and burst size */
	uint16_t sizes;
	/** Polling interval */
	uint8_t interval;
} __attribute__ (( packed ));

/** A USB endpoint descriptor */
#define USB_ENDPOINT_DESCRIPTOR 5

/** Endpoint attribute transfer type mask */
#define USB_ENDPOINT_ATTR_TYPE_MASK 0x03

/** Endpoint periodic type */
#define USB_ENDPOINT_ATTR_PERIODIC 0x01

/** Control endpoint transfer type */
#define USB_ENDPOINT_ATTR_CONTROL 0x00

/** Bulk endpoint transfer type */
#define USB_ENDPOINT_ATTR_BULK 0x02

/** Interrupt endpoint transfer type */
#define USB_ENDPOINT_ATTR_INTERRUPT 0x03

/** Bulk OUT endpoint (internal) type */
#define USB_BULK_OUT ( USB_ENDPOINT_ATTR_BULK | USB_DIR_OUT )

/** Bulk IN endpoint (internal) type */
#define USB_BULK_IN ( USB_ENDPOINT_ATTR_BULK | USB_DIR_IN )

/** Interrupt IN endpoint (internal) type */
#define USB_INTERRUPT_IN ( USB_ENDPOINT_ATTR_INTERRUPT | USB_DIR_IN )

/** Interrupt OUT endpoint (internal) type */
#define USB_INTERRUPT_OUT ( USB_ENDPOINT_ATTR_INTERRUPT | USB_DIR_OUT )

/** USB endpoint MTU */
#define USB_ENDPOINT_MTU(sizes) ( ( (sizes) >> 0 ) & 0x07ff )

/** USB endpoint maximum burst size */
#define USB_ENDPOINT_BURST(sizes) ( ( (sizes) >> 11 ) & 0x0003 )

/** A USB endpoint companion descriptor */
struct usb_endpoint_companion_descriptor {
	/** Descriptor header */
	struct usb_descriptor_header header;
	/** Maximum burst size */
	uint8_t burst;
	/** Extended attributes */
	uint8_t extended;
	/** Number of bytes per service interval */
	uint16_t periodic;
} __attribute__ (( packed ));

/** A USB endpoint companion descriptor */
#define USB_ENDPOINT_COMPANION_DESCRIPTOR 48

/** A USB interface association descriptor */
struct usb_interface_association_descriptor {
	/** Descriptor header */
	struct usb_descriptor_header header;
	/** First interface number */
	uint8_t first;
	/** Interface count */
	uint8_t count;
	/** Association class */
	struct usb_class class;
	/** Association name */
	uint8_t name;
} __attribute__ (( packed ));

/** A USB interface association descriptor */
#define USB_INTERFACE_ASSOCIATION_DESCRIPTOR 11

/** A class-specific interface descriptor */
#define USB_CS_INTERFACE_DESCRIPTOR 36

/** A class-specific endpoint descriptor */
#define USB_CS_ENDPOINT_DESCRIPTOR 37

/**
 * Get next USB descriptor
 *
 * @v desc		USB descriptor header
 * @ret next		Next USB descriptor header
 */
static inline __attribute__ (( always_inline )) struct usb_descriptor_header *
usb_next_descriptor ( struct usb_descriptor_header *desc ) {

	return ( ( ( void * ) desc ) + desc->len );
}

/**
 * Check that descriptor lies within a configuration descriptor
 *
 * @v config		Configuration descriptor
 * @v desc		Descriptor header
 * @v is_within		Descriptor is within the configuration descriptor
 */
static inline __attribute__ (( always_inline )) int
usb_is_within_config ( struct usb_configuration_descriptor *config,
		       struct usb_descriptor_header *desc ) {
	struct usb_descriptor_header *end =
		( ( ( void * ) config ) + le16_to_cpu ( config->len ) );

	/* Check that descriptor starts within the configuration
	 * descriptor, and that the length does not exceed the
	 * configuration descriptor.  This relies on the fact that
	 * usb_next_descriptor() needs to access only the first byte
	 * of the descriptor in order to determine the length.
	 */
	return ( ( desc < end ) && ( usb_next_descriptor ( desc ) <= end ) );
}

/** Iterate over all configuration descriptors */
#define for_each_config_descriptor( desc, config )			   \
	for ( desc = container_of ( &(config)->header,			   \
				    typeof ( *desc ), header ) ;	   \
	      usb_is_within_config ( (config), &desc->header ) ;	   \
	      desc = container_of ( usb_next_descriptor ( &desc->header ), \
				    typeof ( *desc ), header ) )

/** Iterate over all configuration descriptors within an interface descriptor */
#define for_each_interface_descriptor( desc, config, interface )	   \
	for ( desc = container_of ( usb_next_descriptor ( &(interface)->   \
							  header ),	   \
				    typeof ( *desc ), header ) ;	   \
	      ( usb_is_within_config ( (config), &desc->header ) &&	   \
		( desc->header.type != USB_INTERFACE_DESCRIPTOR ) ) ;	   \
	      desc = container_of ( usb_next_descriptor ( &desc->header ), \
				    typeof ( *desc ), header ) )

/** A USB endpoint */
struct usb_endpoint {
	/** USB device */
	struct usb_device *usb;
	/** Endpoint address */
	unsigned int address;
	/** Attributes */
	unsigned int attributes;
	/** Maximum transfer size */
	size_t mtu;
	/** Maximum burst size */
	unsigned int burst;
	/** Interval (in microframes) */
	unsigned int interval;

	/** Endpoint is open */
	int open;
	/** Buffer fill level */
	unsigned int fill;

	/** List of halted endpoints */
	struct list_head halted;

	/** Host controller operations */
	struct usb_endpoint_host_operations *host;
	/** Host controller private data */
	void *priv;
	/** Driver operations */
	struct usb_endpoint_driver_operations *driver;

	/** Recycled I/O buffer list */
	struct list_head recycled;
	/** Refill buffer length */
	size_t len;
	/** Maximum fill level */
	unsigned int max;
};

/** USB endpoint host controller operations */
struct usb_endpoint_host_operations {
	/** Open endpoint
	 *
	 * @v ep		USB endpoint
	 * @ret rc		Return status code
	 */
	int ( * open ) ( struct usb_endpoint *ep );
	/** Close endpoint
	 *
	 * @v ep		USB endpoint
	 */
	void ( * close ) ( struct usb_endpoint *ep );
	/**
	 * Reset endpoint
	 *
	 * @v ep		USB endpoint
	 * @ret rc		Return status code
	 */
	int ( * reset ) ( struct usb_endpoint *ep );
	/** Update MTU
	 *
	 * @v ep		USB endpoint
	 * @ret rc		Return status code
	 */
	int ( * mtu ) ( struct usb_endpoint *ep );
	/** Enqueue message transfer
	 *
	 * @v ep		USB endpoint
	 * @v iobuf		I/O buffer
	 * @ret rc		Return status code
	 */
	int ( * message ) ( struct usb_endpoint *ep,
			    struct io_buffer *iobuf );
	/** Enqueue stream transfer
	 *
	 * @v ep		USB endpoint
	 * @v iobuf		I/O buffer
	 * @v terminate		Terminate using a short packet
	 * @ret rc		Return status code
	 */
	int ( * stream ) ( struct usb_endpoint *ep, struct io_buffer *iobuf,
			   int terminate );
};

/** USB endpoint driver operations */
struct usb_endpoint_driver_operations {
	/** Complete transfer
	 *
	 * @v ep		USB endpoint
	 * @v iobuf		I/O buffer
	 * @v rc		Completion status code
	 */
	void ( * complete ) ( struct usb_endpoint *ep,
			      struct io_buffer *iobuf, int rc );
};

/** Control endpoint address */
#define USB_EP0_ADDRESS 0x00

/** Control endpoint attributes */
#define USB_EP0_ATTRIBUTES 0x00

/** Calculate default MTU based on device speed
 *
 * @v speed		Device speed
 * @ret mtu		Default MTU
 */
#define USB_EP0_DEFAULT_MTU(speed)			\
	( ( (speed) >= USB_SPEED_SUPER ) ? 512 :	\
	  ( ( (speed) >= USB_SPEED_FULL ) ? 64 : 8 ) )

/** Control endpoint maximum burst size */
#define USB_EP0_BURST 0

/** Control endpoint interval */
#define USB_EP0_INTERVAL 0

/** Maximum endpoint number */
#define USB_ENDPOINT_MAX 0x0f

/** Endpoint direction is in */
#define USB_ENDPOINT_IN 0x80

/** Construct endpoint index from endpoint address */
#define USB_ENDPOINT_IDX(address)					\
	( ( (address) & USB_ENDPOINT_MAX ) |				\
	  ( ( (address) & USB_ENDPOINT_IN ) >> 3 ) )

/**
 * Initialise USB endpoint
 *
 * @v ep		USB endpoint
 * @v usb		USB device
 * @v driver		Driver operations
 */
static inline __attribute__ (( always_inline )) void
usb_endpoint_init ( struct usb_endpoint *ep, struct usb_device *usb,
		    struct usb_endpoint_driver_operations *driver ) {

	ep->usb = usb;
	ep->driver = driver;
}

/**
 * Describe USB endpoint
 *
 * @v ep		USB endpoint
 * @v address		Endpoint address
 * @v attributes	Attributes
 * @v mtu		Maximum packet size
 * @v burst		Maximum burst size
 * @v interval		Interval (in microframes)
 */
static inline __attribute__ (( always_inline )) void
usb_endpoint_describe ( struct usb_endpoint *ep, unsigned int address,
			unsigned int attributes, size_t mtu,
			unsigned int burst, unsigned int interval ) {

	ep->address = address;
	ep->attributes = attributes;
	ep->mtu = mtu;
	ep->burst = burst;
	ep->interval = interval;
}

/**
 * Set USB endpoint host controller private data
 *
 * @v ep		USB endpoint
 * @v priv		Host controller private data
 */
static inline __attribute__ (( always_inline )) void
usb_endpoint_set_hostdata ( struct usb_endpoint *ep, void *priv ) {
	ep->priv = priv;
}

/**
 * Get USB endpoint host controller private data
 *
 * @v ep		USB endpoint
 * @ret priv		Host controller private data
 */
static inline __attribute__ (( always_inline )) void *
usb_endpoint_get_hostdata ( struct usb_endpoint *ep ) {
	return ep->priv;
}

extern const char * usb_endpoint_name ( struct usb_endpoint *ep );
extern int
usb_endpoint_described ( struct usb_endpoint *ep,
			 struct usb_configuration_descriptor *config,
			 struct usb_interface_descriptor *interface,
			 unsigned int type, unsigned int index );
extern int usb_endpoint_open ( struct usb_endpoint *ep );
extern void usb_endpoint_close ( struct usb_endpoint *ep );
extern int usb_message ( struct usb_endpoint *ep, unsigned int request,
			 unsigned int value, unsigned int index,
			 struct io_buffer *iobuf );
extern int usb_stream ( struct usb_endpoint *ep, struct io_buffer *iobuf,
			int terminate );
extern void usb_complete_err ( struct usb_endpoint *ep,
			       struct io_buffer *iobuf, int rc );

/**
 * Initialise USB endpoint refill
 *
 * @v ep		USB endpoint
 * @v len		Refill buffer length (or zero to use endpoint's MTU)
 * @v max		Maximum fill level
 */
static inline __attribute__ (( always_inline )) void
usb_refill_init ( struct usb_endpoint *ep, size_t len, unsigned int max ) {

	INIT_LIST_HEAD ( &ep->recycled );
	ep->len = len;
	ep->max = max;
}

/**
 * Recycle I/O buffer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 */
static inline __attribute__ (( always_inline )) void
usb_recycle ( struct usb_endpoint *ep, struct io_buffer *iobuf ) {

	list_add_tail ( &iobuf->list, &ep->recycled );
}

extern int usb_prefill ( struct usb_endpoint *ep );
extern int usb_refill ( struct usb_endpoint *ep );
extern void usb_flush ( struct usb_endpoint *ep );

/**
 * A USB function
 *
 * A USB function represents an association of interfaces within a USB
 * device.
 */
struct usb_function {
	/** Name */
	const char *name;
	/** USB device */
	struct usb_device *usb;
	/** Class */
	struct usb_class class;
	/** Number of interfaces */
	unsigned int count;
	/** Generic device */
	struct device dev;
	/** List of functions within this USB device */
	struct list_head list;

	/** Driver */
	struct usb_driver *driver;
	/** Driver private data */
	void *priv;

	/** List of interface numbers
	 *
	 * This must be the last field within the structure.
	 */
	uint8_t interface[0];
};

/**
 * Set USB function driver private data
 *
 * @v func		USB function
 * @v priv		Driver private data
 */
static inline __attribute__ (( always_inline )) void
usb_func_set_drvdata ( struct usb_function *func, void *priv ) {
	func->priv = priv;
}

/**
 * Get USB function driver private data
 *
 * @v function		USB function
 * @ret priv		Driver private data
 */
static inline __attribute__ (( always_inline )) void *
usb_func_get_drvdata ( struct usb_function *func ) {
	return func->priv;
}

/** A USB device */
struct usb_device {
	/** Name */
	char name[32];
	/** USB port */
	struct usb_port *port;
	/** List of devices on this bus */
	struct list_head list;
	/** Device address, if assigned */
	unsigned int address;
	/** Device descriptor */
	struct usb_device_descriptor device;
	/** List of functions */
	struct list_head functions;

	/** Host controller operations */
	struct usb_device_host_operations *host;
	/** Host controller private data */
	void *priv;

	/** Endpoint list */
	struct usb_endpoint *ep[32];

	/** Control endpoint */
	struct usb_endpoint control;
	/** Completed control transfers */
	struct list_head complete;
};

/** USB device host controller operations */
struct usb_device_host_operations {
	/** Open device
	 *
	 * @v usb		USB device
	 * @ret rc		Return status code
	 */
	int ( * open ) ( struct usb_device *usb );
	/** Close device
	 *
	 * @v usb		USB device
	 */
	void ( * close ) ( struct usb_device *usb );
	/** Assign device address
	 *
	 * @v usb		USB device
	 * @ret rc		Return status code
	 */
	int ( * address ) ( struct usb_device *usb );
};

/**
 * Set USB device host controller private data
 *
 * @v usb		USB device
 * @v priv		Host controller private data
 */
static inline __attribute__ (( always_inline )) void
usb_set_hostdata ( struct usb_device *usb, void *priv ) {
	usb->priv = priv;
}

/**
 * Get USB device host controller private data
 *
 * @v usb		USB device
 * @ret priv		Host controller private data
 */
static inline __attribute__ (( always_inline )) void *
usb_get_hostdata ( struct usb_device *usb ) {
	return usb->priv;
}

/**
 * Get USB endpoint
 *
 * @v usb		USB device
 * @v address		Endpoint address
 * @ret ep		USB endpoint, or NULL if not opened
 */
static inline struct usb_endpoint * usb_endpoint ( struct usb_device *usb,
						   unsigned int address ) {

	return usb->ep[ USB_ENDPOINT_IDX ( address ) ];
}

/** A USB port */
struct usb_port {
	/** USB hub */
	struct usb_hub *hub;
	/** Port address */
	unsigned int address;
	/** Port protocol */
	unsigned int protocol;
	/** Port speed */
	unsigned int speed;
	/** Port disconnection has been detected
	 *
	 * This should be set whenever the underlying hardware reports
	 * a connection status change.
	 */
	int disconnected;
	/** Port has an attached device */
	int attached;
	/** Currently attached device (if in use)
	 *
	 * Note that this field will be NULL if the attached device
	 * has been freed (e.g. because there were no drivers found).
	 */
	struct usb_device *usb;
	/** List of changed ports */
	struct list_head changed;
};

/** A USB hub */
struct usb_hub {
	/** Name */
	const char *name;
	/** USB bus */
	struct usb_bus *bus;
	/** Underlying USB device, if any */
	struct usb_device *usb;
	/** Hub protocol */
	unsigned int protocol;
	/** Number of ports */
	unsigned int ports;

	/** List of hubs */
	struct list_head list;

	/** Host controller operations */
	struct usb_hub_host_operations *host;
	/** Driver operations */
	struct usb_hub_driver_operations *driver;
	/** Driver private data */
	void *priv;

	/** Port list
	 *
	 * This must be the last field within the structure.
	 */
	struct usb_port port[0];
};

/** USB hub host controller operations */
struct usb_hub_host_operations {
	/** Open hub
	 *
	 * @v hub		USB hub
	 * @ret rc		Return status code
	 */
	int ( * open ) ( struct usb_hub *hub );
	/** Close hub
	 *
	 * @v hub		USB hub
	 */
	void ( * close ) ( struct usb_hub *hub );
};

/** USB hub driver operations */
struct usb_hub_driver_operations {
	/** Open hub
	 *
	 * @v hub		USB hub
	 * @ret rc		Return status code
	 */
	int ( * open ) ( struct usb_hub *hub );
	/** Close hub
	 *
	 * @v hub		USB hub
	 */
	void ( * close ) ( struct usb_hub *hub );
	/** Enable port
	 *
	 * @v hub		USB hub
	 * @v port		USB port
	 * @ret rc		Return status code
	 */
	int ( * enable ) ( struct usb_hub *hub, struct usb_port *port );
	/** Disable port
	 *
	 * @v hub		USB hub
	 * @v port		USB port
	 * @ret rc		Return status code
	 */
	int ( * disable ) ( struct usb_hub *hub, struct usb_port *port );
	/** Update port speed
	 *
	 * @v hub		USB hub
	 * @v port		USB port
	 * @ret rc		Return status code
	 */
	int ( * speed ) ( struct usb_hub *hub, struct usb_port *port );
	/** Clear transaction translator buffer
	 *
	 * @v hub		USB hub
	 * @v port		USB port
	 * @v ep		USB endpoint
	 * @ret rc		Return status code
	 */
	int ( * clear_tt ) ( struct usb_hub *hub, struct usb_port *port,
			     struct usb_endpoint *ep );
};

/**
 * Set USB hub driver private data
 *
 * @v hub		USB hub
 * @v priv		Driver private data
 */
static inline __attribute__ (( always_inline )) void
usb_hub_set_drvdata ( struct usb_hub *hub, void *priv ) {
	hub->priv = priv;
}

/**
 * Get USB hub driver private data
 *
 * @v hub		USB hub
 * @ret priv		Driver private data
 */
static inline __attribute__ (( always_inline )) void *
usb_hub_get_drvdata ( struct usb_hub *hub ) {
	return hub->priv;
}

/**
 * Get USB port
 *
 * @v hub		USB hub
 * @v address		Port address
 * @ret port		USB port
 */
static inline __attribute__ (( always_inline )) struct usb_port *
usb_port ( struct usb_hub *hub, unsigned int address ) {

	return &hub->port[ address - 1 ];
}

/** A USB bus */
struct usb_bus {
	/** Name */
	const char *name;
	/** Underlying hardware device */
	struct device *dev;
	/** Host controller operations set */
	struct usb_host_operations *op;

	/** Largest transfer allowed on the bus */
	size_t mtu;
	/** Address in-use mask
	 *
	 * This is used only by buses which perform manual address
	 * assignment.  USB allows for addresses in the range [1,127].
	 * We use a simple bitmask which restricts us to the range
	 * [1,64]; this is unlikely to be a problem in practice.  For
	 * comparison: controllers which perform autonomous address
	 * assignment (such as xHCI) typically allow for only 32
	 * devices per bus anyway.
	 */
	unsigned long long addresses;

	/** Root hub */
	struct usb_hub *hub;

	/** List of USB buses */
	struct list_head list;
	/** List of devices */
	struct list_head devices;
	/** List of hubs */
	struct list_head hubs;

	/** Host controller operations */
	struct usb_bus_host_operations *host;
	/** Host controller private data */
	void *priv;
};

/** USB bus host controller operations */
struct usb_bus_host_operations {
	/** Open bus
	 *
	 * @v bus		USB bus
	 * @ret rc		Return status code
	 */
	int ( * open ) ( struct usb_bus *bus );
	/** Close bus
	 *
	 * @v bus		USB bus
	 */
	void ( * close ) ( struct usb_bus *bus );
	/** Poll bus
	 *
	 * @v bus		USB bus
	 */
	void ( * poll ) ( struct usb_bus *bus );
};

/** USB host controller operations */
struct usb_host_operations {
	/** Endpoint operations */
	struct usb_endpoint_host_operations endpoint;
	/** Device operations */
	struct usb_device_host_operations device;
	/** Bus operations */
	struct usb_bus_host_operations bus;
	/** Hub operations */
	struct usb_hub_host_operations hub;
	/** Root hub operations */
	struct usb_hub_driver_operations root;
};

/**
 * Set USB bus host controller private data
 *
 * @v bus		USB bus
 * @v priv		Host controller private data
 */
static inline __attribute__ (( always_inline )) void
usb_bus_set_hostdata ( struct usb_bus *bus, void *priv ) {
	bus->priv = priv;
}

/**
 * Get USB bus host controller private data
 *
 * @v bus		USB bus
 * @ret priv		Host controller private data
 */
static inline __attribute__ (( always_inline )) void *
usb_bus_get_hostdata ( struct usb_bus *bus ) {
	return bus->priv;
}

/**
 * Poll USB bus
 *
 * @v bus		USB bus
 */
static inline __attribute__ (( always_inline )) void
usb_poll ( struct usb_bus *bus ) {
	bus->host->poll ( bus );
}

/** Iterate over all USB buses */
#define for_each_usb_bus( bus ) \
	list_for_each_entry ( (bus), &usb_buses, list )

/**
 * Complete transfer (without error)
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 */
static inline __attribute__ (( always_inline )) void
usb_complete ( struct usb_endpoint *ep, struct io_buffer *iobuf ) {
	usb_complete_err ( ep, iobuf, 0 );
}

extern int usb_control ( struct usb_device *usb, unsigned int request,
			 unsigned int value, unsigned int index, void *data,
			 size_t len );
extern int usb_get_string_descriptor ( struct usb_device *usb,
				       unsigned int index,
				       unsigned int language,
				       char *buf, size_t len );

/**
 * Get status
 *
 * @v usb		USB device
 * @v type		Request type
 * @v index		Target index
 * @v data		Status to fill in
 * @v len		Length of status descriptor
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_get_status ( struct usb_device *usb, unsigned int type, unsigned int index,
		 void *data, size_t len ) {

	return usb_control ( usb, ( USB_GET_STATUS | type ), 0, index,
			     data, len );
}

/**
 * Clear feature
 *
 * @v usb		USB device
 * @v type		Request type
 * @v feature		Feature selector
 * @v index		Target index
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_clear_feature ( struct usb_device *usb, unsigned int type,
		    unsigned int feature, unsigned int index ) {

	return usb_control ( usb, ( USB_CLEAR_FEATURE | type ),
			     feature, index, NULL, 0 );
}

/**
 * Set feature
 *
 * @v usb		USB device
 * @v type		Request type
 * @v feature		Feature selector
 * @v index		Target index
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_set_feature ( struct usb_device *usb, unsigned int type,
		  unsigned int feature, unsigned int index ) {

	return usb_control ( usb, ( USB_SET_FEATURE | type ),
			     feature, index, NULL, 0 );
}

/**
 * Set address
 *
 * @v usb		USB device
 * @v address		Device address
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_set_address ( struct usb_device *usb, unsigned int address ) {

	return usb_control ( usb, USB_SET_ADDRESS, address, 0, NULL, 0 );
}

/**
 * Get USB descriptor
 *
 * @v usb		USB device
 * @v type		Request type
 * @v desc		Descriptor type
 * @v index		Descriptor index
 * @v language		Language ID (for string descriptors)
 * @v data		Descriptor to fill in
 * @v len		Maximum length of descriptor
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_get_descriptor ( struct usb_device *usb, unsigned int type,
		     unsigned int desc, unsigned int index,
		     unsigned int language, struct usb_descriptor_header *data,
		     size_t len ) {

	return usb_control ( usb, ( USB_GET_DESCRIPTOR | type ),
			     ( ( desc << 8 ) | index ), language, data, len );
}

/**
 * Get first part of USB device descriptor (up to and including MTU)
 *
 * @v usb		USB device
 * @v data		Device descriptor to (partially) fill in
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_get_mtu ( struct usb_device *usb, struct usb_device_descriptor *data ) {

	return usb_get_descriptor ( usb, 0, USB_DEVICE_DESCRIPTOR, 0, 0,
				    &data->header,
				    ( offsetof ( typeof ( *data ), mtu ) +
				      sizeof ( data->mtu ) ) );
}

/**
 * Get USB device descriptor
 *
 * @v usb		USB device
 * @v data		Device descriptor to fill in
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_get_device_descriptor ( struct usb_device *usb,
			    struct usb_device_descriptor *data ) {

	return usb_get_descriptor ( usb, 0, USB_DEVICE_DESCRIPTOR, 0, 0,
				    &data->header, sizeof ( *data ) );
}

/**
 * Get USB configuration descriptor
 *
 * @v usb		USB device
 * @v index		Configuration index
 * @v data		Configuration descriptor to fill in
 * @ret rc		Return status code
 */
static inline __attribute (( always_inline )) int
usb_get_config_descriptor ( struct usb_device *usb, unsigned int index,
			    struct usb_configuration_descriptor *data,
			    size_t len ) {

	return usb_get_descriptor ( usb, 0, USB_CONFIGURATION_DESCRIPTOR, index,
				    0, &data->header, len );
}

/**
 * Set USB configuration
 *
 * @v usb		USB device
 * @v index		Configuration index
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_set_configuration ( struct usb_device *usb, unsigned int index ) {

	return usb_control ( usb, USB_SET_CONFIGURATION, index, 0, NULL, 0 );
}

/**
 * Set USB interface alternate setting
 *
 * @v usb		USB device
 * @v interface		Interface number
 * @v alternate		Alternate setting
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
usb_set_interface ( struct usb_device *usb, unsigned int interface,
		    unsigned int alternate ) {

	return usb_control ( usb, USB_SET_INTERFACE, alternate, interface,
			     NULL, 0 );
}

extern struct list_head usb_buses;

extern struct usb_interface_descriptor *
usb_interface_descriptor ( struct usb_configuration_descriptor *config,
			   unsigned int interface, unsigned int alternate );
extern struct usb_endpoint_descriptor *
usb_endpoint_descriptor ( struct usb_configuration_descriptor *config,
			  struct usb_interface_descriptor *interface,
			  unsigned int type, unsigned int index );
extern struct usb_endpoint_companion_descriptor *
usb_endpoint_companion_descriptor ( struct usb_configuration_descriptor *config,
				    struct usb_endpoint_descriptor *desc );

extern struct usb_hub * alloc_usb_hub ( struct usb_bus *bus,
					struct usb_device *usb,
					unsigned int ports,
					struct usb_hub_driver_operations *op );
extern int register_usb_hub ( struct usb_hub *hub );
extern void unregister_usb_hub ( struct usb_hub *hub );
extern void free_usb_hub ( struct usb_hub *hub );

extern void usb_port_changed ( struct usb_port *port );

extern struct usb_bus * alloc_usb_bus ( struct device *dev,
					unsigned int ports, size_t mtu,
					struct usb_host_operations *op );
extern int register_usb_bus ( struct usb_bus *bus );
extern void unregister_usb_bus ( struct usb_bus *bus );
extern void free_usb_bus ( struct usb_bus *bus );
extern struct usb_bus * find_usb_bus_by_location ( unsigned int bus_type,
						   unsigned int location );

extern int usb_alloc_address ( struct usb_bus *bus );
extern void usb_free_address ( struct usb_bus *bus, unsigned int address );
extern unsigned int usb_route_string ( struct usb_device *usb );
extern unsigned int usb_depth ( struct usb_device *usb );
extern struct usb_port * usb_root_hub_port ( struct usb_device *usb );
extern struct usb_port * usb_transaction_translator ( struct usb_device *usb );

/** Minimum reset time
 *
 * Section 7.1.7.5 of the USB2 specification states that root hub
 * ports should assert reset signalling for at least 50ms.
 */
#define USB_RESET_DELAY_MS 50

/** Reset recovery time
 *
 * Section 9.2.6.2 of the USB2 specification states that the
 * "recovery" interval after a port reset is 10ms.
 */
#define USB_RESET_RECOVER_DELAY_MS 10

/** Maximum time to wait for a control transaction to complete
 *
 * Section 9.2.6.1 of the USB2 specification states that the upper
 * limit for commands to be processed is 5 seconds.
 */
#define USB_CONTROL_MAX_WAIT_MS 5000

/** Set address recovery time
 *
 * Section 9.2.6.3 of the USB2 specification states that devices are
 * allowed a 2ms recovery interval after receiving a new address.
 */
#define USB_SET_ADDRESS_RECOVER_DELAY_MS 2

/** Time to wait for ports to stabilise
 *
 * Section 7.1.7.3 of the USB specification states that we must allow
 * 100ms for devices to signal attachment, and an additional 100ms for
 * connection debouncing.  (This delay is parallelised across all
 * ports on a hub; we do not delay separately for each port.)
 */
#define USB_PORT_DELAY_MS 200

/** A USB device ID */
struct usb_device_id {
	/** Name */
	const char *name;
	/** Vendor ID */
	uint16_t vendor;
	/** Product ID */
	uint16_t product;
	/** Class */
	struct usb_class class;
};

/** Match-anything ID */
#define USB_ANY_ID 0xffff

/** A USB driver */
struct usb_driver {
	/** USB ID table */
	struct usb_device_id *ids;
	/** Number of entries in ID table */
	unsigned int id_count;
	/**
	 * Probe device
	 *
	 * @v func		USB function
	 * @v config		Configuration descriptor
	 * @ret rc		Return status code
	 */
	int ( * probe ) ( struct usb_function *func,
			  struct usb_configuration_descriptor *config );
	/**
	 * Remove device
	 *
	 * @v func		USB function
	 */
	void ( * remove ) ( struct usb_function *func );
};

/** USB driver table */
#define USB_DRIVERS __table ( struct usb_driver, "usb_drivers" )

/** Declare a USB driver */
#define __usb_driver __table_entry ( USB_DRIVERS, 01 )

#endif /* _IPXE_USB_H */
