#ifndef _NCM_H
#define _NCM_H

/** @file
 *
 * CDC-NCM USB Ethernet driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/usb.h>
#include <ipxe/cdc.h>
#include <byteswap.h>
#include "ecm.h"

/** CDC-NCM subclass */
#define USB_SUBCLASS_CDC_NCM 0x0d

/** Get NTB parameters */
#define NCM_GET_NTB_PARAMETERS						\
	( USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE |		\
	  USB_REQUEST_TYPE ( 0x80 ) )

/** NTB datagram parameters */
struct ncm_ntb_datagram_parameters {
	/** Maximum size */
	uint32_t mtu;
	/** Alignment divisor */
	uint16_t divisor;
	/** Alignment remainder */
	uint16_t remainder;
	/** Alignment modulus */
	uint16_t modulus;
} __attribute__ (( packed ));

/** NTB parameters */
struct ncm_ntb_parameters {
	/** Length */
	uint16_t len;
	/** Supported formats */
	uint16_t formats;
	/** IN datagram parameters */
	struct ncm_ntb_datagram_parameters in;
	/** Reserved */
	uint16_t reserved;
	/** OUT datagram parameters */
	struct ncm_ntb_datagram_parameters out;
	/** Maximum number of datagrams per OUT NTB */
	uint16_t max;
} __attribute__ (( packed ));

/** Set NTB input size */
#define NCM_SET_NTB_INPUT_SIZE						\
	( USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE |		\
	  USB_REQUEST_TYPE ( 0x86 ) )

/** Set NTB input size */
struct ncm_set_ntb_input_size {
	/** Maximum size */
	uint32_t mtu;
} __attribute__ (( packed ));

/** Minimum allowed NTB input size */
#define NCM_MIN_NTB_INPUT_SIZE 2048

/** Maximum allowed NTB input size (16-bit) */
#define NCM_MAX_NTB_INPUT_SIZE 65536

/** CDC-NCM transfer header (16-bit) */
struct ncm_transfer_header {
	/** Signature */
	uint32_t magic;
	/** Header length */
	uint16_t header_len;
	/** Sequence number */
	uint16_t sequence;
	/** Total length */
	uint16_t len;
	/** Offset of first datagram pointer */
	uint16_t offset;
} __attribute__ (( packed ));

/** CDC-NCM transfer header magic */
#define NCM_TRANSFER_HEADER_MAGIC 0x484d434eUL

/** CDC-NCM datagram descriptor (16-bit) */
struct ncm_datagram_descriptor {
	/** Starting offset */
	uint16_t offset;
	/** Length */
	uint16_t len;
} __attribute__ (( packed ));

/** CDC-NCM datagram pointer (16-bit) */
struct ncm_datagram_pointer {
	/** Signature */
	uint32_t magic;
	/** Header length */
	uint16_t header_len;
	/** Offset of next datagram pointer */
	uint16_t offset;
	/** Datagram descriptors
	 *
	 * Must be terminated by an empty descriptor.
	 */
	struct ncm_datagram_descriptor desc[0];
} __attribute__ (( packed ));

/** CDC-NCM datagram pointer magic */
#define NCM_DATAGRAM_POINTER_MAGIC 0x304d434eUL

/** CDC-NCM datagram pointer CRC present flag */
#define NCM_DATAGRAM_POINTER_MAGIC_CRC 0x01000000UL

/** NTB constructed for transmitted packets (excluding padding)
 *
 * This is a policy decision.
 */
struct ncm_ntb_header {
	/** Transfer header */
	struct ncm_transfer_header nth;
	/** Datagram pointer */
	struct ncm_datagram_pointer ndp;
	/** Datagram descriptors */
	struct ncm_datagram_descriptor desc[2];
} __attribute__ (( packed ));

/** A CDC-NCM network device */
struct ncm_device {
	/** USB device */
	struct usb_device *usb;
	/** USB bus */
	struct usb_bus *bus;
	/** Network device */
	struct net_device *netdev;
	/** USB network device */
	struct usbnet_device usbnet;

	/** Maximum supported NTB input size */
	size_t mtu;
	/** Transmitted packet sequence number */
	uint16_t sequence;
	/** Alignment padding required on transmitted packets */
	size_t padding;
};

/** Bulk IN ring minimum buffer count
 *
 * This is a policy decision.
 */
#define NCM_IN_MIN_COUNT 3

/** Bulk IN ring minimum total buffer size
 *
 * This is a policy decision.
 */
#define NCM_IN_MIN_SIZE 16384

/** Bulk IN ring maximum total buffer size
 *
 * This is a policy decision.
 */
#define NCM_IN_MAX_SIZE 131072

/** Interrupt ring buffer count
 *
 * This is a policy decision.
 */
#define NCM_INTR_COUNT 2

#endif /* _NCM_H */
