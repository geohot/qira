#ifndef _DM96XX_H
#define _DM96XX_H

/** @file
 *
 * Davicom DM96xx USB Ethernet driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/usb.h>
#include <ipxe/usbnet.h>
#include <ipxe/if_ether.h>

/** Read register(s) */
#define DM96XX_READ_REGISTER					\
	( USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE |	\
	  USB_REQUEST_TYPE ( 0x00 ) )

/** Write register(s) */
#define DM96XX_WRITE_REGISTER					\
	( USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE |	\
	  USB_REQUEST_TYPE ( 0x01 ) )

/** Write single register */
#define DM96XX_WRITE1_REGISTER					\
	( USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE |	\
	  USB_REQUEST_TYPE ( 0x03 ) )

/** Network control register */
#define DM96XX_NCR 0x00
#define DM96XX_NCR_RST		0x01	/**< Software reset */

/** Network status register */
#define DM96XX_NSR 0x01
#define DM96XX_NSR_LINKST	0x40	/**< Link status */

/** Receive control register */
#define DM96XX_RCR 0x05
#define DM96XX_RCR_ALL		0x08	/**< Pass all multicast */
#define DM96XX_RCR_RUNT		0x04	/**< Pass runt packet */
#define DM96XX_RCR_PRMSC	0x02	/**< Promiscuous mode */
#define DM96XX_RCR_RXEN		0x01	/**< RX enable */

/** Receive status register */
#define DM96XX_RSR 0x06
#define DM96XX_RSR_MF		0x40	/**< Multicast frame */

/** PHY address registers */
#define DM96XX_PAR 0x10

/** Chip revision register */
#define DM96XX_CHIPR 0x2c
#define DM96XX_CHIPR_9601	0x00	/**< DM9601 */
#define DM96XX_CHIPR_9620	0x01	/**< DM9620 */

/** RX header control/status register (DM9620+ only) */
#define DM96XX_MODE_CTL 0x91
#define DM96XX_MODE_CTL_MODE	0x80	/**< 4-byte header mode */

/** DM96xx interrupt data */
struct dm96xx_interrupt {
	/** Network status register */
	uint8_t nsr;
	/** Transmit status registers */
	uint8_t tsr[2];
	/** Receive status register */
	uint8_t rsr;
	/** Receive overflow counter register */
	uint8_t rocr;
	/** Receive packet counter */
	uint8_t rxc;
	/** Transmit packet counter */
	uint8_t txc;
	/** General purpose register */
	uint8_t gpr;
} __attribute__ (( packed ));

/** DM96xx receive header */
struct dm96xx_rx_header {
	/** Packet status */
	uint8_t rsr;
	/** Packet length (excluding this header, including CRC) */
	uint16_t len;
} __attribute__ (( packed ));

/** DM96xx transmit header */
struct dm96xx_tx_header {
	/** Packet length (excluding this header) */
	uint16_t len;
} __attribute__ (( packed ));

/** A DM96xx network device */
struct dm96xx_device {
	/** USB device */
	struct usb_device *usb;
	/** USB bus */
	struct usb_bus *bus;
	/** Network device */
	struct net_device *netdev;
	/** USB network device */
	struct usbnet_device usbnet;
};

/**
 * Read registers
 *
 * @v dm96xx		DM96xx device
 * @v offset		Register offset
 * @v data		Data buffer
 * @v len		Length of data
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
dm96xx_read_registers ( struct dm96xx_device *dm96xx, unsigned int offset,
			void *data, size_t len ) {

	return usb_control ( dm96xx->usb, DM96XX_READ_REGISTER, 0, offset,
			     data, len );
}

/**
 * Read register
 *
 * @v dm96xx		DM96xx device
 * @v offset		Register offset
 * @ret value		Register value, or negative error
 */
static inline __attribute__ (( always_inline )) int
dm96xx_read_register ( struct dm96xx_device *dm96xx, unsigned int offset ) {
	uint8_t value;
	int rc;

	if ( ( rc = dm96xx_read_registers ( dm96xx, offset, &value,
					    sizeof ( value ) ) ) != 0 )
		return rc;
	return value;
}

/**
 * Write registers
 *
 * @v dm96xx		DM96xx device
 * @v offset		Register offset
 * @v data		Data buffer
 * @v len		Length of data
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
dm96xx_write_registers ( struct dm96xx_device *dm96xx, unsigned int offset,
			 void *data, size_t len ) {

	return usb_control ( dm96xx->usb, DM96XX_WRITE_REGISTER, 0, offset,
			     data, len );
}

/**
 * Write register
 *
 * @v dm96xx		DM96xx device
 * @v offset		Register offset
 * @v value		Register value
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
dm96xx_write_register ( struct dm96xx_device *dm96xx, unsigned int offset,
			uint8_t value ) {

	return usb_control ( dm96xx->usb, DM96XX_WRITE1_REGISTER, value,
			     offset, NULL, 0 );
}

/** Reset delay (in microseconds) */
#define DM96XX_RESET_DELAY_US 10

/** Interrupt maximum fill level
 *
 * This is a policy decision.
 */
#define DM96XX_INTR_MAX_FILL 2

/** Bulk IN maximum fill level
 *
 * This is a policy decision.
 */
#define DM96XX_IN_MAX_FILL 8

/** Bulk IN buffer size */
#define DM96XX_IN_MTU					\
	( 4 /* DM96xx header */ + ETH_FRAME_LEN +	\
	  4 /* possible VLAN header */ + 4 /* CRC */ )

#endif /* _DM96XX_H */
