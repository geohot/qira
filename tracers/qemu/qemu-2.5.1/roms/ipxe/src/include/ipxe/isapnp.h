/**************************************************************************
*
*    isapnp.h -- Etherboot isapnp support for the 3Com 3c515
*    Written 2002-2003 by Timothy Legge <tlegge@rogers.com>
*
*    This program is free software; you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation; either version 2 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
*    02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
*
*    Portions of this code:
*		Copyright (C) 2001  P.J.H.Fox (fox@roestock.demon.co.uk)
*
*
*
*    REVISION HISTORY:
*    ================
*        Version 0.1 April 26, 2002 	TJL
*	 Version 0.2 01/08/2003			TJL Renamed from 3c515_isapnp.h
*
*
*    Generalised into an ISAPnP bus that can be used by more than just
*    the 3c515 by Michael Brown <mbrown@fensystems.co.uk>
*
***************************************************************************/

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifndef ISAPNP_H
#define ISAPNP_H

#include <stdint.h>
#include <ipxe/isa_ids.h>
#include <ipxe/device.h>
#include <ipxe/tables.h>

/*
 * ISAPnP constants
 *
 */

/* Port addresses */
#define ISAPNP_ADDRESS		0x279
#define ISAPNP_WRITE_DATA	0xa79
#define ISAPNP_READ_PORT_MIN	0x203
#define ISAPNP_READ_PORT_START	0x213	/* ISAPnP spec says 0x203, but
					 * Linux ISAPnP starts at
					 * 0x213 with no explanatory
					 * comment.  0x203 probably
					 * clashes with something. */
#define ISAPNP_READ_PORT_MAX	0x3ff
#define ISAPNP_READ_PORT_STEP	0x10	/* Can be any multiple of 4
					 * according to the spec, but
					 * since ISA I/O addresses are
					 * allocated in blocks of 16,
					 * it makes no sense to use
					 * any value less than 16.
					 */

/* Card select numbers */
#define ISAPNP_CSN_MIN		0x01
#define ISAPNP_CSN_MAX		0x0f

/* Registers */
#define ISAPNP_READPORT			0x00
#define ISAPNP_SERIALISOLATION 		0x01
#define ISAPNP_CONFIGCONTROL		0x02
#define ISAPNP_WAKE			0x03
#define ISAPNP_RESOURCEDATA		0x04
#define ISAPNP_STATUS          		0x05
#define ISAPNP_CARDSELECTNUMBER		0x06
#define ISAPNP_LOGICALDEVICENUMBER	0x07
#define ISAPNP_ACTIVATE			0x30
#define ISAPNP_IORANGECHECK		0x31
#define ISAPNP_IOBASE(n)		( 0x60 + ( (n) * 2 ) )
#define ISAPNP_IRQNO(n)			( 0x70 + ( (n) * 2 ) )
#define ISAPNP_IRQTYPE(n)		( 0x71 + ( (n) * 2 ) )

/* Bits in the CONFIGCONTROL register */
#define ISAPNP_CONFIG_RESET		( 1 << 0 )
#define ISAPNP_CONFIG_WAIT_FOR_KEY	( 1 << 1 )
#define ISAPNP_CONFIG_RESET_CSN		( 1 << 2 )
#define ISAPNP_CONFIG_RESET_DRV		( ISAPNP_CONFIG_RESET | 	\
					  ISAPNP_CONFIG_WAIT_FOR_KEY |	\
					  ISAPNP_CONFIG_RESET_CSN )

/* The LFSR used for the initiation key and for checksumming */
#define ISAPNP_LFSR_SEED		0x6a

/* Small tags */
#define ISAPNP_IS_SMALL_TAG(tag)	( ! ( (tag) & 0x80 ) )
#define ISAPNP_SMALL_TAG_NAME(tag)	( ( (tag) >> 3 ) & 0xf )
#define ISAPNP_SMALL_TAG_LEN(tag)	( ( (tag) & 0x7 ) )
#define ISAPNP_TAG_PNPVERNO		0x01
#define ISAPNP_TAG_LOGDEVID		0x02
#define ISAPNP_TAG_COMPATDEVID		0x03
#define ISAPNP_TAG_IRQ			0x04
#define ISAPNP_TAG_DMA			0x05
#define ISAPNP_TAG_STARTDEP		0x06
#define ISAPNP_TAG_ENDDEP		0x07
#define ISAPNP_TAG_IOPORT		0x08
#define ISAPNP_TAG_FIXEDIO		0x09
#define ISAPNP_TAG_RSVDSHORTA		0x0A
#define ISAPNP_TAG_RSVDSHORTB		0x0B
#define ISAPNP_TAG_RSVDSHORTC		0x0C
#define ISAPNP_TAG_RSVDSHORTD		0x0D
#define ISAPNP_TAG_VENDORSHORT		0x0E
#define ISAPNP_TAG_END			0x0F
/* Large tags */
#define ISAPNP_IS_LARGE_TAG(tag)	( ( (tag) & 0x80 ) )
#define ISAPNP_LARGE_TAG_NAME(tag)	(tag)
#define ISAPNP_TAG_MEMRANGE		0x81
#define ISAPNP_TAG_ANSISTR		0x82
#define ISAPNP_TAG_UNICODESTR		0x83
#define ISAPNP_TAG_VENDORLONG		0x84
#define ISAPNP_TAG_MEM32RANGE		0x85
#define ISAPNP_TAG_FIXEDMEM32RANGE	0x86
#define ISAPNP_TAG_RSVDLONG0		0xF0
#define ISAPNP_TAG_RSVDLONG1		0xF1
#define ISAPNP_TAG_RSVDLONG2		0xF2
#define ISAPNP_TAG_RSVDLONG3		0xF3
#define ISAPNP_TAG_RSVDLONG4		0xF4
#define ISAPNP_TAG_RSVDLONG5		0xF5
#define ISAPNP_TAG_RSVDLONG6		0xF6
#define ISAPNP_TAG_RSVDLONG7		0xF7
#define ISAPNP_TAG_RSVDLONG8		0xF8
#define ISAPNP_TAG_RSVDLONG9		0xF9
#define ISAPNP_TAG_RSVDLONGA		0xFA
#define ISAPNP_TAG_RSVDLONGB		0xFB
#define ISAPNP_TAG_RSVDLONGC		0xFC
#define ISAPNP_TAG_RSVDLONGD		0xFD
#define ISAPNP_TAG_RSVDLONGE		0xFE
#define ISAPNP_TAG_RSVDLONGF		0xFF
#define ISAPNP_TAG_PSEUDO_NEWBOARD	0x100

/** An ISAPnP serial identifier */
struct isapnp_identifier {
	/** Vendor ID */
	uint16_t vendor_id;
	/** Product ID */
	uint16_t prod_id;
	/** Serial number */
	uint32_t serial;
	/** Checksum */
	uint8_t checksum;
} __attribute__ (( packed ));

/** An ISAPnP logical device ID structure */
struct isapnp_logdevid {
	/** Vendor ID */
	uint16_t vendor_id;
	/** Product ID */
	uint16_t prod_id;
	/** Flags */
	uint16_t flags;
} __attribute__ (( packed ));

/** An ISAPnP device ID list entry */
struct isapnp_device_id {
	/** Name */
        const char *name;
	/** Vendor ID */
	uint16_t vendor_id;
	/** Product ID */
	uint16_t prod_id;
};

/** An ISAPnP device */
struct isapnp_device {
	/** Generic device */
	struct device dev;
	/** Vendor ID */
	uint16_t vendor_id;
	/** Product ID */
	uint16_t prod_id;
	/** I/O address */
	uint16_t ioaddr;
	/** Interrupt number */
	uint8_t irqno;
	/** Card Select Number */
	uint8_t csn;
	/** Logical Device ID */
	uint8_t logdev;
	/** Driver for this device */
	struct isapnp_driver *driver;
	/** Driver-private data
	 *
	 * Use isapnp_set_drvdata() and isapnp_get_drvdata() to access
	 * this field.
	 */
	void *priv;
};

/** An ISAPnP driver */
struct isapnp_driver {
	/** ISAPnP ID table */
	struct isapnp_device_id *ids;
	/** Number of entries in ISAPnP ID table */
	unsigned int id_count;
	/**
	 * Probe device
	 *
	 * @v isapnp	ISAPnP device
	 * @v id	Matching entry in ID table
	 * @ret rc	Return status code
	 */
	int ( * probe ) ( struct isapnp_device *isapnp,
			  const struct isapnp_device_id *id );
	/**
	 * Remove device
	 *
	 * @v isapnp	ISAPnP device
	 */
	void ( * remove ) ( struct isapnp_device *isapnp );
};

/** ISAPnP driver table */
#define ISAPNP_DRIVERS __table ( struct isapnp_driver, "isapnp_drivers" )

/** Declare an ISAPnP driver */
#define __isapnp_driver __table_entry ( ISAPNP_DRIVERS, 01 )

extern uint16_t isapnp_read_port;

extern void isapnp_device_activation ( struct isapnp_device *isapnp,
				       int activation );

/**
 * Activate ISAPnP device
 *
 * @v isapnp		ISAPnP device
 */
static inline void activate_isapnp_device ( struct isapnp_device *isapnp ) {
	isapnp_device_activation ( isapnp, 1 );
}

/**
 * Deactivate ISAPnP device
 *
 * @v isapnp		ISAPnP device
 */
static inline void deactivate_isapnp_device ( struct isapnp_device *isapnp ) {
	isapnp_device_activation ( isapnp, 0 );
}

/**
 * Set ISAPnP driver-private data
 *
 * @v isapnp		ISAPnP device
 * @v priv		Private data
 */
static inline void isapnp_set_drvdata ( struct isapnp_device *isapnp,
					void *priv ) {
	isapnp->priv = priv;
}

/**
 * Get ISAPnP driver-private data
 *
 * @v isapnp		ISAPnP device
 * @ret priv		Private data
 */
static inline void * isapnp_get_drvdata ( struct isapnp_device *isapnp ) {
	return isapnp->priv;
}

#endif /* ISAPNP_H */
