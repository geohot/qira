/**************************************************************************
*
*    isapnp.c -- Etherboot isapnp support for the 3Com 3c515
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
*    Portions of this code:
*	Copyright (C) 2001  P.J.H.Fox (fox@roestock.demon.co.uk)
*
*
*    REVISION HISTORY:
*    ================
*    Version 0.1 April 26, 2002 TJL
*    Version 0.2 01/08/2003	TJL Moved outside the 3c515.c driver file
*    Version 0.3 Sept 23, 2003	timlegge Change delay to currticks
*		
*
*    Generalised into an ISAPnP bus that can be used by more than just
*    the 3c515 by Michael Brown <mbrown@fensystems.co.uk>
*
***************************************************************************/

/** @file
 *
 * ISAPnP bus support
 *
 * Etherboot orignally gained ISAPnP support in a very limited way for
 * the 3c515 NIC.  The current implementation is almost a complete
 * rewrite based on the ISAPnP specification, with passing reference
 * to the Linux ISAPnP code.
 *
 * There can be only one ISAPnP bus in a system.  Once the read port
 * is known and all cards have been allocated CSNs, there's nothing to
 * be gained by re-scanning for cards.
 *
 * External code (e.g. the ISAPnP ROM prefix) may already know the
 * read port address, in which case it can store it in
 * #isapnp_read_port.  Note that setting the read port address in this
 * way will prevent further isolation from taking place; you should
 * set the read port address only if you know that devices have
 * already been allocated CSNs.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/io.h>
#include <unistd.h>
#include <ipxe/isapnp.h>

/**
 * ISAPnP Read Port address.
 *
 * ROM prefix may be able to set this address, which is why this is
 * non-static.
 */
uint16_t isapnp_read_port;

static void isapnpbus_remove ( struct root_device *rootdev );

/*
 * ISAPnP utility functions
 *
 */

#define ISAPNP_CARD_ID_FMT "ID %04x:%04x (\"%s\") serial %x"
#define ISAPNP_CARD_ID_DATA(identifier)					  \
	(identifier)->vendor_id, (identifier)->prod_id,			  \
	isa_id_string ( (identifier)->vendor_id, (identifier)->prod_id ), \
	(identifier)->serial
#define ISAPNP_DEV_ID_FMT "ID %04x:%04x (\"%s\")"
#define ISAPNP_DEV_ID_DATA(isapnp)					  \
	(isapnp)->vendor_id, (isapnp)->prod_id,				  \
	isa_id_string ( (isapnp)->vendor_id, (isapnp)->prod_id )

static inline void isapnp_write_address ( unsigned int address ) {
	outb ( address, ISAPNP_ADDRESS );
}

static inline void isapnp_write_data ( unsigned int data ) {
	outb ( data, ISAPNP_WRITE_DATA );
}

static inline unsigned int isapnp_read_data ( void ) {
	return inb ( isapnp_read_port );
}

static inline void isapnp_write_byte ( unsigned int address,
				       unsigned int value ) {
	isapnp_write_address ( address );
	isapnp_write_data ( value );
}

static inline unsigned int isapnp_read_byte ( unsigned int address ) {
	isapnp_write_address ( address );
	return isapnp_read_data ();
}

static inline unsigned int isapnp_read_word ( unsigned int address ) {
	/* Yes, they're in big-endian order */
	return ( ( isapnp_read_byte ( address ) << 8 )
		 | isapnp_read_byte ( address + 1 ) );
}

/** Inform cards of a new read port address */
static inline void isapnp_set_read_port ( void ) {
	isapnp_write_byte ( ISAPNP_READPORT, ( isapnp_read_port >> 2 ) );
}

/**
 * Enter the Isolation state.
 *
 * Only cards currently in the Sleep state will respond to this
 * command.
 */
static inline void isapnp_serialisolation ( void ) {
	isapnp_write_address ( ISAPNP_SERIALISOLATION );
}

/**
 * Enter the Wait for Key state.
 *
 * All cards will respond to this command, regardless of their current
 * state.
 */
static inline void isapnp_wait_for_key ( void ) {
	isapnp_write_byte ( ISAPNP_CONFIGCONTROL, ISAPNP_CONFIG_WAIT_FOR_KEY );
}

/**
 * Reset (i.e. remove) Card Select Number.
 *
 * Only cards currently in the Sleep state will respond to this
 * command.
 */
static inline void isapnp_reset_csn ( void ) {
	isapnp_write_byte ( ISAPNP_CONFIGCONTROL, ISAPNP_CONFIG_RESET_CSN );
}

/**
 * Place a specified card into the Config state.
 *
 * @v csn		Card Select Number
 * @ret None		-
 * @err None		-
 *
 * Only cards currently in the Sleep, Isolation, or Config states will
 * respond to this command.  The card that has the specified CSN will
 * enter the Config state, all other cards will enter the Sleep state.
 */
static inline void isapnp_wake ( uint8_t csn ) {
	isapnp_write_byte ( ISAPNP_WAKE, csn );
}

static inline unsigned int isapnp_read_resourcedata ( void ) {
	return isapnp_read_byte ( ISAPNP_RESOURCEDATA );
}

static inline unsigned int isapnp_read_status ( void ) {
	return isapnp_read_byte ( ISAPNP_STATUS );
}

/**
 * Assign a Card Select Number to a card, and enter the Config state.
 *
 * @v csn		Card Select Number
 *
 * Only cards in the Isolation state will respond to this command.
 * The isolation protocol is designed so that only one card will
 * remain in the Isolation state by the time the isolation protocol
 * completes.
 */
static inline void isapnp_write_csn ( unsigned int csn ) {
	isapnp_write_byte ( ISAPNP_CARDSELECTNUMBER, csn );
}

static inline void isapnp_logicaldevice ( unsigned int logdev ) {
	isapnp_write_byte ( ISAPNP_LOGICALDEVICENUMBER, logdev );
}

static inline void isapnp_activate ( unsigned int logdev ) {
	isapnp_logicaldevice ( logdev );
	isapnp_write_byte ( ISAPNP_ACTIVATE, 1 );
}

static inline void isapnp_deactivate ( unsigned int logdev ) {
	isapnp_logicaldevice ( logdev );
	isapnp_write_byte ( ISAPNP_ACTIVATE, 0 );
}

static inline unsigned int isapnp_read_iobase ( unsigned int index ) {
	return isapnp_read_word ( ISAPNP_IOBASE ( index ) );
}

static inline unsigned int isapnp_read_irqno ( unsigned int index ) {
	return isapnp_read_byte ( ISAPNP_IRQNO ( index ) );
}

static void isapnp_delay ( void ) {
	udelay ( 1000 );
}

/**
 * Linear feedback shift register.
 *
 * @v lfsr		Current value of the LFSR
 * @v input_bit		Current input bit to the LFSR
 * @ret lfsr		Next value of the LFSR
 *
 * This routine implements the linear feedback shift register as
 * described in Appendix B of the PnP ISA spec.  The hardware
 * implementation uses eight D-type latches and two XOR gates.  I
 * think this is probably the smallest possible implementation in
 * software.  Six instructions when input_bit is a constant 0 (for
 * isapnp_send_key).  :)
 */
static inline unsigned int isapnp_lfsr_next ( unsigned int lfsr,
					      unsigned int input_bit ) {
	register uint8_t lfsr_next;

	lfsr_next = lfsr >> 1;
	lfsr_next |= ( ( ( lfsr ^ lfsr_next ) ^ input_bit ) ) << 7;
	return lfsr_next;
}

/**
 * Send the ISAPnP initiation key.
 *
 * Sending the key causes all ISAPnP cards that are currently in the
 * Wait for Key state to transition into the Sleep state.
 */
static void isapnp_send_key ( void ) {
	unsigned int i;
	unsigned int lfsr;

	isapnp_delay();
	isapnp_write_address ( 0x00 );
	isapnp_write_address ( 0x00 );

	lfsr = ISAPNP_LFSR_SEED;
	for ( i = 0 ; i < 32 ; i++ ) {
		isapnp_write_address ( lfsr );
		lfsr = isapnp_lfsr_next ( lfsr, 0 );
	}
}

/**
 * Compute ISAPnP identifier checksum
 *
 * @v identifier	ISAPnP identifier
 * @ret checksum	Expected checksum value
 */
static unsigned int isapnp_checksum ( struct isapnp_identifier *identifier ) {
	unsigned int i, j;
	unsigned int lfsr;
	unsigned int byte;

	lfsr = ISAPNP_LFSR_SEED;
	for ( i = 0 ; i < 8 ; i++ ) {
		byte = * ( ( ( uint8_t * ) identifier ) + i );
		for ( j = 0 ; j < 8 ; j++ ) {
			lfsr = isapnp_lfsr_next ( lfsr, byte );
			byte >>= 1;
		}
	}
	return lfsr;
}

/*
 * Read a byte of resource data from the current location
 *
 * @ret byte		Byte of resource data
 */
static inline unsigned int isapnp_peek_byte ( void ) {
	unsigned int i;

	/* Wait for data to be ready */
	for ( i = 0 ; i < 20 ; i++ ) {
		if ( isapnp_read_status() & 0x01 ) {
			/* Byte ready - read it */
			return isapnp_read_resourcedata();
		}
		isapnp_delay();
	}
	/* Data never became ready - return 0xff */
	return 0xff;
}

/**
 * Read resource data.
 *
 * @v buf		Buffer in which to store data, or NULL
 * @v bytes		Number of bytes to read
 *
 * Resource data is read from the current location.  If #buf is NULL,
 * the data is discarded.
 */
static void isapnp_peek ( void *buf, size_t len ) {
	unsigned int i;
	unsigned int byte;

	for ( i = 0 ; i < len ; i++) {
		byte = isapnp_peek_byte();
		if ( buf )
			* ( ( uint8_t * ) buf + i ) = byte;
	}
}

/**
 * Find a tag within the resource data.
 *
 * @v wanted_tag	The tag that we're looking for
 * @v buf		Buffer in which to store the tag's contents
 * @v len		Length of buffer
 * @ret rc		Return status code
 *
 * Scan through the resource data until we find a particular tag, and
 * read its contents into a buffer.
 */
static int isapnp_find_tag ( unsigned int wanted_tag, void *buf, size_t len ) {
	unsigned int tag;
	unsigned int tag_len;

	DBG2 ( "ISAPnP read tag" );
	do {
		tag = isapnp_peek_byte();
		if ( ISAPNP_IS_SMALL_TAG ( tag ) ) {
			tag_len = ISAPNP_SMALL_TAG_LEN ( tag );
			tag = ISAPNP_SMALL_TAG_NAME ( tag );
		} else {
			tag_len = ( isapnp_peek_byte() +
				    ( isapnp_peek_byte() << 8 ) );
			tag = ISAPNP_LARGE_TAG_NAME ( tag );
		}
		DBG2 ( " %02x (%02x)", tag, tag_len );
		if ( tag == wanted_tag ) {
			if ( len > tag_len )
				len = tag_len;
			isapnp_peek ( buf, len );
			DBG2 ( "\n" );
			return 0;
		} else {
			isapnp_peek ( NULL, tag_len );
		}
	} while ( tag != ISAPNP_TAG_END );
	DBG2 ( "\n" );
	return -ENOENT;
}

/**
 * Find specified Logical Device ID tag
 *
 * @v logdev		Logical device ID
 * @v logdevid		Logical device ID structure to fill in
 * @ret rc		Return status code
 */
static int isapnp_find_logdevid ( unsigned int logdev,
				  struct isapnp_logdevid *logdevid ) {
	unsigned int i;
	int rc;

	for ( i = 0 ; i <= logdev ; i++ ) {
		if ( ( rc = isapnp_find_tag ( ISAPNP_TAG_LOGDEVID, logdevid,
					      sizeof ( *logdevid ) ) ) != 0 )
			return rc;
	}
	return 0;
}

/**
 * Try isolating ISAPnP cards at the current read port.
 *
 * @ret \>0		Number of ISAPnP cards found
 * @ret 0		There are no ISAPnP cards in the system
 * @ret \<0		A conflict was detected; try a new read port
 * @err None		-
 *
 * The state diagram on page 18 (PDF page 24) of the PnP ISA spec
 * gives the best overview of what happens here.
 */
static int isapnp_try_isolate ( void ) {
	struct isapnp_identifier identifier;
	unsigned int i, j;
	unsigned int seen_55aa, seen_life;
	unsigned int csn = 0;
	unsigned int data;
	unsigned int byte;

	DBG ( "ISAPnP attempting isolation at read port %04x\n",
	      isapnp_read_port );

	/* Place all cards into the Sleep state, whatever state
	 * they're currently in.
	 */
	isapnp_wait_for_key();
	isapnp_send_key();

	/* Reset all assigned CSNs */
	isapnp_reset_csn();
	isapnp_delay();
	isapnp_delay();
	
	/* Place all cards into the Isolation state */
	isapnp_wait_for_key ();
	isapnp_send_key();
	isapnp_wake ( 0x00 );
	
	/* Set the read port */
	isapnp_set_read_port();
	isapnp_delay();

	while ( 1 ) {

		/* All cards that do not have assigned CSNs are
		 * currently in the Isolation state, each time we go
		 * through this loop.
		 */

		/* Initiate serial isolation */
		isapnp_serialisolation();
		isapnp_delay();

		/* Read identifier serially via the ISAPnP read port. */
		memset ( &identifier, 0, sizeof ( identifier ) );
		seen_55aa = seen_life = 0;
		for ( i = 0 ; i < 9 ; i++ ) {
			byte = 0;
			for ( j = 0 ; j < 8 ; j++ ) {
				data = isapnp_read_data();
				isapnp_delay();
				data = ( ( data << 8 ) | isapnp_read_data() );
				isapnp_delay();
				byte >>= 1;
				if (  data != 0xffff ) {
					seen_life++;
					if ( data == 0x55aa ) {
						byte |= 0x80;
						seen_55aa++;
					}
				}
			}
			*( ( ( uint8_t * ) &identifier ) + i ) = byte;
		}

		/* If we didn't see any 55aa patterns, stop here */
		if ( ! seen_55aa ) {
			if ( csn ) {
				DBG ( "ISAPnP found no more cards\n" );
			} else {
				if ( seen_life ) {
					DBG ( "ISAPnP saw life but no cards, "
					      "trying new read port\n" );
					csn = -1;
				} else {
					DBG ( "ISAPnP saw no signs of life, "
					      "abandoning isolation\n" );
				}
			}
			break;
		}

		/* If the checksum was invalid stop here */
		if ( identifier.checksum != isapnp_checksum ( &identifier) ) {
			DBG ( "ISAPnP found malformed card "
			      ISAPNP_CARD_ID_FMT "\n  with checksum %02x "
			      "(should be %02x), trying new read port\n",
			      ISAPNP_CARD_ID_DATA ( &identifier ),
			      identifier.checksum,
			      isapnp_checksum ( &identifier) );
			csn = -1;
			break;
		}

		/* Give the device a CSN */
		csn++;
		DBG ( "ISAPnP found card " ISAPNP_CARD_ID_FMT
		      ", assigning CSN %02x\n",
		      ISAPNP_CARD_ID_DATA ( &identifier ), csn );
		
		isapnp_write_csn ( csn );
		isapnp_delay();

		/* Send this card back to Sleep and force all cards
		 * without a CSN into Isolation state
		 */
		isapnp_wake ( 0x00 );
		isapnp_delay();
	}

	/* Place all cards in Wait for Key state */
	isapnp_wait_for_key();

	/* Return number of cards found */
	if ( csn > 0 ) {
		DBG ( "ISAPnP found %d cards at read port %04x\n",
		      csn, isapnp_read_port );
	}
	return csn;
}

/**
 * Find a valid read port and isolate all ISAPnP cards.
 *
 */
static void isapnp_isolate ( void ) {
	for ( isapnp_read_port = ISAPNP_READ_PORT_START ;
	      isapnp_read_port <= ISAPNP_READ_PORT_MAX ;
	      isapnp_read_port += ISAPNP_READ_PORT_STEP ) {
		/* Avoid problematic locations such as the NE2000
		 * probe space
		 */
		if ( ( isapnp_read_port >= 0x280 ) &&
		     ( isapnp_read_port <= 0x380 ) )
			continue;
		
		/* If we detect any ISAPnP cards at this location, stop */
		if ( isapnp_try_isolate() >= 0 )
			return;
	}
}

/**
 * Activate or deactivate an ISAPnP device.
 *
 * @v isapnp		ISAPnP device
 * @v activation	True to enable, False to disable the device
 * @ret None		-
 * @err None		-
 *
 * This routine simply activates the device in its current
 * configuration, or deactivates the device.  It does not attempt any
 * kind of resource arbitration.
 *
 */
void isapnp_device_activation ( struct isapnp_device *isapnp,
				int activation ) {
	/* Wake the card and select the logical device */
	isapnp_wait_for_key ();
	isapnp_send_key ();
	isapnp_wake ( isapnp->csn );
	isapnp_logicaldevice ( isapnp->logdev );

	/* Activate/deactivate the logical device */
	isapnp_activate ( activation );
	isapnp_delay();

	/* Return all cards to Wait for Key state */
	isapnp_wait_for_key ();

	DBG ( "ISAPnP %s device %02x:%02x\n",
	      ( activation ? "activated" : "deactivated" ),
	      isapnp->csn, isapnp->logdev );
}

/**
 * Probe an ISAPnP device
 *
 * @v isapnp		ISAPnP device
 * @ret rc		Return status code
 *
 * Searches for a driver for the ISAPnP device.  If a driver is found,
 * its probe() routine is called.
 */
static int isapnp_probe ( struct isapnp_device *isapnp ) {
	struct isapnp_driver *driver;
	struct isapnp_device_id *id;
	unsigned int i;
	int rc;

	DBG ( "Adding ISAPnP device %02x:%02x (%04x:%04x (\"%s\") "
	      "io %x irq %d)\n", isapnp->csn, isapnp->logdev,
	      isapnp->vendor_id, isapnp->prod_id,
	      isa_id_string ( isapnp->vendor_id, isapnp->prod_id ),
	      isapnp->ioaddr, isapnp->irqno );

	for_each_table_entry ( driver, ISAPNP_DRIVERS ) {
		for ( i = 0 ; i < driver->id_count ; i++ ) {
			id = &driver->ids[i];
			if ( id->vendor_id != isapnp->vendor_id )
				continue;
			if ( ISA_PROD_ID ( id->prod_id ) !=
			     ISA_PROD_ID ( isapnp->prod_id ) )
				continue;
			isapnp->driver = driver;
			isapnp->dev.driver_name = id->name;
			DBG ( "...using driver %s\n", isapnp->dev.driver_name );
			if ( ( rc = driver->probe ( isapnp, id ) ) != 0 ) {
				DBG ( "......probe failed\n" );
				continue;
			}
			return 0;
		}
	}

	DBG ( "...no driver found\n" );
	return -ENOTTY;
}

/**
 * Remove an ISAPnP device
 *
 * @v isapnp		ISAPnP device
 */
static void isapnp_remove ( struct isapnp_device *isapnp ) {
	isapnp->driver->remove ( isapnp );
	DBG ( "Removed ISAPnP device %02x:%02x\n",
	      isapnp->csn, isapnp->logdev );
}

/**
 * Probe ISAPnP root bus
 *
 * @v rootdev		ISAPnP bus root device
 *
 * Scans the ISAPnP bus for devices and registers all devices it can
 * find.
 */
static int isapnpbus_probe ( struct root_device *rootdev ) {
	struct isapnp_device *isapnp = NULL;
	struct isapnp_identifier identifier;
	struct isapnp_logdevid logdevid;
	unsigned int csn;
	unsigned int logdev;
	int rc;

	/* Perform isolation if it hasn't yet been done */
	if ( ! isapnp_read_port )
		isapnp_isolate();

	for ( csn = 1 ; csn <= 0xff ; csn++ ) {
		for ( logdev = 0 ; logdev <= 0xff ; logdev++ ) {

			/* Allocate struct isapnp_device */
			if ( ! isapnp )
				isapnp = malloc ( sizeof ( *isapnp ) );
			if ( ! isapnp ) {
				rc = -ENOMEM;
				goto err;
			}
			memset ( isapnp, 0, sizeof ( *isapnp ) );
			isapnp->csn = csn;
			isapnp->logdev = logdev;

			/* Wake the card */
			isapnp_wait_for_key();
			isapnp_send_key();
			isapnp_wake ( csn );

			/* Read the card identifier */
			isapnp_peek ( &identifier, sizeof ( identifier ) );
			
			/* No card with this CSN; stop here */
			if ( identifier.vendor_id & 0x80 )
				goto done;

			/* Find the Logical Device ID tag */
			if ( ( rc = isapnp_find_logdevid ( logdev,
							   &logdevid ) ) != 0){
				/* No more logical devices; go to next CSN */
				break;
			}
			
			/* Select the logical device */
			isapnp_logicaldevice ( logdev );

			/* Populate struct isapnp_device */
			isapnp->vendor_id = logdevid.vendor_id;
			isapnp->prod_id = logdevid.prod_id;
			isapnp->ioaddr = isapnp_read_iobase ( 0 );
			isapnp->irqno = isapnp_read_irqno ( 0 );

			/* Return all cards to Wait for Key state */
			isapnp_wait_for_key();

			/* Add to device hierarchy */
			snprintf ( isapnp->dev.name,
				   sizeof ( isapnp->dev.name ),
				   "ISAPnP%02x:%02x", csn, logdev );
			isapnp->dev.desc.bus_type = BUS_TYPE_ISAPNP;
			isapnp->dev.desc.vendor = isapnp->vendor_id;
			isapnp->dev.desc.device = isapnp->prod_id;
			isapnp->dev.desc.ioaddr = isapnp->ioaddr;
			isapnp->dev.desc.irq = isapnp->irqno;
			isapnp->dev.parent = &rootdev->dev;
			list_add ( &isapnp->dev.siblings,
				   &rootdev->dev.children );
			INIT_LIST_HEAD ( &isapnp->dev.children );
			
			/* Look for a driver */
			if ( isapnp_probe ( isapnp ) == 0 ) {
				/* isapnpdev registered, we can drop our ref */
				isapnp = NULL;
			} else {
				/* Not registered; re-use struct */
				list_del ( &isapnp->dev.siblings );
			}
		}
	}

 done:
	free ( isapnp );
	return 0;

 err:
	free ( isapnp );
	isapnpbus_remove ( rootdev );
	return rc;
}

/**
 * Remove ISAPnP root bus
 *
 * @v rootdev		ISAPnP bus root device
 */
static void isapnpbus_remove ( struct root_device *rootdev ) {
	struct isapnp_device *isapnp;
	struct isapnp_device *tmp;

	list_for_each_entry_safe ( isapnp, tmp, &rootdev->dev.children,
				   dev.siblings ) {
		isapnp_remove ( isapnp );
		list_del ( &isapnp->dev.siblings );
		free ( isapnp );
	}
}

/** ISAPnP bus root device driver */
static struct root_driver isapnp_root_driver = {
	.probe = isapnpbus_probe,
	.remove = isapnpbus_remove,
};

/** ISAPnP bus root device */
struct root_device isapnp_root_device __root_device = {
	.dev = { .name = "ISAPnP" },
	.driver = &isapnp_root_driver,
};
