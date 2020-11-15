/*
 * Split out into 3c509.c and 3c5x9.c, to make it possible to build a
 * 3c529 module without including ISA, ISAPnP and EISA code.
 *
 */

FILE_LICENCE ( BSD2 );

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/io.h>
#include <unistd.h>
#include <ipxe/device.h>
#include <ipxe/isa.h>
#include "3c509.h"

/*
 * 3c509 cards have their own method of contention resolution; this
 * effectively defines another bus type similar to ISAPnP.  Even the
 * original ISA cards can be programatically mapped to any I/O address
 * in the range 0x200-0x3e0.
 * 
 * However, there is a small problem: once you've activated a card,
 * the only ways to deactivate it will also wipe its tag, meaning that
 * you won't be able to subsequently reactivate it without going
 * through the whole ID sequence again.  The solution we adopt is to
 * isolate and tag all cards at the start, and to immediately
 * re-isolate and re-tag a card after disabling it.
 *
 */

static void t509bus_remove ( struct root_device *rootdev );

static unsigned int t509_id_port = 0;
static unsigned int t509_max_tag = 0;

/** A 3c509 device */
struct t509_device {
	/** Generic device */
	struct device dev;
	/** Tag */
	unsigned int tag;
	/** I/O address */
	uint16_t ioaddr;
	/** Driver-private data
	 *
	 * Use t509_set_drvdata() and t509_get_drvdata() to access
	 * this field.
	 */
	void *priv;
};

/**
 * Set 3c509 driver-private data
 *
 * @v t509		3c509 device
 * @v priv		Private data
 */
static inline void t509_set_drvdata ( struct t509_device *t509, void *priv ) {
	t509->priv = priv;
}

/**
 * Get 3c509 driver-private data
 *
 * @v t509		3c509 device
 * @ret priv		Private data
 */
static inline void * t509_get_drvdata ( struct t509_device *t509 ) {
	return t509->priv;
}

/*
 * t509 utility functions
 *
 */

static inline void t509_set_id_port ( void ) {
	outb ( 0x00, t509_id_port );
}

static inline void t509_wait_for_id_sequence ( void ) {
	outb ( 0x00, t509_id_port );
}

static inline void t509_global_reset ( void ) {
	outb ( 0xc0, t509_id_port );
}

static inline void t509_reset_tag ( void ) {
	outb ( 0xd0, t509_id_port );
}

static inline void t509_set_tag ( uint8_t tag ) {
	outb ( 0xd0 | tag, t509_id_port );
}

static inline void t509_select_tag ( uint8_t tag ) {
	outb ( 0xd8 | tag, t509_id_port );
}

static inline void t509_activate ( uint16_t ioaddr ) {
	outb ( 0xe0 | ( ioaddr >> 4 ), t509_id_port );
}

static inline void t509_deactivate_and_reset_tag ( uint16_t ioaddr ) {
	outb ( GLOBAL_RESET, ioaddr + EP_COMMAND );
}

static inline void t509_load_eeprom_word ( uint8_t offset ) {
	outb ( 0x80 | offset, t509_id_port );
}

/*
 * Find a suitable ID port
 *
 */
static inline int t509_find_id_port ( void ) {

	for ( t509_id_port = EP_ID_PORT_START ;
	      t509_id_port < EP_ID_PORT_END ;
	      t509_id_port += EP_ID_PORT_INC ) {
		t509_set_id_port ();
		/* See if anything's listening */
		outb ( 0xff, t509_id_port );
		if ( inb ( t509_id_port ) & 0x01 ) {
			/* Found a suitable port */
			DBG ( "T509 using ID port at %04x\n", t509_id_port );
			return 0;
		}
	}
	/* No id port available */
	DBG ( "T509 found no available ID port\n" );
	return -ENOENT;
}

/*
 * Send ID sequence to the ID port
 *
 */
static void t509_send_id_sequence ( void ) {
	unsigned short lrs_state, i;

	t509_set_id_port ();
	/* Reset IDS on cards */
	t509_wait_for_id_sequence ();
	lrs_state = 0xff;
        for ( i = 0; i < 255; i++ ) {
                outb ( lrs_state, t509_id_port );
                lrs_state <<= 1;
                lrs_state = lrs_state & 0x100 ? lrs_state ^ 0xcf : lrs_state;
        }
}

/*
 * We get eeprom data from the id_port given an offset into the eeprom.
 * Basically; after the ID_sequence is sent to all of the cards; they enter
 * the ID_CMD state where they will accept command requests. 0x80-0xbf loads
 * the eeprom data.  We then read the port 16 times and with every read; the
 * cards check for contention (ie: if one card writes a 0 bit and another
 * writes a 1 bit then the host sees a 0. At the end of the cycle; each card
 * compares the data on the bus; if there is a difference then that card goes
 * into ID_WAIT state again). In the meantime; one bit of data is returned in
 * the AX register which is conveniently returned to us by inb().  Hence; we
 * read 16 times getting one bit of data with each read.
 */
static uint16_t t509_id_read_eeprom ( int offset ) {
	int i, data = 0;

	t509_load_eeprom_word ( offset );
	/* Do we really need this wait? Won't be noticeable anyway */
	udelay(10000);

	for ( i = 0; i < 16; i++ ) {
		data = ( data << 1 ) | ( inw ( t509_id_port ) & 1 );
	}
	return data;
}

/*
 * Isolate and tag all t509 cards
 *
 */
static int t509_isolate ( void ) {
	unsigned int i;
	uint16_t contend[3];
	int rc;

	/* Find a suitable ID port */
	if ( ( rc = t509_find_id_port() ) != 0 )
		return rc;

	while ( 1 ) {

		/* All cards are in ID_WAIT state each time we go
		 * through this loop.
		 */

		/* Send the ID sequence */
		t509_send_id_sequence();

		/* First time through, reset all tags.  On subsequent
		 * iterations, kill off any already-tagged cards
		 */
		if ( t509_max_tag == 0 ) {
			t509_reset_tag();
		} else {
			t509_select_tag ( 0 );
		}
	
		/* Read the manufacturer ID, to see if there are any
		 * more cards
		 */
		if ( t509_id_read_eeprom ( EEPROM_MFG_ID ) != MFG_ID ) {
			DBG ( "T509 saw %s signs of life\n",
			      t509_max_tag ? "no further" : "no" );
			break;
		}

		/* Perform contention selection on the MAC address */
		for ( i = 0 ; i < 3 ; i++ ) {
			contend[i] = t509_id_read_eeprom ( i );
		}

		/* Only one device will still be left alive.  Tag it. */
		++t509_max_tag;
		DBG ( "T509 found card %04x%04x%04x, assigning tag %02x\n",
		      contend[0], contend[1], contend[2], t509_max_tag );
		t509_set_tag ( t509_max_tag );

		/* Return all cards back to ID_WAIT state */
		t509_wait_for_id_sequence();
	}

	DBG ( "T509 found %d cards using ID port %04x\n",
	      t509_max_tag, t509_id_port );
	return 0;
}

/*
 * Activate a T509 device
 *
 * The device will be enabled at whatever ioaddr is specified in the
 * struct t509_device; there is no need to stick with the default
 * ioaddr read from the EEPROM.
 *
 */
static inline void activate_t509_device ( struct t509_device *t509 ) {
	t509_send_id_sequence ();
	t509_select_tag ( t509->tag );
	t509_activate ( t509->ioaddr );
	DBG ( "T509 activated device %02x at ioaddr %04x\n",
	      t509->tag, t509->ioaddr );
}

/*
 * Deactivate a T509 device
 *
 * Disabling also clears the tag, so we immediately isolate and re-tag
 * this card.
 *
 */
static inline void deactivate_t509_device ( struct t509_device *t509 ) {
	t509_deactivate_and_reset_tag ( t509->ioaddr );
	udelay ( 1000 );
	t509_send_id_sequence ();
	t509_select_tag ( 0 );
	t509_set_tag ( t509->tag );
	t509_wait_for_id_sequence ();
	DBG ( "T509 deactivated device at %04x and re-tagged as %02x\n",
	      t509->ioaddr, t509->tag );
}

/*
 * The ISA probe function
 *
 */
static int legacy_t509_probe ( struct nic *nic, void *hwdev ) {
	struct t509_device *t509 = hwdev;

	/* We could change t509->ioaddr if we wanted to */
	activate_t509_device ( t509 );
	nic->ioaddr = t509->ioaddr;

	/* Hand off to generic t5x9 probe routine */
	return t5x9_probe ( nic, ISA_PROD_ID ( PROD_ID ), ISA_PROD_ID_MASK );
}

static void legacy_t509_disable ( struct nic *nic, void *hwdev ) {
	struct t509_device *t509 = hwdev;

	t5x9_disable ( nic );
	deactivate_t509_device ( t509 );
}

static inline void legacy_t509_set_drvdata ( void *hwdev, void *priv ) {
	t509_set_drvdata ( hwdev, priv );
}

static inline void * legacy_t509_get_drvdata ( void *hwdev ) {
	return t509_get_drvdata ( hwdev );
}

/**
 * Probe a 3c509 device
 *
 * @v t509		3c509 device
 * @ret rc		Return status code
 *
 * Searches for a driver for the 3c509 device.  If a driver is found,
 * its probe() routine is called.
 */
static int t509_probe ( struct t509_device *t509 ) {
	DBG ( "Adding 3c509 device %02x (I/O %04x)\n",
	      t509->tag, t509->ioaddr );
	return legacy_probe ( t509, legacy_t509_set_drvdata, &t509->dev,
			      legacy_t509_probe, legacy_t509_disable );
}

/**
 * Remove a 3c509 device
 *
 * @v t509		3c509 device
 */
static void t509_remove ( struct t509_device *t509 ) {
	legacy_remove ( t509, legacy_t509_get_drvdata, legacy_t509_disable );
	DBG ( "Removed 3c509 device %02x\n", t509->tag );
}

/**
 * Probe 3c509 root bus
 *
 * @v rootdev		3c509 bus root device
 *
 * Scans the 3c509 bus for devices and registers all devices it can
 * find.
 */
static int t509bus_probe ( struct root_device *rootdev ) {
	struct t509_device *t509 = NULL;
	unsigned int tag;
	unsigned int iobase;
	int rc;

	/* Perform isolation and tagging */
	if ( ( rc = t509_isolate() ) != 0 )
		return rc;

	for ( tag = 1 ; tag <= t509_max_tag ; tag++ ) {
		/* Allocate struct t509_device */
		if ( ! t509 )
			t509 = malloc ( sizeof ( *t509 ) );
		if ( ! t509 ) {
			rc = -ENOMEM;
			goto err;
		}
		memset ( t509, 0, sizeof ( *t509 ) );
		t509->tag = tag;

		/* Send the ID sequence */
		t509_send_id_sequence ();

		/* Select the specified tag */
		t509_select_tag ( t509->tag );

		/* Read the default I/O address */
		iobase = t509_id_read_eeprom ( EEPROM_ADDR_CFG );
		t509->ioaddr = 0x200 + ( ( iobase & 0x1f ) << 4 );

		/* Send card back to ID_WAIT */
		t509_wait_for_id_sequence();

		/* Add to device hierarchy */
		snprintf ( t509->dev.name, sizeof ( t509->dev.name ),
			   "t509%02x", tag );
		t509->dev.desc.bus_type = BUS_TYPE_ISA;
		t509->dev.desc.vendor = MFG_ID;
		t509->dev.desc.device = PROD_ID;
		t509->dev.parent = &rootdev->dev;
		list_add ( &t509->dev.siblings, &rootdev->dev.children );
		INIT_LIST_HEAD ( &t509->dev.children );
			
		/* Look for a driver */
		if ( t509_probe ( t509 ) == 0 ) {
			/* t509dev registered, we can drop our ref */
			t509 = NULL;
		} else {
			/* Not registered; re-use struct */
			list_del ( &t509->dev.siblings );
		}
	}

	free ( t509 );
	return 0;

 err:
	free ( t509 );
	t509bus_remove ( rootdev );
	return rc;
}

/**
 * Remove 3c509 root bus
 *
 * @v rootdev		3c509 bus root device
 */
static void t509bus_remove ( struct root_device *rootdev ) {
	struct t509_device *t509;
	struct t509_device *tmp;

	list_for_each_entry_safe ( t509, tmp, &rootdev->dev.children,
				   dev.siblings ) {
		t509_remove ( t509 );
		list_del ( &t509->dev.siblings );
		free ( t509 );
	}
}

/** 3c509 bus root device driver */
static struct root_driver t509_root_driver = {
	.probe = t509bus_probe,
	.remove = t509bus_remove,
};

/** 3c509 bus root device */
struct root_device t509_root_device __root_device = {
	.dev = { .name = "3c509" },
	.driver = &t509_root_driver,
};

ISA_ROM ( "3c509", "3c509" );
