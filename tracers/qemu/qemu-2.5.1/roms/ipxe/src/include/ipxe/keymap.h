#ifndef _IPXE_KEYMAP_H
#define _IPXE_KEYMAP_H

/**
 * @file
 *
 * Keyboard mappings
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/tables.h>

/** A keyboard mapping */
struct key_mapping {
	/** Character read from keyboard */
	uint8_t from;
	/** Character to be used instead */
	uint8_t to;
} __attribute__ (( packed ));

/** Keyboard mapping table */
#define KEYMAP __table ( struct key_mapping, "keymap" )

/** Define a keyboard mapping */
#define __keymap __table_entry ( KEYMAP, 01 )

#endif /* _IPXE_KEYMAP_H */
