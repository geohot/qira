#ifndef _BASEMEM_H
#define _BASEMEM_H

/** @file
 *
 * Base memory allocation
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <realmode.h>
#include <bios.h>

/**
 * Read the BIOS free base memory counter
 *
 * @ret fbms		Free base memory counter (in kB)
 */
static inline unsigned int get_fbms ( void ) {
	uint16_t fbms;

	get_real ( fbms, BDA_SEG, BDA_FBMS );
	return fbms;
}

extern void set_fbms ( unsigned int new_fbms );

/* Actually in hidemem.c, but putting it here avoids polluting the
 * architecture-independent include/hidemem.h.
 */
extern void hide_basemem ( void );

#endif /* _BASEMEM_H */
