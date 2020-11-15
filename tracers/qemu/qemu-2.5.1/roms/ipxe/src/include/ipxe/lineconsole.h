#ifndef _IPXE_LINECONSOLE_H
#define _IPXE_LINECONSOLE_H

/** @file
 *
 * Line-based console
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/ansiesc.h>

/** A line-based console */
struct line_console {
	/** Data buffer
	 *
	 * Must initially be filled with NULs
	 */
	char *buffer;
	/** Current index within buffer */
	size_t index;
	/** Length of buffer
	 *
	 * The final character of the buffer will only ever be used as
	 * a potential terminating NUL.
	 */
	size_t len;
	/** ANSI escape sequence context */
	struct ansiesc_context ctx;
};

extern size_t line_putchar ( struct line_console *line, int character );

#endif /* _IPXE_LINECONSOLE_H */
