#ifndef _IPXE_LINEBUF_H
#define _IPXE_LINEBUF_H

/** @file
 *
 * Line buffering
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stddef.h>

/** A line buffer */
struct line_buffer {
	/** Data buffer */
	char *data;
	/** Length of buffered data */
	size_t len;
	/** Most recently consumed length */
	size_t consumed;
};

extern char * buffered_line ( struct line_buffer *linebuf );
extern int line_buffer ( struct line_buffer *linebuf,
			 const char *data, size_t len );
extern void empty_line_buffer ( struct line_buffer *linebuf );

#endif /* _IPXE_LINEBUF_H */
