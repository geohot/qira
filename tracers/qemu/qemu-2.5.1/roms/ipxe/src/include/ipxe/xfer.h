#ifndef _IPXE_XFER_H
#define _IPXE_XFER_H

/** @file
 *
 * Data transfer interfaces
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <stdarg.h>
#include <ipxe/interface.h>

struct xfer_metadata;
struct io_buffer;
struct sockaddr;
struct net_device;

/** Data transfer metadata */
struct xfer_metadata {
	/** Flags
	 *
	 * This is the bitwise OR of zero or more @c XFER_FL_XXX
	 * constants.
	 */
	unsigned int flags;
	/** Offset of data within stream
	 *
	 * This is an absolute offset if the @c XFER_FL_ABS_OFFSET
	 * flag is set, otherwise a relative offset.  (A freshly
	 * zeroed @c xfer_metadata structure therefore represents a
	 * relative offset of zero, i.e. no offset from the current
	 * position.)
	 */
	off_t offset;
	/** Source socket address, or NULL */
	struct sockaddr *src;
	/** Destination socket address, or NULL */
	struct sockaddr *dest;
	/** Network device, or NULL */
	struct net_device *netdev;
};

/** Offset is absolute */
#define XFER_FL_ABS_OFFSET 0x0001

/** Sender is relinquishing use of half-duplex channel */
#define XFER_FL_OVER 0x0002

/** This is the final data transfer */
#define XFER_FL_OUT 0x0004

/** Data content represents a command or status message
 *
 * The flag @c XFER_FL_RESPONSE is used to distinguish between a
 * command message and a status message.
 */
#define XFER_FL_CMD_STAT 0x0008

/** Data content is a response */
#define XFER_FL_RESPONSE 0x0010

/* Data transfer interface operations */

extern int xfer_vredirect ( struct interface *intf, int type,
			    va_list args );
#define xfer_vredirect_TYPE( object_type ) \
	typeof ( int ( object_type, int type, va_list args ) )

extern size_t xfer_window ( struct interface *intf );
#define xfer_window_TYPE( object_type ) \
	typeof ( size_t ( object_type ) )

extern void xfer_window_changed ( struct interface *intf );
#define xfer_window_changed_TYPE( object_type ) \
	typeof ( void ( object_type ) )

extern struct io_buffer * xfer_alloc_iob ( struct interface *intf,
					   size_t len );
#define xfer_alloc_iob_TYPE( object_type ) \
	typeof ( struct io_buffer * ( object_type, size_t len ) )

extern int xfer_deliver ( struct interface *intf,
			  struct io_buffer *iobuf,
			  struct xfer_metadata *meta );
#define xfer_deliver_TYPE( object_type )			\
	typeof ( int ( object_type, struct io_buffer *iobuf,	\
		       struct xfer_metadata *meta ) )

/* Data transfer interface helper functions */

extern int xfer_redirect ( struct interface *xfer, int type, ... );
extern int xfer_deliver_iob ( struct interface *intf,
			      struct io_buffer *iobuf );
extern int xfer_deliver_raw_meta ( struct interface *intf, const void *data,
				   size_t len, struct xfer_metadata *meta );
extern int xfer_deliver_raw ( struct interface *intf,
			      const void *data, size_t len );
extern int xfer_vprintf ( struct interface *intf,
			  const char *format, va_list args );
extern int __attribute__ (( format ( printf, 2, 3 ) ))
xfer_printf ( struct interface *intf, const char *format, ... );
extern int xfer_seek ( struct interface *intf, off_t offset );
extern int xfer_check_order ( struct xfer_metadata *meta, size_t *pos,
			      size_t len );

#endif /* _IPXE_XFER_H */
