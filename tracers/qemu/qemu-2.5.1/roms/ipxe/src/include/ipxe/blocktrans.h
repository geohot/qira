#ifndef _IPXE_BLOCKTRANS_H
#define _IPXE_BLOCKTRANS_H

/** @file
 *
 * Block device translator
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/refcnt.h>
#include <ipxe/interface.h>
#include <ipxe/xferbuf.h>
#include <ipxe/uaccess.h>

/** A block device translator */
struct block_translator {
	/** Reference count */
	struct refcnt refcnt;
	/** Block device interface */
	struct interface block;
	/** Data transfer interface */
	struct interface xfer;

	/** Data transfer buffer */
	struct xfer_buffer xferbuf;
	/** Data buffer */
	userptr_t buffer;
	/** Block size */
	size_t blksize;
};

extern int block_translate ( struct interface *block,
			     userptr_t buffer, size_t size );

#endif /* _IPXE_BLOCKTRANS_H */
