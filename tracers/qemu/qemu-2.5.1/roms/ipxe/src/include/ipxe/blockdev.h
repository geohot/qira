#ifndef _IPXE_BLOCKDEV_H
#define _IPXE_BLOCKDEV_H

/**
 * @file
 *
 * Block devices
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/uaccess.h>
#include <ipxe/interface.h>

/** Block device capacity */
struct block_device_capacity {
	/** Total number of blocks */
	uint64_t blocks;
	/** Block size */
	size_t blksize;
	/** Maximum number of blocks per single transfer */
	unsigned int max_count;
};

extern int block_read ( struct interface *control, struct interface *data,
			uint64_t lba, unsigned int count,
			userptr_t buffer, size_t len );
#define block_read_TYPE( object_type )					\
	typeof ( int ( object_type, struct interface *data,		\
		       uint64_t lba, unsigned int count,		\
		       userptr_t buffer, size_t len ) )

extern int block_write ( struct interface *control, struct interface *data,
			 uint64_t lba, unsigned int count,
			 userptr_t buffer, size_t len );
#define block_write_TYPE( object_type )					\
	typeof ( int ( object_type, struct interface *data,		\
		       uint64_t lba, unsigned int count,		\
		       userptr_t buffer, size_t len ) )

extern int block_read_capacity ( struct interface *control,
				 struct interface *data );
#define block_read_capacity_TYPE( object_type )				\
	typeof ( int ( object_type, struct interface *data ) )

extern void block_capacity ( struct interface *intf,
			     struct block_device_capacity *capacity );
#define block_capacity_TYPE( object_type )				\
	typeof ( void ( object_type,					\
			struct block_device_capacity *capacity ) )


#endif /* _IPXE_BLOCKDEV_H */
