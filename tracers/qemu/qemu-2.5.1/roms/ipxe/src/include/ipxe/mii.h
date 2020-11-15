#ifndef _IPXE_MII_H
#define _IPXE_MII_H

/** @file
 *
 * Media Independent Interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <mii.h>
#include <ipxe/netdevice.h>

struct mii_interface;

/** MII interface operations */
struct mii_operations {
	/**
	 * Read from MII register
	 *
	 * @v mii		MII interface
	 * @v reg		Register address
	 * @ret data		Data read, or negative error
	 */
	int ( * read ) ( struct mii_interface *mii, unsigned int reg );
	/**
	 * Write to MII register
	 *
	 * @v mii		MII interface
	 * @v reg		Register address
	 * @v data		Data to write
	 * @ret rc		Return status code
	 */
	int ( * write ) ( struct mii_interface *mii, unsigned int reg,
			  unsigned int data );
};

/** An MII interface */
struct mii_interface {
	/** Interface operations */
	struct mii_operations *op;
};

/**
 * Initialise MII interface
 *
 * @v mii		MII interface
 * @v op		MII interface operations
 */
static inline __attribute__ (( always_inline )) void
mii_init ( struct mii_interface *mii, struct mii_operations *op ) {
	mii->op = op;
}

/**
 * Read from MII register
 *
 * @v mii		MII interface
 * @v reg		Register address
 * @ret data		Data read, or negative error
 */
static inline __attribute__ (( always_inline )) int
mii_read ( struct mii_interface *mii, unsigned int reg ) {
	return mii->op->read ( mii, reg );
}

/**
 * Write to MII register
 *
 * @v mii		MII interface
 * @v reg		Register address
 * @v data		Data to write
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
mii_write ( struct mii_interface *mii, unsigned int reg, unsigned int data ) {
	return mii->op->write ( mii, reg, data );
}

/**
 * Dump MII registers (for debugging)
 *
 * @v mii		MII interface
 */
static inline void
mii_dump ( struct mii_interface *mii ) {
	unsigned int i;
	int data;

	/* Do nothing unless debug output is enabled */
	if ( ! DBG_LOG )
		return;

	/* Dump basic MII register set */
	for ( i = 0 ; i < 16 ; i++ ) {
		if ( ( i % 8 ) == 0 ) {
			DBGC ( mii, "MII %p registers %02x-%02x:",
			       mii, i, ( i + 7 ) );
		}
		data = mii_read ( mii, i );
		if ( data >= 0 ) {
			DBGC ( mii, " %04x", data );
		} else {
			DBGC ( mii, " XXXX" );
		}
		if ( ( i % 8 ) == 7 )
			DBGC ( mii, "\n" );
	}
}

/** Maximum time to wait for a reset, in milliseconds */
#define MII_RESET_MAX_WAIT_MS 500

extern int mii_restart ( struct mii_interface *mii );
extern int mii_reset ( struct mii_interface *mii );
extern int mii_check_link ( struct mii_interface *mii,
			    struct net_device *netdev );

#endif /* _IPXE_MII_H */
