#ifndef _SKELETON_H
#define _SKELETON_H

/** @file
 *
 * Skeleton network driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** Skeleton BAR size */
#define SKELETON_BAR_SIZE 256

/** A skeleton network card */
struct skeleton_nic {
	/** Registers */
	void *regs;
	/** MII interface */
	struct mii_interface mii;
};

#endif /* _SKELETON_H */
