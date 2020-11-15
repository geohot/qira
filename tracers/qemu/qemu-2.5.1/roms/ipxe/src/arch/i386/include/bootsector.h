#ifndef _BOOTSECTOR_H
#define _BOOTSECTOR_H

/** @file
 *
 * x86 bootsector image format
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

extern int call_bootsector ( unsigned int segment, unsigned int offset,
			     unsigned int drive );

#endif /* _BOOTSECTOR_H */
