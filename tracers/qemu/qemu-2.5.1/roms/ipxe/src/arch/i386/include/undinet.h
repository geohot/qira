#ifndef _UNDINET_H
#define _UNDINET_H

/** @file
 *
 * UNDI network device driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct undi_device;

extern int undinet_probe ( struct undi_device *undi );
extern void undinet_remove ( struct undi_device *undi );

#endif /* _UNDINET_H */
