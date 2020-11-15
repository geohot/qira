#ifndef _IPXE_MONOJOB_H
#define _IPXE_MONOJOB_H

/** @file
 *
 * Single foreground job
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct interface;

extern struct interface monojob;

extern int monojob_wait ( const char *string, unsigned long timeout );

#endif /* _IPXE_MONOJOB_H */
