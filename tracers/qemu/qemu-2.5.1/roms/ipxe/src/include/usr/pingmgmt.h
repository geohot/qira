#ifndef _USR_PINGMGMT_H
#define _USR_PINGMGMT_H

/** @file
 *
 * ICMP ping management
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

extern int ping ( const char *hostname, unsigned long timeout, size_t len,
		  unsigned int count, int quiet );

#endif /* _USR_PINGMGMT_H */
