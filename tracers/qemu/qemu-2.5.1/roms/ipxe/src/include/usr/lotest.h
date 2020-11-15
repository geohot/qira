#ifndef _USR_LOTEST_H
#define _USR_LOTEST_H

/** @file
 *
 * Loopback testing
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

extern int loopback_test ( struct net_device *sender,
			   struct net_device *receiver, size_t mtu );

#endif /* _USR_LOTEST_H */
