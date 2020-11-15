#ifndef _USR_IWMGMT_H
#define _USR_IWMGMT_H

/** @file
 *
 * Wireless network interface management
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

struct net80211_device;

extern void iwstat ( struct net80211_device *dev );
extern int iwlist ( struct net80211_device *dev );

#endif /* _USR_IWMGMT_H */
