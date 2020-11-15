#ifndef _USR_IFMGMT_H
#define _USR_IFMGMT_H

/** @file
 *
 * Network interface management
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct net_device;
struct net_device_configurator;

extern int ifopen ( struct net_device *netdev );
extern int ifconf ( struct net_device *netdev,
		    struct net_device_configurator *configurator );
extern void ifclose ( struct net_device *netdev );
extern void ifstat ( struct net_device *netdev );
extern int iflinkwait ( struct net_device *netdev, unsigned long timeout );

#endif /* _USR_IFMGMT_H */
