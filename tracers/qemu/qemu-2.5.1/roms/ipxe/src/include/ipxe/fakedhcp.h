#ifndef _IPXE_FAKEDHCP_H
#define _IPXE_FAKEDHCP_H

/** @file
 *
 * Fake DHCP packets
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

struct net_device;

extern int create_fakedhcpdiscover ( struct net_device *netdev,
				     void *data, size_t max_len );
extern int create_fakedhcpack ( struct net_device *netdev,
				void *data, size_t max_len );
extern int create_fakepxebsack ( struct net_device *netdev,
				 void *data, size_t max_len );

#endif /* _IPXE_FAKEDHCP_H */
