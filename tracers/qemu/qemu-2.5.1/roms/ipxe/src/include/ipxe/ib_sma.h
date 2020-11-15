#ifndef _IPXE_IB_SMA_H
#define _IPXE_IB_SMA_H

/** @file
 *
 * Infiniband subnet management agent
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct ib_device;
struct ib_mad_interface;

extern int ib_create_sma ( struct ib_device *ibdev,
			   struct ib_mad_interface *mi );
extern void ib_destroy_sma ( struct ib_device *ibdev,
			     struct ib_mad_interface *mi );

#endif /* _IPXE_IB_SMA_H */
