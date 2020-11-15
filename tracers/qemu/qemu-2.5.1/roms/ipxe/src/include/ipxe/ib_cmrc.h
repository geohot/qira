#ifndef _IPXE_IB_CMRC_H
#define _IPXE_IB_CMRC_H

/** @file
 *
 * Infiniband Communication-managed Reliable Connections
 *
 */

FILE_LICENCE ( BSD2 );

#include <ipxe/infiniband.h>
#include <ipxe/xfer.h>

extern int ib_cmrc_open ( struct interface *xfer,
			  struct ib_device *ibdev,
			  union ib_gid *dgid,
			  union ib_guid *service_id );

#endif /* _IPXE_IB_CMRC_H */
