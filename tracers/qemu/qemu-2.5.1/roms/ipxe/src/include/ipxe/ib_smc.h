#ifndef _IPXE_IB_SMC_H
#define _IPXE_IB_SMC_H

/** @file
 *
 * Infiniband Subnet Management Client
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/infiniband.h>

typedef int ( * ib_local_mad_t ) ( struct ib_device *ibdev,
				   union ib_mad *mad );

extern int ib_smc_init ( struct ib_device *ibdev, ib_local_mad_t local_mad );
extern int ib_smc_update ( struct ib_device *ibdev, ib_local_mad_t local_mad );

#endif /* _IPXE_IB_SMC_H */
