#ifndef _IPXE_IB_SRP_H
#define _IPXE_IB_SRP_H

/** @file
 *
 * SCSI RDMA Protocol over Infiniband
 *
 */

FILE_LICENCE ( BSD2 );

#include <stdint.h>
#include <ipxe/infiniband.h>
#include <ipxe/srp.h>

/** SRP initiator port identifier for Infiniband */
union ib_srp_initiator_port_id {
	/** SRP version of port identifier */
	union srp_port_id srp;
	/** Infiniband version of port identifier */
	struct {
		/** Identifier extension */
		union ib_guid id_ext;
		/** IB channel adapter GUID */
		union ib_guid hca_guid;
	} __attribute__ (( packed )) ib;
};

/** SRP target port identifier for Infiniband */
union ib_srp_target_port_id {
	/** SRP version of port identifier */
	union srp_port_id srp;
	/** Infiniband version of port identifier */
	struct {
		/** Identifier extension */
		union ib_guid id_ext;
		/** I/O controller GUID */
		union ib_guid ioc_guid;
	} __attribute__ (( packed )) ib;
};

/**
 * sBFT Infiniband subtable
 */
struct sbft_ib_subtable {
	/** Source GID */
	union ib_gid sgid;
	/** Destination GID */
	union ib_gid dgid;
	/** Service ID */
	union ib_guid service_id;
	/** Partition key */
	uint16_t pkey;
	/** Reserved */
	uint8_t reserved[6];
} __attribute__ (( packed ));

#endif /* _IPXE_IB_SRP_H */
