/*
 * Copyright (C) 2009 Fen Systems Ltd <mbrown@fensystems.co.uk>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

FILE_LICENCE ( BSD2 );

#include <stdlib.h>
#include <errno.h>
#include <ipxe/interface.h>
#include <ipxe/uri.h>
#include <ipxe/open.h>
#include <ipxe/base16.h>
#include <ipxe/acpi.h>
#include <ipxe/srp.h>
#include <ipxe/infiniband.h>
#include <ipxe/ib_cmrc.h>
#include <ipxe/ib_srp.h>

/**
 * @file
 *
 * SCSI RDMA Protocol over Infiniband
 *
 */

/* Disambiguate the various possible EINVALs */
#define EINVAL_BYTE_STRING_LEN __einfo_error ( EINFO_EINVAL_BYTE_STRING_LEN )
#define EINFO_EINVAL_BYTE_STRING_LEN __einfo_uniqify \
	( EINFO_EINVAL, 0x01, "Invalid byte string length" )
#define EINVAL_INTEGER __einfo_error ( EINFO_EINVAL_INTEGER )
#define EINFO_EINVAL_INTEGER __einfo_uniqify \
	( EINFO_EINVAL, 0x03, "Invalid integer" )
#define EINVAL_RP_TOO_SHORT __einfo_error ( EINFO_EINVAL_RP_TOO_SHORT )
#define EINFO_EINVAL_RP_TOO_SHORT __einfo_uniqify \
	( EINFO_EINVAL, 0x04, "Root path too short" )

/******************************************************************************
 *
 * IB SRP devices
 *
 ******************************************************************************
 */

/** An Infiniband SRP device */
struct ib_srp_device {
	/** Reference count */
	struct refcnt refcnt;

	/** SRP transport interface */
	struct interface srp;
	/** CMRC interface */
	struct interface cmrc;

	/** Infiniband device */
	struct ib_device *ibdev;

	/** Destination GID (for boot firmware table) */
	union ib_gid dgid;
	/** Service ID (for boot firmware table) */
	union ib_guid service_id;
};

/**
 * Free IB SRP device
 *
 * @v refcnt		Reference count
 */
static void ib_srp_free ( struct refcnt *refcnt ) {
	struct ib_srp_device *ib_srp =
		container_of ( refcnt, struct ib_srp_device, refcnt );

	ibdev_put ( ib_srp->ibdev );
	free ( ib_srp );
}

/**
 * Close IB SRP device
 *
 * @v ib_srp		IB SRP device
 * @v rc		Reason for close
 */
static void ib_srp_close ( struct ib_srp_device *ib_srp, int rc ) {

	/* Shut down interfaces */
	intf_shutdown ( &ib_srp->cmrc, rc );
	intf_shutdown ( &ib_srp->srp, rc );
}

/**
 * Describe IB SRP device in an ACPI table
 *
 * @v srpdev		SRP device
 * @v acpi		ACPI table
 * @v len		Length of ACPI table
 * @ret rc		Return status code
 */
static int ib_srp_describe ( struct ib_srp_device *ib_srp,
			     struct acpi_description_header *acpi,
			     size_t len ) {
	struct ib_device *ibdev = ib_srp->ibdev;
	struct sbft_table *sbft =
		container_of ( acpi, struct sbft_table, acpi );
	struct sbft_ib_subtable *ib_sbft;
	size_t used;

	/* Sanity check */
	if ( acpi->signature != SBFT_SIG )
		return -EINVAL;

	/* Append IB subtable to existing table */
	used = le32_to_cpu ( sbft->acpi.length );
	sbft->ib_offset = cpu_to_le16 ( used );
	ib_sbft = ( ( ( void * ) sbft ) + used );
	used += sizeof ( *ib_sbft );
	if ( used > len )
		return -ENOBUFS;
	sbft->acpi.length = cpu_to_le32 ( used );

	/* Populate subtable */
	memcpy ( &ib_sbft->sgid, &ibdev->gid, sizeof ( ib_sbft->sgid ) );
	memcpy ( &ib_sbft->dgid, &ib_srp->dgid, sizeof ( ib_sbft->dgid ) );
	memcpy ( &ib_sbft->service_id, &ib_srp->service_id,
		 sizeof ( ib_sbft->service_id ) );
	ib_sbft->pkey = cpu_to_le16 ( ibdev->pkey );

	return 0;
}

/** IB SRP CMRC interface operations */
static struct interface_operation ib_srp_cmrc_op[] = {
	INTF_OP ( intf_close, struct ib_srp_device *, ib_srp_close ),
};

/** IB SRP CMRC interface descriptor */
static struct interface_descriptor ib_srp_cmrc_desc =
	INTF_DESC_PASSTHRU ( struct ib_srp_device, cmrc, ib_srp_cmrc_op, srp );

/** IB SRP SRP interface operations */
static struct interface_operation ib_srp_srp_op[] = {
	INTF_OP ( acpi_describe, struct ib_srp_device *, ib_srp_describe ),
	INTF_OP ( intf_close, struct ib_srp_device *, ib_srp_close ),
};

/** IB SRP SRP interface descriptor */
static struct interface_descriptor ib_srp_srp_desc =
	INTF_DESC_PASSTHRU ( struct ib_srp_device, srp, ib_srp_srp_op, cmrc );

/**
 * Open IB SRP device
 *
 * @v block		Block control interface
 * @v ibdev		Infiniband device
 * @v dgid		Destination GID
 * @v service_id	Service ID
 * @v initiator		Initiator port ID
 * @v target		Target port ID
 * @v lun		SCSI LUN
 * @ret rc		Return status code
 */
static int ib_srp_open ( struct interface *block, struct ib_device *ibdev,
			 union ib_gid *dgid, union ib_guid *service_id,
			 union srp_port_id *initiator,
			 union srp_port_id *target, struct scsi_lun *lun ) {
	struct ib_srp_device *ib_srp;
	int rc;

	/* Allocate and initialise structure */
	ib_srp = zalloc ( sizeof ( *ib_srp ) );
	if ( ! ib_srp ) {
		rc = -ENOMEM;
		goto err_zalloc;
	}
	ref_init ( &ib_srp->refcnt, ib_srp_free );
	intf_init ( &ib_srp->srp, &ib_srp_srp_desc, &ib_srp->refcnt );
	intf_init ( &ib_srp->cmrc, &ib_srp_cmrc_desc, &ib_srp->refcnt );
	ib_srp->ibdev = ibdev_get ( ibdev );
	DBGC ( ib_srp, "IBSRP %p for " IB_GID_FMT " " IB_GUID_FMT "\n",
	       ib_srp, IB_GID_ARGS ( dgid ), IB_GUID_ARGS ( service_id ) );

	/* Preserve parameters required for boot firmware table */
	memcpy ( &ib_srp->dgid, dgid, sizeof ( ib_srp->dgid ) );
	memcpy ( &ib_srp->service_id, service_id,
		 sizeof ( ib_srp->service_id ) );

	/* Open CMRC socket */
	if ( ( rc = ib_cmrc_open ( &ib_srp->cmrc, ibdev, dgid,
				   service_id ) ) != 0 ) {
		DBGC ( ib_srp, "IBSRP %p could not open CMRC socket: %s\n",
		       ib_srp, strerror ( rc ) );
		goto err_cmrc_open;
	}

	/* Attach SRP device to parent interface */
	if ( ( rc = srp_open ( block, &ib_srp->srp, initiator, target,
			       ibdev->rdma_key, lun ) ) != 0 ) {
		DBGC ( ib_srp, "IBSRP %p could not create SRP device: %s\n",
		       ib_srp, strerror ( rc ) );
		goto err_srp_open;
	}

	/* Mortalise self and return */
	ref_put ( &ib_srp->refcnt );
	return 0;

 err_srp_open:
 err_cmrc_open:
	ib_srp_close ( ib_srp, rc );
	ref_put ( &ib_srp->refcnt );
 err_zalloc:
	return rc;
}

/******************************************************************************
 *
 * IB SRP URIs
 *
 ******************************************************************************
 */

/** IB SRP parse flags */
enum ib_srp_parse_flags {
	IB_SRP_PARSE_REQUIRED = 0x0000,
	IB_SRP_PARSE_OPTIONAL = 0x8000,
	IB_SRP_PARSE_FLAG_MASK = 0xf000,
};

/** IB SRP root path parameters */
struct ib_srp_root_path {
	/** Source GID */
	union ib_gid sgid;
	/** Initiator port ID */
	union ib_srp_initiator_port_id initiator;
	/** Destination GID */
	union ib_gid dgid;
	/** Partition key */
	uint16_t pkey;
	/** Service ID */
	union ib_guid service_id;
	/** SCSI LUN */
	struct scsi_lun lun;
	/** Target port ID */
	union ib_srp_target_port_id target;
};

/**
 * Parse IB SRP root path byte-string value
 *
 * @v rp_comp		Root path component string
 * @v default_value	Default value to use if component string is empty
 * @ret value		Value
 */
static int ib_srp_parse_byte_string ( const char *rp_comp, uint8_t *bytes,
				      unsigned int size_flags ) {
	size_t size = ( size_flags & ~IB_SRP_PARSE_FLAG_MASK );
	size_t rp_comp_len = strlen ( rp_comp );
	int decoded_size;

	/* Allow optional components to be empty */
	if ( ( rp_comp_len == 0 ) &&
	     ( size_flags & IB_SRP_PARSE_OPTIONAL ) )
		return 0;

	/* Check string length */
	if ( rp_comp_len != ( 2 * size ) )
		return -EINVAL_BYTE_STRING_LEN;

	/* Parse byte string */
	decoded_size = base16_decode ( rp_comp, bytes, size );
	if ( decoded_size < 0 )
		return decoded_size;

	return 0;
}

/**
 * Parse IB SRP root path integer value
 *
 * @v rp_comp		Root path component string
 * @v default_value	Default value to use if component string is empty
 * @ret value		Value
 */
static int ib_srp_parse_integer ( const char *rp_comp, int default_value ) {
	int value;
	char *end;

	value = strtoul ( rp_comp, &end, 16 );
	if ( *end )
		return -EINVAL_INTEGER;

	if ( end == rp_comp )
		return default_value;

	return value;
}

/**
 * Parse IB SRP root path source GID
 *
 * @v rp_comp		Root path component string
 * @v rp		IB SRP root path
 * @ret rc		Return status code
 */
static int ib_srp_parse_sgid ( const char *rp_comp,
			       struct ib_srp_root_path *rp ) {
	struct ib_device *ibdev;

	/* Default to the GID of the last opened Infiniband device */
	if ( ( ibdev = last_opened_ibdev() ) != NULL )
		memcpy ( &rp->sgid, &ibdev->gid, sizeof ( rp->sgid ) );

	return ib_srp_parse_byte_string ( rp_comp, rp->sgid.bytes,
					  ( sizeof ( rp->sgid ) |
					    IB_SRP_PARSE_OPTIONAL ) );
}

/**
 * Parse IB SRP root path initiator identifier extension
 *
 * @v rp_comp		Root path component string
 * @v rp		IB SRP root path
 * @ret rc		Return status code
 */
static int ib_srp_parse_initiator_id_ext ( const char *rp_comp,
					   struct ib_srp_root_path *rp ) {
	union ib_srp_initiator_port_id *port_id = &rp->initiator;

	return ib_srp_parse_byte_string ( rp_comp, port_id->ib.id_ext.bytes,
					  ( sizeof ( port_id->ib.id_ext ) |
					    IB_SRP_PARSE_OPTIONAL ) );
}

/**
 * Parse IB SRP root path initiator HCA GUID
 *
 * @v rp_comp		Root path component string
 * @v rp		IB SRP root path
 * @ret rc		Return status code
 */
static int ib_srp_parse_initiator_hca_guid ( const char *rp_comp,
					     struct ib_srp_root_path *rp ) {
	union ib_srp_initiator_port_id *port_id = &rp->initiator;

	/* Default to the GUID portion of the source GID */
	memcpy ( &port_id->ib.hca_guid, &rp->sgid.s.guid,
		 sizeof ( port_id->ib.hca_guid ) );

	return ib_srp_parse_byte_string ( rp_comp, port_id->ib.hca_guid.bytes,
					  ( sizeof ( port_id->ib.hca_guid ) |
					    IB_SRP_PARSE_OPTIONAL ) );
}

/**
 * Parse IB SRP root path destination GID
 *
 * @v rp_comp		Root path component string
 * @v rp		IB SRP root path
 * @ret rc		Return status code
 */
static int ib_srp_parse_dgid ( const char *rp_comp,
			       struct ib_srp_root_path *rp ) {
	return ib_srp_parse_byte_string ( rp_comp, rp->dgid.bytes,
					  ( sizeof ( rp->dgid ) |
					    IB_SRP_PARSE_REQUIRED ) );
}

/**
 * Parse IB SRP root path partition key
 *
 * @v rp_comp		Root path component string
 * @v rp		IB SRP root path
 * @ret rc		Return status code
 */
static int ib_srp_parse_pkey ( const char *rp_comp,
			       struct ib_srp_root_path *rp ) {
	int pkey;

	if ( ( pkey = ib_srp_parse_integer ( rp_comp, IB_PKEY_DEFAULT ) ) < 0 )
		return pkey;
	rp->pkey = pkey;
	return 0;
}

/**
 * Parse IB SRP root path service ID
 *
 * @v rp_comp		Root path component string
 * @v rp		IB SRP root path
 * @ret rc		Return status code
 */
static int ib_srp_parse_service_id ( const char *rp_comp,
				     struct ib_srp_root_path *rp ) {
	return ib_srp_parse_byte_string ( rp_comp, rp->service_id.bytes,
					  ( sizeof ( rp->service_id ) |
					    IB_SRP_PARSE_REQUIRED ) );
}

/**
 * Parse IB SRP root path LUN
 *
 * @v rp_comp		Root path component string
 * @v rp		IB SRP root path
 * @ret rc		Return status code
 */
static int ib_srp_parse_lun ( const char *rp_comp,
			      struct ib_srp_root_path *rp ) {
	return scsi_parse_lun ( rp_comp, &rp->lun );
}

/**
 * Parse IB SRP root path target identifier extension
 *
 * @v rp_comp		Root path component string
 * @v rp		IB SRP root path
 * @ret rc		Return status code
 */
static int ib_srp_parse_target_id_ext ( const char *rp_comp,
					struct ib_srp_root_path *rp ) {
	union ib_srp_target_port_id *port_id = &rp->target;

	return ib_srp_parse_byte_string ( rp_comp, port_id->ib.id_ext.bytes,
					  ( sizeof ( port_id->ib.id_ext ) |
					    IB_SRP_PARSE_REQUIRED ) );
}

/**
 * Parse IB SRP root path target I/O controller GUID
 *
 * @v rp_comp		Root path component string
 * @v rp		IB SRP root path
 * @ret rc		Return status code
 */
static int ib_srp_parse_target_ioc_guid ( const char *rp_comp,
					  struct ib_srp_root_path *rp ) {
	union ib_srp_target_port_id *port_id = &rp->target;

	return ib_srp_parse_byte_string ( rp_comp, port_id->ib.ioc_guid.bytes,
					  ( sizeof ( port_id->ib.ioc_guid ) |
					    IB_SRP_PARSE_REQUIRED ) );
}

/** IB SRP root path component parser */
struct ib_srp_root_path_parser {
	/**
	 * Parse IB SRP root path component
	 *
	 * @v rp_comp		Root path component string
	 * @v rp		IB SRP root path
	 * @ret rc		Return status code
	 */
	int ( * parse ) ( const char *rp_comp, struct ib_srp_root_path *rp );
};

/** IB SRP root path components */
static struct ib_srp_root_path_parser ib_srp_rp_parser[] = {
	{ ib_srp_parse_sgid },
	{ ib_srp_parse_initiator_id_ext },
	{ ib_srp_parse_initiator_hca_guid },
	{ ib_srp_parse_dgid },
	{ ib_srp_parse_pkey },
	{ ib_srp_parse_service_id },
	{ ib_srp_parse_lun },
	{ ib_srp_parse_target_id_ext },
	{ ib_srp_parse_target_ioc_guid },
};

/** Number of IB SRP root path components */
#define IB_SRP_NUM_RP_COMPONENTS \
	( sizeof ( ib_srp_rp_parser ) / sizeof ( ib_srp_rp_parser[0] ) )

/**
 * Parse IB SRP root path
 *
 * @v rp_string		Root path string
 * @v rp		IB SRP root path
 * @ret rc		Return status code
 */
static int ib_srp_parse_root_path ( const char *rp_string,
				    struct ib_srp_root_path *rp ) {
	struct ib_srp_root_path_parser *parser;
	char rp_string_copy[ strlen ( rp_string ) + 1 ];
	char *rp_comp[IB_SRP_NUM_RP_COMPONENTS];
	char *rp_string_tmp = rp_string_copy;
	unsigned int i = 0;
	int rc;

	/* Split root path into component parts */
	strcpy ( rp_string_copy, rp_string );
	while ( 1 ) {
		rp_comp[i++] = rp_string_tmp;
		if ( i == IB_SRP_NUM_RP_COMPONENTS )
			break;
		for ( ; *rp_string_tmp != ':' ; rp_string_tmp++ ) {
			if ( ! *rp_string_tmp ) {
				DBG ( "IBSRP root path \"%s\" too short\n",
				      rp_string );
				return -EINVAL_RP_TOO_SHORT;
			}
		}
		*(rp_string_tmp++) = '\0';
	}

	/* Parse root path components */
	for ( i = 0 ; i < IB_SRP_NUM_RP_COMPONENTS ; i++ ) {
		parser = &ib_srp_rp_parser[i];
		if ( ( rc = parser->parse ( rp_comp[i], rp ) ) != 0 ) {
			DBG ( "IBSRP could not parse \"%s\" in root path "
			      "\"%s\": %s\n", rp_comp[i], rp_string,
			      strerror ( rc ) );
			return rc;
		}
	}

	return 0;
}

/**
 * Open IB SRP URI
 *
 * @v parent		Parent interface
 * @v uri		URI
 * @ret rc		Return status code
 */
static int ib_srp_open_uri ( struct interface *parent, struct uri *uri ) {
	struct ib_srp_root_path rp;
	struct ib_device *ibdev;
	int rc;

	/* Parse URI */
	if ( ! uri->opaque )
		return -EINVAL;
	memset ( &rp, 0, sizeof ( rp ) );
	if ( ( rc = ib_srp_parse_root_path ( uri->opaque, &rp ) ) != 0 )
		return rc;

	/* Identify Infiniband device */
	ibdev = find_ibdev ( &rp.sgid );
	if ( ! ibdev ) {
		DBG ( "IBSRP could not identify Infiniband device\n" );
		return -ENODEV;
	}

	/* Open IB SRP device */
	if ( ( rc = ib_srp_open ( parent, ibdev, &rp.dgid, &rp.service_id,
				  &rp.initiator.srp, &rp.target.srp,
				  &rp.lun ) ) != 0 )
		return rc;

	return 0;
}

/** IB SRP URI opener */
struct uri_opener ib_srp_uri_opener __uri_opener = {
	.scheme = "ib_srp",
	.open = ib_srp_open_uri,
};
