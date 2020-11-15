/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <byteswap.h>
#include <ipxe/settings.h>
#include <ipxe/infiniband.h>
#include <ipxe/iobuf.h>
#include <ipxe/ib_mi.h>
#include <ipxe/ib_sma.h>

/**
 * @file
 *
 * Infiniband Subnet Management Agent
 *
 */

/**
 * Node information
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		Received MAD
 * @v av		Source address vector
 */
static void ib_sma_node_info ( struct ib_device *ibdev,
			       struct ib_mad_interface *mi,
			       union ib_mad *mad,
			       struct ib_address_vector *av ) {
	struct ib_node_info *node_info = &mad->smp.smp_data.node_info;
	int rc;

	/* Fill in information */
	memset ( node_info, 0, sizeof ( *node_info ) );
	node_info->base_version = IB_MGMT_BASE_VERSION;
	node_info->class_version = IB_SMP_CLASS_VERSION;
	node_info->node_type = IB_NODE_TYPE_HCA;
	node_info->num_ports = ib_count_ports ( ibdev );
	memcpy ( &node_info->sys_guid, &ibdev->node_guid,
		 sizeof ( node_info->sys_guid ) );
	memcpy ( &node_info->node_guid, &ibdev->node_guid,
		 sizeof ( node_info->node_guid ) );
	memcpy ( &node_info->port_guid, &ibdev->gid.s.guid,
		 sizeof ( node_info->port_guid ) );
	node_info->partition_cap = htons ( 1 );
	node_info->local_port_num = ibdev->port;

	/* Send GetResponse */
	mad->hdr.method = IB_MGMT_METHOD_GET_RESP;
	if ( ( rc = ib_mi_send ( ibdev, mi, mad, av ) ) != 0 ) {
		DBGC ( mi, "SMA %p could not send NodeInfo GetResponse: %s\n",
		       mi, strerror ( rc ) );
		return;
	}
}

/**
 * Node description
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		Received MAD
 * @v av		Source address vector
 */
static void ib_sma_node_desc ( struct ib_device *ibdev,
			       struct ib_mad_interface *mi,
			       union ib_mad *mad,
			       struct ib_address_vector *av ) {
	struct ib_node_desc *node_desc = &mad->smp.smp_data.node_desc;
	union ib_guid *guid = &ibdev->node_guid;
	char hostname[ sizeof ( node_desc->node_string ) ];
	int hostname_len;
	int rc;

	/* Fill in information */
	memset ( node_desc, 0, sizeof ( *node_desc ) );
	hostname_len = fetch_string_setting ( NULL, &hostname_setting,
					      hostname, sizeof ( hostname ) );
	snprintf ( node_desc->node_string, sizeof ( node_desc->node_string ),
		   "iPXE %s%s%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x (%s)",
		   hostname, ( ( hostname_len >= 0 ) ? " " : "" ),
		   guid->bytes[0], guid->bytes[1], guid->bytes[2],
		   guid->bytes[3], guid->bytes[4], guid->bytes[5],
		   guid->bytes[6], guid->bytes[7], ibdev->dev->name );

	/* Send GetResponse */
	mad->hdr.method = IB_MGMT_METHOD_GET_RESP;
	if ( ( rc = ib_mi_send ( ibdev, mi, mad, av ) ) != 0 ) {
		DBGC ( mi, "SMA %p could not send NodeDesc GetResponse: %s\n",
		       mi, strerror ( rc ) );
		return;
	}
}

/**
 * GUID information
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		Received MAD
 * @v av		Source address vector
 */
static void ib_sma_guid_info ( struct ib_device *ibdev,
			       struct ib_mad_interface *mi,
			       union ib_mad *mad,
			       struct ib_address_vector *av ) {
	struct ib_guid_info *guid_info = &mad->smp.smp_data.guid_info;
	int rc;

	/* Fill in information */
	memset ( guid_info, 0, sizeof ( *guid_info ) );
	memcpy ( guid_info->guid[0], &ibdev->gid.s.guid,
		 sizeof ( guid_info->guid[0] ) );

	/* Send GetResponse */
	mad->hdr.method = IB_MGMT_METHOD_GET_RESP;
	if ( ( rc = ib_mi_send ( ibdev, mi, mad, av ) ) != 0 ) {
		DBGC ( mi, "SMA %p could not send GuidInfo GetResponse: %s\n",
		       mi, strerror ( rc ) );
		return;
	}
}

/**
 * Set port information
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		Received MAD
 * @ret rc		Return status code
 */
static int ib_sma_set_port_info ( struct ib_device *ibdev,
				  struct ib_mad_interface *mi,
				  union ib_mad *mad ) {
	const struct ib_port_info *port_info = &mad->smp.smp_data.port_info;
	unsigned int link_width_enabled;
	unsigned int link_speed_enabled;
	int rc;

	/* Set parameters */
	memcpy ( &ibdev->gid.s.prefix, port_info->gid_prefix,
		 sizeof ( ibdev->gid.s.prefix ) );
	ibdev->lid = ntohs ( port_info->lid );
	ibdev->sm_lid = ntohs ( port_info->mastersm_lid );
	if ( ( link_width_enabled = port_info->link_width_enabled ) )
		ibdev->link_width_enabled = link_width_enabled;
	if ( ( link_speed_enabled =
	       ( port_info->link_speed_active__link_speed_enabled & 0xf ) ) )
		ibdev->link_speed_enabled = link_speed_enabled;
	ibdev->sm_sl = ( port_info->neighbour_mtu__mastersm_sl & 0xf );
	DBGC ( mi, "SMA %p set LID %04x SMLID %04x link width %02x speed "
	       "%02x\n", mi, ibdev->lid, ibdev->sm_lid,
	       ibdev->link_width_enabled, ibdev->link_speed_enabled );

	/* Update parameters on device */
	if ( ( rc = ib_set_port_info ( ibdev, mad ) ) != 0 ) {
		DBGC ( mi, "SMA %p could not set port information: %s\n",
		       mi, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Port information
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		Received MAD
 * @v av		Source address vector
 */
static void ib_sma_port_info ( struct ib_device *ibdev,
			       struct ib_mad_interface *mi,
			       union ib_mad *mad,
			       struct ib_address_vector *av ) {
	struct ib_port_info *port_info = &mad->smp.smp_data.port_info;
	int rc;

	/* Set parameters if applicable */
	if ( mad->hdr.method == IB_MGMT_METHOD_SET ) {
		if ( ( rc = ib_sma_set_port_info ( ibdev, mi, mad ) ) != 0 ) {
			mad->hdr.status =
			      htons ( IB_MGMT_STATUS_UNSUPPORTED_METHOD_ATTR );
			/* Fall through to generate GetResponse */
		}
	}

	/* Fill in information */
	memset ( port_info, 0, sizeof ( *port_info ) );
	memcpy ( port_info->gid_prefix, &ibdev->gid.s.prefix,
		 sizeof ( port_info->gid_prefix ) );
	port_info->lid = ntohs ( ibdev->lid );
	port_info->mastersm_lid = ntohs ( ibdev->sm_lid );
	port_info->local_port_num = ibdev->port;
	port_info->link_width_enabled = ibdev->link_width_enabled;
	port_info->link_width_supported = ibdev->link_width_supported;
	port_info->link_width_active = ibdev->link_width_active;
	port_info->link_speed_supported__port_state =
		( ( ibdev->link_speed_supported << 4 ) | ibdev->port_state );
	port_info->port_phys_state__link_down_def_state =
		( ( IB_PORT_PHYS_STATE_POLLING << 4 ) |
		  IB_PORT_PHYS_STATE_POLLING );
	port_info->link_speed_active__link_speed_enabled =
		( ( ibdev->link_speed_active << 4 ) |
		  ibdev->link_speed_enabled );
	port_info->neighbour_mtu__mastersm_sl =
		( ( IB_MTU_2048 << 4 ) | ibdev->sm_sl );
	port_info->vl_cap__init_type = ( IB_VL_0 << 4 );
	port_info->init_type_reply__mtu_cap = IB_MTU_2048;
	port_info->operational_vls__enforcement = ( IB_VL_0 << 4 );
	port_info->guid_cap = 1;

	/* Send GetResponse */
	mad->hdr.method = IB_MGMT_METHOD_GET_RESP;
	if ( ( rc = ib_mi_send ( ibdev, mi, mad, av ) ) != 0 ) {
		DBGC ( mi, "SMA %p could not send PortInfo GetResponse: %s\n",
		       mi, strerror ( rc ) );
		return;
	}
}

/**
 * Set partition key table
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		Received MAD
 * @ret rc		Return status code
 */
static int ib_sma_set_pkey_table ( struct ib_device *ibdev,
				   struct ib_mad_interface *mi,
				   union ib_mad *mad ) {
	struct ib_pkey_table *pkey_table = &mad->smp.smp_data.pkey_table;
	int rc;

	/* Set parameters */
	ibdev->pkey = ntohs ( pkey_table->pkey[0] );
	DBGC ( mi, "SMA %p set pkey %04x\n", mi, ibdev->pkey );

	/* Update parameters on device */
	if ( ( rc = ib_set_pkey_table ( ibdev, mad ) ) != 0 ) {
		DBGC ( mi, "SMA %p could not set pkey table: %s\n",
		       mi, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Partition key table
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @v mad		Received MAD
 * @v av		Source address vector
 */
static void ib_sma_pkey_table ( struct ib_device *ibdev,
				struct ib_mad_interface *mi,
				union ib_mad *mad,
				struct ib_address_vector *av ) {
	struct ib_pkey_table *pkey_table = &mad->smp.smp_data.pkey_table;
	int rc;

	/* Set parameters, if applicable */
	if ( mad->hdr.method == IB_MGMT_METHOD_SET ) {
		if ( ( rc = ib_sma_set_pkey_table ( ibdev, mi, mad ) ) != 0 ) {
			mad->hdr.status =
			      htons ( IB_MGMT_STATUS_UNSUPPORTED_METHOD_ATTR );
			/* Fall through to generate GetResponse */
		}
	}

	/* Fill in information */
	mad->hdr.method = IB_MGMT_METHOD_GET_RESP;
	memset ( pkey_table, 0, sizeof ( *pkey_table ) );
	pkey_table->pkey[0] = htons ( ibdev->pkey );

	/* Send GetResponse */
	mad->hdr.method = IB_MGMT_METHOD_GET_RESP;
	if ( ( rc = ib_mi_send ( ibdev, mi, mad, av ) ) != 0 ) {
		DBGC ( mi, "SMA %p could not send PKeyTable GetResponse: %s\n",
		       mi, strerror ( rc ) );
		return;
	}
}

/** Subnet management agent */
struct ib_mad_agent ib_sma_agent[] __ib_mad_agent = {
	{
		.mgmt_class = IB_MGMT_CLASS_SUBN_LID_ROUTED,
		.class_version = IB_SMP_CLASS_VERSION,
		.attr_id = htons ( IB_SMP_ATTR_NODE_INFO ),
		.handle = ib_sma_node_info,
	},
	{
		.mgmt_class = IB_MGMT_CLASS_SUBN_LID_ROUTED,
		.class_version = IB_SMP_CLASS_VERSION,
		.attr_id = htons ( IB_SMP_ATTR_NODE_DESC ),
		.handle = ib_sma_node_desc,
	},
	{
		.mgmt_class = IB_MGMT_CLASS_SUBN_LID_ROUTED,
		.class_version = IB_SMP_CLASS_VERSION,
		.attr_id = htons ( IB_SMP_ATTR_GUID_INFO ),
		.handle = ib_sma_guid_info,
	},
	{
		.mgmt_class = IB_MGMT_CLASS_SUBN_LID_ROUTED,
		.class_version = IB_SMP_CLASS_VERSION,
		.attr_id = htons ( IB_SMP_ATTR_PORT_INFO ),
		.handle = ib_sma_port_info,
	},
	{
		.mgmt_class = IB_MGMT_CLASS_SUBN_LID_ROUTED,
		.class_version = IB_SMP_CLASS_VERSION,
		.attr_id = htons ( IB_SMP_ATTR_PKEY_TABLE ),
		.handle = ib_sma_pkey_table,
	},
};

/**
 * Create subnet management agent and interface
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 * @ret rc		Return status code
 */
int ib_create_sma ( struct ib_device *ibdev, struct ib_mad_interface *mi ) {

	/* Nothing to do */
	DBGC ( ibdev, "IBDEV %p SMA using SMI %p\n", ibdev, mi );

	return 0;
}

/**
 * Destroy subnet management agent and interface
 *
 * @v ibdev		Infiniband device
 * @v mi		Management interface
 */
void ib_destroy_sma ( struct ib_device *ibdev __unused,
		      struct ib_mad_interface *mi __unused ) {
	/* Nothing to do */
}
