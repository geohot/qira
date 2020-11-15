/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * Based in part upon the original driver by Mellanox Technologies
 * Ltd.  Portions may be Copyright (c) Mellanox Technologies Ltd.
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
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/io.h>
#include <ipxe/pci.h>
#include <ipxe/pcibackup.h>
#include <ipxe/malloc.h>
#include <ipxe/umalloc.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/infiniband.h>
#include <ipxe/ib_smc.h>
#include "arbel.h"

/**
 * @file
 *
 * Mellanox Arbel Infiniband HCA
 *
 */

/***************************************************************************
 *
 * Queue number allocation
 *
 ***************************************************************************
 */

/**
 * Allocate offset within usage bitmask
 *
 * @v bits		Usage bitmask
 * @v bits_len		Length of usage bitmask
 * @ret bit		First free bit within bitmask, or negative error
 */
static int arbel_bitmask_alloc ( arbel_bitmask_t *bits,
				 unsigned int bits_len ) {
	unsigned int bit = 0;
	arbel_bitmask_t mask = 1;

	while ( bit < bits_len ) {
		if ( ( mask & *bits ) == 0 ) {
			*bits |= mask;
			return bit;
		}
		bit++;
		mask = ( mask << 1 ) | ( mask >> ( 8 * sizeof ( mask ) - 1 ) );
		if ( mask == 1 )
			bits++;
	}
	return -ENFILE;
}

/**
 * Free offset within usage bitmask
 *
 * @v bits		Usage bitmask
 * @v bit		Bit within bitmask
 */
static void arbel_bitmask_free ( arbel_bitmask_t *bits, int bit ) {
	arbel_bitmask_t mask;

	mask = ( 1 << ( bit % ( 8 * sizeof ( mask ) ) ) );
	bits += ( bit / ( 8 * sizeof ( mask ) ) );
	*bits &= ~mask;
}

/***************************************************************************
 *
 * HCA commands
 *
 ***************************************************************************
 */

/**
 * Wait for Arbel command completion
 *
 * @v arbel		Arbel device
 * @ret rc		Return status code
 */
static int arbel_cmd_wait ( struct arbel *arbel,
			    struct arbelprm_hca_command_register *hcr ) {
	unsigned int wait;

	for ( wait = ARBEL_HCR_MAX_WAIT_MS ; wait ; wait-- ) {
		hcr->u.dwords[6] =
			readl ( arbel->config + ARBEL_HCR_REG ( 6 ) );
		if ( MLX_GET ( hcr, go ) == 0 )
			return 0;
		mdelay ( 1 );
	}
	return -EBUSY;
}

/**
 * Issue HCA command
 *
 * @v arbel		Arbel device
 * @v command		Command opcode, flags and input/output lengths
 * @v op_mod		Opcode modifier (0 if no modifier applicable)
 * @v in		Input parameters
 * @v in_mod		Input modifier (0 if no modifier applicable)
 * @v out		Output parameters
 * @ret rc		Return status code
 */
static int arbel_cmd ( struct arbel *arbel, unsigned long command,
		       unsigned int op_mod, const void *in,
		       unsigned int in_mod, void *out ) {
	struct arbelprm_hca_command_register hcr;
	unsigned int opcode = ARBEL_HCR_OPCODE ( command );
	size_t in_len = ARBEL_HCR_IN_LEN ( command );
	size_t out_len = ARBEL_HCR_OUT_LEN ( command );
	void *in_buffer;
	void *out_buffer;
	unsigned int status;
	unsigned int i;
	int rc;

	assert ( in_len <= ARBEL_MBOX_SIZE );
	assert ( out_len <= ARBEL_MBOX_SIZE );

	DBGC2 ( arbel, "Arbel %p command %02x in %zx%s out %zx%s\n",
		arbel, opcode, in_len,
		( ( command & ARBEL_HCR_IN_MBOX ) ? "(mbox)" : "" ), out_len,
		( ( command & ARBEL_HCR_OUT_MBOX ) ? "(mbox)" : "" ) );

	/* Check that HCR is free */
	if ( ( rc = arbel_cmd_wait ( arbel, &hcr ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p command interface locked\n", arbel );
		return rc;
	}

	/* Prepare HCR */
	memset ( &hcr, 0, sizeof ( hcr ) );
	in_buffer = &hcr.u.dwords[0];
	if ( in_len && ( command & ARBEL_HCR_IN_MBOX ) ) {
		in_buffer = arbel->mailbox_in;
		MLX_FILL_H ( &hcr, 0, in_param_h, virt_to_bus ( in_buffer ) );
		MLX_FILL_1 ( &hcr, 1, in_param_l, virt_to_bus ( in_buffer ) );
	}
	memcpy ( in_buffer, in, in_len );
	MLX_FILL_1 ( &hcr, 2, input_modifier, in_mod );
	out_buffer = &hcr.u.dwords[3];
	if ( out_len && ( command & ARBEL_HCR_OUT_MBOX ) ) {
		out_buffer = arbel->mailbox_out;
		MLX_FILL_H ( &hcr, 3, out_param_h,
			     virt_to_bus ( out_buffer ) );
		MLX_FILL_1 ( &hcr, 4, out_param_l,
			     virt_to_bus ( out_buffer ) );
	}
	MLX_FILL_3 ( &hcr, 6,
		     opcode, opcode,
		     opcode_modifier, op_mod,
		     go, 1 );
	DBGC ( arbel, "Arbel %p issuing command %04x\n", arbel, opcode );
	DBGC2_HDA ( arbel, virt_to_phys ( arbel->config + ARBEL_HCR_BASE ),
		    &hcr, sizeof ( hcr ) );
	if ( in_len && ( command & ARBEL_HCR_IN_MBOX ) ) {
		DBGC2 ( arbel, "Input mailbox:\n" );
		DBGC2_HDA ( arbel, virt_to_phys ( in_buffer ), in_buffer,
			    ( ( in_len < 512 ) ? in_len : 512 ) );
	}

	/* Issue command */
	for ( i = 0 ; i < ( sizeof ( hcr ) / sizeof ( hcr.u.dwords[0] ) ) ;
	      i++ ) {
		writel ( hcr.u.dwords[i],
			 arbel->config + ARBEL_HCR_REG ( i ) );
		barrier();
	}

	/* Wait for command completion */
	if ( ( rc = arbel_cmd_wait ( arbel, &hcr ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p timed out waiting for command:\n",
		       arbel );
		DBGC_HD ( arbel, &hcr, sizeof ( hcr ) );
		return rc;
	}

	/* Check command status */
	status = MLX_GET ( &hcr, status );
	if ( status != 0 ) {
		DBGC ( arbel, "Arbel %p command failed with status %02x:\n",
		       arbel, status );
		DBGC_HD ( arbel, &hcr, sizeof ( hcr ) );
		return -EIO;
	}

	/* Read output parameters, if any */
	hcr.u.dwords[3] = readl ( arbel->config + ARBEL_HCR_REG ( 3 ) );
	hcr.u.dwords[4] = readl ( arbel->config + ARBEL_HCR_REG ( 4 ) );
	memcpy ( out, out_buffer, out_len );
	if ( out_len ) {
		DBGC2 ( arbel, "Output%s:\n",
			( command & ARBEL_HCR_OUT_MBOX ) ? " mailbox" : "" );
		DBGC2_HDA ( arbel, virt_to_phys ( out_buffer ), out_buffer,
			    ( ( out_len < 512 ) ? out_len : 512 ) );
	}

	return 0;
}

static inline int
arbel_cmd_query_dev_lim ( struct arbel *arbel,
			  struct arbelprm_query_dev_lim *dev_lim ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_OUT_CMD ( ARBEL_HCR_QUERY_DEV_LIM,
					       1, sizeof ( *dev_lim ) ),
			   0, NULL, 0, dev_lim );
}

static inline int
arbel_cmd_query_fw ( struct arbel *arbel, struct arbelprm_query_fw *fw ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_OUT_CMD ( ARBEL_HCR_QUERY_FW, 
					       1, sizeof ( *fw ) ),
			   0, NULL, 0, fw );
}

static inline int
arbel_cmd_init_hca ( struct arbel *arbel,
		     const struct arbelprm_init_hca *init_hca ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_INIT_HCA,
					      1, sizeof ( *init_hca ) ),
			   0, init_hca, 0, NULL );
}

static inline int
arbel_cmd_close_hca ( struct arbel *arbel ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_VOID_CMD ( ARBEL_HCR_CLOSE_HCA ),
			   0, NULL, 0, NULL );
}

static inline int
arbel_cmd_init_ib ( struct arbel *arbel, unsigned int port,
		    const struct arbelprm_init_ib *init_ib ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_INIT_IB,
					      1, sizeof ( *init_ib ) ),
			   0, init_ib, port, NULL );
}

static inline int
arbel_cmd_close_ib ( struct arbel *arbel, unsigned int port ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_VOID_CMD ( ARBEL_HCR_CLOSE_IB ),
			   0, NULL, port, NULL );
}

static inline int
arbel_cmd_sw2hw_mpt ( struct arbel *arbel, unsigned int index,
		      const struct arbelprm_mpt *mpt ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_SW2HW_MPT,
					      1, sizeof ( *mpt ) ),
			   0, mpt, index, NULL );
}

static inline int
arbel_cmd_map_eq ( struct arbel *arbel, unsigned long index_map,
		   const struct arbelprm_event_mask *mask ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_MAP_EQ,
					      0, sizeof ( *mask ) ),
			   0, mask, index_map, NULL );
}

static inline int
arbel_cmd_sw2hw_eq ( struct arbel *arbel, unsigned int index,
		     const struct arbelprm_eqc *eqctx ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_SW2HW_EQ,
					      1, sizeof ( *eqctx ) ),
			   0, eqctx, index, NULL );
}

static inline int
arbel_cmd_hw2sw_eq ( struct arbel *arbel, unsigned int index,
		     struct arbelprm_eqc *eqctx ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_OUT_CMD ( ARBEL_HCR_HW2SW_EQ,
					       1, sizeof ( *eqctx ) ),
			   1, NULL, index, eqctx );
}

static inline int
arbel_cmd_sw2hw_cq ( struct arbel *arbel, unsigned long cqn,
		     const struct arbelprm_completion_queue_context *cqctx ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_SW2HW_CQ,
					      1, sizeof ( *cqctx ) ),
			   0, cqctx, cqn, NULL );
}

static inline int
arbel_cmd_hw2sw_cq ( struct arbel *arbel, unsigned long cqn,
		     struct arbelprm_completion_queue_context *cqctx) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_OUT_CMD ( ARBEL_HCR_HW2SW_CQ,
					       1, sizeof ( *cqctx ) ),
			   0, NULL, cqn, cqctx );
}

static inline int
arbel_cmd_query_cq ( struct arbel *arbel, unsigned long cqn,
		     struct arbelprm_completion_queue_context *cqctx ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_OUT_CMD ( ARBEL_HCR_QUERY_CQ,
					       1, sizeof ( *cqctx ) ),
			   0, NULL, cqn, cqctx );
}

static inline int
arbel_cmd_rst2init_qpee ( struct arbel *arbel, unsigned long qpn,
			  const struct arbelprm_qp_ee_state_transitions *ctx ){
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_RST2INIT_QPEE,
					      1, sizeof ( *ctx ) ),
			   0, ctx, qpn, NULL );
}

static inline int
arbel_cmd_init2rtr_qpee ( struct arbel *arbel, unsigned long qpn,
			  const struct arbelprm_qp_ee_state_transitions *ctx ){
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_INIT2RTR_QPEE,
					      1, sizeof ( *ctx ) ),
			   0, ctx, qpn, NULL );
}

static inline int
arbel_cmd_rtr2rts_qpee ( struct arbel *arbel, unsigned long qpn,
			 const struct arbelprm_qp_ee_state_transitions *ctx ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_RTR2RTS_QPEE,
					      1, sizeof ( *ctx ) ),
			   0, ctx, qpn, NULL );
}

static inline int
arbel_cmd_rts2rts_qpee ( struct arbel *arbel, unsigned long qpn,
			 const struct arbelprm_qp_ee_state_transitions *ctx ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_RTS2RTS_QPEE,
					      1, sizeof ( *ctx ) ),
			   0, ctx, qpn, NULL );
}

static inline int
arbel_cmd_2rst_qpee ( struct arbel *arbel, unsigned long qpn ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_VOID_CMD ( ARBEL_HCR_2RST_QPEE ),
			   0x03, NULL, qpn, NULL );
}

static inline int
arbel_cmd_query_qpee ( struct arbel *arbel, unsigned long qpn,
		       struct arbelprm_qp_ee_state_transitions *ctx ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_OUT_CMD ( ARBEL_HCR_QUERY_QPEE,
					       1, sizeof ( *ctx ) ),
			   0, NULL, qpn, ctx );
}

static inline int
arbel_cmd_conf_special_qp ( struct arbel *arbel, unsigned int qp_type,
			    unsigned long base_qpn ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_VOID_CMD ( ARBEL_HCR_CONF_SPECIAL_QP ),
			   qp_type, NULL, base_qpn, NULL );
}

static inline int
arbel_cmd_mad_ifc ( struct arbel *arbel, unsigned int port,
		    union arbelprm_mad *mad ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_INOUT_CMD ( ARBEL_HCR_MAD_IFC,
						 1, sizeof ( *mad ),
						 1, sizeof ( *mad ) ),
			   0x03, mad, port, mad );
}

static inline int
arbel_cmd_read_mgm ( struct arbel *arbel, unsigned int index,
		     struct arbelprm_mgm_entry *mgm ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_OUT_CMD ( ARBEL_HCR_READ_MGM,
					       1, sizeof ( *mgm ) ),
			   0, NULL, index, mgm );
}

static inline int
arbel_cmd_write_mgm ( struct arbel *arbel, unsigned int index,
		      const struct arbelprm_mgm_entry *mgm ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_WRITE_MGM,
					      1, sizeof ( *mgm ) ),
			   0, mgm, index, NULL );
}

static inline int
arbel_cmd_mgid_hash ( struct arbel *arbel, const union ib_gid *gid,
		      struct arbelprm_mgm_hash *hash ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_INOUT_CMD ( ARBEL_HCR_MGID_HASH,
						 1, sizeof ( *gid ),
						 0, sizeof ( *hash ) ),
			   0, gid, 0, hash );
}

static inline int
arbel_cmd_run_fw ( struct arbel *arbel ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_VOID_CMD ( ARBEL_HCR_RUN_FW ),
			   0, NULL, 0, NULL );
}

static inline int
arbel_cmd_disable_lam ( struct arbel *arbel ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_VOID_CMD ( ARBEL_HCR_DISABLE_LAM ),
			   0, NULL, 0, NULL );
}

static inline int
arbel_cmd_enable_lam ( struct arbel *arbel, struct arbelprm_access_lam *lam ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_OUT_CMD ( ARBEL_HCR_ENABLE_LAM,
					       1, sizeof ( *lam ) ),
			   1, NULL, 0, lam );
}

static inline int
arbel_cmd_unmap_icm ( struct arbel *arbel, unsigned int page_count,
		      const struct arbelprm_scalar_parameter *offset ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_UNMAP_ICM, 0,
					      sizeof ( *offset ) ),
			   0, offset, page_count, NULL );
}

static inline int
arbel_cmd_map_icm ( struct arbel *arbel,
		    const struct arbelprm_virtual_physical_mapping *map ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_MAP_ICM,
					      1, sizeof ( *map ) ),
			   0, map, 1, NULL );
}

static inline int
arbel_cmd_unmap_icm_aux ( struct arbel *arbel ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_VOID_CMD ( ARBEL_HCR_UNMAP_ICM_AUX ),
			   0, NULL, 0, NULL );
}

static inline int
arbel_cmd_map_icm_aux ( struct arbel *arbel,
			const struct arbelprm_virtual_physical_mapping *map ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_MAP_ICM_AUX,
					      1, sizeof ( *map ) ),
			   0, map, 1, NULL );
}

static inline int
arbel_cmd_set_icm_size ( struct arbel *arbel,
			 const struct arbelprm_scalar_parameter *icm_size,
			 struct arbelprm_scalar_parameter *icm_aux_size ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_INOUT_CMD ( ARBEL_HCR_SET_ICM_SIZE,
						 0, sizeof ( *icm_size ),
						 0, sizeof ( *icm_aux_size ) ),
			   0, icm_size, 0, icm_aux_size );
}

static inline int
arbel_cmd_unmap_fa ( struct arbel *arbel ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_VOID_CMD ( ARBEL_HCR_UNMAP_FA ),
			   0, NULL, 0, NULL );
}

static inline int
arbel_cmd_map_fa ( struct arbel *arbel,
		   const struct arbelprm_virtual_physical_mapping *map ) {
	return arbel_cmd ( arbel,
			   ARBEL_HCR_IN_CMD ( ARBEL_HCR_MAP_FA,
					      1, sizeof ( *map ) ),
			   0, map, 1, NULL );
}

/***************************************************************************
 *
 * MAD operations
 *
 ***************************************************************************
 */

/**
 * Issue management datagram
 *
 * @v ibdev		Infiniband device
 * @v mad		Management datagram
 * @ret rc		Return status code
 */
static int arbel_mad ( struct ib_device *ibdev, union ib_mad *mad ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	union arbelprm_mad mad_ifc;
	int rc;

	linker_assert ( sizeof ( *mad ) == sizeof ( mad_ifc.mad ),
			mad_size_mismatch );

	/* Copy in request packet */
	memcpy ( &mad_ifc.mad, mad, sizeof ( mad_ifc.mad ) );

	/* Issue MAD */
	if ( ( rc = arbel_cmd_mad_ifc ( arbel, ibdev->port,
					&mad_ifc ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p port %d could not issue MAD IFC: %s\n",
		       arbel, ibdev->port, strerror ( rc ) );
		return rc;
	}

	/* Copy out reply packet */
	memcpy ( mad, &mad_ifc.mad, sizeof ( *mad ) );

	if ( mad->hdr.status != 0 ) {
		DBGC ( arbel, "Arbel %p port %d MAD IFC status %04x\n",
		       arbel, ibdev->port, ntohs ( mad->hdr.status ) );
		return -EIO;
	}
	return 0;
}

/***************************************************************************
 *
 * Completion queue operations
 *
 ***************************************************************************
 */

/**
 * Dump completion queue context (for debugging only)
 *
 * @v arbel		Arbel device
 * @v cq		Completion queue
 * @ret rc		Return status code
 */
static __attribute__ (( unused )) int
arbel_dump_cqctx ( struct arbel *arbel, struct ib_completion_queue *cq ) {
	struct arbelprm_completion_queue_context cqctx;
	int rc;

	memset ( &cqctx, 0, sizeof ( cqctx ) );
	if ( ( rc = arbel_cmd_query_cq ( arbel, cq->cqn, &cqctx ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p CQN %#lx QUERY_CQ failed: %s\n",
		       arbel, cq->cqn, strerror ( rc ) );
		return rc;
	}
	DBGC ( arbel, "Arbel %p CQN %#lx context:\n", arbel, cq->cqn );
	DBGC_HDA ( arbel, 0, &cqctx, sizeof ( cqctx ) );

	return 0;
}

/**
 * Create completion queue
 *
 * @v ibdev		Infiniband device
 * @v cq		Completion queue
 * @ret rc		Return status code
 */
static int arbel_create_cq ( struct ib_device *ibdev,
			     struct ib_completion_queue *cq ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbel_completion_queue *arbel_cq;
	struct arbelprm_completion_queue_context cqctx;
	struct arbelprm_cq_ci_db_record *ci_db_rec;
	struct arbelprm_cq_arm_db_record *arm_db_rec;
	int cqn_offset;
	unsigned int i;
	int rc;

	/* Find a free completion queue number */
	cqn_offset = arbel_bitmask_alloc ( arbel->cq_inuse, ARBEL_MAX_CQS );
	if ( cqn_offset < 0 ) {
		DBGC ( arbel, "Arbel %p out of completion queues\n", arbel );
		rc = cqn_offset;
		goto err_cqn_offset;
	}
	cq->cqn = ( arbel->limits.reserved_cqs + cqn_offset );

	/* Allocate control structures */
	arbel_cq = zalloc ( sizeof ( *arbel_cq ) );
	if ( ! arbel_cq ) {
		rc = -ENOMEM;
		goto err_arbel_cq;
	}
	arbel_cq->ci_doorbell_idx = arbel_cq_ci_doorbell_idx ( arbel, cq );
	arbel_cq->arm_doorbell_idx = arbel_cq_arm_doorbell_idx ( arbel, cq );

	/* Allocate completion queue itself */
	arbel_cq->cqe_size = ( cq->num_cqes * sizeof ( arbel_cq->cqe[0] ) );
	arbel_cq->cqe = malloc_dma ( arbel_cq->cqe_size,
				     sizeof ( arbel_cq->cqe[0] ) );
	if ( ! arbel_cq->cqe ) {
		rc = -ENOMEM;
		goto err_cqe;
	}
	memset ( arbel_cq->cqe, 0, arbel_cq->cqe_size );
	for ( i = 0 ; i < cq->num_cqes ; i++ ) {
		MLX_FILL_1 ( &arbel_cq->cqe[i].normal, 7, owner, 1 );
	}
	barrier();

	/* Initialise doorbell records */
	ci_db_rec = &arbel->db_rec[arbel_cq->ci_doorbell_idx].cq_ci;
	MLX_FILL_1 ( ci_db_rec, 0, counter, 0 );
	MLX_FILL_2 ( ci_db_rec, 1,
		     res, ARBEL_UAR_RES_CQ_CI,
		     cq_number, cq->cqn );
	arm_db_rec = &arbel->db_rec[arbel_cq->arm_doorbell_idx].cq_arm;
	MLX_FILL_1 ( arm_db_rec, 0, counter, 0 );
	MLX_FILL_2 ( arm_db_rec, 1,
		     res, ARBEL_UAR_RES_CQ_ARM,
		     cq_number, cq->cqn );

	/* Hand queue over to hardware */
	memset ( &cqctx, 0, sizeof ( cqctx ) );
	MLX_FILL_1 ( &cqctx, 0, st, 0xa /* "Event fired" */ );
	MLX_FILL_H ( &cqctx, 1, start_address_h,
		     virt_to_bus ( arbel_cq->cqe ) );
	MLX_FILL_1 ( &cqctx, 2, start_address_l,
		     virt_to_bus ( arbel_cq->cqe ) );
	MLX_FILL_2 ( &cqctx, 3,
		     usr_page, arbel->limits.reserved_uars,
		     log_cq_size, fls ( cq->num_cqes - 1 ) );
	MLX_FILL_1 ( &cqctx, 5, c_eqn, arbel->eq.eqn );
	MLX_FILL_1 ( &cqctx, 6, pd, ARBEL_GLOBAL_PD );
	MLX_FILL_1 ( &cqctx, 7, l_key, arbel->lkey );
	MLX_FILL_1 ( &cqctx, 12, cqn, cq->cqn );
	MLX_FILL_1 ( &cqctx, 13,
		     cq_ci_db_record, arbel_cq->ci_doorbell_idx );
	MLX_FILL_1 ( &cqctx, 14,
		     cq_state_db_record, arbel_cq->arm_doorbell_idx );
	if ( ( rc = arbel_cmd_sw2hw_cq ( arbel, cq->cqn, &cqctx ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p CQN %#lx SW2HW_CQ failed: %s\n",
		       arbel, cq->cqn, strerror ( rc ) );
		goto err_sw2hw_cq;
	}

	DBGC ( arbel, "Arbel %p CQN %#lx ring [%08lx,%08lx), doorbell %08lx\n",
	       arbel, cq->cqn, virt_to_phys ( arbel_cq->cqe ),
	       ( virt_to_phys ( arbel_cq->cqe ) + arbel_cq->cqe_size ),
	       virt_to_phys ( ci_db_rec ) );
	ib_cq_set_drvdata ( cq, arbel_cq );
	return 0;

 err_sw2hw_cq:
	MLX_FILL_1 ( ci_db_rec, 1, res, ARBEL_UAR_RES_NONE );
	MLX_FILL_1 ( arm_db_rec, 1, res, ARBEL_UAR_RES_NONE );
	free_dma ( arbel_cq->cqe, arbel_cq->cqe_size );
 err_cqe:
	free ( arbel_cq );
 err_arbel_cq:
	arbel_bitmask_free ( arbel->cq_inuse, cqn_offset );
 err_cqn_offset:
	return rc;
}

/**
 * Destroy completion queue
 *
 * @v ibdev		Infiniband device
 * @v cq		Completion queue
 */
static void arbel_destroy_cq ( struct ib_device *ibdev,
			       struct ib_completion_queue *cq ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbel_completion_queue *arbel_cq = ib_cq_get_drvdata ( cq );
	struct arbelprm_completion_queue_context cqctx;
	struct arbelprm_cq_ci_db_record *ci_db_rec;
	struct arbelprm_cq_arm_db_record *arm_db_rec;
	int cqn_offset;
	int rc;

	/* Take ownership back from hardware */
	if ( ( rc = arbel_cmd_hw2sw_cq ( arbel, cq->cqn, &cqctx ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p CQN %#lx FATAL HW2SW_CQ failed: "
		       "%s\n", arbel, cq->cqn, strerror ( rc ) );
		/* Leak memory and return; at least we avoid corruption */
		return;
	}

	/* Clear doorbell records */
	ci_db_rec = &arbel->db_rec[arbel_cq->ci_doorbell_idx].cq_ci;
	arm_db_rec = &arbel->db_rec[arbel_cq->arm_doorbell_idx].cq_arm;
	MLX_FILL_1 ( ci_db_rec, 1, res, ARBEL_UAR_RES_NONE );
	MLX_FILL_1 ( arm_db_rec, 1, res, ARBEL_UAR_RES_NONE );

	/* Free memory */
	free_dma ( arbel_cq->cqe, arbel_cq->cqe_size );
	free ( arbel_cq );

	/* Mark queue number as free */
	cqn_offset = ( cq->cqn - arbel->limits.reserved_cqs );
	arbel_bitmask_free ( arbel->cq_inuse, cqn_offset );

	ib_cq_set_drvdata ( cq, NULL );
}

/***************************************************************************
 *
 * Queue pair operations
 *
 ***************************************************************************
 */

/**
 * Assign queue pair number
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @ret rc		Return status code
 */
static int arbel_alloc_qpn ( struct ib_device *ibdev,
			     struct ib_queue_pair *qp ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	unsigned int port_offset;
	int qpn_offset;

	/* Calculate queue pair number */
	port_offset = ( ibdev->port - ARBEL_PORT_BASE );

	switch ( qp->type ) {
	case IB_QPT_SMI:
		qp->qpn = ( arbel->special_qpn_base + port_offset );
		return 0;
	case IB_QPT_GSI:
		qp->qpn = ( arbel->special_qpn_base + 2 + port_offset );
		return 0;
	case IB_QPT_UD:
	case IB_QPT_RC:
		/* Find a free queue pair number */
		qpn_offset = arbel_bitmask_alloc ( arbel->qp_inuse,
						   ARBEL_MAX_QPS );
		if ( qpn_offset < 0 ) {
			DBGC ( arbel, "Arbel %p out of queue pairs\n",
			       arbel );
			return qpn_offset;
		}
		qp->qpn = ( ( random() & ARBEL_QPN_RANDOM_MASK ) |
			    ( arbel->qpn_base + qpn_offset ) );
		return 0;
	default:
		DBGC ( arbel, "Arbel %p unsupported QP type %d\n",
		       arbel, qp->type );
		return -ENOTSUP;
	}
}

/**
 * Free queue pair number
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 */
static void arbel_free_qpn ( struct ib_device *ibdev,
			     struct ib_queue_pair *qp ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	int qpn_offset;

	qpn_offset = ( ( qp->qpn & ~ARBEL_QPN_RANDOM_MASK ) - arbel->qpn_base );
	if ( qpn_offset >= 0 )
		arbel_bitmask_free ( arbel->qp_inuse, qpn_offset );
}

/**
 * Calculate transmission rate
 *
 * @v av		Address vector
 * @ret arbel_rate	Arbel rate
 */
static unsigned int arbel_rate ( struct ib_address_vector *av ) {
	return ( ( ( av->rate >= IB_RATE_2_5 ) && ( av->rate <= IB_RATE_120 ) )
		 ? ( av->rate + 5 ) : 0 );
}

/** Queue pair transport service type map */
static uint8_t arbel_qp_st[] = {
	[IB_QPT_SMI] = ARBEL_ST_MLX,
	[IB_QPT_GSI] = ARBEL_ST_MLX,
	[IB_QPT_UD] = ARBEL_ST_UD,
	[IB_QPT_RC] = ARBEL_ST_RC,
};

/**
 * Dump queue pair context (for debugging only)
 *
 * @v arbel		Arbel device
 * @v qp		Queue pair
 * @ret rc		Return status code
 */
static __attribute__ (( unused )) int
arbel_dump_qpctx ( struct arbel *arbel, struct ib_queue_pair *qp ) {
	struct arbelprm_qp_ee_state_transitions qpctx;
	int rc;

	memset ( &qpctx, 0, sizeof ( qpctx ) );
	if ( ( rc = arbel_cmd_query_qpee ( arbel, qp->qpn, &qpctx ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p QPN %#lx QUERY_QPEE failed: %s\n",
		       arbel, qp->qpn, strerror ( rc ) );
		return rc;
	}
	DBGC ( arbel, "Arbel %p QPN %#lx context:\n", arbel, qp->qpn );
	DBGC_HDA ( arbel, 0, &qpctx.u.dwords[2], ( sizeof ( qpctx ) - 8 ) );

	return 0;
}

/**
 * Create send work queue
 *
 * @v arbel_send_wq	Send work queue
 * @v num_wqes		Number of work queue entries
 * @ret rc		Return status code
 */
static int arbel_create_send_wq ( struct arbel_send_work_queue *arbel_send_wq,
				  unsigned int num_wqes ) {
	union arbel_send_wqe *wqe;
	union arbel_send_wqe *next_wqe;
	unsigned int wqe_idx_mask;
	unsigned int i;

	/* Allocate work queue */
	arbel_send_wq->wqe_size = ( num_wqes *
				    sizeof ( arbel_send_wq->wqe[0] ) );
	arbel_send_wq->wqe = malloc_dma ( arbel_send_wq->wqe_size,
					  sizeof ( arbel_send_wq->wqe[0] ) );
	if ( ! arbel_send_wq->wqe )
		return -ENOMEM;
	memset ( arbel_send_wq->wqe, 0, arbel_send_wq->wqe_size );

	/* Link work queue entries */
	wqe_idx_mask = ( num_wqes - 1 );
	for ( i = 0 ; i < num_wqes ; i++ ) {
		wqe = &arbel_send_wq->wqe[i];
		next_wqe = &arbel_send_wq->wqe[ ( i + 1 ) & wqe_idx_mask ];
		MLX_FILL_1 ( &wqe->next, 0, nda_31_6,
			     ( virt_to_bus ( next_wqe ) >> 6 ) );
		MLX_FILL_1 ( &wqe->next, 1, always1, 1 );
	}
	
	return 0;
}

/**
 * Create receive work queue
 *
 * @v arbel_recv_wq	Receive work queue
 * @v num_wqes		Number of work queue entries
 * @ret rc		Return status code
 */
static int arbel_create_recv_wq ( struct arbel_recv_work_queue *arbel_recv_wq,
				  unsigned int num_wqes ) {
	struct arbelprm_recv_wqe *wqe;
	struct arbelprm_recv_wqe *next_wqe;
	unsigned int wqe_idx_mask;
	size_t nds;
	unsigned int i;
	unsigned int j;

	/* Allocate work queue */
	arbel_recv_wq->wqe_size = ( num_wqes *
				    sizeof ( arbel_recv_wq->wqe[0] ) );
	arbel_recv_wq->wqe = malloc_dma ( arbel_recv_wq->wqe_size,
					  sizeof ( arbel_recv_wq->wqe[0] ) );
	if ( ! arbel_recv_wq->wqe )
		return -ENOMEM;
	memset ( arbel_recv_wq->wqe, 0, arbel_recv_wq->wqe_size );

	/* Link work queue entries */
	wqe_idx_mask = ( num_wqes - 1 );
	nds = ( ( offsetof ( typeof ( *wqe ), data ) +
		  sizeof ( wqe->data[0] ) ) >> 4 );
	for ( i = 0 ; i < num_wqes ; i++ ) {
		wqe = &arbel_recv_wq->wqe[i].recv;
		next_wqe = &arbel_recv_wq->wqe[( i + 1 ) & wqe_idx_mask].recv;
		MLX_FILL_1 ( &wqe->next, 0, nda_31_6,
			     ( virt_to_bus ( next_wqe ) >> 6 ) );
		MLX_FILL_1 ( &wqe->next, 1, nds, nds );
		for ( j = 0 ; ( ( ( void * ) &wqe->data[j] ) <
				( ( void * ) ( wqe + 1 ) ) ) ; j++ ) {
			MLX_FILL_1 ( &wqe->data[j], 1,
				     l_key, ARBEL_INVALID_LKEY );
		}
	}
	
	return 0;
}

/**
 * Create queue pair
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @ret rc		Return status code
 */
static int arbel_create_qp ( struct ib_device *ibdev,
			     struct ib_queue_pair *qp ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbel_queue_pair *arbel_qp;
	struct arbelprm_qp_ee_state_transitions qpctx;
	struct arbelprm_qp_db_record *send_db_rec;
	struct arbelprm_qp_db_record *recv_db_rec;
	physaddr_t send_wqe_base_adr;
	physaddr_t recv_wqe_base_adr;
	physaddr_t wqe_base_adr;
	int rc;

	/* Warn about dysfunctional code
	 *
	 * Arbel seems to crash the system as soon as the first send
	 * WQE completes on an RC queue pair.  (NOPs complete
	 * successfully, so this is a problem specific to the work
	 * queue rather than the completion queue.)  The cause of this
	 * problem has remained unknown for over a year.  Patches to
	 * fix this are welcome.
	 */
	if ( qp->type == IB_QPT_RC )
		DBG ( "*** WARNING: Arbel RC support is non-functional ***\n" );

	/* Calculate queue pair number */
	if ( ( rc = arbel_alloc_qpn ( ibdev, qp ) ) != 0 )
		goto err_alloc_qpn;

	/* Allocate control structures */
	arbel_qp = zalloc ( sizeof ( *arbel_qp ) );
	if ( ! arbel_qp ) {
		rc = -ENOMEM;
		goto err_arbel_qp;
	}
	arbel_qp->send.doorbell_idx = arbel_send_doorbell_idx ( arbel, qp );
	arbel_qp->recv.doorbell_idx = arbel_recv_doorbell_idx ( arbel, qp );

	/* Create send and receive work queues */
	if ( ( rc = arbel_create_send_wq ( &arbel_qp->send,
					   qp->send.num_wqes ) ) != 0 )
		goto err_create_send_wq;
	if ( ( rc = arbel_create_recv_wq ( &arbel_qp->recv,
					   qp->recv.num_wqes ) ) != 0 )
		goto err_create_recv_wq;

	/* Send and receive work queue entries must be within the same 4GB */
	send_wqe_base_adr = virt_to_bus ( arbel_qp->send.wqe );
	recv_wqe_base_adr = virt_to_bus ( arbel_qp->recv.wqe );
	if ( ( sizeof ( physaddr_t ) > sizeof ( uint32_t ) ) &&
	     ( ( ( ( uint64_t ) send_wqe_base_adr ) >> 32 ) !=
	       ( ( ( uint64_t ) recv_wqe_base_adr ) >> 32 ) ) ) {
		DBGC ( arbel, "Arbel %p QPN %#lx cannot support send %08lx "
		       "recv %08lx\n", arbel, qp->qpn,
		       send_wqe_base_adr, recv_wqe_base_adr );
		rc = -ENOTSUP;
		goto err_unsupported_address_split;
	}
	wqe_base_adr = send_wqe_base_adr;

	/* Initialise doorbell records */
	send_db_rec = &arbel->db_rec[arbel_qp->send.doorbell_idx].qp;
	MLX_FILL_1 ( send_db_rec, 0, counter, 0 );
	MLX_FILL_2 ( send_db_rec, 1,
		     res, ARBEL_UAR_RES_SQ,
		     qp_number, qp->qpn );
	recv_db_rec = &arbel->db_rec[arbel_qp->recv.doorbell_idx].qp;
	MLX_FILL_1 ( recv_db_rec, 0, counter, 0 );
	MLX_FILL_2 ( recv_db_rec, 1,
		     res, ARBEL_UAR_RES_RQ,
		     qp_number, qp->qpn );

	/* Transition queue to INIT state */
	memset ( &qpctx, 0, sizeof ( qpctx ) );
	MLX_FILL_3 ( &qpctx, 2,
		     qpc_eec_data.de, 1,
		     qpc_eec_data.pm_state, ARBEL_PM_STATE_MIGRATED,
		     qpc_eec_data.st, arbel_qp_st[qp->type] );
	MLX_FILL_4 ( &qpctx, 4,
		     qpc_eec_data.log_rq_size, fls ( qp->recv.num_wqes - 1 ),
		     qpc_eec_data.log_rq_stride,
		     ( fls ( sizeof ( arbel_qp->recv.wqe[0] ) - 1 ) - 4 ),
		     qpc_eec_data.log_sq_size, fls ( qp->send.num_wqes - 1 ),
		     qpc_eec_data.log_sq_stride,
		     ( fls ( sizeof ( arbel_qp->send.wqe[0] ) - 1 ) - 4 ) );
	MLX_FILL_1 ( &qpctx, 5,
		     qpc_eec_data.usr_page, arbel->limits.reserved_uars );
	MLX_FILL_1 ( &qpctx, 10, qpc_eec_data.primary_address_path.port_number,
		     ibdev->port );
	MLX_FILL_1 ( &qpctx, 27, qpc_eec_data.pd, ARBEL_GLOBAL_PD );
	MLX_FILL_H ( &qpctx, 28, qpc_eec_data.wqe_base_adr_h, wqe_base_adr );
	MLX_FILL_1 ( &qpctx, 29, qpc_eec_data.wqe_lkey, arbel->lkey );
	MLX_FILL_1 ( &qpctx, 30, qpc_eec_data.ssc, 1 );
	MLX_FILL_1 ( &qpctx, 33, qpc_eec_data.cqn_snd, qp->send.cq->cqn );
	MLX_FILL_1 ( &qpctx, 34, qpc_eec_data.snd_wqe_base_adr_l,
		     ( send_wqe_base_adr >> 6 ) );
	MLX_FILL_1 ( &qpctx, 35, qpc_eec_data.snd_db_record_index,
		     arbel_qp->send.doorbell_idx );
	MLX_FILL_4 ( &qpctx, 38,
		     qpc_eec_data.rre, 1,
		     qpc_eec_data.rwe, 1,
		     qpc_eec_data.rae, 1,
		     qpc_eec_data.rsc, 1 );
	MLX_FILL_1 ( &qpctx, 41, qpc_eec_data.cqn_rcv, qp->recv.cq->cqn );
	MLX_FILL_1 ( &qpctx, 42, qpc_eec_data.rcv_wqe_base_adr_l,
		     ( recv_wqe_base_adr >> 6 ) );
	MLX_FILL_1 ( &qpctx, 43, qpc_eec_data.rcv_db_record_index,
		     arbel_qp->recv.doorbell_idx );
	if ( ( rc = arbel_cmd_rst2init_qpee ( arbel, qp->qpn, &qpctx )) != 0 ){
		DBGC ( arbel, "Arbel %p QPN %#lx RST2INIT_QPEE failed: %s\n",
		       arbel, qp->qpn, strerror ( rc ) );
		goto err_rst2init_qpee;
	}
	arbel_qp->state = ARBEL_QP_ST_INIT;

	DBGC ( arbel, "Arbel %p QPN %#lx send ring [%08lx,%08lx), doorbell "
	       "%08lx\n", arbel, qp->qpn, virt_to_phys ( arbel_qp->send.wqe ),
	       ( virt_to_phys ( arbel_qp->send.wqe ) +
		 arbel_qp->send.wqe_size ),
	       virt_to_phys ( send_db_rec ) );
	DBGC ( arbel, "Arbel %p QPN %#lx receive ring [%08lx,%08lx), doorbell "
	       "%08lx\n", arbel, qp->qpn, virt_to_phys ( arbel_qp->recv.wqe ),
	       ( virt_to_phys ( arbel_qp->recv.wqe ) +
		 arbel_qp->recv.wqe_size ),
	       virt_to_phys ( recv_db_rec ) );
	DBGC ( arbel, "Arbel %p QPN %#lx send CQN %#lx receive CQN %#lx\n",
	       arbel, qp->qpn, qp->send.cq->cqn, qp->recv.cq->cqn );
	ib_qp_set_drvdata ( qp, arbel_qp );
	return 0;

	arbel_cmd_2rst_qpee ( arbel, qp->qpn );
 err_rst2init_qpee:
	MLX_FILL_1 ( send_db_rec, 1, res, ARBEL_UAR_RES_NONE );
	MLX_FILL_1 ( recv_db_rec, 1, res, ARBEL_UAR_RES_NONE );
 err_unsupported_address_split:
	free_dma ( arbel_qp->recv.wqe, arbel_qp->recv.wqe_size );
 err_create_recv_wq:
	free_dma ( arbel_qp->send.wqe, arbel_qp->send.wqe_size );
 err_create_send_wq:
	free ( arbel_qp );
 err_arbel_qp:
	arbel_free_qpn ( ibdev, qp );
 err_alloc_qpn:
	return rc;
}

/**
 * Modify queue pair
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @ret rc		Return status code
 */
static int arbel_modify_qp ( struct ib_device *ibdev,
			     struct ib_queue_pair *qp ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbel_queue_pair *arbel_qp = ib_qp_get_drvdata ( qp );
	struct arbelprm_qp_ee_state_transitions qpctx;
	int rc;

	/* Transition queue to RTR state, if applicable */
	if ( arbel_qp->state < ARBEL_QP_ST_RTR ) {
		memset ( &qpctx, 0, sizeof ( qpctx ) );
		MLX_FILL_2 ( &qpctx, 4,
			     qpc_eec_data.mtu, ARBEL_MTU_2048,
			     qpc_eec_data.msg_max, 31 );
		MLX_FILL_1 ( &qpctx, 7,
			     qpc_eec_data.remote_qpn_een, qp->av.qpn );
		MLX_FILL_2 ( &qpctx, 11,
			     qpc_eec_data.primary_address_path.rnr_retry,
			     ARBEL_RETRY_MAX,
			     qpc_eec_data.primary_address_path.rlid,
			     qp->av.lid );
		MLX_FILL_2 ( &qpctx, 12,
			     qpc_eec_data.primary_address_path.ack_timeout,
			     14 /* 4.096us * 2^(14) = 67ms */,
			     qpc_eec_data.primary_address_path.max_stat_rate,
			     arbel_rate ( &qp->av ) );
		memcpy ( &qpctx.u.dwords[14], &qp->av.gid,
			 sizeof ( qp->av.gid ) );
		MLX_FILL_1 ( &qpctx, 30,
			     qpc_eec_data.retry_count, ARBEL_RETRY_MAX );
		MLX_FILL_1 ( &qpctx, 39,
			     qpc_eec_data.next_rcv_psn, qp->recv.psn );
		MLX_FILL_1 ( &qpctx, 40,
			     qpc_eec_data.ra_buff_indx,
			     ( arbel->limits.reserved_rdbs +
			       ( ( qp->qpn & ~ARBEL_QPN_RANDOM_MASK ) -
				 arbel->special_qpn_base ) ) );
		if ( ( rc = arbel_cmd_init2rtr_qpee ( arbel, qp->qpn,
						      &qpctx ) ) != 0 ) {
			DBGC ( arbel, "Arbel %p QPN %#lx INIT2RTR_QPEE failed:"
			       " %s\n", arbel, qp->qpn, strerror ( rc ) );
			return rc;
		}
		arbel_qp->state = ARBEL_QP_ST_RTR;
	}

	/* Transition queue to RTS state, if applicable */
	if ( arbel_qp->state < ARBEL_QP_ST_RTS ) {
		memset ( &qpctx, 0, sizeof ( qpctx ) );
		MLX_FILL_1 ( &qpctx, 11,
			     qpc_eec_data.primary_address_path.rnr_retry,
			     ARBEL_RETRY_MAX );
		MLX_FILL_1 ( &qpctx, 12,
			     qpc_eec_data.primary_address_path.ack_timeout,
			     14 /* 4.096us * 2^(14) = 67ms */ );
		MLX_FILL_2 ( &qpctx, 30,
			     qpc_eec_data.retry_count, ARBEL_RETRY_MAX,
			     qpc_eec_data.sic, 1 );
		MLX_FILL_1 ( &qpctx, 32,
			     qpc_eec_data.next_send_psn, qp->send.psn );
		if ( ( rc = arbel_cmd_rtr2rts_qpee ( arbel, qp->qpn,
						     &qpctx ) ) != 0 ) {
			DBGC ( arbel, "Arbel %p QPN %#lx RTR2RTS_QPEE failed: "
			       "%s\n", arbel, qp->qpn, strerror ( rc ) );
			return rc;
		}
		arbel_qp->state = ARBEL_QP_ST_RTS;
	}

	/* Update parameters in RTS state */
	memset ( &qpctx, 0, sizeof ( qpctx ) );
	MLX_FILL_1 ( &qpctx, 0, opt_param_mask, ARBEL_QPEE_OPT_PARAM_QKEY );
	MLX_FILL_1 ( &qpctx, 44, qpc_eec_data.q_key, qp->qkey );
	if ( ( rc = arbel_cmd_rts2rts_qpee ( arbel, qp->qpn, &qpctx ) ) != 0 ){
		DBGC ( arbel, "Arbel %p QPN %#lx RTS2RTS_QPEE failed: %s\n",
		       arbel, qp->qpn, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Destroy queue pair
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 */
static void arbel_destroy_qp ( struct ib_device *ibdev,
			       struct ib_queue_pair *qp ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbel_queue_pair *arbel_qp = ib_qp_get_drvdata ( qp );
	struct arbelprm_qp_db_record *send_db_rec;
	struct arbelprm_qp_db_record *recv_db_rec;
	int rc;

	/* Take ownership back from hardware */
	if ( ( rc = arbel_cmd_2rst_qpee ( arbel, qp->qpn ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p QPN %#lx FATAL 2RST_QPEE failed: "
		       "%s\n", arbel, qp->qpn, strerror ( rc ) );
		/* Leak memory and return; at least we avoid corruption */
		return;
	}

	/* Clear doorbell records */
	send_db_rec = &arbel->db_rec[arbel_qp->send.doorbell_idx].qp;
	recv_db_rec = &arbel->db_rec[arbel_qp->recv.doorbell_idx].qp;
	MLX_FILL_1 ( send_db_rec, 1, res, ARBEL_UAR_RES_NONE );
	MLX_FILL_1 ( recv_db_rec, 1, res, ARBEL_UAR_RES_NONE );

	/* Free memory */
	free_dma ( arbel_qp->send.wqe, arbel_qp->send.wqe_size );
	free_dma ( arbel_qp->recv.wqe, arbel_qp->recv.wqe_size );
	free ( arbel_qp );

	/* Mark queue number as free */
	arbel_free_qpn ( ibdev, qp );

	ib_qp_set_drvdata ( qp, NULL );
}

/***************************************************************************
 *
 * Work request operations
 *
 ***************************************************************************
 */

/**
 * Ring doorbell register in UAR
 *
 * @v arbel		Arbel device
 * @v db_reg		Doorbell register structure
 * @v offset		Address of doorbell
 */
static void arbel_ring_doorbell ( struct arbel *arbel,
				  union arbelprm_doorbell_register *db_reg,
				  unsigned int offset ) {

	DBGC2 ( arbel, "Arbel %p ringing doorbell %08x:%08x at %lx\n",
		arbel, ntohl ( db_reg->dword[0] ), ntohl ( db_reg->dword[1] ),
		virt_to_phys ( arbel->uar + offset ) );

	barrier();
	writel ( db_reg->dword[0], ( arbel->uar + offset + 0 ) );
	barrier();
	writel ( db_reg->dword[1], ( arbel->uar + offset + 4 ) );
}

/** GID used for GID-less send work queue entries */
static const union ib_gid arbel_no_gid = {
	.bytes = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0 },
};

/**
 * Construct UD send work queue entry
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v dest		Destination address vector
 * @v iobuf		I/O buffer
 * @v wqe		Send work queue entry
 * @ret nds		Work queue entry size
 */
static size_t arbel_fill_ud_send_wqe ( struct ib_device *ibdev,
				       struct ib_queue_pair *qp __unused,
				       struct ib_address_vector *dest,
				       struct io_buffer *iobuf,
				       union arbel_send_wqe *wqe ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	const union ib_gid *gid;

	/* Construct this work queue entry */
	MLX_FILL_1 ( &wqe->ud.ctrl, 0, always1, 1 );
	MLX_FILL_2 ( &wqe->ud.ud, 0,
		     ud_address_vector.pd, ARBEL_GLOBAL_PD,
		     ud_address_vector.port_number, ibdev->port );
	MLX_FILL_2 ( &wqe->ud.ud, 1,
		     ud_address_vector.rlid, dest->lid,
		     ud_address_vector.g, dest->gid_present );
	MLX_FILL_2 ( &wqe->ud.ud, 2,
		     ud_address_vector.max_stat_rate, arbel_rate ( dest ),
		     ud_address_vector.msg, 3 );
	MLX_FILL_1 ( &wqe->ud.ud, 3, ud_address_vector.sl, dest->sl );
	gid = ( dest->gid_present ? &dest->gid : &arbel_no_gid );
	memcpy ( &wqe->ud.ud.u.dwords[4], gid, sizeof ( *gid ) );
	MLX_FILL_1 ( &wqe->ud.ud, 8, destination_qp, dest->qpn );
	MLX_FILL_1 ( &wqe->ud.ud, 9, q_key, dest->qkey );
	MLX_FILL_1 ( &wqe->ud.data[0], 0, byte_count, iob_len ( iobuf ) );
	MLX_FILL_1 ( &wqe->ud.data[0], 1, l_key, arbel->lkey );
	MLX_FILL_H ( &wqe->ud.data[0], 2,
		     local_address_h, virt_to_bus ( iobuf->data ) );
	MLX_FILL_1 ( &wqe->ud.data[0], 3,
		     local_address_l, virt_to_bus ( iobuf->data ) );

	return ( offsetof ( typeof ( wqe->ud ), data[1] ) >> 4 );
}

/**
 * Construct MLX send work queue entry
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v dest		Destination address vector
 * @v iobuf		I/O buffer
 * @v wqe		Send work queue entry
 * @ret nds		Work queue entry size
 */
static size_t arbel_fill_mlx_send_wqe ( struct ib_device *ibdev,
					struct ib_queue_pair *qp,
					struct ib_address_vector *dest,
					struct io_buffer *iobuf,
					union arbel_send_wqe *wqe ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct io_buffer headers;

	/* Construct IB headers */
	iob_populate ( &headers, &wqe->mlx.headers, 0,
		       sizeof ( wqe->mlx.headers ) );
	iob_reserve ( &headers, sizeof ( wqe->mlx.headers ) );
	ib_push ( ibdev, &headers, qp, iob_len ( iobuf ), dest );

	/* Construct this work queue entry */
	MLX_FILL_5 ( &wqe->mlx.ctrl, 0,
		     c, 1 /* generate completion */,
		     icrc, 0 /* generate ICRC */,
		     max_statrate, arbel_rate ( dest ),
		     slr, 0,
		     v15, ( ( qp->ext_qpn == IB_QPN_SMI ) ? 1 : 0 ) );
	MLX_FILL_1 ( &wqe->mlx.ctrl, 1, rlid, dest->lid );
	MLX_FILL_1 ( &wqe->mlx.data[0], 0,
		     byte_count, iob_len ( &headers ) );
	MLX_FILL_1 ( &wqe->mlx.data[0], 1, l_key, arbel->lkey );
	MLX_FILL_H ( &wqe->mlx.data[0], 2,
		     local_address_h, virt_to_bus ( headers.data ) );
	MLX_FILL_1 ( &wqe->mlx.data[0], 3,
		     local_address_l, virt_to_bus ( headers.data ) );
	MLX_FILL_1 ( &wqe->mlx.data[1], 0,
		     byte_count, ( iob_len ( iobuf ) + 4 /* ICRC */ ) );
	MLX_FILL_1 ( &wqe->mlx.data[1], 1, l_key, arbel->lkey );
	MLX_FILL_H ( &wqe->mlx.data[1], 2,
		     local_address_h, virt_to_bus ( iobuf->data ) );
	MLX_FILL_1 ( &wqe->mlx.data[1], 3,
		     local_address_l, virt_to_bus ( iobuf->data ) );

	return ( offsetof ( typeof ( wqe->mlx ), data[2] ) >> 4 );
}

/**
 * Construct RC send work queue entry
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v dest		Destination address vector
 * @v iobuf		I/O buffer
 * @v wqe		Send work queue entry
 * @ret nds		Work queue entry size
 */
static size_t arbel_fill_rc_send_wqe ( struct ib_device *ibdev,
				       struct ib_queue_pair *qp __unused,
				       struct ib_address_vector *dest __unused,
				       struct io_buffer *iobuf,
				       union arbel_send_wqe *wqe ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );

	/* Construct this work queue entry */
	MLX_FILL_1 ( &wqe->rc.ctrl, 0, always1, 1 );
	MLX_FILL_1 ( &wqe->rc.data[0], 0, byte_count, iob_len ( iobuf ) );
	MLX_FILL_1 ( &wqe->rc.data[0], 1, l_key, arbel->lkey );
	MLX_FILL_H ( &wqe->rc.data[0], 2,
		     local_address_h, virt_to_bus ( iobuf->data ) );
	MLX_FILL_1 ( &wqe->rc.data[0], 3,
		     local_address_l, virt_to_bus ( iobuf->data ) );

	return ( offsetof ( typeof ( wqe->rc ), data[1] ) >> 4 );
}

/** Work queue entry constructors */
static size_t
( * arbel_fill_send_wqe[] ) ( struct ib_device *ibdev,
			      struct ib_queue_pair *qp,
			      struct ib_address_vector *dest,
			      struct io_buffer *iobuf,
			      union arbel_send_wqe *wqe ) = {
	[IB_QPT_SMI] = arbel_fill_mlx_send_wqe,
	[IB_QPT_GSI] = arbel_fill_mlx_send_wqe,
	[IB_QPT_UD] = arbel_fill_ud_send_wqe,
	[IB_QPT_RC] = arbel_fill_rc_send_wqe,
};

/**
 * Post send work queue entry
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v dest		Destination address vector
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int arbel_post_send ( struct ib_device *ibdev,
			     struct ib_queue_pair *qp,
			     struct ib_address_vector *dest,
			     struct io_buffer *iobuf ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbel_queue_pair *arbel_qp = ib_qp_get_drvdata ( qp );
	struct ib_work_queue *wq = &qp->send;
	struct arbel_send_work_queue *arbel_send_wq = &arbel_qp->send;
	union arbel_send_wqe *prev_wqe;
	union arbel_send_wqe *wqe;
	struct arbelprm_qp_db_record *qp_db_rec;
	union arbelprm_doorbell_register db_reg;
	unsigned long wqe_idx_mask;
	size_t nds;

	/* Allocate work queue entry */
	wqe_idx_mask = ( wq->num_wqes - 1 );
	if ( wq->iobufs[wq->next_idx & wqe_idx_mask] ) {
		DBGC ( arbel, "Arbel %p QPN %#lx send queue full",
		       arbel, qp->qpn );
		return -ENOBUFS;
	}
	wq->iobufs[wq->next_idx & wqe_idx_mask] = iobuf;
	prev_wqe = &arbel_send_wq->wqe[(wq->next_idx - 1) & wqe_idx_mask];
	wqe = &arbel_send_wq->wqe[wq->next_idx & wqe_idx_mask];

	/* Construct work queue entry */
	memset ( ( ( ( void * ) wqe ) + sizeof ( wqe->next ) ), 0,
		 ( sizeof ( *wqe ) - sizeof ( wqe->next ) ) );
	assert ( qp->type < ( sizeof ( arbel_fill_send_wqe ) /
			      sizeof ( arbel_fill_send_wqe[0] ) ) );
	assert ( arbel_fill_send_wqe[qp->type] != NULL );
	nds = arbel_fill_send_wqe[qp->type] ( ibdev, qp, dest, iobuf, wqe );
	DBGCP ( arbel, "Arbel %p QPN %#lx posting send WQE %#lx:\n",
		arbel, qp->qpn, ( wq->next_idx & wqe_idx_mask ) );
	DBGCP_HDA ( arbel, virt_to_phys ( wqe ), wqe, sizeof ( *wqe ) );

	/* Update previous work queue entry's "next" field */
	MLX_SET ( &prev_wqe->next, nopcode, ARBEL_OPCODE_SEND );
	MLX_FILL_3 ( &prev_wqe->next, 1,
		     nds, nds,
		     f, 0,
		     always1, 1 );

	/* Update doorbell record */
	barrier();
	qp_db_rec = &arbel->db_rec[arbel_send_wq->doorbell_idx].qp;
	MLX_FILL_1 ( qp_db_rec, 0,
		     counter, ( ( wq->next_idx + 1 ) & 0xffff ) );

	/* Ring doorbell register */
	MLX_FILL_4 ( &db_reg.send, 0,
		     nopcode, ARBEL_OPCODE_SEND,
		     f, 0,
		     wqe_counter, ( wq->next_idx & 0xffff ),
		     wqe_cnt, 1 );
	MLX_FILL_2 ( &db_reg.send, 1,
		     nds, nds,
		     qpn, qp->qpn );
	arbel_ring_doorbell ( arbel, &db_reg, ARBEL_DB_POST_SND_OFFSET );

	/* Update work queue's index */
	wq->next_idx++;

	return 0;
}

/**
 * Post receive work queue entry
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int arbel_post_recv ( struct ib_device *ibdev,
			     struct ib_queue_pair *qp,
			     struct io_buffer *iobuf ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbel_queue_pair *arbel_qp = ib_qp_get_drvdata ( qp );
	struct ib_work_queue *wq = &qp->recv;
	struct arbel_recv_work_queue *arbel_recv_wq = &arbel_qp->recv;
	struct arbelprm_recv_wqe *wqe;
	union arbelprm_doorbell_record *db_rec;
	unsigned int wqe_idx_mask;

	/* Allocate work queue entry */
	wqe_idx_mask = ( wq->num_wqes - 1 );
	if ( wq->iobufs[wq->next_idx & wqe_idx_mask] ) {
		DBGC ( arbel, "Arbel %p QPN %#lx receive queue full\n",
		       arbel, qp->qpn );
		return -ENOBUFS;
	}
	wq->iobufs[wq->next_idx & wqe_idx_mask] = iobuf;
	wqe = &arbel_recv_wq->wqe[wq->next_idx & wqe_idx_mask].recv;

	/* Construct work queue entry */
	MLX_FILL_1 ( &wqe->data[0], 0, byte_count, iob_tailroom ( iobuf ) );
	MLX_FILL_1 ( &wqe->data[0], 1, l_key, arbel->lkey );
	MLX_FILL_H ( &wqe->data[0], 2,
		     local_address_h, virt_to_bus ( iobuf->data ) );
	MLX_FILL_1 ( &wqe->data[0], 3,
		     local_address_l, virt_to_bus ( iobuf->data ) );

	/* Update doorbell record */
	barrier();
	db_rec = &arbel->db_rec[arbel_recv_wq->doorbell_idx];
	MLX_FILL_1 ( &db_rec->qp, 0,
		     counter, ( ( wq->next_idx + 1 ) & 0xffff ) );	

	/* Update work queue's index */
	wq->next_idx++;

	return 0;	
}

/**
 * Handle completion
 *
 * @v ibdev		Infiniband device
 * @v cq		Completion queue
 * @v cqe		Hardware completion queue entry
 * @ret rc		Return status code
 */
static int arbel_complete ( struct ib_device *ibdev,
			    struct ib_completion_queue *cq,
			    union arbelprm_completion_entry *cqe ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct ib_work_queue *wq;
	struct ib_queue_pair *qp;
	struct arbel_queue_pair *arbel_qp;
	struct arbel_send_work_queue *arbel_send_wq;
	struct arbel_recv_work_queue *arbel_recv_wq;
	struct arbelprm_recv_wqe *recv_wqe;
	struct io_buffer *iobuf;
	struct ib_address_vector recv_dest;
	struct ib_address_vector recv_source;
	struct ib_global_route_header *grh;
	struct ib_address_vector *source;
	unsigned int opcode;
	unsigned long qpn;
	int is_send;
	unsigned long wqe_adr;
	unsigned long wqe_idx;
	size_t len;
	int rc = 0;

	/* Parse completion */
	qpn = MLX_GET ( &cqe->normal, my_qpn );
	is_send = MLX_GET ( &cqe->normal, s );
	wqe_adr = ( MLX_GET ( &cqe->normal, wqe_adr ) << 6 );
	opcode = MLX_GET ( &cqe->normal, opcode );
	if ( opcode >= ARBEL_OPCODE_RECV_ERROR ) {
		/* "s" field is not valid for error opcodes */
		is_send = ( opcode == ARBEL_OPCODE_SEND_ERROR );
		DBGC ( arbel, "Arbel %p CQN %#lx %s QPN %#lx syndrome %#x "
		       "vendor %#x\n", arbel, cq->cqn,
		       ( is_send ? "send" : "recv" ), qpn,
		       MLX_GET ( &cqe->error, syndrome ),
		       MLX_GET ( &cqe->error, vendor_code ) );
		DBGC_HDA ( arbel, virt_to_phys ( cqe ), cqe, sizeof ( *cqe ) );
		rc = -EIO;
		/* Don't return immediately; propagate error to completer */
	}

	/* Identify work queue */
	wq = ib_find_wq ( cq, qpn, is_send );
	if ( ! wq ) {
		DBGC ( arbel, "Arbel %p CQN %#lx unknown %s QPN %#lx\n",
		       arbel, cq->cqn, ( is_send ? "send" : "recv" ), qpn );
		return -EIO;
	}
	qp = wq->qp;
	arbel_qp = ib_qp_get_drvdata ( qp );
	arbel_send_wq = &arbel_qp->send;
	arbel_recv_wq = &arbel_qp->recv;

	/* Identify work queue entry index */
	if ( is_send ) {
		wqe_idx = ( ( wqe_adr - virt_to_bus ( arbel_send_wq->wqe ) ) /
			    sizeof ( arbel_send_wq->wqe[0] ) );
		assert ( wqe_idx < qp->send.num_wqes );
	} else {
		wqe_idx = ( ( wqe_adr - virt_to_bus ( arbel_recv_wq->wqe ) ) /
			    sizeof ( arbel_recv_wq->wqe[0] ) );
		assert ( wqe_idx < qp->recv.num_wqes );
	}

	DBGCP ( arbel, "Arbel %p CQN %#lx QPN %#lx %s WQE %#lx completed:\n",
		arbel, cq->cqn, qp->qpn, ( is_send ? "send" : "recv" ),
		wqe_idx );
	DBGCP_HDA ( arbel, virt_to_phys ( cqe ), cqe, sizeof ( *cqe ) );

	/* Identify I/O buffer */
	iobuf = wq->iobufs[wqe_idx];
	if ( ! iobuf ) {
		DBGC ( arbel, "Arbel %p CQN %#lx QPN %#lx empty %s WQE %#lx\n",
		       arbel, cq->cqn, qp->qpn, ( is_send ? "send" : "recv" ),
		       wqe_idx );
		return -EIO;
	}
	wq->iobufs[wqe_idx] = NULL;

	if ( is_send ) {
		/* Hand off to completion handler */
		ib_complete_send ( ibdev, qp, iobuf, rc );
	} else {
		/* Set received length */
		len = MLX_GET ( &cqe->normal, byte_cnt );
		recv_wqe = &arbel_recv_wq->wqe[wqe_idx].recv;
		assert ( MLX_GET ( &recv_wqe->data[0], local_address_l ) ==
			 virt_to_bus ( iobuf->data ) );
		assert ( MLX_GET ( &recv_wqe->data[0], byte_count ) ==
			 iob_tailroom ( iobuf ) );
		MLX_FILL_1 ( &recv_wqe->data[0], 0, byte_count, 0 );
		MLX_FILL_1 ( &recv_wqe->data[0], 1,
			     l_key, ARBEL_INVALID_LKEY );
		assert ( len <= iob_tailroom ( iobuf ) );
		iob_put ( iobuf, len );
		memset ( &recv_dest, 0, sizeof ( recv_dest ) );
		recv_dest.qpn = qpn;
		switch ( qp->type ) {
		case IB_QPT_SMI:
		case IB_QPT_GSI:
		case IB_QPT_UD:
			assert ( iob_len ( iobuf ) >= sizeof ( *grh ) );
			grh = iobuf->data;
			iob_pull ( iobuf, sizeof ( *grh ) );
			/* Construct address vector */
			source = &recv_source;
			memset ( source, 0, sizeof ( *source ) );
			source->qpn = MLX_GET ( &cqe->normal, rqpn );
			source->lid = MLX_GET ( &cqe->normal, rlid );
			source->sl = MLX_GET ( &cqe->normal, sl );
			recv_dest.gid_present = source->gid_present =
				MLX_GET ( &cqe->normal, g );
			memcpy ( &recv_dest.gid, &grh->dgid,
				 sizeof ( recv_dest.gid ) );
			memcpy ( &source->gid, &grh->sgid,
				 sizeof ( source->gid ) );
			break;
		case IB_QPT_RC:
			source = &qp->av;
			break;
		default:
			assert ( 0 );
			return -EINVAL;
		}
		/* Hand off to completion handler */
		ib_complete_recv ( ibdev, qp, &recv_dest, source, iobuf, rc );
	}

	return rc;
}			     

/**
 * Poll completion queue
 *
 * @v ibdev		Infiniband device
 * @v cq		Completion queue
 */
static void arbel_poll_cq ( struct ib_device *ibdev,
			    struct ib_completion_queue *cq ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbel_completion_queue *arbel_cq = ib_cq_get_drvdata ( cq );
	struct arbelprm_cq_ci_db_record *ci_db_rec;
	union arbelprm_completion_entry *cqe;
	unsigned int cqe_idx_mask;
	int rc;

	while ( 1 ) {
		/* Look for completion entry */
		cqe_idx_mask = ( cq->num_cqes - 1 );
		cqe = &arbel_cq->cqe[cq->next_idx & cqe_idx_mask];
		if ( MLX_GET ( &cqe->normal, owner ) != 0 ) {
			/* Entry still owned by hardware; end of poll */
			break;
		}

		/* Handle completion */
		if ( ( rc = arbel_complete ( ibdev, cq, cqe ) ) != 0 ) {
			DBGC ( arbel, "Arbel %p CQN %#lx failed to complete: "
			       "%s\n", arbel, cq->cqn, strerror ( rc ) );
			DBGC_HD ( arbel, cqe, sizeof ( *cqe ) );
		}

		/* Return ownership to hardware */
		MLX_FILL_1 ( &cqe->normal, 7, owner, 1 );
		barrier();
		/* Update completion queue's index */
		cq->next_idx++;
		/* Update doorbell record */
		ci_db_rec = &arbel->db_rec[arbel_cq->ci_doorbell_idx].cq_ci;
		MLX_FILL_1 ( ci_db_rec, 0,
			     counter, ( cq->next_idx & 0xffffffffUL ) );
	}
}

/***************************************************************************
 *
 * Event queues
 *
 ***************************************************************************
 */

/**
 * Create event queue
 *
 * @v arbel		Arbel device
 * @ret rc		Return status code
 */
static int arbel_create_eq ( struct arbel *arbel ) {
	struct arbel_event_queue *arbel_eq = &arbel->eq;
	struct arbelprm_eqc eqctx;
	struct arbelprm_event_mask mask;
	unsigned int i;
	int rc;

	/* Select event queue number */
	arbel_eq->eqn = arbel->limits.reserved_eqs;

	/* Calculate doorbell address */
	arbel_eq->doorbell = ( arbel->eq_ci_doorbells +
			       ARBEL_DB_EQ_OFFSET ( arbel_eq->eqn ) );

	/* Allocate event queue itself */
	arbel_eq->eqe_size =
		( ARBEL_NUM_EQES * sizeof ( arbel_eq->eqe[0] ) );
	arbel_eq->eqe = malloc_dma ( arbel_eq->eqe_size,
				     sizeof ( arbel_eq->eqe[0] ) );
	if ( ! arbel_eq->eqe ) {
		rc = -ENOMEM;
		goto err_eqe;
	}
	memset ( arbel_eq->eqe, 0, arbel_eq->eqe_size );
	for ( i = 0 ; i < ARBEL_NUM_EQES ; i++ ) {
		MLX_FILL_1 ( &arbel_eq->eqe[i].generic, 7, owner, 1 );
	}
	barrier();

	/* Hand queue over to hardware */
	memset ( &eqctx, 0, sizeof ( eqctx ) );
	MLX_FILL_1 ( &eqctx, 0, st, 0xa /* "Fired" */ );
	MLX_FILL_H ( &eqctx, 1,
		     start_address_h, virt_to_phys ( arbel_eq->eqe ) );
	MLX_FILL_1 ( &eqctx, 2,
		     start_address_l, virt_to_phys ( arbel_eq->eqe ) );
	MLX_FILL_1 ( &eqctx, 3, log_eq_size, fls ( ARBEL_NUM_EQES - 1 ) );
	MLX_FILL_1 ( &eqctx, 6, pd, ARBEL_GLOBAL_PD );
	MLX_FILL_1 ( &eqctx, 7, lkey, arbel->lkey );
	if ( ( rc = arbel_cmd_sw2hw_eq ( arbel, arbel_eq->eqn,
					 &eqctx ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p EQN %#lx SW2HW_EQ failed: %s\n",
		       arbel, arbel_eq->eqn, strerror ( rc ) );
		goto err_sw2hw_eq;
	}

	/* Map events to this event queue */
	memset ( &mask, 0xff, sizeof ( mask ) );
	if ( ( rc = arbel_cmd_map_eq ( arbel,
				       ( ARBEL_MAP_EQ | arbel_eq->eqn ),
				       &mask ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p EQN %#lx MAP_EQ failed: %s\n",
		       arbel, arbel_eq->eqn, strerror ( rc )  );
		goto err_map_eq;
	}

	DBGC ( arbel, "Arbel %p EQN %#lx ring [%08lx,%08lx), doorbell %08lx\n",
	       arbel, arbel_eq->eqn, virt_to_phys ( arbel_eq->eqe ),
	       ( virt_to_phys ( arbel_eq->eqe ) + arbel_eq->eqe_size ),
	       virt_to_phys ( arbel_eq->doorbell ) );
	return 0;

 err_map_eq:
	arbel_cmd_hw2sw_eq ( arbel, arbel_eq->eqn, &eqctx );
 err_sw2hw_eq:
	free_dma ( arbel_eq->eqe, arbel_eq->eqe_size );
 err_eqe:
	memset ( arbel_eq, 0, sizeof ( *arbel_eq ) );
	return rc;
}

/**
 * Destroy event queue
 *
 * @v arbel		Arbel device
 */
static void arbel_destroy_eq ( struct arbel *arbel ) {
	struct arbel_event_queue *arbel_eq = &arbel->eq;
	struct arbelprm_eqc eqctx;
	struct arbelprm_event_mask mask;
	int rc;

	/* Unmap events from event queue */
	memset ( &mask, 0, sizeof ( mask ) );
	MLX_FILL_1 ( &mask, 1, port_state_change, 1 );
	if ( ( rc = arbel_cmd_map_eq ( arbel,
				       ( ARBEL_UNMAP_EQ | arbel_eq->eqn ),
				       &mask ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p EQN %#lx FATAL MAP_EQ failed to "
		       "unmap: %s\n", arbel, arbel_eq->eqn, strerror ( rc ) );
		/* Continue; HCA may die but system should survive */
	}

	/* Take ownership back from hardware */
	if ( ( rc = arbel_cmd_hw2sw_eq ( arbel, arbel_eq->eqn,
					 &eqctx ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p EQN %#lx FATAL HW2SW_EQ failed: %s\n",
		       arbel, arbel_eq->eqn, strerror ( rc ) );
		/* Leak memory and return; at least we avoid corruption */
		return;
	}

	/* Free memory */
	free_dma ( arbel_eq->eqe, arbel_eq->eqe_size );
	memset ( arbel_eq, 0, sizeof ( *arbel_eq ) );
}

/**
 * Handle port state event
 *
 * @v arbel		Arbel device
 * @v eqe		Port state change event queue entry
 */
static void arbel_event_port_state_change ( struct arbel *arbel,
					    union arbelprm_event_entry *eqe){
	unsigned int port;
	int link_up;

	/* Get port and link status */
	port = ( MLX_GET ( &eqe->port_state_change, data.p ) - 1 );
	link_up = ( MLX_GET ( &eqe->generic, event_sub_type ) & 0x04 );
	DBGC ( arbel, "Arbel %p port %d link %s\n", arbel, ( port + 1 ),
	       ( link_up ? "up" : "down" ) );

	/* Sanity check */
	if ( port >= ARBEL_NUM_PORTS ) {
		DBGC ( arbel, "Arbel %p port %d does not exist!\n",
		       arbel, ( port + 1 ) );
		return;
	}

	/* Update MAD parameters */
	ib_smc_update ( arbel->ibdev[port], arbel_mad );
}

/**
 * Poll event queue
 *
 * @v ibdev		Infiniband device
 */
static void arbel_poll_eq ( struct ib_device *ibdev ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbel_event_queue *arbel_eq = &arbel->eq;
	union arbelprm_event_entry *eqe;
	union arbelprm_eq_doorbell_register db_reg;
	unsigned int eqe_idx_mask;
	unsigned int event_type;

	/* No event is generated upon reaching INIT, so we must poll
	 * separately for link state changes while we remain DOWN.
	 */
	if ( ib_is_open ( ibdev ) &&
	     ( ibdev->port_state == IB_PORT_STATE_DOWN ) ) {
		ib_smc_update ( ibdev, arbel_mad );
	}

	/* Poll event queue */
	while ( 1 ) {
		/* Look for event entry */
		eqe_idx_mask = ( ARBEL_NUM_EQES - 1 );
		eqe = &arbel_eq->eqe[arbel_eq->next_idx & eqe_idx_mask];
		if ( MLX_GET ( &eqe->generic, owner ) != 0 ) {
			/* Entry still owned by hardware; end of poll */
			break;
		}
		DBGCP ( arbel, "Arbel %p EQN %#lx event:\n",
			arbel, arbel_eq->eqn );
		DBGCP_HDA ( arbel, virt_to_phys ( eqe ),
			    eqe, sizeof ( *eqe ) );

		/* Handle event */
		event_type = MLX_GET ( &eqe->generic, event_type );
		switch ( event_type ) {
		case ARBEL_EV_PORT_STATE_CHANGE:
			arbel_event_port_state_change ( arbel, eqe );
			break;
		default:
			DBGC ( arbel, "Arbel %p EQN %#lx unrecognised event "
			       "type %#x:\n",
			       arbel, arbel_eq->eqn, event_type );
			DBGC_HDA ( arbel, virt_to_phys ( eqe ),
				   eqe, sizeof ( *eqe ) );
			break;
		}

		/* Return ownership to hardware */
		MLX_FILL_1 ( &eqe->generic, 7, owner, 1 );
		barrier();

		/* Update event queue's index */
		arbel_eq->next_idx++;

		/* Ring doorbell */
		MLX_FILL_1 ( &db_reg.ci, 0, ci, arbel_eq->next_idx );
		writel ( db_reg.dword[0], arbel_eq->doorbell );
	}
}

/***************************************************************************
 *
 * Firmware control
 *
 ***************************************************************************
 */

/**
 * Map virtual to physical address for firmware usage
 *
 * @v arbel		Arbel device
 * @v map		Mapping function
 * @v va		Virtual address
 * @v pa		Physical address
 * @v len		Length of region
 * @ret rc		Return status code
 */
static int arbel_map_vpm ( struct arbel *arbel,
			   int ( *map ) ( struct arbel *arbel,
			     const struct arbelprm_virtual_physical_mapping* ),
			   uint64_t va, physaddr_t pa, size_t len ) {
	struct arbelprm_virtual_physical_mapping mapping;
	physaddr_t start;
	physaddr_t low;
	physaddr_t high;
	physaddr_t end;
	size_t size;
	int rc;

	/* Sanity checks */
	assert ( ( va & ( ARBEL_PAGE_SIZE - 1 ) ) == 0 );
	assert ( ( pa & ( ARBEL_PAGE_SIZE - 1 ) ) == 0 );
	assert ( ( len & ( ARBEL_PAGE_SIZE - 1 ) ) == 0 );

	/* Calculate starting points */
	start = pa;
	end = ( start + len );
	size = ( 1UL << ( fls ( start ^ end ) - 1 ) );
	low = high = ( end & ~( size - 1 ) );
	assert ( start < low );
	assert ( high <= end );

	/* These mappings tend to generate huge volumes of
	 * uninteresting debug data, which basically makes it
	 * impossible to use debugging otherwise.
	 */
	DBG_DISABLE ( DBGLVL_LOG | DBGLVL_EXTRA );

	/* Map blocks in descending order of size */
	while ( size >= ARBEL_PAGE_SIZE ) {

		/* Find the next candidate block */
		if ( ( low - size ) >= start ) {
			low -= size;
			pa = low;
		} else if ( ( high + size ) <= end ) {
			pa = high;
			high += size;
		} else {
			size >>= 1;
			continue;
		}
		assert ( ( va & ( size - 1 ) ) == 0 );
		assert ( ( pa & ( size - 1 ) ) == 0 );

		/* Map this block */
		memset ( &mapping, 0, sizeof ( mapping ) );
		MLX_FILL_1 ( &mapping, 0, va_h, ( va >> 32 ) );
		MLX_FILL_1 ( &mapping, 1, va_l, ( va >> 12 ) );
		MLX_FILL_H ( &mapping, 2, pa_h, pa );
		MLX_FILL_2 ( &mapping, 3,
			     log2size, ( ( fls ( size ) - 1 ) - 12 ),
			     pa_l, ( pa >> 12 ) );
		if ( ( rc = map ( arbel, &mapping ) ) != 0 ) {
			DBG_ENABLE ( DBGLVL_LOG | DBGLVL_EXTRA );
			DBGC ( arbel, "Arbel %p could not map %08llx+%zx to "
			       "%08lx: %s\n",
			       arbel, va, size, pa, strerror ( rc ) );
			return rc;
		}
		va += size;
	}
	assert ( low == start );
	assert ( high == end );

	DBG_ENABLE ( DBGLVL_LOG | DBGLVL_EXTRA );
	return 0;
}

/**
 * Start firmware running
 *
 * @v arbel		Arbel device
 * @ret rc		Return status code
 */
static int arbel_start_firmware ( struct arbel *arbel ) {
	struct arbelprm_query_fw fw;
	struct arbelprm_access_lam lam;
	unsigned int fw_pages;
	size_t fw_len;
	physaddr_t fw_base;
	uint64_t eq_set_ci_base_addr;
	int rc;

	/* Get firmware parameters */
	if ( ( rc = arbel_cmd_query_fw ( arbel, &fw ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not query firmware: %s\n",
		       arbel, strerror ( rc ) );
		goto err_query_fw;
	}
	DBGC ( arbel, "Arbel %p firmware version %d.%d.%d\n", arbel,
	       MLX_GET ( &fw, fw_rev_major ), MLX_GET ( &fw, fw_rev_minor ),
	       MLX_GET ( &fw, fw_rev_subminor ) );
	fw_pages = MLX_GET ( &fw, fw_pages );
	DBGC ( arbel, "Arbel %p requires %d kB for firmware\n",
	       arbel, ( fw_pages * 4 ) );
	eq_set_ci_base_addr =
		( ( (uint64_t) MLX_GET ( &fw, eq_set_ci_base_addr_h ) << 32 ) |
		  ( (uint64_t) MLX_GET ( &fw, eq_set_ci_base_addr_l ) ) );
	arbel->eq_ci_doorbells = ioremap ( eq_set_ci_base_addr, 0x200 );

	/* Enable locally-attached memory.  Ignore failure; there may
	 * be no attached memory.
	 */
	arbel_cmd_enable_lam ( arbel, &lam );

	/* Allocate firmware pages and map firmware area */
	fw_len = ( fw_pages * ARBEL_PAGE_SIZE );
	if ( ! arbel->firmware_area ) {
		arbel->firmware_len = fw_len;
		arbel->firmware_area = umalloc ( arbel->firmware_len );
		if ( ! arbel->firmware_area ) {
			rc = -ENOMEM;
			goto err_alloc_fa;
		}
	} else {
		assert ( arbel->firmware_len == fw_len );
	}
	fw_base = user_to_phys ( arbel->firmware_area, 0 );
	DBGC ( arbel, "Arbel %p firmware area at [%08lx,%08lx)\n",
	       arbel, fw_base, ( fw_base + fw_len ) );
	if ( ( rc = arbel_map_vpm ( arbel, arbel_cmd_map_fa,
				    0, fw_base, fw_len ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not map firmware: %s\n",
		       arbel, strerror ( rc ) );
		goto err_map_fa;
	}

	/* Start firmware */
	if ( ( rc = arbel_cmd_run_fw ( arbel ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not run firmware: %s\n",
		       arbel, strerror ( rc ) );
		goto err_run_fw;
	}

	DBGC ( arbel, "Arbel %p firmware started\n", arbel );
	return 0;

 err_run_fw:
	arbel_cmd_unmap_fa ( arbel );
 err_map_fa:
 err_alloc_fa:
 err_query_fw:
	return rc;
}

/**
 * Stop firmware running
 *
 * @v arbel		Arbel device
 */
static void arbel_stop_firmware ( struct arbel *arbel ) {
	int rc;

	if ( ( rc = arbel_cmd_unmap_fa ( arbel ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p FATAL could not stop firmware: %s\n",
		       arbel, strerror ( rc ) );
		/* Leak memory and return; at least we avoid corruption */
		arbel->firmware_area = UNULL;
		return;
	}
}

/***************************************************************************
 *
 * Infinihost Context Memory management
 *
 ***************************************************************************
 */

/**
 * Get device limits
 *
 * @v arbel		Arbel device
 * @ret rc		Return status code
 */
static int arbel_get_limits ( struct arbel *arbel ) {
	struct arbelprm_query_dev_lim dev_lim;
	int rc;

	if ( ( rc = arbel_cmd_query_dev_lim ( arbel, &dev_lim ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not get device limits: %s\n",
		       arbel, strerror ( rc ) );
		return rc;
	}

	arbel->limits.reserved_qps =
		( 1 << MLX_GET ( &dev_lim, log2_rsvd_qps ) );
	arbel->limits.qpc_entry_size = MLX_GET ( &dev_lim, qpc_entry_sz );
	arbel->limits.eqpc_entry_size = MLX_GET ( &dev_lim, eqpc_entry_sz );
	arbel->limits.reserved_srqs =
		( 1 << MLX_GET ( &dev_lim, log2_rsvd_srqs ) );
	arbel->limits.srqc_entry_size = MLX_GET ( &dev_lim, srq_entry_sz );
	arbel->limits.reserved_ees =
		( 1 << MLX_GET ( &dev_lim, log2_rsvd_ees ) );
	arbel->limits.eec_entry_size = MLX_GET ( &dev_lim, eec_entry_sz );
	arbel->limits.eeec_entry_size = MLX_GET ( &dev_lim, eeec_entry_sz );
	arbel->limits.reserved_cqs =
		( 1 << MLX_GET ( &dev_lim, log2_rsvd_cqs ) );
	arbel->limits.cqc_entry_size = MLX_GET ( &dev_lim, cqc_entry_sz );
	arbel->limits.reserved_mtts =
		( 1 << MLX_GET ( &dev_lim, log2_rsvd_mtts ) );
	arbel->limits.mtt_entry_size = MLX_GET ( &dev_lim, mtt_entry_sz );
	arbel->limits.reserved_mrws =
		( 1 << MLX_GET ( &dev_lim, log2_rsvd_mrws ) );
	arbel->limits.mpt_entry_size = MLX_GET ( &dev_lim, mpt_entry_sz );
	arbel->limits.reserved_rdbs =
		( 1 << MLX_GET ( &dev_lim, log2_rsvd_rdbs ) );
	arbel->limits.reserved_eqs = MLX_GET ( &dev_lim, num_rsvd_eqs );
	arbel->limits.eqc_entry_size = MLX_GET ( &dev_lim, eqc_entry_sz );
	arbel->limits.reserved_uars = MLX_GET ( &dev_lim, num_rsvd_uars );
	arbel->limits.uar_scratch_entry_size =
		MLX_GET ( &dev_lim, uar_scratch_entry_sz );

	DBGC ( arbel, "Arbel %p reserves %d x %#zx QPC, %d x %#zx EQPC, "
	       "%d x %#zx SRQC\n", arbel,
	       arbel->limits.reserved_qps, arbel->limits.qpc_entry_size,
	       arbel->limits.reserved_qps, arbel->limits.eqpc_entry_size,
	       arbel->limits.reserved_srqs, arbel->limits.srqc_entry_size );
	DBGC ( arbel, "Arbel %p reserves %d x %#zx EEC, %d x %#zx EEEC, "
	       "%d x %#zx CQC\n", arbel,
	       arbel->limits.reserved_ees, arbel->limits.eec_entry_size,
	       arbel->limits.reserved_ees, arbel->limits.eeec_entry_size,
	       arbel->limits.reserved_cqs, arbel->limits.cqc_entry_size );
	DBGC ( arbel, "Arbel %p reserves %d x %#zx EQC, %d x %#zx MTT, "
	       "%d x %#zx MPT\n", arbel,
	       arbel->limits.reserved_eqs, arbel->limits.eqc_entry_size,
	       arbel->limits.reserved_mtts, arbel->limits.mtt_entry_size,
	       arbel->limits.reserved_mrws, arbel->limits.mpt_entry_size );
	DBGC ( arbel, "Arbel %p reserves %d x %#zx RDB, %d x %#zx UAR, "
	       "%d x %#zx UAR scratchpad\n", arbel,
	       arbel->limits.reserved_rdbs, ARBEL_RDB_ENTRY_SIZE,
	       arbel->limits.reserved_uars, ARBEL_PAGE_SIZE,
	       arbel->limits.reserved_uars,
	       arbel->limits.uar_scratch_entry_size );

	return 0;
}

/**
 * Align ICM table
 *
 * @v icm_offset	Current ICM offset
 * @v len		ICM table length
 * @ret icm_offset	ICM offset
 */
static size_t icm_align ( size_t icm_offset, size_t len ) {

	/* Round up to a multiple of the table size */
	assert ( len == ( 1UL << ( fls ( len ) - 1 ) ) );
	return ( ( icm_offset + len - 1 ) & ~( len - 1 ) );
}

/**
 * Allocate ICM
 *
 * @v arbel		Arbel device
 * @v init_hca		INIT_HCA structure to fill in
 * @ret rc		Return status code
 */
static int arbel_alloc_icm ( struct arbel *arbel,
			     struct arbelprm_init_hca *init_hca ) {
	struct arbelprm_scalar_parameter icm_size;
	struct arbelprm_scalar_parameter icm_aux_size;
	struct arbelprm_scalar_parameter unmap_icm;
	union arbelprm_doorbell_record *db_rec;
	size_t icm_offset = 0;
	unsigned int log_num_uars, log_num_qps, log_num_srqs, log_num_ees;
	unsigned int log_num_cqs, log_num_mtts, log_num_mpts, log_num_rdbs;
	unsigned int log_num_eqs, log_num_mcs;
	size_t icm_len, icm_aux_len;
	size_t len;
	physaddr_t icm_phys;
	int rc;

	/* Calculate number of each object type within ICM */
	log_num_qps = fls ( arbel->limits.reserved_qps +
			    ARBEL_RSVD_SPECIAL_QPS + ARBEL_MAX_QPS - 1 );
	log_num_srqs = fls ( arbel->limits.reserved_srqs - 1 );
	log_num_ees = fls ( arbel->limits.reserved_ees - 1 );
	log_num_cqs = fls ( arbel->limits.reserved_cqs + ARBEL_MAX_CQS - 1 );
	log_num_eqs = fls ( arbel->limits.reserved_eqs + ARBEL_MAX_EQS - 1 );
	log_num_mtts = fls ( arbel->limits.reserved_mtts - 1 );
	log_num_mpts = fls ( arbel->limits.reserved_mrws + 1 - 1 );
	log_num_rdbs = fls ( arbel->limits.reserved_rdbs +
			     ARBEL_RSVD_SPECIAL_QPS + ARBEL_MAX_QPS - 1 );
	log_num_uars = fls ( arbel->limits.reserved_uars +
			     1 /* single UAR used */ - 1 );
	log_num_mcs = ARBEL_LOG_MULTICAST_HASH_SIZE;

	/* Queue pair contexts */
	len = ( ( 1 << log_num_qps ) * arbel->limits.qpc_entry_size );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_2 ( init_hca, 13,
		     qpc_eec_cqc_eqc_rdb_parameters.qpc_base_addr_l,
		     ( icm_offset >> 7 ),
		     qpc_eec_cqc_eqc_rdb_parameters.log_num_of_qp,
		     log_num_qps );
	DBGC ( arbel, "Arbel %p ICM QPC is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_qps ), arbel->limits.qpc_entry_size,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* Extended queue pair contexts */
	len = ( ( 1 << log_num_qps ) * arbel->limits.eqpc_entry_size );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_1 ( init_hca, 25,
		     qpc_eec_cqc_eqc_rdb_parameters.eqpc_base_addr_l,
		     icm_offset );
	DBGC ( arbel, "Arbel %p ICM EQPC is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_qps ), arbel->limits.eqpc_entry_size,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* Completion queue contexts */
	len = ( ( 1 << log_num_cqs ) * arbel->limits.cqc_entry_size );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_2 ( init_hca, 21,
		     qpc_eec_cqc_eqc_rdb_parameters.cqc_base_addr_l,
		     ( icm_offset >> 6 ),
		     qpc_eec_cqc_eqc_rdb_parameters.log_num_of_cq,
		     log_num_cqs );
	DBGC ( arbel, "Arbel %p ICM CQC is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_cqs ), arbel->limits.cqc_entry_size,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* Event queue contexts */
	len = ( ( 1 << log_num_eqs ) * arbel->limits.eqc_entry_size );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_2 ( init_hca, 33,
		     qpc_eec_cqc_eqc_rdb_parameters.eqc_base_addr_l,
		     ( icm_offset >> 6 ),
		     qpc_eec_cqc_eqc_rdb_parameters.log_num_eq,
		     log_num_eqs );
	DBGC ( arbel, "Arbel %p ICM EQC is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_eqs ), arbel->limits.eqc_entry_size,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* End-to-end contexts */
	len = ( ( 1 << log_num_ees ) * arbel->limits.eec_entry_size );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_2 ( init_hca, 17,
		     qpc_eec_cqc_eqc_rdb_parameters.eec_base_addr_l,
		     ( icm_offset >> 7 ),
		     qpc_eec_cqc_eqc_rdb_parameters.log_num_of_ee,
		     log_num_ees );
	DBGC ( arbel, "Arbel %p ICM EEC is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_ees ), arbel->limits.eec_entry_size,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* Shared receive queue contexts */
	len = ( ( 1 << log_num_srqs ) * arbel->limits.srqc_entry_size );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_2 ( init_hca, 19,
		     qpc_eec_cqc_eqc_rdb_parameters.srqc_base_addr_l,
		     ( icm_offset >> 5 ),
		     qpc_eec_cqc_eqc_rdb_parameters.log_num_of_srq,
		     log_num_srqs );
	DBGC ( arbel, "Arbel %p ICM SRQC is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_srqs ), arbel->limits.srqc_entry_size,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* Memory protection table */
	len = ( ( 1 << log_num_mpts ) * arbel->limits.mpt_entry_size );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_1 ( init_hca, 61,
		     tpt_parameters.mpt_base_adr_l, icm_offset );
	MLX_FILL_1 ( init_hca, 62,
		     tpt_parameters.log_mpt_sz, log_num_mpts );
	DBGC ( arbel, "Arbel %p ICM MPT is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_mpts ), arbel->limits.mpt_entry_size,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* Remote read data base table */
	len = ( ( 1 << log_num_rdbs ) * ARBEL_RDB_ENTRY_SIZE );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_1 ( init_hca, 37,
		     qpc_eec_cqc_eqc_rdb_parameters.rdb_base_addr_l,
		     icm_offset );
	DBGC ( arbel, "Arbel %p ICM RDB is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_rdbs ), ARBEL_RDB_ENTRY_SIZE,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* Extended end-to-end contexts */
	len = ( ( 1 << log_num_ees ) * arbel->limits.eeec_entry_size );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_1 ( init_hca, 29,
		     qpc_eec_cqc_eqc_rdb_parameters.eeec_base_addr_l,
		     icm_offset );
	DBGC ( arbel, "Arbel %p ICM EEEC is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_ees ), arbel->limits.eeec_entry_size,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* Multicast table */
	len = ( ( 1 << log_num_mcs ) * sizeof ( struct arbelprm_mgm_entry ) );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_1 ( init_hca, 49,
		     multicast_parameters.mc_base_addr_l, icm_offset );
	MLX_FILL_1 ( init_hca, 52,
		     multicast_parameters.log_mc_table_entry_sz,
		     fls ( sizeof ( struct arbelprm_mgm_entry ) - 1 ) );
	MLX_FILL_1 ( init_hca, 53,
		     multicast_parameters.mc_table_hash_sz,
		     ( 1 << log_num_mcs ) );
	MLX_FILL_1 ( init_hca, 54,
		     multicast_parameters.log_mc_table_sz,
		     log_num_mcs /* Only one entry per hash */ );
	DBGC ( arbel, "Arbel %p ICM MC is %d x %#zx at [%zx,%zx)\n", arbel,
	       ( 1 << log_num_mcs ), sizeof ( struct arbelprm_mgm_entry ),
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* Memory translation table */
	len = ( ( 1 << log_num_mtts ) * arbel->limits.mtt_entry_size );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_1 ( init_hca, 65,
		     tpt_parameters.mtt_base_addr_l, icm_offset );
	DBGC ( arbel, "Arbel %p ICM MTT is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_mtts ), arbel->limits.mtt_entry_size,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* User access region scratchpads */
	len = ( ( 1 << log_num_uars ) * arbel->limits.uar_scratch_entry_size );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_1 ( init_hca, 77,
		     uar_parameters.uar_scratch_base_addr_l, icm_offset );
	DBGC ( arbel, "Arbel %p UAR scratchpad is %d x %#zx at [%zx,%zx)\n",
	       arbel, ( 1 << log_num_uars ),
	       arbel->limits.uar_scratch_entry_size,
	       icm_offset, ( icm_offset + len ) );
	icm_offset += len;

	/* Record amount of ICM to be allocated */
	icm_offset = icm_align ( icm_offset, ARBEL_PAGE_SIZE );
	icm_len = icm_offset;

	/* User access region contexts
	 *
	 * The reserved UAR(s) do not need to be backed by physical
	 * memory, and our UAR is allocated separately; neither are
	 * part of the umalloc()ed ICM block, but both contribute to
	 * the total length of ICM virtual address space.
	 */
	len = ( ( 1 << log_num_uars ) * ARBEL_PAGE_SIZE );
	icm_offset = icm_align ( icm_offset, len );
	MLX_FILL_1 ( init_hca, 74, uar_parameters.log_max_uars, log_num_uars );
	MLX_FILL_1 ( init_hca, 79,
		     uar_parameters.uar_context_base_addr_l, icm_offset );
	arbel->db_rec_offset =
		( icm_offset +
		  ( arbel->limits.reserved_uars * ARBEL_PAGE_SIZE ) );
	DBGC ( arbel, "Arbel %p UAR is %d x %#zx at [%zx,%zx), doorbells "
	       "[%zx,%zx)\n", arbel, ( 1 << log_num_uars ), ARBEL_PAGE_SIZE,
	       icm_offset, ( icm_offset + len ), arbel->db_rec_offset,
	       ( arbel->db_rec_offset + ARBEL_PAGE_SIZE ) );
	icm_offset += len;

	/* Get ICM auxiliary area size */
	memset ( &icm_size, 0, sizeof ( icm_size ) );
	MLX_FILL_1 ( &icm_size, 1, value, icm_len );
	if ( ( rc = arbel_cmd_set_icm_size ( arbel, &icm_size,
					     &icm_aux_size ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not set ICM size: %s\n",
		       arbel, strerror ( rc ) );
		goto err_set_icm_size;
	}
	icm_aux_len = ( MLX_GET ( &icm_aux_size, value ) * ARBEL_PAGE_SIZE );

	/* Allocate ICM data and auxiliary area */
	DBGC ( arbel, "Arbel %p requires %zd kB ICM and %zd kB AUX ICM\n",
	       arbel, ( icm_len / 1024 ), ( icm_aux_len / 1024 ) );
	if ( ! arbel->icm ) {
		arbel->icm_len = icm_len;
		arbel->icm_aux_len = icm_aux_len;
		arbel->icm = umalloc ( arbel->icm_len + arbel->icm_aux_len );
		if ( ! arbel->icm ) {
			rc = -ENOMEM;
			goto err_alloc_icm;
		}
	} else {
		assert ( arbel->icm_len == icm_len );
		assert ( arbel->icm_aux_len == icm_aux_len );
	}
	icm_phys = user_to_phys ( arbel->icm, 0 );

	/* Allocate doorbell UAR */
	arbel->db_rec = malloc_dma ( ARBEL_PAGE_SIZE, ARBEL_PAGE_SIZE );
	if ( ! arbel->db_rec ) {
		rc = -ENOMEM;
		goto err_alloc_doorbell;
	}

	/* Map ICM auxiliary area */
	DBGC ( arbel, "Arbel %p ICM AUX at [%08lx,%08lx)\n",
	       arbel, icm_phys, ( icm_phys + arbel->icm_aux_len ) );
	if ( ( rc = arbel_map_vpm ( arbel, arbel_cmd_map_icm_aux,
				    0, icm_phys, arbel->icm_aux_len ) ) != 0 ){
		DBGC ( arbel, "Arbel %p could not map AUX ICM: %s\n",
		       arbel, strerror ( rc ) );
		goto err_map_icm_aux;
	}
	icm_phys += arbel->icm_aux_len;

	/* Map ICM area */
	DBGC ( arbel, "Arbel %p ICM at [%08lx,%08lx)\n",
	       arbel, icm_phys, ( icm_phys + arbel->icm_len ) );
	if ( ( rc = arbel_map_vpm ( arbel, arbel_cmd_map_icm,
				    0, icm_phys, arbel->icm_len ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not map ICM: %s\n",
		       arbel, strerror ( rc ) );
		goto err_map_icm;
	}
	icm_phys += arbel->icm_len;

	/* Map doorbell UAR */
	DBGC ( arbel, "Arbel %p UAR at [%08lx,%08lx)\n",
	       arbel, virt_to_phys ( arbel->db_rec ),
	       ( virt_to_phys ( arbel->db_rec ) + ARBEL_PAGE_SIZE ) );
	if ( ( rc = arbel_map_vpm ( arbel, arbel_cmd_map_icm,
				    arbel->db_rec_offset,
				    virt_to_phys ( arbel->db_rec ),
				    ARBEL_PAGE_SIZE ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not map doorbell UAR: %s\n",
		       arbel, strerror ( rc ) );
		goto err_map_doorbell;
	}

	/* Initialise doorbell records */
	memset ( arbel->db_rec, 0, ARBEL_PAGE_SIZE );
	db_rec = &arbel->db_rec[ARBEL_GROUP_SEPARATOR_DOORBELL];
	MLX_FILL_1 ( &db_rec->qp, 1, res, ARBEL_UAR_RES_GROUP_SEP );

	return 0;

	memset ( &unmap_icm, 0, sizeof ( unmap_icm ) );
	MLX_FILL_1 ( &unmap_icm, 1, value, arbel->db_rec_offset );
	arbel_cmd_unmap_icm ( arbel, 1, &unmap_icm );
 err_map_doorbell:
	memset ( &unmap_icm, 0, sizeof ( unmap_icm ) );
	arbel_cmd_unmap_icm ( arbel, ( arbel->icm_len / ARBEL_PAGE_SIZE ),
			      &unmap_icm );
 err_map_icm:
	arbel_cmd_unmap_icm_aux ( arbel );
 err_map_icm_aux:
	free_dma ( arbel->db_rec, ARBEL_PAGE_SIZE );
	arbel->db_rec= NULL;
 err_alloc_doorbell:
 err_alloc_icm:
 err_set_icm_size:
	return rc;
}

/**
 * Free ICM
 *
 * @v arbel		Arbel device
 */
static void arbel_free_icm ( struct arbel *arbel ) {
	struct arbelprm_scalar_parameter unmap_icm;

	memset ( &unmap_icm, 0, sizeof ( unmap_icm ) );
	MLX_FILL_1 ( &unmap_icm, 1, value, arbel->db_rec_offset );
	arbel_cmd_unmap_icm ( arbel, 1, &unmap_icm );
	memset ( &unmap_icm, 0, sizeof ( unmap_icm ) );
	arbel_cmd_unmap_icm ( arbel, ( arbel->icm_len / ARBEL_PAGE_SIZE ),
			      &unmap_icm );
	arbel_cmd_unmap_icm_aux ( arbel );
	free_dma ( arbel->db_rec, ARBEL_PAGE_SIZE );
	arbel->db_rec = NULL;
}

/***************************************************************************
 *
 * Initialisation and teardown
 *
 ***************************************************************************
 */

/**
 * Reset device
 *
 * @v arbel		Arbel device
 */
static void arbel_reset ( struct arbel *arbel ) {
	struct pci_device *pci = arbel->pci;
	struct pci_config_backup backup;
	static const uint8_t backup_exclude[] =
		PCI_CONFIG_BACKUP_EXCLUDE ( 0x58, 0x5c );
	uint16_t vendor;
	unsigned int i;

	/* Perform device reset and preserve PCI configuration */
	pci_backup ( pci, &backup, backup_exclude );
	writel ( ARBEL_RESET_MAGIC,
		 ( arbel->config + ARBEL_RESET_OFFSET ) );
	for ( i = 0 ; i < ARBEL_RESET_WAIT_TIME_MS ; i++ ) {
		mdelay ( 1 );
		pci_read_config_word ( pci, PCI_VENDOR_ID, &vendor );
		if ( vendor != 0xffff )
			break;
	}
	pci_restore ( pci, &backup, backup_exclude );
}

/**
 * Set up memory protection table
 *
 * @v arbel		Arbel device
 * @ret rc		Return status code
 */
static int arbel_setup_mpt ( struct arbel *arbel ) {
	struct arbelprm_mpt mpt;
	uint32_t key;
	int rc;

	/* Derive key */
	key = ( arbel->limits.reserved_mrws | ARBEL_MKEY_PREFIX );
	arbel->lkey = ( ( key << 8 ) | ( key >> 24 ) );

	/* Initialise memory protection table */
	memset ( &mpt, 0, sizeof ( mpt ) );
	MLX_FILL_7 ( &mpt, 0,
		     a, 1,
		     rw, 1,
		     rr, 1,
		     lw, 1,
		     lr, 1,
		     pa, 1,
		     r_w, 1 );
	MLX_FILL_1 ( &mpt, 2, mem_key, key );
	MLX_FILL_2 ( &mpt, 3,
		     pd, ARBEL_GLOBAL_PD,
		     rae, 1 );
	MLX_FILL_1 ( &mpt, 6, reg_wnd_len_h, 0xffffffffUL );
	MLX_FILL_1 ( &mpt, 7, reg_wnd_len_l, 0xffffffffUL );
	if ( ( rc = arbel_cmd_sw2hw_mpt ( arbel, arbel->limits.reserved_mrws,
					  &mpt ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not set up MPT: %s\n",
		       arbel, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Configure special queue pairs
 *
 * @v arbel		Arbel device
 * @ret rc		Return status code
 */
static int arbel_configure_special_qps ( struct arbel *arbel ) {
	unsigned int smi_qpn_base;
	unsigned int gsi_qpn_base;
	int rc;

	/* Special QP block must be aligned on an even number */
	arbel->special_qpn_base = ( ( arbel->limits.reserved_qps + 1 ) & ~1 );
	arbel->qpn_base = ( arbel->special_qpn_base +
			    ARBEL_NUM_SPECIAL_QPS );
	DBGC ( arbel, "Arbel %p special QPs at [%lx,%lx]\n", arbel,
	       arbel->special_qpn_base, ( arbel->qpn_base - 1 ) );
	smi_qpn_base = arbel->special_qpn_base;
	gsi_qpn_base = ( smi_qpn_base + 2 );

	/* Issue commands to configure special QPs */
	if ( ( rc = arbel_cmd_conf_special_qp ( arbel, 0,
						smi_qpn_base ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not configure SMI QPs: %s\n",
		       arbel, strerror ( rc ) );
		return rc;
	}
	if ( ( rc = arbel_cmd_conf_special_qp ( arbel, 1,
						gsi_qpn_base ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not configure GSI QPs: %s\n",
		       arbel, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Start Arbel device
 *
 * @v arbel		Arbel device
 * @v running		Firmware is already running
 * @ret rc		Return status code
 */
static int arbel_start ( struct arbel *arbel, int running ) {
	struct arbelprm_init_hca init_hca;
	unsigned int i;
	int rc;

	/* Start firmware if not already running */
	if ( ! running ) {
		if ( ( rc = arbel_start_firmware ( arbel ) ) != 0 )
			goto err_start_firmware;
	}

	/* Allocate ICM */
	memset ( &init_hca, 0, sizeof ( init_hca ) );
	if ( ( rc = arbel_alloc_icm ( arbel, &init_hca ) ) != 0 )
		goto err_alloc_icm;

	/* Initialise HCA */
	if ( ( rc = arbel_cmd_init_hca ( arbel, &init_hca ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not initialise HCA: %s\n",
		       arbel, strerror ( rc ) );
		goto err_init_hca;
	}

	/* Set up memory protection */
	if ( ( rc = arbel_setup_mpt ( arbel ) ) != 0 )
		goto err_setup_mpt;
	for ( i = 0 ; i < ARBEL_NUM_PORTS ; i++ )
		arbel->ibdev[i]->rdma_key = arbel->lkey;

	/* Set up event queue */
	if ( ( rc = arbel_create_eq ( arbel ) ) != 0 )
		goto err_create_eq;

	/* Configure special QPs */
	if ( ( rc = arbel_configure_special_qps ( arbel ) ) != 0 )
		goto err_conf_special_qps;

	return 0;

 err_conf_special_qps:
	arbel_destroy_eq ( arbel );
 err_create_eq:
 err_setup_mpt:
	arbel_cmd_close_hca ( arbel );
 err_init_hca:
	arbel_free_icm ( arbel );
 err_alloc_icm:
	arbel_stop_firmware ( arbel );
 err_start_firmware:
	return rc;
}

/**
 * Stop Arbel device
 *
 * @v arbel		Arbel device
 */
static void arbel_stop ( struct arbel *arbel ) {
	arbel_destroy_eq ( arbel );
	arbel_cmd_close_hca ( arbel );
	arbel_free_icm ( arbel );
	arbel_stop_firmware ( arbel );
	arbel_reset ( arbel );
}

/**
 * Open Arbel device
 *
 * @v arbel		Arbel device
 * @ret rc		Return status code
 */
static int arbel_open ( struct arbel *arbel ) {
	int rc;

	/* Start device if applicable */
	if ( arbel->open_count == 0 ) {
		if ( ( rc = arbel_start ( arbel, 0 ) ) != 0 )
			return rc;
	}

	/* Increment open counter */
	arbel->open_count++;

	return 0;
}

/**
 * Close Arbel device
 *
 * @v arbel		Arbel device
 */
static void arbel_close ( struct arbel *arbel ) {

	/* Decrement open counter */
	assert ( arbel->open_count != 0 );
	arbel->open_count--;

	/* Stop device if applicable */
	if ( arbel->open_count == 0 )
		arbel_stop ( arbel );
}

/***************************************************************************
 *
 * Infiniband link-layer operations
 *
 ***************************************************************************
 */

/**
 * Initialise Infiniband link
 *
 * @v ibdev		Infiniband device
 * @ret rc		Return status code
 */
static int arbel_ib_open ( struct ib_device *ibdev ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbelprm_init_ib init_ib;
	int rc;

	/* Open hardware */
	if ( ( rc = arbel_open ( arbel ) ) != 0 )
		goto err_open;

	/* Initialise IB */
	memset ( &init_ib, 0, sizeof ( init_ib ) );
	MLX_FILL_3 ( &init_ib, 0,
		     mtu_cap, ARBEL_MTU_2048,
		     port_width_cap, 3,
		     vl_cap, 1 );
	MLX_FILL_1 ( &init_ib, 1, max_gid, 1 );
	MLX_FILL_1 ( &init_ib, 2, max_pkey, 64 );
	if ( ( rc = arbel_cmd_init_ib ( arbel, ibdev->port,
					&init_ib ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p port %d could not intialise IB: %s\n",
		       arbel, ibdev->port, strerror ( rc ) );
		goto err_init_ib;
	}

	/* Update MAD parameters */
	ib_smc_update ( ibdev, arbel_mad );

	return 0;

 err_init_ib:
	arbel_close ( arbel );
 err_open:
	return rc;
}

/**
 * Close Infiniband link
 *
 * @v ibdev		Infiniband device
 */
static void arbel_ib_close ( struct ib_device *ibdev ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	int rc;

	/* Close IB */
	if ( ( rc = arbel_cmd_close_ib ( arbel, ibdev->port ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p port %d could not close IB: %s\n",
		       arbel, ibdev->port, strerror ( rc ) );
		/* Nothing we can do about this */
	}

	/* Close hardware */
	arbel_close ( arbel );
}

/**
 * Inform embedded subnet management agent of a received MAD
 *
 * @v ibdev		Infiniband device
 * @v mad		MAD
 * @ret rc		Return status code
 */
static int arbel_inform_sma ( struct ib_device *ibdev, union ib_mad *mad ) {
	int rc;

	/* Send the MAD to the embedded SMA */
	if ( ( rc = arbel_mad ( ibdev, mad ) ) != 0 )
		return rc;

	/* Update parameters held in software */
	ib_smc_update ( ibdev, arbel_mad );

	return 0;
}

/***************************************************************************
 *
 * Multicast group operations
 *
 ***************************************************************************
 */

/**
 * Attach to multicast group
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v gid		Multicast GID
 * @ret rc		Return status code
 */
static int arbel_mcast_attach ( struct ib_device *ibdev,
				struct ib_queue_pair *qp,
				union ib_gid *gid ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbelprm_mgm_hash hash;
	struct arbelprm_mgm_entry mgm;
	unsigned int index;
	int rc;

	/* Generate hash table index */
	if ( ( rc = arbel_cmd_mgid_hash ( arbel, gid, &hash ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not hash GID: %s\n",
		       arbel, strerror ( rc ) );
		return rc;
	}
	index = MLX_GET ( &hash, hash );

	/* Check for existing hash table entry */
	if ( ( rc = arbel_cmd_read_mgm ( arbel, index, &mgm ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not read MGM %#x: %s\n",
		       arbel, index, strerror ( rc ) );
		return rc;
	}
	if ( MLX_GET ( &mgm, mgmqp_0.qi ) != 0 ) {
		/* FIXME: this implementation allows only a single QP
		 * per multicast group, and doesn't handle hash
		 * collisions.  Sufficient for IPoIB but may need to
		 * be extended in future.
		 */
		DBGC ( arbel, "Arbel %p MGID index %#x already in use\n",
		       arbel, index );
		return -EBUSY;
	}

	/* Update hash table entry */
	MLX_FILL_2 ( &mgm, 8,
		     mgmqp_0.qpn_i, qp->qpn,
		     mgmqp_0.qi, 1 );
	memcpy ( &mgm.u.dwords[4], gid, sizeof ( *gid ) );
	if ( ( rc = arbel_cmd_write_mgm ( arbel, index, &mgm ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not write MGM %#x: %s\n",
		       arbel, index, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Detach from multicast group
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v gid		Multicast GID
 */
static void arbel_mcast_detach ( struct ib_device *ibdev,
				 struct ib_queue_pair *qp __unused,
				 union ib_gid *gid ) {
	struct arbel *arbel = ib_get_drvdata ( ibdev );
	struct arbelprm_mgm_hash hash;
	struct arbelprm_mgm_entry mgm;
	unsigned int index;
	int rc;

	/* Generate hash table index */
	if ( ( rc = arbel_cmd_mgid_hash ( arbel, gid, &hash ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not hash GID: %s\n",
		       arbel, strerror ( rc ) );
		return;
	}
	index = MLX_GET ( &hash, hash );

	/* Clear hash table entry */
	memset ( &mgm, 0, sizeof ( mgm ) );
	if ( ( rc = arbel_cmd_write_mgm ( arbel, index, &mgm ) ) != 0 ) {
		DBGC ( arbel, "Arbel %p could not write MGM %#x: %s\n",
		       arbel, index, strerror ( rc ) );
		return;
	}
}

/** Arbel Infiniband operations */
static struct ib_device_operations arbel_ib_operations = {
	.create_cq	= arbel_create_cq,
	.destroy_cq	= arbel_destroy_cq,
	.create_qp	= arbel_create_qp,
	.modify_qp	= arbel_modify_qp,
	.destroy_qp	= arbel_destroy_qp,
	.post_send	= arbel_post_send,
	.post_recv	= arbel_post_recv,
	.poll_cq	= arbel_poll_cq,
	.poll_eq	= arbel_poll_eq,
	.open		= arbel_ib_open,
	.close		= arbel_ib_close,
	.mcast_attach	= arbel_mcast_attach,
	.mcast_detach	= arbel_mcast_detach,
	.set_port_info	= arbel_inform_sma,
	.set_pkey_table	= arbel_inform_sma,
};

/***************************************************************************
 *
 * PCI interface
 *
 ***************************************************************************
 */

/**
 * Allocate Arbel device
 *
 * @ret arbel		Arbel device
 */
static struct arbel * arbel_alloc ( void ) {
	struct arbel *arbel;

	/* Allocate Arbel device */
	arbel = zalloc ( sizeof ( *arbel ) );
	if ( ! arbel )
		goto err_arbel;

	/* Allocate space for mailboxes */
	arbel->mailbox_in = malloc_dma ( ARBEL_MBOX_SIZE, ARBEL_MBOX_ALIGN );
	if ( ! arbel->mailbox_in )
		goto err_mailbox_in;
	arbel->mailbox_out = malloc_dma ( ARBEL_MBOX_SIZE, ARBEL_MBOX_ALIGN );
	if ( ! arbel->mailbox_out )
		goto err_mailbox_out;

	return arbel;

	free_dma ( arbel->mailbox_out, ARBEL_MBOX_SIZE );
 err_mailbox_out:
	free_dma ( arbel->mailbox_in, ARBEL_MBOX_SIZE );
 err_mailbox_in:
	free ( arbel );
 err_arbel:
	return NULL;
}

/**
 * Free Arbel device
 *
 * @v arbel		Arbel device
 */
static void arbel_free ( struct arbel *arbel ) {

	ufree ( arbel->icm );
	ufree ( arbel->firmware_area );
	free_dma ( arbel->mailbox_out, ARBEL_MBOX_SIZE );
	free_dma ( arbel->mailbox_in, ARBEL_MBOX_SIZE );
	free ( arbel );
}

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @v id		PCI ID
 * @ret rc		Return status code
 */
static int arbel_probe ( struct pci_device *pci ) {
	struct arbel *arbel;
	struct ib_device *ibdev;
	int i;
	int rc;

	/* Allocate Arbel device */
	arbel = arbel_alloc();
	if ( ! arbel ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	pci_set_drvdata ( pci, arbel );
	arbel->pci = pci;

	/* Allocate Infiniband devices */
	for ( i = 0 ; i < ARBEL_NUM_PORTS ; i++ ) {
		ibdev = alloc_ibdev ( 0 );
		if ( ! ibdev ) {
			rc = -ENOMEM;
			goto err_alloc_ibdev;
		}
		arbel->ibdev[i] = ibdev;
		ibdev->op = &arbel_ib_operations;
		ibdev->dev = &pci->dev;
		ibdev->port = ( ARBEL_PORT_BASE + i );
		ib_set_drvdata ( ibdev, arbel );
	}

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Get PCI BARs */
	arbel->config = ioremap ( pci_bar_start ( pci, ARBEL_PCI_CONFIG_BAR ),
				  ARBEL_PCI_CONFIG_BAR_SIZE );
	arbel->uar = ioremap ( ( pci_bar_start ( pci, ARBEL_PCI_UAR_BAR ) +
				 ARBEL_PCI_UAR_IDX * ARBEL_PCI_UAR_SIZE ),
			       ARBEL_PCI_UAR_SIZE );

	/* Reset device */
	arbel_reset ( arbel );

	/* Start firmware */
	if ( ( rc = arbel_start_firmware ( arbel ) ) != 0 )
		goto err_start_firmware;

	/* Get device limits */
	if ( ( rc = arbel_get_limits ( arbel ) ) != 0 )
		goto err_get_limits;

	/* Start device */
	if ( ( rc = arbel_start ( arbel, 1 ) ) != 0 )
		goto err_start;

	/* Initialise parameters using SMC */
	for ( i = 0 ; i < ARBEL_NUM_PORTS ; i++ )
		ib_smc_init ( arbel->ibdev[i], arbel_mad );

	/* Register Infiniband devices */
	for ( i = 0 ; i < ARBEL_NUM_PORTS ; i++ ) {
		if ( ( rc = register_ibdev ( arbel->ibdev[i] ) ) != 0 ) {
			DBGC ( arbel, "Arbel %p port %d could not register IB "
			       "device: %s\n", arbel,
			       arbel->ibdev[i]->port, strerror ( rc ) );
			goto err_register_ibdev;
		}
	}

	/* Leave device quiescent until opened */
	if ( arbel->open_count == 0 )
		arbel_stop ( arbel );

	return 0;

	i = ARBEL_NUM_PORTS;
 err_register_ibdev:
	for ( i-- ; i >= 0 ; i-- )
		unregister_ibdev ( arbel->ibdev[i] );
	arbel_stop ( arbel );
 err_start:
 err_get_limits:
	arbel_stop_firmware ( arbel );
 err_start_firmware:
	i = ARBEL_NUM_PORTS;
 err_alloc_ibdev:
	for ( i-- ; i >= 0 ; i-- )
		ibdev_put ( arbel->ibdev[i] );
	arbel_free ( arbel );
 err_alloc:
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci		PCI device
 */
static void arbel_remove ( struct pci_device *pci ) {
	struct arbel *arbel = pci_get_drvdata ( pci );
	int i;

	for ( i = ( ARBEL_NUM_PORTS - 1 ) ; i >= 0 ; i-- )
		unregister_ibdev ( arbel->ibdev[i] );
	for ( i = ( ARBEL_NUM_PORTS - 1 ) ; i >= 0 ; i-- )
		ibdev_put ( arbel->ibdev[i] );
	arbel_free ( arbel );
}

static struct pci_device_id arbel_nics[] = {
	PCI_ROM ( 0x15b3, 0x6282, "mt25218", "MT25218 HCA driver", 0 ),
	PCI_ROM ( 0x15b3, 0x6274, "mt25204", "MT25204 HCA driver", 0 ),
};

struct pci_driver arbel_driver __pci_driver = {
	.ids = arbel_nics,
	.id_count = ( sizeof ( arbel_nics ) / sizeof ( arbel_nics[0] ) ),
	.probe = arbel_probe,
	.remove = arbel_remove,
};
