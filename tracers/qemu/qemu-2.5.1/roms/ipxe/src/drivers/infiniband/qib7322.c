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
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <ipxe/io.h>
#include <ipxe/pci.h>
#include <ipxe/infiniband.h>
#include <ipxe/i2c.h>
#include <ipxe/bitbash.h>
#include <ipxe/malloc.h>
#include <ipxe/iobuf.h>
#include <ipxe/pcibackup.h>
#include "qib7322.h"

/**
 * @file
 *
 * QLogic QIB7322 Infiniband HCA
 *
 */

/** A QIB7322 send buffer set */
struct qib7322_send_buffers {
	/** Offset within register space of the first send buffer */
	unsigned long base;
	/** Send buffer size */
	unsigned int size;
	/** Index of first send buffer */
	unsigned int start;
	/** Number of send buffers
	 *
	 * Must be a power of two.
	 */
	unsigned int count;
	/** Send buffer availability producer counter */
	unsigned int prod;
	/** Send buffer availability consumer counter */
	unsigned int cons;
	/** Send buffer availability */
	uint16_t avail[0];
};

/** A QIB7322 send work queue */
struct qib7322_send_work_queue {
	/** Send buffer set */
	struct qib7322_send_buffers *send_bufs;
	/** Send buffer usage */
	uint16_t *used;
	/** Producer index */
	unsigned int prod;
	/** Consumer index */
	unsigned int cons;
};

/** A QIB7322 receive work queue */
struct qib7322_recv_work_queue {
	/** Receive header ring */
	void *header;
	/** Receive header producer offset (written by hardware) */
	struct QIB_7322_scalar header_prod;
	/** Receive header consumer offset */
	unsigned int header_cons;
	/** Offset within register space of the eager array */
	unsigned long eager_array;
	/** Number of entries in eager array */
	unsigned int eager_entries;
	/** Eager array producer index */
	unsigned int eager_prod;
	/** Eager array consumer index */
	unsigned int eager_cons;
};

/** A QIB7322 HCA */
struct qib7322 {
	/** Registers */
	void *regs;

	/** In-use contexts */
	uint8_t used_ctx[QIB7322_NUM_CONTEXTS];
	/** Send work queues */
	struct qib7322_send_work_queue send_wq[QIB7322_NUM_CONTEXTS];
	/** Receive work queues */
	struct qib7322_recv_work_queue recv_wq[QIB7322_NUM_CONTEXTS];

	/** Send buffer availability (reported by hardware) */
	struct QIB_7322_SendBufAvail *sendbufavail;
	/** Small send buffers */
	struct qib7322_send_buffers *send_bufs_small;
	/** VL15 port 0 send buffers */
	struct qib7322_send_buffers *send_bufs_vl15_port0;
	/** VL15 port 1 send buffers */
	struct qib7322_send_buffers *send_bufs_vl15_port1;

	/** I2C bit-bashing interface */
	struct i2c_bit_basher i2c;
	/** I2C serial EEPROM */
	struct i2c_device eeprom;

	/** Base GUID */
	union ib_guid guid;
	/** Infiniband devices */
	struct ib_device *ibdev[QIB7322_MAX_PORTS];
};

/***************************************************************************
 *
 * QIB7322 register access
 *
 ***************************************************************************
 *
 * This card requires atomic 64-bit accesses.  Strange things happen
 * if you try to use 32-bit accesses; sometimes they work, sometimes
 * they don't, sometimes you get random data.
 *
 * These accessors use the "movq" MMX instruction, and so won't work
 * on really old Pentiums (which won't have PCIe anyway, so this is
 * something of a moot point).
 */

/**
 * Read QIB7322 qword register
 *
 * @v qib7322		QIB7322 device
 * @v dwords		Register buffer to read into
 * @v offset		Register offset
 */
static void qib7322_readq ( struct qib7322 *qib7322, uint32_t *dwords,
			    unsigned long offset ) {
	void *addr = ( qib7322->regs + offset );

	__asm__ __volatile__ ( "movq (%1), %%mm0\n\t"
			       "movq %%mm0, (%0)\n\t"
			       : : "r" ( dwords ), "r" ( addr ) : "memory" );

	DBGIO ( "[%08lx] => %08x%08x\n",
		virt_to_phys ( addr ), dwords[1], dwords[0] );
}
#define qib7322_readq( _qib7322, _ptr, _offset ) \
	qib7322_readq ( (_qib7322), (_ptr)->u.dwords, (_offset) )
#define qib7322_readq_array8b( _qib7322, _ptr, _offset, _idx ) \
	qib7322_readq ( (_qib7322), (_ptr), ( (_offset) + ( (_idx) * 8 ) ) )
#define qib7322_readq_array64k( _qib7322, _ptr, _offset, _idx ) \
	qib7322_readq ( (_qib7322), (_ptr), ( (_offset) + ( (_idx) * 65536 ) ) )
#define qib7322_readq_port( _qib7322, _ptr, _offset, _port ) \
	qib7322_readq ( (_qib7322), (_ptr), ( (_offset) + ( (_port) * 4096 ) ) )

/**
 * Write QIB7322 qword register
 *
 * @v qib7322		QIB7322 device
 * @v dwords		Register buffer to write
 * @v offset		Register offset
 */
static void qib7322_writeq ( struct qib7322 *qib7322, const uint32_t *dwords,
			     unsigned long offset ) {
	void *addr = ( qib7322->regs + offset );

	DBGIO ( "[%08lx] <= %08x%08x\n",
		virt_to_phys ( addr ), dwords[1], dwords[0] );

	__asm__ __volatile__ ( "movq (%0), %%mm0\n\t"
			       "movq %%mm0, (%1)\n\t"
			       : : "r" ( dwords ), "r" ( addr ) : "memory" );
}
#define qib7322_writeq( _qib7322, _ptr, _offset ) \
	qib7322_writeq ( (_qib7322), (_ptr)->u.dwords, (_offset) )
#define qib7322_writeq_array8b( _qib7322, _ptr, _offset, _idx ) \
	qib7322_writeq ( (_qib7322), (_ptr), ( (_offset) + ( (_idx) * 8 ) ) )
#define qib7322_writeq_array64k( _qib7322, _ptr, _offset, _idx ) \
	qib7322_writeq ( (_qib7322), (_ptr), ( (_offset) + ( (_idx) * 65536 ) ))
#define qib7322_writeq_port( _qib7322, _ptr, _offset, _port ) \
	qib7322_writeq ( (_qib7322), (_ptr), ( (_offset) + ( (_port) * 4096 ) ))

/**
 * Write QIB7322 dword register
 *
 * @v qib7322		QIB7322 device
 * @v dword		Value to write
 * @v offset		Register offset
 */
static void qib7322_writel ( struct qib7322 *qib7322, uint32_t dword,
			     unsigned long offset ) {
	writel ( dword, ( qib7322->regs + offset ) );
}

/***************************************************************************
 *
 * Link state management
 *
 ***************************************************************************
 */

/**
 * Textual representation of link state
 *
 * @v link_state	Link state
 * @ret link_text	Link state text
 */
static const char * qib7322_link_state_text ( unsigned int link_state ) {
	switch ( link_state ) {
	case QIB7322_LINK_STATE_DOWN:		return "DOWN";
	case QIB7322_LINK_STATE_INIT:		return "INIT";
	case QIB7322_LINK_STATE_ARM:		return "ARM";
	case QIB7322_LINK_STATE_ACTIVE:		return "ACTIVE";
	case QIB7322_LINK_STATE_ACT_DEFER:	return "ACT_DEFER";
	default:				return "UNKNOWN";
	}
}

/**
 * Handle link state change
 *
 * @v qib7322		QIB7322 device
 */
static void qib7322_link_state_changed ( struct ib_device *ibdev ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct QIB_7322_IBCStatusA_0 ibcstatusa;
	struct QIB_7322_EXTCtrl extctrl;
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );
	unsigned int link_training_state;
	unsigned int link_state;
	unsigned int link_width;
	unsigned int link_speed;
	unsigned int link_speed_qdr;
	unsigned int green;
	unsigned int yellow;

	/* Read link state */
	qib7322_readq_port ( qib7322, &ibcstatusa,
			     QIB_7322_IBCStatusA_0_offset, port );
	link_training_state = BIT_GET ( &ibcstatusa, LinkTrainingState );
	link_state = BIT_GET ( &ibcstatusa, LinkState );
	link_width = BIT_GET ( &ibcstatusa, LinkWidthActive );
	link_speed = BIT_GET ( &ibcstatusa, LinkSpeedActive );
	link_speed_qdr = BIT_GET ( &ibcstatusa, LinkSpeedQDR );
	DBGC ( qib7322, "QIB7322 %p port %d training state %#x link state %s "
	       "(%s %s)\n", qib7322, port, link_training_state,
	       qib7322_link_state_text ( link_state ),
	       ( link_speed_qdr ? "QDR" : ( link_speed ? "DDR" : "SDR" ) ),
	       ( link_width ? "x4" : "x1" ) );

	/* Set LEDs according to link state */
	qib7322_readq ( qib7322, &extctrl, QIB_7322_EXTCtrl_offset );
	green = ( ( link_state >= QIB7322_LINK_STATE_INIT ) ? 1 : 0 );
	yellow = ( ( link_state >= QIB7322_LINK_STATE_ACTIVE ) ? 1 : 0 );
	if ( port == 0 ) {
		BIT_SET ( &extctrl, LEDPort0GreenOn, green );
		BIT_SET ( &extctrl, LEDPort0YellowOn, yellow );
	} else {
		BIT_SET ( &extctrl, LEDPort1GreenOn, green );
		BIT_SET ( &extctrl, LEDPort1YellowOn, yellow );
	}
	qib7322_writeq ( qib7322, &extctrl, QIB_7322_EXTCtrl_offset );

	/* Notify Infiniband core of link state change */
	ibdev->port_state = ( link_state + 1 );
	ibdev->link_width_active =
		( link_width ? IB_LINK_WIDTH_4X : IB_LINK_WIDTH_1X );
	ibdev->link_speed_active =
		( link_speed ? IB_LINK_SPEED_DDR : IB_LINK_SPEED_SDR );
	ib_link_state_changed ( ibdev );
}

/**
 * Wait for link state change to take effect
 *
 * @v ibdev		Infiniband device
 * @v new_link_state	Expected link state
 * @ret rc		Return status code
 */
static int qib7322_link_state_check ( struct ib_device *ibdev,
				      unsigned int new_link_state ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct QIB_7322_IBCStatusA_0 ibcstatusa;
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );
	unsigned int link_state;
	unsigned int i;

	for ( i = 0 ; i < QIB7322_LINK_STATE_MAX_WAIT_US ; i++ ) {
		qib7322_readq_port ( qib7322, &ibcstatusa,
				     QIB_7322_IBCStatusA_0_offset, port );
		link_state = BIT_GET ( &ibcstatusa, LinkState );
		if ( link_state == new_link_state )
			return 0;
		udelay ( 1 );
	}

	DBGC ( qib7322, "QIB7322 %p port %d timed out waiting for link state "
	       "%s\n", qib7322, port, qib7322_link_state_text ( link_state ) );
	return -ETIMEDOUT;
}

/**
 * Set port information
 *
 * @v ibdev		Infiniband device
 * @v mad		Set port information MAD
 */
static int qib7322_set_port_info ( struct ib_device *ibdev,
				   union ib_mad *mad ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct ib_port_info *port_info = &mad->smp.smp_data.port_info;
	struct QIB_7322_IBCCtrlA_0 ibcctrla;
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );
	unsigned int port_state;
	unsigned int link_state;

	/* Set new link state */
	port_state = ( port_info->link_speed_supported__port_state & 0xf );
	if ( port_state ) {
		link_state = ( port_state - 1 );
		DBGC ( qib7322, "QIB7322 %p set link state to %s (%x)\n",
		       qib7322, qib7322_link_state_text ( link_state ),
		       link_state );
		qib7322_readq_port ( qib7322, &ibcctrla,
				     QIB_7322_IBCCtrlA_0_offset, port );
		BIT_SET ( &ibcctrla, LinkCmd, link_state );
		qib7322_writeq_port ( qib7322, &ibcctrla,
				      QIB_7322_IBCCtrlA_0_offset, port );

		/* Wait for link state change to take effect.  Ignore
		 * errors; the current link state will be returned via
		 * the GetResponse MAD.
		 */
		qib7322_link_state_check ( ibdev, link_state );
	}

	/* Detect and report link state change */
	qib7322_link_state_changed ( ibdev );

	return 0;
}

/**
 * Set partition key table
 *
 * @v ibdev		Infiniband device
 * @v mad		Set partition key table MAD
 */
static int qib7322_set_pkey_table ( struct ib_device *ibdev __unused,
				    union ib_mad *mad __unused ) {
	/* Nothing to do */
	return 0;
}

/***************************************************************************
 *
 * Context allocation
 *
 ***************************************************************************
 */

/**
 * Allocate a context and set queue pair number
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @ret rc		Return status code
 */
static int qib7322_alloc_ctx ( struct ib_device *ibdev,
			       struct ib_queue_pair *qp ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );
	unsigned int ctx;

	for ( ctx = port ; ctx < QIB7322_NUM_CONTEXTS ; ctx += 2 ) {

		if ( ! qib7322->used_ctx[ctx] ) {
			qib7322->used_ctx[ctx] = 1;
			qp->qpn = ( ctx & ~0x01 );
			DBGC2 ( qib7322, "QIB7322 %p port %d QPN %ld is CTX "
				"%d\n", qib7322, port, qp->qpn, ctx );
			return 0;
		}
	}

	DBGC ( qib7322, "QIB7322 %p port %d out of available contexts\n",
	       qib7322, port );
	return -ENOENT;
}

/**
 * Get queue pair context number
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @ret ctx		Context index
 */
static unsigned int qib7322_ctx ( struct ib_device *ibdev,
				  struct ib_queue_pair *qp ) {
	return ( qp->qpn + ( ibdev->port - QIB7322_PORT_BASE ) );
}

/**
 * Free a context
 *
 * @v qib7322		QIB7322 device
 * @v ctx		Context index
 */
static void qib7322_free_ctx ( struct ib_device *ibdev,
			       struct ib_queue_pair *qp ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );
	unsigned int ctx = qib7322_ctx ( ibdev, qp );

	qib7322->used_ctx[ctx] = 0;
	DBGC2 ( qib7322, "QIB7322 %p port %d CTX %d freed\n",
		qib7322, port, ctx );
}

/***************************************************************************
 *
 * Send datapath
 *
 ***************************************************************************
 */

/** Send buffer toggle bit
 *
 * We encode send buffers as 15 bits of send buffer index plus a
 * single bit which should match the "check" bit in the SendBufAvail
 * array.
 */
#define QIB7322_SEND_BUF_TOGGLE 0x8000

/**
 * Create send buffer set
 *
 * @v qib7322		QIB7322 device
 * @v base		Send buffer base offset
 * @v size		Send buffer size
 * @v start		Index of first send buffer
 * @v count		Number of send buffers
 * @ret send_bufs	Send buffer set
 */
static struct qib7322_send_buffers *
qib7322_create_send_bufs ( struct qib7322 *qib7322, unsigned long base,
			   unsigned int size, unsigned int start,
			   unsigned int count ) {
	struct qib7322_send_buffers *send_bufs;
	unsigned int i;

	/* Allocate send buffer set */
	send_bufs = zalloc ( sizeof ( *send_bufs ) +
			     ( count * sizeof ( send_bufs->avail[0] ) ) );
	if ( ! send_bufs )
		return NULL;

	/* Populate send buffer set */
	send_bufs->base = base;
	send_bufs->size = size;
	send_bufs->start = start;
	send_bufs->count = count;
	for ( i = 0 ; i < count ; i++ )
		send_bufs->avail[i] = ( start + i );

	DBGC2 ( qib7322, "QIB7322 %p send buffer set %p [%d,%d] at %lx\n",
		qib7322, send_bufs, start, ( start + count - 1 ),
		send_bufs->base );

	return send_bufs;
}

/**
 * Destroy send buffer set
 *
 * @v qib7322		QIB7322 device
 * @v send_bufs		Send buffer set
 */
static void
qib7322_destroy_send_bufs ( struct qib7322 *qib7322 __unused,
			    struct qib7322_send_buffers *send_bufs ) {
	free ( send_bufs );
}

/**
 * Allocate a send buffer
 *
 * @v qib7322		QIB7322 device
 * @v send_bufs		Send buffer set
 * @ret send_buf	Send buffer, or negative error
 */
static int qib7322_alloc_send_buf ( struct qib7322 *qib7322,
				    struct qib7322_send_buffers *send_bufs ) {
	unsigned int used;
	unsigned int mask;
	unsigned int send_buf;

	used = ( send_bufs->cons - send_bufs->prod );
	if ( used >= send_bufs->count ) {
		DBGC ( qib7322, "QIB7322 %p send buffer set %p out of "
		       "buffers\n", qib7322, send_bufs );
		return -ENOBUFS;
	}

	mask = ( send_bufs->count - 1 );
	send_buf = send_bufs->avail[ send_bufs->cons++ & mask ];
	send_buf ^= QIB7322_SEND_BUF_TOGGLE;
	return send_buf;
}

/**
 * Free a send buffer
 *
 * @v qib7322		QIB7322 device
 * @v send_bufs		Send buffer set
 * @v send_buf		Send buffer
 */
static void qib7322_free_send_buf ( struct qib7322 *qib7322 __unused,
				    struct qib7322_send_buffers *send_bufs,
				    unsigned int send_buf ) {
	unsigned int mask;

	mask = ( send_bufs->count - 1 );
	send_bufs->avail[ send_bufs->prod++ & mask ] = send_buf;
}

/**
 * Check to see if send buffer is in use
 *
 * @v qib7322		QIB7322 device
 * @v send_buf		Send buffer
 * @ret in_use		Send buffer is in use
 */
static int qib7322_send_buf_in_use ( struct qib7322 *qib7322,
				     unsigned int send_buf ) {
	unsigned int send_idx;
	unsigned int send_check;
	unsigned int inusecheck;
	unsigned int inuse;
	unsigned int check;

	send_idx = ( send_buf & ~QIB7322_SEND_BUF_TOGGLE );
	send_check = ( !! ( send_buf & QIB7322_SEND_BUF_TOGGLE ) );
	inusecheck = BIT_GET ( qib7322->sendbufavail, InUseCheck[send_idx] );
	inuse = ( !! ( inusecheck & 0x02 ) );
	check = ( !! ( inusecheck & 0x01 ) );
	return ( inuse || ( check != send_check ) );
}

/**
 * Calculate starting offset for send buffer
 *
 * @v qib7322		QIB7322 device
 * @v send_buf		Send buffer
 * @ret offset		Starting offset
 */
static unsigned long
qib7322_send_buffer_offset ( struct qib7322 *qib7322 __unused,
			     struct qib7322_send_buffers *send_bufs,
			     unsigned int send_buf ) {
	unsigned int index;

	index = ( ( send_buf & ~QIB7322_SEND_BUF_TOGGLE ) - send_bufs->start );
	return ( send_bufs->base + ( index * send_bufs->size ) );
}

/**
 * Create send work queue
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 */
static int qib7322_create_send_wq ( struct ib_device *ibdev,
				    struct ib_queue_pair *qp ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct ib_work_queue *wq = &qp->send;
	struct qib7322_send_work_queue *qib7322_wq = ib_wq_get_drvdata ( wq );
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );

	/* Select send buffer set */
	if ( qp->type == IB_QPT_SMI ) {
		if ( port == 0 ) {
			qib7322_wq->send_bufs = qib7322->send_bufs_vl15_port0;
		} else {
			qib7322_wq->send_bufs = qib7322->send_bufs_vl15_port1;
		}
	} else {
		qib7322_wq->send_bufs = qib7322->send_bufs_small;
	}

	/* Allocate space for send buffer usage list */
	qib7322_wq->used = zalloc ( qp->send.num_wqes *
				    sizeof ( qib7322_wq->used[0] ) );
	if ( ! qib7322_wq->used )
		return -ENOMEM;

	/* Reset work queue */
	qib7322_wq->prod = 0;
	qib7322_wq->cons = 0;

	return 0;
}

/**
 * Destroy send work queue
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 */
static void qib7322_destroy_send_wq ( struct ib_device *ibdev __unused,
				      struct ib_queue_pair *qp ) {
	struct ib_work_queue *wq = &qp->send;
	struct qib7322_send_work_queue *qib7322_wq = ib_wq_get_drvdata ( wq );

	free ( qib7322_wq->used );
}

/**
 * Initialise send datapath
 *
 * @v qib7322		QIB7322 device
 * @ret rc		Return status code
 */
static int qib7322_init_send ( struct qib7322 *qib7322 ) {
	struct QIB_7322_SendBufBase sendbufbase;
	struct QIB_7322_SendBufAvailAddr sendbufavailaddr;
	struct QIB_7322_SendCtrl sendctrl;
	struct QIB_7322_SendCtrl_0 sendctrlp;
	unsigned long baseaddr_smallpio;
	unsigned long baseaddr_largepio;
	unsigned long baseaddr_vl15_port0;
	unsigned long baseaddr_vl15_port1;
	int rc;

	/* Create send buffer sets */
	qib7322_readq ( qib7322, &sendbufbase, QIB_7322_SendBufBase_offset );
	baseaddr_smallpio = BIT_GET ( &sendbufbase, BaseAddr_SmallPIO );
	baseaddr_largepio = BIT_GET ( &sendbufbase, BaseAddr_LargePIO );
	baseaddr_vl15_port0 = ( baseaddr_largepio +
				( QIB7322_LARGE_SEND_BUF_SIZE *
				  QIB7322_LARGE_SEND_BUF_COUNT ) );
	baseaddr_vl15_port1 = ( baseaddr_vl15_port0 +
				QIB7322_VL15_PORT0_SEND_BUF_SIZE );
	qib7322->send_bufs_small =
		qib7322_create_send_bufs ( qib7322, baseaddr_smallpio,
					   QIB7322_SMALL_SEND_BUF_SIZE,
					   QIB7322_SMALL_SEND_BUF_START,
					   QIB7322_SMALL_SEND_BUF_USED );
	if ( ! qib7322->send_bufs_small ) {
		rc = -ENOMEM;
		goto err_create_send_bufs_small;
	}
	qib7322->send_bufs_vl15_port0 =
		qib7322_create_send_bufs ( qib7322, baseaddr_vl15_port0,
					   QIB7322_VL15_PORT0_SEND_BUF_SIZE,
					   QIB7322_VL15_PORT0_SEND_BUF_START,
					   QIB7322_VL15_PORT0_SEND_BUF_COUNT );
	if ( ! qib7322->send_bufs_vl15_port0 ) {
		rc = -ENOMEM;
		goto err_create_send_bufs_vl15_port0;
	}
	qib7322->send_bufs_vl15_port1 =
		qib7322_create_send_bufs ( qib7322, baseaddr_vl15_port1,
					   QIB7322_VL15_PORT1_SEND_BUF_SIZE,
					   QIB7322_VL15_PORT1_SEND_BUF_START,
					   QIB7322_VL15_PORT1_SEND_BUF_COUNT );
	if ( ! qib7322->send_bufs_vl15_port1 ) {
		rc = -ENOMEM;
		goto err_create_send_bufs_vl15_port1;
	}

	/* Allocate space for the SendBufAvail array */
	qib7322->sendbufavail = malloc_dma ( sizeof ( *qib7322->sendbufavail ),
					     QIB7322_SENDBUFAVAIL_ALIGN );
	if ( ! qib7322->sendbufavail ) {
		rc = -ENOMEM;
		goto err_alloc_sendbufavail;
	}
	memset ( qib7322->sendbufavail, 0, sizeof ( qib7322->sendbufavail ) );

	/* Program SendBufAvailAddr into the hardware */
	memset ( &sendbufavailaddr, 0, sizeof ( sendbufavailaddr ) );
	BIT_FILL_1 ( &sendbufavailaddr, SendBufAvailAddr,
		     ( virt_to_bus ( qib7322->sendbufavail ) >> 6 ) );
	qib7322_writeq ( qib7322, &sendbufavailaddr,
			 QIB_7322_SendBufAvailAddr_offset );

	/* Enable sending */
	memset ( &sendctrlp, 0, sizeof ( sendctrlp ) );
	BIT_FILL_1 ( &sendctrlp, SendEnable, 1 );
	qib7322_writeq ( qib7322, &sendctrlp, QIB_7322_SendCtrl_0_offset );
	qib7322_writeq ( qib7322, &sendctrlp, QIB_7322_SendCtrl_1_offset );

	/* Enable DMA of SendBufAvail */
	memset ( &sendctrl, 0, sizeof ( sendctrl ) );
	BIT_FILL_1 ( &sendctrl, SendBufAvailUpd, 1 );
	qib7322_writeq ( qib7322, &sendctrl, QIB_7322_SendCtrl_offset );

	return 0;

	free_dma ( qib7322->sendbufavail, sizeof ( *qib7322->sendbufavail ) );
 err_alloc_sendbufavail:
	qib7322_destroy_send_bufs ( qib7322, qib7322->send_bufs_vl15_port1 );
 err_create_send_bufs_vl15_port1:
	qib7322_destroy_send_bufs ( qib7322, qib7322->send_bufs_vl15_port0 );
 err_create_send_bufs_vl15_port0:
	qib7322_destroy_send_bufs ( qib7322, qib7322->send_bufs_small );
 err_create_send_bufs_small:
	return rc;
}

/**
 * Shut down send datapath
 *
 * @v qib7322		QIB7322 device
 */
static void qib7322_fini_send ( struct qib7322 *qib7322 ) {
	struct QIB_7322_SendCtrl sendctrl;

	/* Disable sending and DMA of SendBufAvail */
	memset ( &sendctrl, 0, sizeof ( sendctrl ) );
	qib7322_writeq ( qib7322, &sendctrl, QIB_7322_SendCtrl_offset );
	mb();

	/* Ensure hardware has seen this disable */
	qib7322_readq ( qib7322, &sendctrl, QIB_7322_SendCtrl_offset );

	free_dma ( qib7322->sendbufavail, sizeof ( *qib7322->sendbufavail ) );
	qib7322_destroy_send_bufs ( qib7322, qib7322->send_bufs_vl15_port1 );
	qib7322_destroy_send_bufs ( qib7322, qib7322->send_bufs_vl15_port0 );
	qib7322_destroy_send_bufs ( qib7322, qib7322->send_bufs_small );
}

/***************************************************************************
 *
 * Receive datapath
 *
 ***************************************************************************
 */

/**
 * Create receive work queue
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @ret rc		Return status code
 */
static int qib7322_create_recv_wq ( struct ib_device *ibdev,
				    struct ib_queue_pair *qp ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct ib_work_queue *wq = &qp->recv;
	struct qib7322_recv_work_queue *qib7322_wq = ib_wq_get_drvdata ( wq );
	struct QIB_7322_RcvHdrAddr0 rcvhdraddr;
	struct QIB_7322_RcvHdrTailAddr0 rcvhdrtailaddr;
	struct QIB_7322_RcvHdrHead0 rcvhdrhead;
	struct QIB_7322_scalar rcvegrindexhead;
	struct QIB_7322_RcvCtrl rcvctrl;
	struct QIB_7322_RcvCtrl_P rcvctrlp;
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );
	unsigned int ctx = qib7322_ctx ( ibdev, qp );
	int rc;

	/* Reset context information */
	memset ( &qib7322_wq->header_prod, 0,
		 sizeof ( qib7322_wq->header_prod ) );
	qib7322_wq->header_cons = 0;
	qib7322_wq->eager_prod = 0;
	qib7322_wq->eager_cons = 0;

	/* Allocate receive header buffer */
	qib7322_wq->header = malloc_dma ( QIB7322_RECV_HEADERS_SIZE,
					  QIB7322_RECV_HEADERS_ALIGN );
	if ( ! qib7322_wq->header ) {
		rc = -ENOMEM;
		goto err_alloc_header;
	}

	/* Enable context in hardware */
	memset ( &rcvhdraddr, 0, sizeof ( rcvhdraddr ) );
	BIT_FILL_1 ( &rcvhdraddr, RcvHdrAddr,
		     ( virt_to_bus ( qib7322_wq->header ) >> 2 ) );
	qib7322_writeq_array8b ( qib7322, &rcvhdraddr,
				 QIB_7322_RcvHdrAddr0_offset, ctx );
	memset ( &rcvhdrtailaddr, 0, sizeof ( rcvhdrtailaddr ) );
	BIT_FILL_1 ( &rcvhdrtailaddr, RcvHdrTailAddr,
		     ( virt_to_bus ( &qib7322_wq->header_prod ) >> 2 ) );
	qib7322_writeq_array8b ( qib7322, &rcvhdrtailaddr,
				 QIB_7322_RcvHdrTailAddr0_offset, ctx );
	memset ( &rcvhdrhead, 0, sizeof ( rcvhdrhead ) );
	BIT_FILL_1 ( &rcvhdrhead, counter, 1 );
	qib7322_writeq_array64k ( qib7322, &rcvhdrhead,
				  QIB_7322_RcvHdrHead0_offset, ctx );
	memset ( &rcvegrindexhead, 0, sizeof ( rcvegrindexhead ) );
	BIT_FILL_1 ( &rcvegrindexhead, Value, 1 );
	qib7322_writeq_array64k ( qib7322, &rcvegrindexhead,
				  QIB_7322_RcvEgrIndexHead0_offset, ctx );
	qib7322_readq_port ( qib7322, &rcvctrlp,
			     QIB_7322_RcvCtrl_0_offset, port );
	BIT_SET ( &rcvctrlp, ContextEnable[ctx], 1 );
	qib7322_writeq_port ( qib7322, &rcvctrlp,
			      QIB_7322_RcvCtrl_0_offset, port );
	qib7322_readq ( qib7322, &rcvctrl, QIB_7322_RcvCtrl_offset );
	BIT_SET ( &rcvctrl, IntrAvail[ctx], 1 );
	qib7322_writeq ( qib7322, &rcvctrl, QIB_7322_RcvCtrl_offset );

	DBGC ( qib7322, "QIB7322 %p port %d QPN %ld CTX %d hdrs [%lx,%lx) prod "
	       "%lx\n", qib7322, port, qp->qpn, ctx,
	       virt_to_bus ( qib7322_wq->header ),
	       ( virt_to_bus ( qib7322_wq->header )
		 + QIB7322_RECV_HEADERS_SIZE ),
	       virt_to_bus ( &qib7322_wq->header_prod ) );
	return 0;

	free_dma ( qib7322_wq->header, QIB7322_RECV_HEADERS_SIZE );
 err_alloc_header:
	return rc;
}

/**
 * Destroy receive work queue
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 */
static void qib7322_destroy_recv_wq ( struct ib_device *ibdev,
				      struct ib_queue_pair *qp ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct ib_work_queue *wq = &qp->recv;
	struct qib7322_recv_work_queue *qib7322_wq = ib_wq_get_drvdata ( wq );
	struct QIB_7322_RcvCtrl rcvctrl;
	struct QIB_7322_RcvCtrl_P rcvctrlp;
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );
	unsigned int ctx = qib7322_ctx ( ibdev, qp );

	/* Disable context in hardware */
	qib7322_readq_port ( qib7322, &rcvctrlp,
			     QIB_7322_RcvCtrl_0_offset, port );
	BIT_SET ( &rcvctrlp, ContextEnable[ctx], 0 );
	qib7322_writeq_port ( qib7322, &rcvctrlp,
			      QIB_7322_RcvCtrl_0_offset, port );
	qib7322_readq ( qib7322, &rcvctrl, QIB_7322_RcvCtrl_offset );
	BIT_SET ( &rcvctrl, IntrAvail[ctx], 0 );
	qib7322_writeq ( qib7322, &rcvctrl, QIB_7322_RcvCtrl_offset );

	/* Make sure the hardware has seen that the context is disabled */
	qib7322_readq ( qib7322, &rcvctrl, QIB_7322_RcvCtrl_offset );
	mb();

	/* Free headers ring */
	free_dma ( qib7322_wq->header, QIB7322_RECV_HEADERS_SIZE );
}

/**
 * Initialise receive datapath
 *
 * @v qib7322		QIB7322 device
 * @ret rc		Return status code
 */
static int qib7322_init_recv ( struct qib7322 *qib7322 ) {
	struct QIB_7322_RcvCtrl rcvctrl;
	struct QIB_7322_RcvCtrl_0 rcvctrlp;
	struct QIB_7322_RcvQPMapTableA_0 rcvqpmaptablea0;
	struct QIB_7322_RcvQPMapTableB_0 rcvqpmaptableb0;
	struct QIB_7322_RcvQPMapTableA_1 rcvqpmaptablea1;
	struct QIB_7322_RcvQPMapTableB_1 rcvqpmaptableb1;
	struct QIB_7322_RcvQPMulticastContext_0 rcvqpmcastctx0;
	struct QIB_7322_RcvQPMulticastContext_1 rcvqpmcastctx1;
	struct QIB_7322_scalar rcvegrbase;
	struct QIB_7322_scalar rcvhdrentsize;
	struct QIB_7322_scalar rcvhdrcnt;
	struct QIB_7322_RcvBTHQP_0 rcvbthqp;
	struct QIB_7322_RxCreditVL0_0 rxcreditvl;
	unsigned int contextcfg;
	unsigned long egrbase;
	unsigned int eager_array_size_kernel;
	unsigned int eager_array_size_user;
	unsigned int ctx;

	/* Select configuration based on number of contexts */
	switch ( QIB7322_NUM_CONTEXTS ) {
	case 6:
		contextcfg = QIB7322_CONTEXTCFG_6CTX;
		eager_array_size_kernel = QIB7322_EAGER_ARRAY_SIZE_6CTX_KERNEL;
		eager_array_size_user = QIB7322_EAGER_ARRAY_SIZE_6CTX_USER;
		break;
	case 10:
		contextcfg = QIB7322_CONTEXTCFG_10CTX;
		eager_array_size_kernel = QIB7322_EAGER_ARRAY_SIZE_10CTX_KERNEL;
		eager_array_size_user = QIB7322_EAGER_ARRAY_SIZE_10CTX_USER;
		break;
	case 18:
		contextcfg = QIB7322_CONTEXTCFG_18CTX;
		eager_array_size_kernel = QIB7322_EAGER_ARRAY_SIZE_18CTX_KERNEL;
		eager_array_size_user = QIB7322_EAGER_ARRAY_SIZE_18CTX_USER;
		break;
	default:
		linker_assert ( 0, invalid_QIB7322_NUM_CONTEXTS );
		return -EINVAL;
	}

	/* Configure number of contexts */
	memset ( &rcvctrl, 0, sizeof ( rcvctrl ) );
	BIT_FILL_2 ( &rcvctrl,
		     TailUpd, 1,
		     ContextCfg, contextcfg );
	qib7322_writeq ( qib7322, &rcvctrl, QIB_7322_RcvCtrl_offset );

	/* Map QPNs to contexts */
	memset ( &rcvctrlp, 0, sizeof ( rcvctrlp ) );
	BIT_FILL_3 ( &rcvctrlp,
		     RcvIBPortEnable, 1,
		     RcvQPMapEnable, 1,
		     RcvPartitionKeyDisable, 1 );
	qib7322_writeq ( qib7322, &rcvctrlp, QIB_7322_RcvCtrl_0_offset );
	qib7322_writeq ( qib7322, &rcvctrlp, QIB_7322_RcvCtrl_1_offset );
	memset ( &rcvqpmaptablea0, 0, sizeof ( rcvqpmaptablea0 ) );
	BIT_FILL_6 ( &rcvqpmaptablea0,
		     RcvQPMapContext0, 0,
		     RcvQPMapContext1, 2,
		     RcvQPMapContext2, 4,
		     RcvQPMapContext3, 6,
		     RcvQPMapContext4, 8,
		     RcvQPMapContext5, 10 );
	qib7322_writeq ( qib7322, &rcvqpmaptablea0,
			 QIB_7322_RcvQPMapTableA_0_offset );
	memset ( &rcvqpmaptableb0, 0, sizeof ( rcvqpmaptableb0 ) );
	BIT_FILL_3 ( &rcvqpmaptableb0,
		     RcvQPMapContext6, 12,
		     RcvQPMapContext7, 14,
		     RcvQPMapContext8, 16 );
	qib7322_writeq ( qib7322, &rcvqpmaptableb0,
			 QIB_7322_RcvQPMapTableB_0_offset );
	memset ( &rcvqpmaptablea1, 0, sizeof ( rcvqpmaptablea1 ) );
	BIT_FILL_6 ( &rcvqpmaptablea1,
		     RcvQPMapContext0, 1,
		     RcvQPMapContext1, 3,
		     RcvQPMapContext2, 5,
		     RcvQPMapContext3, 7,
		     RcvQPMapContext4, 9,
		     RcvQPMapContext5, 11 );
	qib7322_writeq ( qib7322, &rcvqpmaptablea1,
			 QIB_7322_RcvQPMapTableA_1_offset );
	memset ( &rcvqpmaptableb1, 0, sizeof ( rcvqpmaptableb1 ) );
	BIT_FILL_3 ( &rcvqpmaptableb1,
		     RcvQPMapContext6, 13,
		     RcvQPMapContext7, 15,
		     RcvQPMapContext8, 17 );
	qib7322_writeq ( qib7322, &rcvqpmaptableb1,
			 QIB_7322_RcvQPMapTableB_1_offset );

	/* Map multicast QPNs to contexts */
	memset ( &rcvqpmcastctx0, 0, sizeof ( rcvqpmcastctx0 ) );
	BIT_FILL_1 ( &rcvqpmcastctx0, RcvQpMcContext, 0 );
	qib7322_writeq ( qib7322, &rcvqpmcastctx0,
			 QIB_7322_RcvQPMulticastContext_0_offset );
	memset ( &rcvqpmcastctx1, 0, sizeof ( rcvqpmcastctx1 ) );
	BIT_FILL_1 ( &rcvqpmcastctx1, RcvQpMcContext, 1 );
	qib7322_writeq ( qib7322, &rcvqpmcastctx1,
			 QIB_7322_RcvQPMulticastContext_1_offset );

	/* Configure receive header buffer sizes */
	memset ( &rcvhdrcnt, 0, sizeof ( rcvhdrcnt ) );
	BIT_FILL_1 ( &rcvhdrcnt, Value, QIB7322_RECV_HEADER_COUNT );
	qib7322_writeq ( qib7322, &rcvhdrcnt, QIB_7322_RcvHdrCnt_offset );
	memset ( &rcvhdrentsize, 0, sizeof ( rcvhdrentsize ) );
	BIT_FILL_1 ( &rcvhdrentsize, Value, ( QIB7322_RECV_HEADER_SIZE >> 2 ) );
	qib7322_writeq ( qib7322, &rcvhdrentsize,
			 QIB_7322_RcvHdrEntSize_offset );

	/* Calculate eager array start addresses for each context */
	qib7322_readq ( qib7322, &rcvegrbase, QIB_7322_RcvEgrBase_offset );
	egrbase = BIT_GET ( &rcvegrbase, Value );
	for ( ctx = 0 ; ctx < QIB7322_MAX_PORTS ; ctx++ ) {
		qib7322->recv_wq[ctx].eager_array = egrbase;
		qib7322->recv_wq[ctx].eager_entries = eager_array_size_kernel;
		egrbase += ( eager_array_size_kernel *
			     sizeof ( struct QIB_7322_RcvEgr ) );
	}
	for ( ; ctx < QIB7322_NUM_CONTEXTS ; ctx++ ) {
		qib7322->recv_wq[ctx].eager_array = egrbase;
		qib7322->recv_wq[ctx].eager_entries = eager_array_size_user;
		egrbase += ( eager_array_size_user *
			     sizeof ( struct QIB_7322_RcvEgr ) );
	}
	for ( ctx = 0 ; ctx < QIB7322_NUM_CONTEXTS ; ctx++ ) {
		DBGC ( qib7322, "QIB7322 %p CTX %d eager array at %lx (%d "
		       "entries)\n", qib7322, ctx,
		       qib7322->recv_wq[ctx].eager_array,
		       qib7322->recv_wq[ctx].eager_entries );
	}

	/* Set the BTH QP for Infinipath packets to an unused value */
	memset ( &rcvbthqp, 0, sizeof ( rcvbthqp ) );
	BIT_FILL_1 ( &rcvbthqp, RcvBTHQP, QIB7322_QP_IDETH );
	qib7322_writeq ( qib7322, &rcvbthqp, QIB_7322_RcvBTHQP_0_offset );
	qib7322_writeq ( qib7322, &rcvbthqp, QIB_7322_RcvBTHQP_1_offset );

	/* Assign initial credits */
	memset ( &rxcreditvl, 0, sizeof ( rxcreditvl ) );
	BIT_FILL_1 ( &rxcreditvl, RxMaxCreditVL, QIB7322_MAX_CREDITS_VL0 );
	qib7322_writeq_array8b ( qib7322, &rxcreditvl,
				 QIB_7322_RxCreditVL0_0_offset, 0 );
	qib7322_writeq_array8b ( qib7322, &rxcreditvl,
				 QIB_7322_RxCreditVL0_1_offset, 0 );
	BIT_FILL_1 ( &rxcreditvl, RxMaxCreditVL, QIB7322_MAX_CREDITS_VL15 );
	qib7322_writeq_array8b ( qib7322, &rxcreditvl,
				 QIB_7322_RxCreditVL0_0_offset, 15 );
	qib7322_writeq_array8b ( qib7322, &rxcreditvl,
				 QIB_7322_RxCreditVL0_1_offset, 15 );

	return 0;
}

/**
 * Shut down receive datapath
 *
 * @v qib7322		QIB7322 device
 */
static void qib7322_fini_recv ( struct qib7322 *qib7322 __unused ) {
	/* Nothing to do; all contexts were already disabled when the
	 * queue pairs were destroyed
	 */
}

/***************************************************************************
 *
 * Completion queue operations
 *
 ***************************************************************************
 */

/**
 * Create completion queue
 *
 * @v ibdev		Infiniband device
 * @v cq		Completion queue
 * @ret rc		Return status code
 */
static int qib7322_create_cq ( struct ib_device *ibdev,
			       struct ib_completion_queue *cq ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	static int cqn;

	/* The hardware has no concept of completion queues.  We
	 * simply use the association between CQs and WQs (already
	 * handled by the IB core) to decide which WQs to poll.
	 *
	 * We do set a CQN, just to avoid confusing debug messages
	 * from the IB core.
	 */
	cq->cqn = ++cqn;
	DBGC ( qib7322, "QIB7322 %p CQN %ld created\n", qib7322, cq->cqn );

	return 0;
}

/**
 * Destroy completion queue
 *
 * @v ibdev		Infiniband device
 * @v cq		Completion queue
 */
static void qib7322_destroy_cq ( struct ib_device *ibdev,
				 struct ib_completion_queue *cq ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );

	/* Nothing to do */
	DBGC ( qib7322, "QIB7322 %p CQN %ld destroyed\n", qib7322, cq->cqn );
}

/***************************************************************************
 *
 * Queue pair operations
 *
 ***************************************************************************
 */

/**
 * Create queue pair
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @ret rc		Return status code
 */
static int qib7322_create_qp ( struct ib_device *ibdev,
			       struct ib_queue_pair *qp ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	unsigned int ctx;
	int rc;

	/* Allocate a context and QPN */
	if ( ( rc = qib7322_alloc_ctx ( ibdev, qp ) ) != 0 )
		goto err_alloc_ctx;
	ctx = qib7322_ctx ( ibdev, qp );

	/* Set work-queue private data pointers */
	ib_wq_set_drvdata ( &qp->send, &qib7322->send_wq[ctx] );
	ib_wq_set_drvdata ( &qp->recv, &qib7322->recv_wq[ctx] );

	/* Create receive work queue */
	if ( ( rc = qib7322_create_recv_wq ( ibdev, qp ) ) != 0 )
		goto err_create_recv_wq;

	/* Create send work queue */
	if ( ( rc = qib7322_create_send_wq ( ibdev, qp ) ) != 0 )
		goto err_create_send_wq;

	return 0;

	qib7322_destroy_send_wq ( ibdev, qp );
 err_create_send_wq:
	qib7322_destroy_recv_wq ( ibdev, qp );
 err_create_recv_wq:
	qib7322_free_ctx ( ibdev, qp );
 err_alloc_ctx:
	return rc;
}

/**
 * Modify queue pair
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @ret rc		Return status code
 */
static int qib7322_modify_qp ( struct ib_device *ibdev,
			       struct ib_queue_pair *qp ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );

	/* Nothing to do; the hardware doesn't have a notion of queue
	 * keys
	 */
	DBGC2 ( qib7322, "QIB7322 %p QPN %ld modified\n", qib7322, qp->qpn );
	return 0;
}

/**
 * Destroy queue pair
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 */
static void qib7322_destroy_qp ( struct ib_device *ibdev,
				 struct ib_queue_pair *qp ) {

	qib7322_destroy_send_wq ( ibdev, qp );
	qib7322_destroy_recv_wq ( ibdev, qp );
	qib7322_free_ctx ( ibdev, qp );
}

/***************************************************************************
 *
 * Work request operations
 *
 ***************************************************************************
 */

/**
 * Post send work queue entry
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v dest		Destination address vector
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int qib7322_post_send ( struct ib_device *ibdev,
			       struct ib_queue_pair *qp,
			       struct ib_address_vector *dest,
			       struct io_buffer *iobuf ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct ib_work_queue *wq = &qp->send;
	struct qib7322_send_work_queue *qib7322_wq = ib_wq_get_drvdata ( wq );
	struct QIB_7322_SendPbc sendpbc;
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );
	uint8_t header_buf[IB_MAX_HEADER_SIZE];
	struct io_buffer headers;
	int send_buf;
	unsigned long start_offset;
	unsigned long offset;
	size_t len;
	ssize_t frag_len;
	uint32_t *data;

	/* Allocate send buffer and calculate offset */
	send_buf = qib7322_alloc_send_buf ( qib7322, qib7322_wq->send_bufs );
	if ( send_buf < 0 )
		return send_buf;
	start_offset = offset =
		qib7322_send_buffer_offset ( qib7322, qib7322_wq->send_bufs,
					     send_buf );

	/* Store I/O buffer and send buffer index */
	assert ( wq->iobufs[qib7322_wq->prod] == NULL );
	wq->iobufs[qib7322_wq->prod] = iobuf;
	qib7322_wq->used[qib7322_wq->prod] = send_buf;

	/* Construct headers */
	iob_populate ( &headers, header_buf, 0, sizeof ( header_buf ) );
	iob_reserve ( &headers, sizeof ( header_buf ) );
	ib_push ( ibdev, &headers, qp, iob_len ( iobuf ), dest );

	/* Calculate packet length */
	len = ( ( sizeof ( sendpbc ) + iob_len ( &headers ) +
		  iob_len ( iobuf ) + 3 ) & ~3 );

	/* Construct send per-buffer control word */
	memset ( &sendpbc, 0, sizeof ( sendpbc ) );
	BIT_FILL_3 ( &sendpbc,
		     LengthP1_toibc, ( ( len >> 2 ) - 1 ),
		     Port, port,
		     VL15, ( ( qp->type == IB_QPT_SMI ) ? 1 : 0 ) );

	/* Write SendPbc */
	DBG_DISABLE ( DBGLVL_IO );
	qib7322_writeq ( qib7322, &sendpbc, offset );
	offset += sizeof ( sendpbc );

	/* Write headers */
	for ( data = headers.data, frag_len = iob_len ( &headers ) ;
	      frag_len > 0 ; data++, offset += 4, frag_len -= 4 ) {
		qib7322_writel ( qib7322, *data, offset );
	}

	/* Write data */
	for ( data = iobuf->data, frag_len = iob_len ( iobuf ) ;
	      frag_len > 0 ; data++, offset += 4, frag_len -= 4 ) {
		qib7322_writel ( qib7322, *data, offset );
	}
	DBG_ENABLE ( DBGLVL_IO );

	assert ( ( start_offset + len ) == offset );
	DBGC2 ( qib7322, "QIB7322 %p QPN %ld TX %04x(%04x) posted [%lx,%lx)\n",
		qib7322, qp->qpn, send_buf, qib7322_wq->prod,
		start_offset, offset );

	/* Increment producer counter */
	qib7322_wq->prod = ( ( qib7322_wq->prod + 1 ) & ( wq->num_wqes - 1 ) );

	return 0;
}

/**
 * Complete send work queue entry
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v wqe_idx		Work queue entry index
 */
static void qib7322_complete_send ( struct ib_device *ibdev,
				    struct ib_queue_pair *qp,
				    unsigned int wqe_idx ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct ib_work_queue *wq = &qp->send;
	struct qib7322_send_work_queue *qib7322_wq = ib_wq_get_drvdata ( wq );
	struct io_buffer *iobuf;
	unsigned int send_buf;

	/* Parse completion */
	send_buf = qib7322_wq->used[wqe_idx];
	DBGC2 ( qib7322, "QIB7322 %p QPN %ld TX %04x(%04x) complete\n",
		qib7322, qp->qpn, send_buf, wqe_idx );

	/* Complete work queue entry */
	iobuf = wq->iobufs[wqe_idx];
	assert ( iobuf != NULL );
	ib_complete_send ( ibdev, qp, iobuf, 0 );
	wq->iobufs[wqe_idx] = NULL;

	/* Free send buffer */
	qib7322_free_send_buf ( qib7322, qib7322_wq->send_bufs, send_buf );
}

/**
 * Poll send work queue
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 */
static void qib7322_poll_send_wq ( struct ib_device *ibdev,
				   struct ib_queue_pair *qp ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct ib_work_queue *wq = &qp->send;
	struct qib7322_send_work_queue *qib7322_wq = ib_wq_get_drvdata ( wq );
	unsigned int send_buf;

	/* Look for completions */
	while ( wq->fill ) {

		/* Check to see if send buffer has completed */
		send_buf = qib7322_wq->used[qib7322_wq->cons];
		if ( qib7322_send_buf_in_use ( qib7322, send_buf ) )
			break;

		/* Complete this buffer */
		qib7322_complete_send ( ibdev, qp, qib7322_wq->cons );

		/* Increment consumer counter */
		qib7322_wq->cons = ( ( qib7322_wq->cons + 1 ) &
				     ( wq->num_wqes - 1 ) );
	}
}

/**
 * Post receive work queue entry
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int qib7322_post_recv ( struct ib_device *ibdev,
			       struct ib_queue_pair *qp,
			       struct io_buffer *iobuf ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct ib_work_queue *wq = &qp->recv;
	struct qib7322_recv_work_queue *qib7322_wq = ib_wq_get_drvdata ( wq );
	struct QIB_7322_RcvEgr rcvegr;
	struct QIB_7322_scalar rcvegrindexhead;
	unsigned int ctx = qib7322_ctx ( ibdev, qp );
	physaddr_t addr;
	size_t len;
	unsigned int wqe_idx;
	unsigned int bufsize;

	/* Sanity checks */
	addr = virt_to_bus ( iobuf->data );
	len = iob_tailroom ( iobuf );
	if ( addr & ( QIB7322_EAGER_BUFFER_ALIGN - 1 ) ) {
		DBGC ( qib7322, "QIB7322 %p QPN %ld misaligned RX buffer "
		       "(%08lx)\n", qib7322, qp->qpn, addr );
		return -EINVAL;
	}
	if ( len != QIB7322_RECV_PAYLOAD_SIZE ) {
		DBGC ( qib7322, "QIB7322 %p QPN %ld wrong RX buffer size "
		       "(%zd)\n", qib7322, qp->qpn, len );
		return -EINVAL;
	}

	/* Calculate eager producer index and WQE index */
	wqe_idx = ( qib7322_wq->eager_prod & ( wq->num_wqes - 1 ) );
	assert ( wq->iobufs[wqe_idx] == NULL );

	/* Store I/O buffer */
	wq->iobufs[wqe_idx] = iobuf;

	/* Calculate buffer size */
	switch ( QIB7322_RECV_PAYLOAD_SIZE ) {
	case 2048:  bufsize = QIB7322_EAGER_BUFFER_2K;  break;
	case 4096:  bufsize = QIB7322_EAGER_BUFFER_4K;  break;
	case 8192:  bufsize = QIB7322_EAGER_BUFFER_8K;  break;
	case 16384: bufsize = QIB7322_EAGER_BUFFER_16K; break;
	case 32768: bufsize = QIB7322_EAGER_BUFFER_32K; break;
	case 65536: bufsize = QIB7322_EAGER_BUFFER_64K; break;
	default:    linker_assert ( 0, invalid_rx_payload_size );
		    bufsize = QIB7322_EAGER_BUFFER_NONE;
	}

	/* Post eager buffer */
	memset ( &rcvegr, 0, sizeof ( rcvegr ) );
	BIT_FILL_2 ( &rcvegr,
		     Addr, ( addr >> 11 ),
		     BufSize, bufsize );
	qib7322_writeq_array8b ( qib7322, &rcvegr, qib7322_wq->eager_array,
				 qib7322_wq->eager_prod );
	DBGC2 ( qib7322, "QIB7322 %p QPN %ld RX egr %04x(%04x) posted "
		"[%lx,%lx)\n", qib7322, qp->qpn, qib7322_wq->eager_prod,
		wqe_idx, addr, ( addr + len ) );

	/* Increment producer index */
	qib7322_wq->eager_prod = ( ( qib7322_wq->eager_prod + 1 ) &
				   ( qib7322_wq->eager_entries - 1 ) );

	/* Update head index */
	memset ( &rcvegrindexhead, 0, sizeof ( rcvegrindexhead ) );
	BIT_FILL_1 ( &rcvegrindexhead,
		     Value, ( ( qib7322_wq->eager_prod + 1 ) &
			      ( qib7322_wq->eager_entries - 1 ) ) );
	qib7322_writeq_array64k ( qib7322, &rcvegrindexhead,
				  QIB_7322_RcvEgrIndexHead0_offset, ctx );

	return 0;
}

/**
 * Complete receive work queue entry
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v header_offs	Header offset
 */
static void qib7322_complete_recv ( struct ib_device *ibdev,
				    struct ib_queue_pair *qp,
				    unsigned int header_offs ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct ib_work_queue *wq = &qp->recv;
	struct qib7322_recv_work_queue *qib7322_wq = ib_wq_get_drvdata ( wq );
	struct QIB_7322_RcvHdrFlags *rcvhdrflags;
	struct QIB_7322_RcvEgr rcvegr;
	struct io_buffer headers;
	struct io_buffer *iobuf;
	struct ib_queue_pair *intended_qp;
	struct ib_address_vector dest;
	struct ib_address_vector source;
	unsigned int rcvtype;
	unsigned int pktlen;
	unsigned int egrindex;
	unsigned int useegrbfr;
	unsigned int iberr, mkerr, tiderr, khdrerr, mtuerr;
	unsigned int lenerr, parityerr, vcrcerr, icrcerr;
	unsigned int err;
	unsigned int hdrqoffset;
	unsigned int header_len;
	unsigned int padded_payload_len;
	unsigned int wqe_idx;
	size_t payload_len;
	int qp0;
	int rc;

	/* RcvHdrFlags are at the end of the header entry */
	rcvhdrflags = ( qib7322_wq->header + header_offs +
			QIB7322_RECV_HEADER_SIZE - sizeof ( *rcvhdrflags ) );
	rcvtype = BIT_GET ( rcvhdrflags, RcvType );
	pktlen = ( BIT_GET ( rcvhdrflags, PktLen ) << 2 );
	egrindex = BIT_GET ( rcvhdrflags, EgrIndex );
	useegrbfr = BIT_GET ( rcvhdrflags, UseEgrBfr );
	hdrqoffset = ( BIT_GET ( rcvhdrflags, HdrqOffset ) << 2 );
	iberr = BIT_GET ( rcvhdrflags, IBErr );
	mkerr = BIT_GET ( rcvhdrflags, MKErr );
	tiderr = BIT_GET ( rcvhdrflags, TIDErr );
	khdrerr = BIT_GET ( rcvhdrflags, KHdrErr );
	mtuerr = BIT_GET ( rcvhdrflags, MTUErr );
	lenerr = BIT_GET ( rcvhdrflags, LenErr );
	parityerr = BIT_GET ( rcvhdrflags, ParityErr );
	vcrcerr = BIT_GET ( rcvhdrflags, VCRCErr );
	icrcerr = BIT_GET ( rcvhdrflags, ICRCErr );
	header_len = ( QIB7322_RECV_HEADER_SIZE - hdrqoffset -
		       sizeof ( *rcvhdrflags ) );
	padded_payload_len = ( pktlen - header_len - 4 /* ICRC */ );
	err = ( iberr | mkerr | tiderr | khdrerr | mtuerr |
		lenerr | parityerr | vcrcerr | icrcerr );
	/* IB header is placed immediately before RcvHdrFlags */
	iob_populate ( &headers, ( ( ( void * ) rcvhdrflags ) - header_len ),
		       header_len, header_len );

	/* Dump diagnostic information */
	DBGC2 ( qib7322, "QIB7322 %p QPN %ld RX egr %04x%s hdr %d type %d len "
		"%d(%d+%d+4)%s%s%s%s%s%s%s%s%s%s%s\n", qib7322, qp->qpn,
		egrindex, ( useegrbfr ? "" : "(unused)" ),
		( header_offs / QIB7322_RECV_HEADER_SIZE ),
		rcvtype, pktlen, header_len, padded_payload_len,
		( err ? " [Err" : "" ), ( iberr ? " IB" : "" ),
		( mkerr ? " MK" : "" ), ( tiderr ? " TID" : "" ),
		( khdrerr ? " KHdr" : "" ), ( mtuerr ? " MTU" : "" ),
		( lenerr ? " Len" : "" ), ( parityerr ? " Parity" : ""),
		( vcrcerr ? " VCRC" : "" ), ( icrcerr ? " ICRC" : "" ),
		( err ? "]" : "" ) );
	DBGCP_HDA ( qib7322, hdrqoffset, headers.data,
		    ( header_len + sizeof ( *rcvhdrflags ) ) );

	/* Parse header to generate address vector */
	qp0 = ( qp->qpn == 0 );
	intended_qp = NULL;
	if ( ( rc = ib_pull ( ibdev, &headers, ( qp0 ? &intended_qp : NULL ),
			      &payload_len, &dest, &source ) ) != 0 ) {
		DBGC ( qib7322, "QIB7322 %p could not parse headers: %s\n",
		       qib7322, strerror ( rc ) );
		err = 1;
	}
	if ( ! intended_qp )
		intended_qp = qp;

	/* Complete this buffer and any skipped buffers.  Note that
	 * when the hardware runs out of buffers, it will repeatedly
	 * report the same buffer (the tail) as a TID error, and that
	 * it also has a habit of sometimes skipping over several
	 * buffers at once.
	 */
	while ( 1 ) {

		/* If we have caught up to the producer counter, stop.
		 * This will happen when the hardware first runs out
		 * of buffers and starts reporting TID errors against
		 * the eager buffer it wants to use next.
		 */
		if ( qib7322_wq->eager_cons == qib7322_wq->eager_prod )
			break;

		/* If we have caught up to where we should be after
		 * completing this egrindex, stop.  We phrase the test
		 * this way to avoid completing the entire ring when
		 * we receive the same egrindex twice in a row.
		 */
		if ( ( qib7322_wq->eager_cons ==
		       ( ( egrindex + 1 ) & ( qib7322_wq->eager_entries - 1 ))))
			break;

		/* Identify work queue entry and corresponding I/O
		 * buffer.
		 */
		wqe_idx = ( qib7322_wq->eager_cons & ( wq->num_wqes - 1 ) );
		iobuf = wq->iobufs[wqe_idx];
		assert ( iobuf != NULL );
		wq->iobufs[wqe_idx] = NULL;

		/* Complete the eager buffer */
		if ( qib7322_wq->eager_cons == egrindex ) {
			/* Completing the eager buffer described in
			 * this header entry.
			 */
			iob_put ( iobuf, payload_len );
			rc = ( err ? -EIO : ( useegrbfr ? 0 : -ECANCELED ) );
			/* Redirect to target QP if necessary */
			if ( qp != intended_qp ) {
				DBGC2 ( qib7322, "QIB7322 %p redirecting QPN "
					"%ld => %ld\n",
					qib7322, qp->qpn, intended_qp->qpn );
				/* Compensate for incorrect fill levels */
				qp->recv.fill--;
				intended_qp->recv.fill++;
			}
			ib_complete_recv ( ibdev, intended_qp, &dest, &source,
					   iobuf, rc);
		} else {
			/* Completing on a skipped-over eager buffer */
			ib_complete_recv ( ibdev, qp, &dest, &source, iobuf,
					   -ECANCELED );
		}

		/* Clear eager buffer */
		memset ( &rcvegr, 0, sizeof ( rcvegr ) );
		qib7322_writeq_array8b ( qib7322, &rcvegr,
					 qib7322_wq->eager_array,
					 qib7322_wq->eager_cons );

		/* Increment consumer index */
		qib7322_wq->eager_cons = ( ( qib7322_wq->eager_cons + 1 ) &
					   ( qib7322_wq->eager_entries - 1 ) );
	}
}

/**
 * Poll receive work queue
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 */
static void qib7322_poll_recv_wq ( struct ib_device *ibdev,
				   struct ib_queue_pair *qp ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct ib_work_queue *wq = &qp->recv;
	struct qib7322_recv_work_queue *qib7322_wq = ib_wq_get_drvdata ( wq );
	struct QIB_7322_RcvHdrHead0 rcvhdrhead;
	unsigned int ctx = qib7322_ctx ( ibdev, qp );
	unsigned int header_prod;

	/* Check for received packets */
	header_prod = ( BIT_GET ( &qib7322_wq->header_prod, Value ) << 2 );
	if ( header_prod == qib7322_wq->header_cons )
		return;

	/* Process all received packets */
	while ( qib7322_wq->header_cons != header_prod ) {

		/* Complete the receive */
		qib7322_complete_recv ( ibdev, qp, qib7322_wq->header_cons );

		/* Increment the consumer offset */
		qib7322_wq->header_cons += QIB7322_RECV_HEADER_SIZE;
		qib7322_wq->header_cons %= QIB7322_RECV_HEADERS_SIZE;

		/* QIB7322 has only one send buffer per port for VL15,
		 * which almost always leads to send buffer exhaustion
		 * and dropped MADs.  Mitigate this by refusing to
		 * process more than one VL15 MAD per poll, which will
		 * enforce interleaved TX/RX polls.
		 */
		if ( qp->type == IB_QPT_SMI )
			break;
	}

	/* Update consumer offset */
	memset ( &rcvhdrhead, 0, sizeof ( rcvhdrhead ) );
	BIT_FILL_2 ( &rcvhdrhead,
		     RcvHeadPointer, ( qib7322_wq->header_cons >> 2 ),
		     counter, 1 );
	qib7322_writeq_array64k ( qib7322, &rcvhdrhead,
				  QIB_7322_RcvHdrHead0_offset, ctx );
}

/**
 * Poll completion queue
 *
 * @v ibdev		Infiniband device
 * @v cq		Completion queue
 */
static void qib7322_poll_cq ( struct ib_device *ibdev,
			      struct ib_completion_queue *cq ) {
	struct ib_work_queue *wq;

	/* Poll associated send and receive queues */
	list_for_each_entry ( wq, &cq->work_queues, list ) {
		if ( wq->is_send ) {
			qib7322_poll_send_wq ( ibdev, wq->qp );
		} else {
			qib7322_poll_recv_wq ( ibdev, wq->qp );
		}
	}
}

/***************************************************************************
 *
 * Event queues
 *
 ***************************************************************************
 */

/**
 * Poll event queue
 *
 * @v ibdev		Infiniband device
 */
static void qib7322_poll_eq ( struct ib_device *ibdev ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct QIB_7322_ErrStatus_0 errstatus;
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );

	/* Check for and clear status bits */
	DBG_DISABLE ( DBGLVL_IO );
	qib7322_readq_port ( qib7322, &errstatus,
			     QIB_7322_ErrStatus_0_offset, port );
	if ( errstatus.u.qwords[0] ) {
		DBGC ( qib7322, "QIB7322 %p port %d status %08x%08x\n", qib7322,
		       port, errstatus.u.dwords[1],  errstatus.u.dwords[0] );
		qib7322_writeq_port ( qib7322, &errstatus,
				      QIB_7322_ErrClear_0_offset, port );
	}
	DBG_ENABLE ( DBGLVL_IO );

	/* Check for link status changes */
	if ( BIT_GET ( &errstatus, IBStatusChanged ) )
		qib7322_link_state_changed ( ibdev );
}

/***************************************************************************
 *
 * Infiniband link-layer operations
 *
 ***************************************************************************
 */

/**
 * Determine supported link speeds
 *
 * @v qib7322		QIB7322 device
 * @ret supported	Supported link speeds
 */
static unsigned int qib7322_link_speed_supported ( struct qib7322 *qib7322,
						   unsigned int port ) {
	struct QIB_7322_feature_mask features;
	struct QIB_7322_Revision revision;
	unsigned int supported;
	unsigned int boardid;

	/* Read the active feature mask */
	qib7322_readq ( qib7322, &features,
			QIB_7322_active_feature_mask_offset );
	switch ( port ) {
	case 0 :
		supported = BIT_GET ( &features, Port0_Link_Speed_Supported );
		break;
	case 1 :
		supported = BIT_GET ( &features, Port1_Link_Speed_Supported );
		break;
	default:
		DBGC ( qib7322, "QIB7322 %p port %d is invalid\n",
		       qib7322, port );
		supported = 0;
		break;
	}

	/* Apply hacks for specific board IDs */
	qib7322_readq ( qib7322, &revision, QIB_7322_Revision_offset );
	boardid = BIT_GET ( &revision, BoardID );
	switch ( boardid ) {
	case QIB7322_BOARD_QMH7342 :
		DBGC2 ( qib7322, "QIB7322 %p is a QMH7342; forcing QDR-only\n",
			qib7322 );
		supported = IB_LINK_SPEED_QDR;
		break;
	default:
		/* Do nothing */
		break;
	}

	DBGC2 ( qib7322, "QIB7322 %p port %d %s%s%s%s\n", qib7322, port,
		( supported ? "supports" : "disabled" ),
		( ( supported & IB_LINK_SPEED_SDR ) ? " SDR" : "" ),
		( ( supported & IB_LINK_SPEED_DDR ) ? " DDR" : "" ),
		( ( supported & IB_LINK_SPEED_QDR ) ? " QDR" : "" ) );
	return supported;
}

/**
 * Initialise Infiniband link
 *
 * @v ibdev		Infiniband device
 * @ret rc		Return status code
 */
static int qib7322_open ( struct ib_device *ibdev ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct QIB_7322_IBCCtrlA_0 ibcctrla;
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );

	/* Enable link */
	qib7322_readq_port ( qib7322, &ibcctrla,
			     QIB_7322_IBCCtrlA_0_offset, port );
	BIT_SET ( &ibcctrla, IBLinkEn, 1 );
	qib7322_writeq_port ( qib7322, &ibcctrla,
			      QIB_7322_IBCCtrlA_0_offset, port );

	return 0;
}

/**
 * Close Infiniband link
 *
 * @v ibdev		Infiniband device
 */
static void qib7322_close ( struct ib_device *ibdev ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );
	struct QIB_7322_IBCCtrlA_0 ibcctrla;
	unsigned int port = ( ibdev->port - QIB7322_PORT_BASE );

	/* Disable link */
	qib7322_readq_port ( qib7322, &ibcctrla,
			     QIB_7322_IBCCtrlA_0_offset, port );
	BIT_SET ( &ibcctrla, IBLinkEn, 0 );
	qib7322_writeq_port ( qib7322, &ibcctrla,
			      QIB_7322_IBCCtrlA_0_offset, port );
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
static int qib7322_mcast_attach ( struct ib_device *ibdev,
				  struct ib_queue_pair *qp,
				  union ib_gid *gid ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );

	( void ) qib7322;
	( void ) qp;
	( void ) gid;
	return 0;
}

/**
 * Detach from multicast group
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v gid		Multicast GID
 */
static void qib7322_mcast_detach ( struct ib_device *ibdev,
				   struct ib_queue_pair *qp,
				   union ib_gid *gid ) {
	struct qib7322 *qib7322 = ib_get_drvdata ( ibdev );

	( void ) qib7322;
	( void ) qp;
	( void ) gid;
 }

/** QIB7322 Infiniband operations */
static struct ib_device_operations qib7322_ib_operations = {
	.create_cq	= qib7322_create_cq,
	.destroy_cq	= qib7322_destroy_cq,
	.create_qp	= qib7322_create_qp,
	.modify_qp	= qib7322_modify_qp,
	.destroy_qp	= qib7322_destroy_qp,
	.post_send	= qib7322_post_send,
	.post_recv	= qib7322_post_recv,
	.poll_cq	= qib7322_poll_cq,
	.poll_eq	= qib7322_poll_eq,
	.open		= qib7322_open,
	.close		= qib7322_close,
	.mcast_attach	= qib7322_mcast_attach,
	.mcast_detach	= qib7322_mcast_detach,
	.set_port_info	= qib7322_set_port_info,
	.set_pkey_table	= qib7322_set_pkey_table,
};

/***************************************************************************
 *
 * I2C bus operations
 *
 ***************************************************************************
 */

/** QIB7322 I2C bit to GPIO mappings */
static unsigned int qib7322_i2c_bits[] = {
	[I2C_BIT_SCL] = ( 1 << QIB7322_GPIO_SCL ),
	[I2C_BIT_SDA] = ( 1 << QIB7322_GPIO_SDA ),
};

/**
 * Read QIB7322 I2C line status
 *
 * @v basher		Bit-bashing interface
 * @v bit_id		Bit number
 * @ret zero		Input is a logic 0
 * @ret non-zero	Input is a logic 1
 */
static int qib7322_i2c_read_bit ( struct bit_basher *basher,
				  unsigned int bit_id ) {
	struct qib7322 *qib7322 =
		container_of ( basher, struct qib7322, i2c.basher );
	struct QIB_7322_EXTStatus extstatus;
	unsigned int status;

	DBG_DISABLE ( DBGLVL_IO );

	qib7322_readq ( qib7322, &extstatus, QIB_7322_EXTStatus_offset );
	status = ( BIT_GET ( &extstatus, GPIOIn ) & qib7322_i2c_bits[bit_id] );

	DBG_ENABLE ( DBGLVL_IO );

	return status;
}

/**
 * Write QIB7322 I2C line status
 *
 * @v basher		Bit-bashing interface
 * @v bit_id		Bit number
 * @v data		Value to write
 */
static void qib7322_i2c_write_bit ( struct bit_basher *basher,
				    unsigned int bit_id, unsigned long data ) {
	struct qib7322 *qib7322 =
		container_of ( basher, struct qib7322, i2c.basher );
	struct QIB_7322_EXTCtrl extctrl;
	struct QIB_7322_GPIO gpioout;
	unsigned int bit = qib7322_i2c_bits[bit_id];
	unsigned int outputs = 0;
	unsigned int output_enables = 0;

	DBG_DISABLE ( DBGLVL_IO );

	/* Read current GPIO mask and outputs */
	qib7322_readq ( qib7322, &extctrl, QIB_7322_EXTCtrl_offset );
	qib7322_readq ( qib7322, &gpioout, QIB_7322_GPIOOut_offset );

	/* Update outputs and output enables.  I2C lines are tied
	 * high, so we always set the output to 0 and use the output
	 * enable to control the line.
	 */
	output_enables = BIT_GET ( &extctrl, GPIOOe );
	output_enables = ( ( output_enables & ~bit ) | ( ~data & bit ) );
	outputs = BIT_GET ( &gpioout, GPIO );
	outputs = ( outputs & ~bit );
	BIT_SET ( &extctrl, GPIOOe, output_enables );
	BIT_SET ( &gpioout, GPIO, outputs );

	/* Write the output enable first; that way we avoid logic
	 * hazards.
	 */
	qib7322_writeq ( qib7322, &extctrl, QIB_7322_EXTCtrl_offset );
	qib7322_writeq ( qib7322, &gpioout, QIB_7322_GPIOOut_offset );
	mb();

	DBG_ENABLE ( DBGLVL_IO );
}

/** QIB7322 I2C bit-bashing interface operations */
static struct bit_basher_operations qib7322_i2c_basher_ops = {
	.read	= qib7322_i2c_read_bit,
	.write	= qib7322_i2c_write_bit,
};

/**
 * Initialise QIB7322 I2C subsystem
 *
 * @v qib7322		QIB7322 device
 * @ret rc		Return status code
 */
static int qib7322_init_i2c ( struct qib7322 *qib7322 ) {
	static int try_eeprom_address[] = { 0x51, 0x50 };
	unsigned int i;
	int rc;

	/* Initialise bus */
	if ( ( rc = init_i2c_bit_basher ( &qib7322->i2c,
					  &qib7322_i2c_basher_ops ) ) != 0 ) {
		DBGC ( qib7322, "QIB7322 %p could not initialise I2C bus: %s\n",
		       qib7322, strerror ( rc ) );
		return rc;
	}

	/* Probe for devices */
	for ( i = 0 ; i < ( sizeof ( try_eeprom_address ) /
			    sizeof ( try_eeprom_address[0] ) ) ; i++ ) {
		init_i2c_eeprom ( &qib7322->eeprom, try_eeprom_address[i] );
		if ( ( rc = i2c_check_presence ( &qib7322->i2c.i2c,
						 &qib7322->eeprom ) ) == 0 ) {
			DBGC2 ( qib7322, "QIB7322 %p found EEPROM at %02x\n",
				qib7322, try_eeprom_address[i] );
			return 0;
		}
	}

	DBGC ( qib7322, "QIB7322 %p could not find EEPROM\n", qib7322 );
	return -ENODEV;
}

/**
 * Read EEPROM parameters
 *
 * @v qib7322		QIB7322 device
 * @ret rc		Return status code
 */
static int qib7322_read_eeprom ( struct qib7322 *qib7322 ) {
	struct i2c_interface *i2c = &qib7322->i2c.i2c;
	union ib_guid *guid = &qib7322->guid;
	int rc;

	/* Read GUID */
	if ( ( rc = i2c->read ( i2c, &qib7322->eeprom,
				QIB7322_EEPROM_GUID_OFFSET, guid->bytes,
				sizeof ( *guid ) ) ) != 0 ) {
		DBGC ( qib7322, "QIB7322 %p could not read GUID: %s\n",
		       qib7322, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( qib7322, "QIB7322 %p has GUID " IB_GUID_FMT "\n",
		qib7322, IB_GUID_ARGS ( guid ) );

	/* Read serial number (debug only) */
	if ( DBG_LOG ) {
		uint8_t serial[QIB7322_EEPROM_SERIAL_SIZE + 1];

		serial[ sizeof ( serial ) - 1 ] = '\0';
		if ( ( rc = i2c->read ( i2c, &qib7322->eeprom,
					QIB7322_EEPROM_SERIAL_OFFSET, serial,
					( sizeof ( serial ) - 1 ) ) ) != 0 ) {
			DBGC ( qib7322, "QIB7322 %p could not read serial: "
			       "%s\n", qib7322, strerror ( rc ) );
			return rc;
		}
		DBGC2 ( qib7322, "QIB7322 %p has serial number \"%s\"\n",
			qib7322, serial );
	}

	return 0;
}

/***************************************************************************
 *
 * Advanced High-performance Bus (AHB) access
 *
 ***************************************************************************
 */

/**
 * Wait for AHB transaction to complete
 *
 * @v qib7322		QIB7322 device
 * @ret rc		Return status code
 */
static int qib7322_ahb_wait ( struct qib7322 *qib7322 ) {
	struct QIB_7322_ahb_transaction_reg transaction;
	unsigned int i;

	/* Wait for Ready bit to be asserted */
	for ( i = 0 ; i < QIB7322_AHB_MAX_WAIT_US ; i++ ) {
		qib7322_readq ( qib7322, &transaction,
				QIB_7322_ahb_transaction_reg_offset );
		if ( BIT_GET ( &transaction, ahb_rdy ) )
			return 0;
		udelay ( 1 );
	}

	DBGC ( qib7322, "QIB7322 %p timed out waiting for AHB transaction\n",
	       qib7322 );
	return -ETIMEDOUT;
}

/**
 * Request ownership of the AHB
 *
 * @v qib7322		QIB7322 device
 * @v location		AHB location
 * @ret rc		Return status code
 */
static int qib7322_ahb_request ( struct qib7322 *qib7322,
				 unsigned int location ) {
	struct QIB_7322_ahb_access_ctrl access;
	int rc;

	/* Request ownership */
	memset ( &access, 0, sizeof ( access ) );
	BIT_FILL_2 ( &access,
		     sw_ahb_sel, 1,
		     sw_sel_ahb_trgt, QIB7322_AHB_LOC_TARGET ( location ) );
	qib7322_writeq ( qib7322, &access, QIB_7322_ahb_access_ctrl_offset );

	/* Wait for ownership to be granted */
	if ( ( rc = qib7322_ahb_wait ( qib7322 ) ) != 0 )  {
		DBGC ( qib7322, "QIB7322 %p could not obtain AHB ownership: "
		       "%s\n", qib7322, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Release ownership of the AHB
 *
 * @v qib7322		QIB7322 device
 */
static void qib7322_ahb_release ( struct qib7322 *qib7322 ) {
	struct QIB_7322_ahb_access_ctrl access;

	memset ( &access, 0, sizeof ( access ) );
	qib7322_writeq ( qib7322, &access, QIB_7322_ahb_access_ctrl_offset );
}

/**
 * Read data via AHB
 *
 * @v qib7322		QIB7322 device
 * @v location		AHB location
 * @v data		Data to read
 * @ret rc		Return status code
 *
 * You must have already acquired ownership of the AHB.
 */
static int qib7322_ahb_read ( struct qib7322 *qib7322, unsigned int location,
			      uint32_t *data ) {
	struct QIB_7322_ahb_transaction_reg xact;
	int rc;

	/* Avoid returning uninitialised data on error */
	*data = 0;

	/* Initiate transaction */
	memset ( &xact, 0, sizeof ( xact ) );
	BIT_FILL_2 ( &xact,
		     ahb_address, QIB7322_AHB_LOC_ADDRESS ( location ),
		     write_not_read, 0 );
	qib7322_writeq ( qib7322, &xact, QIB_7322_ahb_transaction_reg_offset );

	/* Wait for transaction to complete */
	if ( ( rc = qib7322_ahb_wait ( qib7322 ) ) != 0 )
		return rc;

	/* Read transaction data */
	qib7322_readq ( qib7322, &xact, QIB_7322_ahb_transaction_reg_offset );
	*data = BIT_GET ( &xact, ahb_data );
	return 0;
}

/**
 * Write data via AHB
 *
 * @v qib7322		QIB7322 device
 * @v location		AHB location
 * @v data		Data to write
 * @ret rc		Return status code
 *
 * You must have already acquired ownership of the AHB.
 */
static int qib7322_ahb_write ( struct qib7322 *qib7322, unsigned int location,
			       uint32_t data ) {
	struct QIB_7322_ahb_transaction_reg xact;
	int rc;

	/* Initiate transaction */
	memset ( &xact, 0, sizeof ( xact ) );
	BIT_FILL_3 ( &xact,
		     ahb_address, QIB7322_AHB_LOC_ADDRESS ( location ),
		     write_not_read, 1,
		     ahb_data, data );
	qib7322_writeq ( qib7322, &xact, QIB_7322_ahb_transaction_reg_offset );

	/* Wait for transaction to complete */
	if ( ( rc = qib7322_ahb_wait ( qib7322 ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Read/modify/write AHB register
 *
 * @v qib7322		QIB7322 device
 * @v location		AHB location
 * @v value		Value to set
 * @v mask		Mask to apply to old value
 * @ret rc		Return status code
 */
static int qib7322_ahb_mod_reg ( struct qib7322 *qib7322, unsigned int location,
				 uint32_t value, uint32_t mask ) {
	uint32_t old_value;
	uint32_t new_value;
	int rc;

	DBG_DISABLE ( DBGLVL_IO );

	/* Sanity check */
	assert ( ( value & mask ) == value );

	/* Acquire bus ownership */
	if ( ( rc = qib7322_ahb_request ( qib7322, location ) ) != 0 )
		goto out;

	/* Read existing value */
	if ( ( rc = qib7322_ahb_read ( qib7322, location, &old_value ) ) != 0 )
		goto out_release;

	/* Update value */
	new_value = ( ( old_value & ~mask ) | value );
	DBGCP ( qib7322, "QIB7322 %p AHB %x %#08x => %#08x\n",
		qib7322, location, old_value, new_value );
	if ( ( rc = qib7322_ahb_write ( qib7322, location, new_value ) ) != 0 )
		goto out_release;

 out_release:
	/* Release bus */
	qib7322_ahb_release ( qib7322 );
 out:
	DBG_ENABLE ( DBGLVL_IO );
	return rc;
}

/**
 * Read/modify/write AHB register across all ports and channels
 *
 * @v qib7322		QIB7322 device
 * @v reg		AHB register
 * @v value		Value to set
 * @v mask		Mask to apply to old value
 * @ret rc		Return status code
 */
static int qib7322_ahb_mod_reg_all ( struct qib7322 *qib7322, unsigned int reg,
				     uint32_t value, uint32_t mask ) {
	unsigned int port;
	unsigned int channel;
	unsigned int location;
	int rc;

	for ( port = 0 ; port < QIB7322_MAX_PORTS ; port++ ) {
		for ( channel = 0 ; channel < QIB7322_MAX_WIDTH ; channel++ ) {
			location = QIB7322_AHB_LOCATION ( port, channel, reg );
			if ( ( rc = qib7322_ahb_mod_reg ( qib7322, location,
							  value, mask ) ) != 0 )
				return rc;
		}
	}
	return 0;
}

/***************************************************************************
 *
 * Infiniband SerDes initialisation
 *
 ***************************************************************************
 */

/**
 * Initialise the IB SerDes
 *
 * @v qib7322		QIB7322 device
 * @ret rc		Return status code
 */
static int qib7322_init_ib_serdes ( struct qib7322 *qib7322 ) {
	struct QIB_7322_IBCCtrlA_0 ibcctrla;
	struct QIB_7322_IBCCtrlB_0 ibcctrlb;
	struct QIB_7322_IBPCSConfig_0 ibpcsconfig;

	/* Configure sensible defaults for IBC */
	memset ( &ibcctrla, 0, sizeof ( ibcctrla ) );
	BIT_FILL_5 ( &ibcctrla, /* Tuning values taken from Linux driver */
		     FlowCtrlPeriod, 0x03,
		     FlowCtrlWaterMark, 0x05,
		     MaxPktLen, ( ( QIB7322_RECV_HEADER_SIZE +
				    QIB7322_RECV_PAYLOAD_SIZE +
				    4 /* ICRC */ ) >> 2 ),
		     PhyerrThreshold, 0xf,
		     OverrunThreshold, 0xf );
	qib7322_writeq ( qib7322, &ibcctrla, QIB_7322_IBCCtrlA_0_offset );
	qib7322_writeq ( qib7322, &ibcctrla, QIB_7322_IBCCtrlA_1_offset );

	/* Force SDR only to avoid needing all the DDR tuning,
	 * Mellanox compatibility hacks etc.  SDR is plenty for
	 * boot-time operation.
	 */
	qib7322_readq ( qib7322, &ibcctrlb, QIB_7322_IBCCtrlB_0_offset );
	BIT_SET ( &ibcctrlb, IB_ENHANCED_MODE, 0 );
	BIT_SET ( &ibcctrlb, SD_SPEED_SDR, 1 );
	BIT_SET ( &ibcctrlb, SD_SPEED_DDR, 0 );
	BIT_SET ( &ibcctrlb, SD_SPEED_QDR, 0 );
	BIT_SET ( &ibcctrlb, IB_NUM_CHANNELS, 1 ); /* 4X only */
	BIT_SET ( &ibcctrlb, IB_LANE_REV_SUPPORTED, 0 );
	BIT_SET ( &ibcctrlb, HRTBT_ENB, 0 );
	BIT_SET ( &ibcctrlb, HRTBT_AUTO, 0 );
	qib7322_writeq ( qib7322, &ibcctrlb, QIB_7322_IBCCtrlB_0_offset );
	qib7322_writeq ( qib7322, &ibcctrlb, QIB_7322_IBCCtrlB_1_offset );

	/* Tune SerDes */
	qib7322_ahb_mod_reg_all ( qib7322, 2, 0, 0x00000e00UL );

	/* Bring XGXS out of reset */
	memset ( &ibpcsconfig, 0, sizeof ( ibpcsconfig ) );
	qib7322_writeq ( qib7322, &ibpcsconfig, QIB_7322_IBPCSConfig_0_offset );
	qib7322_writeq ( qib7322, &ibpcsconfig, QIB_7322_IBPCSConfig_1_offset );

	return 0;
}

/***************************************************************************
 *
 * PCI layer interface
 *
 ***************************************************************************
 */

/**
 * Reset QIB7322
 *
 * @v qib7322		QIB7322 device
 * @v pci		PCI device
 * @ret rc		Return status code
 */
static void qib7322_reset ( struct qib7322 *qib7322, struct pci_device *pci ) {
	struct QIB_7322_Control control;
	struct pci_config_backup backup;

	/* Back up PCI configuration space */
	pci_backup ( pci, &backup, NULL );

	/* Assert reset */
	memset ( &control, 0, sizeof ( control ) );
	BIT_FILL_1 ( &control, SyncReset, 1 );
	qib7322_writeq ( qib7322, &control, QIB_7322_Control_offset );

	/* Wait for reset to complete */
	mdelay ( 1000 );

	/* Restore PCI configuration space */
	pci_restore ( pci, &backup, NULL );
}

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @v id		PCI ID
 * @ret rc		Return status code
 */
static int qib7322_probe ( struct pci_device *pci ) {
	struct qib7322 *qib7322;
	struct QIB_7322_Revision revision;
	struct ib_device *ibdev;
	unsigned int link_speed_supported;
	int i;
	int rc;

	/* Allocate QIB7322 device */
	qib7322 = zalloc ( sizeof ( *qib7322 ) );
	if ( ! qib7322 ) {
		rc = -ENOMEM;
		goto err_alloc_qib7322;
	}
	pci_set_drvdata ( pci, qib7322 );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Get PCI BARs */
	qib7322->regs = ioremap ( pci->membase, QIB7322_BAR0_SIZE );
	DBGC2 ( qib7322, "QIB7322 %p has BAR at %08lx\n",
		qib7322, pci->membase );

	/* Reset device */
	qib7322_reset ( qib7322, pci );

	/* Print some general data */
	qib7322_readq ( qib7322, &revision, QIB_7322_Revision_offset );
	DBGC2 ( qib7322, "QIB7322 %p board %02lx v%ld.%ld.%ld.%ld\n", qib7322,
		BIT_GET ( &revision, BoardID ),
		BIT_GET ( &revision, R_SW ),
		BIT_GET ( &revision, R_Arch ),
		BIT_GET ( &revision, R_ChipRevMajor ),
		BIT_GET ( &revision, R_ChipRevMinor ) );

	/* Initialise I2C subsystem */
	if ( ( rc = qib7322_init_i2c ( qib7322 ) ) != 0 )
		goto err_init_i2c;

	/* Read EEPROM parameters */
	if ( ( rc = qib7322_read_eeprom ( qib7322 ) ) != 0 )
		goto err_read_eeprom;

	/* Initialise send datapath */
	if ( ( rc = qib7322_init_send ( qib7322 ) ) != 0 )
		goto err_init_send;

	/* Initialise receive datapath */
	if ( ( rc = qib7322_init_recv ( qib7322 ) ) != 0 )
		goto err_init_recv;

	/* Initialise the IB SerDes */
	if ( ( rc = qib7322_init_ib_serdes ( qib7322 ) ) != 0 )
		goto err_init_ib_serdes;

	/* Allocate Infiniband devices */
	for ( i = 0 ; i < QIB7322_MAX_PORTS ; i++ ) {
		link_speed_supported =
			qib7322_link_speed_supported ( qib7322, i );
		if ( ! link_speed_supported )
			continue;
		ibdev = alloc_ibdev ( 0 );
		if ( ! ibdev ) {
			rc = -ENOMEM;
			goto err_alloc_ibdev;
		}
		qib7322->ibdev[i] = ibdev;
		ibdev->dev = &pci->dev;
		ibdev->op = &qib7322_ib_operations;
		ibdev->port = ( QIB7322_PORT_BASE + i );
		ibdev->link_width_enabled = ibdev->link_width_supported =
			IB_LINK_WIDTH_4X; /* 1x does not work */
		ibdev->link_speed_enabled = ibdev->link_speed_supported =
			IB_LINK_SPEED_SDR; /* to avoid need for link tuning */
		memcpy ( &ibdev->node_guid, &qib7322->guid,
			 sizeof ( ibdev->node_guid ) );
		memcpy ( &ibdev->gid.s.guid, &qib7322->guid,
			 sizeof ( ibdev->gid.s.guid ) );
		assert ( ( ibdev->gid.s.guid.bytes[7] & i ) == 0 );
		ibdev->gid.s.guid.bytes[7] |= i;
		ib_set_drvdata ( ibdev, qib7322 );
	}

	/* Register Infiniband devices */
	for ( i = 0 ; i < QIB7322_MAX_PORTS ; i++ ) {
		if ( ! qib7322->ibdev[i] )
			continue;
		if ( ( rc = register_ibdev ( qib7322->ibdev[i] ) ) != 0 ) {
			DBGC ( qib7322, "QIB7322 %p port %d could not register "
			       "IB device: %s\n", qib7322, i, strerror ( rc ) );
			goto err_register_ibdev;
		}
	}

	return 0;

	i = QIB7322_MAX_PORTS;
 err_register_ibdev:
	for ( i-- ; i >= 0 ; i-- ) {
		if ( qib7322->ibdev[i] )
			unregister_ibdev ( qib7322->ibdev[i] );
	}
	i = QIB7322_MAX_PORTS;
 err_alloc_ibdev:
	for ( i-- ; i >= 0 ; i-- )
		ibdev_put ( qib7322->ibdev[i] );
 err_init_ib_serdes:
	qib7322_fini_send ( qib7322 );
 err_init_send:
	qib7322_fini_recv ( qib7322 );
 err_init_recv:
 err_read_eeprom:
 err_init_i2c:
	free ( qib7322 );
 err_alloc_qib7322:
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci		PCI device
 */
static void qib7322_remove ( struct pci_device *pci ) {
	struct qib7322 *qib7322 = pci_get_drvdata ( pci );
	int i;

	for ( i = ( QIB7322_MAX_PORTS - 1 ) ; i >= 0 ; i-- ) {
		if ( qib7322->ibdev[i] )
			unregister_ibdev ( qib7322->ibdev[i] );
	}
	for ( i = ( QIB7322_MAX_PORTS - 1 ) ; i >= 0 ; i-- )
		ibdev_put ( qib7322->ibdev[i] );
	qib7322_fini_send ( qib7322 );
	qib7322_fini_recv ( qib7322 );
	free ( qib7322 );
}

static struct pci_device_id qib7322_nics[] = {
	PCI_ROM ( 0x1077, 0x7322, "iba7322", "IBA7322 QDR InfiniBand HCA", 0 ),
};

struct pci_driver qib7322_driver __pci_driver = {
	.ids = qib7322_nics,
	.id_count = ( sizeof ( qib7322_nics ) / sizeof ( qib7322_nics[0] ) ),
	.probe = qib7322_probe,
	.remove = qib7322_remove,
};
