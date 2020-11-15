/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
 * Copyright (C) 2008 NetXen, Inc.
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
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/pci.h>
#include <ipxe/io.h>
#include <ipxe/malloc.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/spi.h>
#include <ipxe/settings.h>
#include "phantom.h"

/**
 * @file
 *
 * NetXen Phantom NICs
 *
 */

/** Maximum number of ports */
#define PHN_MAX_NUM_PORTS 8

/** Maximum time to wait for command PEG to initialise
 *
 * BUGxxxx
 *
 * The command PEG will currently report initialisation complete only
 * when at least one PHY has detected a link (so that the global PHY
 * clock can be set to 10G/1G as appropriate).  This can take a very,
 * very long time.
 *
 * A future firmware revision should decouple PHY initialisation from
 * firmware initialisation, at which point the command PEG will report
 * initialisation complete much earlier, and this timeout can be
 * reduced.
 */
#define PHN_CMDPEG_INIT_TIMEOUT_SEC 50

/** Maximum time to wait for receive PEG to initialise */
#define PHN_RCVPEG_INIT_TIMEOUT_SEC 2

/** Maximum time to wait for firmware to accept a command */
#define PHN_ISSUE_CMD_TIMEOUT_MS 2000

/** Maximum time to wait for test memory */
#define PHN_TEST_MEM_TIMEOUT_MS 100

/** Maximum time to wait for CLP command to be issued */
#define PHN_CLP_CMD_TIMEOUT_MS 500

/** Link state poll frequency
 *
 * The link state will be checked once in every N calls to poll().
 */
#define PHN_LINK_POLL_FREQUENCY 4096

/** Number of RX descriptors */
#define PHN_NUM_RDS 32

/** RX maximum fill level.  Must be strictly less than PHN_NUM_RDS. */
#define PHN_RDS_MAX_FILL 16

/** RX buffer size */
#define PHN_RX_BUFSIZE ( 32 /* max LL padding added by card */ + \
			 ETH_FRAME_LEN )

/** Number of RX status descriptors */
#define PHN_NUM_SDS 32

/** Number of TX descriptors */
#define PHN_NUM_CDS 8

/** A Phantom descriptor ring set */
struct phantom_descriptor_rings {
	/** RX descriptors */
	struct phantom_rds rds[PHN_NUM_RDS];
	/** RX status descriptors */
	struct phantom_sds sds[PHN_NUM_SDS];
	/** TX descriptors */
	union phantom_cds cds[PHN_NUM_CDS];
	/** TX consumer index */
	volatile uint32_t cmd_cons;
};

/** RX context creation request and response buffers */
struct phantom_create_rx_ctx_rqrsp {
	struct {
		struct nx_hostrq_rx_ctx_s rx_ctx;
		struct nx_hostrq_rds_ring_s rds;
		struct nx_hostrq_sds_ring_s sds;
	} __unm_dma_aligned hostrq;
	struct {
		struct nx_cardrsp_rx_ctx_s rx_ctx;
		struct nx_cardrsp_rds_ring_s rds;
		struct nx_cardrsp_sds_ring_s sds;
	} __unm_dma_aligned cardrsp;
};

/** TX context creation request and response buffers */
struct phantom_create_tx_ctx_rqrsp {
	struct {
		struct nx_hostrq_tx_ctx_s tx_ctx;
	} __unm_dma_aligned hostrq;
	struct {
		struct nx_cardrsp_tx_ctx_s tx_ctx;
	} __unm_dma_aligned cardrsp;
};

/** A Phantom NIC */
struct phantom_nic {
	/** BAR 0 */
	void *bar0;
	/** Current CRB window */
	unsigned long crb_window;
	/** CRB window access method */
	unsigned long ( *crb_access ) ( struct phantom_nic *phantom,
					unsigned long reg );


	/** Port number */
	unsigned int port;


	/** RX context ID */
	uint16_t rx_context_id;
	/** RX descriptor producer CRB offset */
	unsigned long rds_producer_crb;
	/** RX status descriptor consumer CRB offset */
	unsigned long sds_consumer_crb;
	/** RX interrupt mask CRB offset */
	unsigned long sds_irq_mask_crb;
	/** RX interrupts enabled */
	unsigned int sds_irq_enabled;

	/** RX producer index */
	unsigned int rds_producer_idx;
	/** RX consumer index */
	unsigned int rds_consumer_idx;
	/** RX status consumer index */
	unsigned int sds_consumer_idx;
	/** RX I/O buffers */
	struct io_buffer *rds_iobuf[PHN_RDS_MAX_FILL];


	/** TX context ID */
	uint16_t tx_context_id;
	/** TX descriptor producer CRB offset */
	unsigned long cds_producer_crb;

	/** TX producer index */
	unsigned int cds_producer_idx;
	/** TX consumer index */
	unsigned int cds_consumer_idx;
	/** TX I/O buffers */
	struct io_buffer *cds_iobuf[PHN_NUM_CDS];


	/** Descriptor rings */
	struct phantom_descriptor_rings *desc;


	/** Last known link state */
	uint32_t link_state;
	/** Link state poll timer */
	unsigned long link_poll_timer;


	/** Non-volatile settings */
	struct settings settings;
};

/** Interrupt mask registers */
static const unsigned long phantom_irq_mask_reg[PHN_MAX_NUM_PORTS] = {
	UNM_PCIE_IRQ_MASK_F0,
	UNM_PCIE_IRQ_MASK_F1,
	UNM_PCIE_IRQ_MASK_F2,
	UNM_PCIE_IRQ_MASK_F3,
	UNM_PCIE_IRQ_MASK_F4,
	UNM_PCIE_IRQ_MASK_F5,
	UNM_PCIE_IRQ_MASK_F6,
	UNM_PCIE_IRQ_MASK_F7,
};

/** Interrupt status registers */
static const unsigned long phantom_irq_status_reg[PHN_MAX_NUM_PORTS] = {
	UNM_PCIE_IRQ_STATUS_F0,
	UNM_PCIE_IRQ_STATUS_F1,
	UNM_PCIE_IRQ_STATUS_F2,
	UNM_PCIE_IRQ_STATUS_F3,
	UNM_PCIE_IRQ_STATUS_F4,
	UNM_PCIE_IRQ_STATUS_F5,
	UNM_PCIE_IRQ_STATUS_F6,
	UNM_PCIE_IRQ_STATUS_F7,
};

/***************************************************************************
 *
 * CRB register access
 *
 */

/**
 * Prepare for access to CRB register via 128MB BAR
 *
 * @v phantom		Phantom NIC
 * @v reg		Register offset within abstract address space
 * @ret offset		Register offset within PCI BAR0
 */
static unsigned long phantom_crb_access_128m ( struct phantom_nic *phantom,
					       unsigned long reg ) {
	unsigned long offset = ( 0x6000000 + ( reg & 0x1ffffff ) );
	uint32_t window = ( reg & 0x2000000 );
	uint32_t verify_window;

	if ( phantom->crb_window != window ) {

		/* Write to the CRB window register */
		writel ( window, phantom->bar0 + UNM_128M_CRB_WINDOW );

		/* Ensure that the write has reached the card */
		verify_window = readl ( phantom->bar0 + UNM_128M_CRB_WINDOW );
		assert ( verify_window == window );

		/* Record new window */
		phantom->crb_window = window;
	}

	return offset;
}

/**
 * Prepare for access to CRB register via 32MB BAR
 *
 * @v phantom		Phantom NIC
 * @v reg		Register offset within abstract address space
 * @ret offset		Register offset within PCI BAR0
 */
static unsigned long phantom_crb_access_32m ( struct phantom_nic *phantom,
					      unsigned long reg ) {
	unsigned long offset = ( reg & 0x1ffffff );
	uint32_t window = ( reg & 0x2000000 );
	uint32_t verify_window;

	if ( phantom->crb_window != window ) {

		/* Write to the CRB window register */
		writel ( window, phantom->bar0 + UNM_32M_CRB_WINDOW );

		/* Ensure that the write has reached the card */
		verify_window = readl ( phantom->bar0 + UNM_32M_CRB_WINDOW );
		assert ( verify_window == window );

		/* Record new window */
		phantom->crb_window = window;
	}

	return offset;
}

/**
 * Prepare for access to CRB register via 2MB BAR
 *
 * @v phantom		Phantom NIC
 * @v reg		Register offset within abstract address space
 * @ret offset		Register offset within PCI BAR0
 */
static unsigned long phantom_crb_access_2m ( struct phantom_nic *phantom,
					     unsigned long reg ) {
	static const struct {
		uint8_t block;
		uint16_t window_hi;
	} reg_window_hi[] = {
		{ UNM_CRB_BLK_PCIE,	0x773 },
		{ UNM_CRB_BLK_CAM,	0x416 },
		{ UNM_CRB_BLK_ROMUSB,	0x421 },
		{ UNM_CRB_BLK_TEST,	0x295 },
		{ UNM_CRB_BLK_PEG_0,	0x340 },
		{ UNM_CRB_BLK_PEG_1,	0x341 },
		{ UNM_CRB_BLK_PEG_2,	0x342 },
		{ UNM_CRB_BLK_PEG_3,	0x343 },
		{ UNM_CRB_BLK_PEG_4,	0x34b },
	};
	unsigned int block = UNM_CRB_BLK ( reg );
	unsigned long offset = UNM_CRB_OFFSET ( reg );
	uint32_t window;
	uint32_t verify_window;
	unsigned int i;

	for ( i = 0 ; i < ( sizeof ( reg_window_hi ) /
			    sizeof ( reg_window_hi[0] ) ) ; i++ ) {

		if ( reg_window_hi[i].block != block )
			continue;

		window = ( ( reg_window_hi[i].window_hi << 20 ) |
			   ( offset & 0x000f0000 ) );

		if ( phantom->crb_window != window ) {

			/* Write to the CRB window register */
			writel ( window, phantom->bar0 + UNM_2M_CRB_WINDOW );

			/* Ensure that the write has reached the card */
			verify_window = readl ( phantom->bar0 +
						UNM_2M_CRB_WINDOW );
			assert ( verify_window == window );

			/* Record new window */
			phantom->crb_window = window;
		}

		return ( 0x1e0000 + ( offset & 0xffff ) );
	}

	assert ( 0 );
	return 0;
}

/**
 * Read from Phantom CRB register
 *
 * @v phantom		Phantom NIC
 * @v reg		Register offset within abstract address space
 * @ret	value		Register value
 */
static uint32_t phantom_readl ( struct phantom_nic *phantom,
				unsigned long reg ) {
	unsigned long offset;

	offset = phantom->crb_access ( phantom, reg );
	return readl ( phantom->bar0 + offset );
}

/**
 * Write to Phantom CRB register
 *
 * @v phantom		Phantom NIC
 * @v value		Register value
 * @v reg		Register offset within abstract address space
 */
static void phantom_writel ( struct phantom_nic *phantom, uint32_t value,
			     unsigned long reg ) {
	unsigned long offset;

	offset = phantom->crb_access ( phantom, reg );
	writel ( value, phantom->bar0 + offset );
}

/**
 * Write to Phantom CRB HI/LO register pair
 *
 * @v phantom		Phantom NIC
 * @v value		Register value
 * @v lo_offset		LO register offset within CRB
 * @v hi_offset		HI register offset within CRB
 */
static inline void phantom_write_hilo ( struct phantom_nic *phantom,
					uint64_t value,
					unsigned long lo_offset,
					unsigned long hi_offset ) {
	uint32_t lo = ( value & 0xffffffffUL );
	uint32_t hi = ( value >> 32 );

	phantom_writel ( phantom, lo, lo_offset );
	phantom_writel ( phantom, hi, hi_offset );
}

/***************************************************************************
 *
 * Firmware message buffer access (for debug)
 *
 */

/**
 * Read from Phantom test memory
 *
 * @v phantom		Phantom NIC
 * @v offset		Offset within test memory
 * @v buf		8-byte buffer to fill
 * @ret rc		Return status code
 */
static int phantom_read_test_mem_block ( struct phantom_nic *phantom,
					 unsigned long offset,
					 uint32_t buf[2] ) {
	unsigned int retries;
	uint32_t test_control;

	phantom_write_hilo ( phantom, offset, UNM_TEST_ADDR_LO,
			     UNM_TEST_ADDR_HI );
	phantom_writel ( phantom, UNM_TEST_CONTROL_ENABLE, UNM_TEST_CONTROL );
	phantom_writel ( phantom,
			 ( UNM_TEST_CONTROL_ENABLE | UNM_TEST_CONTROL_START ),
			 UNM_TEST_CONTROL );
	
	for ( retries = 0 ; retries < PHN_TEST_MEM_TIMEOUT_MS ; retries++ ) {
		test_control = phantom_readl ( phantom, UNM_TEST_CONTROL );
		if ( ( test_control & UNM_TEST_CONTROL_BUSY ) == 0 ) {
			buf[0] = phantom_readl ( phantom, UNM_TEST_RDDATA_LO );
			buf[1] = phantom_readl ( phantom, UNM_TEST_RDDATA_HI );
			return 0;
		}
		mdelay ( 1 );
	}

	DBGC ( phantom, "Phantom %p timed out waiting for test memory\n",
	       phantom );
	return -ETIMEDOUT;
}

/**
 * Read single byte from Phantom test memory
 *
 * @v phantom		Phantom NIC
 * @v offset		Offset within test memory
 * @ret byte		Byte read, or negative error
 */
static int phantom_read_test_mem ( struct phantom_nic *phantom,
				   unsigned long offset ) {
	static union {
		uint8_t bytes[8];
		uint32_t dwords[2];
	} cache;
	static unsigned long cache_offset = -1UL;
	unsigned long sub_offset;
	int rc;

	sub_offset = ( offset & ( sizeof ( cache ) - 1 ) );
	offset = ( offset & ~( sizeof ( cache ) - 1 ) );

	if ( cache_offset != offset ) {
		if ( ( rc = phantom_read_test_mem_block ( phantom, offset,
							  cache.dwords )) !=0 )
			return rc;
		cache_offset = offset;
	}

	return cache.bytes[sub_offset];
}

/**
 * Dump Phantom firmware dmesg log
 *
 * @v phantom		Phantom NIC
 * @v log		Log number
 * @v max_lines		Maximum number of lines to show, or -1 to show all
 * @ret rc		Return status code
 */
static int phantom_dmesg ( struct phantom_nic *phantom, unsigned int log,
			    unsigned int max_lines ) {
	uint32_t head;
	uint32_t tail;
	uint32_t sig;
	uint32_t offset;
	int byte;

	/* Optimise out for non-debug builds */
	if ( ! DBG_LOG )
		return 0;

	/* Locate log */
	head = phantom_readl ( phantom, UNM_CAM_RAM_DMESG_HEAD ( log ) );
	tail = phantom_readl ( phantom, UNM_CAM_RAM_DMESG_TAIL ( log ) );
	sig = phantom_readl ( phantom, UNM_CAM_RAM_DMESG_SIG ( log ) );
	DBGC ( phantom, "Phantom %p firmware dmesg buffer %d (%08x-%08x)\n",
	       phantom, log, head, tail );
	assert ( ( head & 0x07 ) == 0 );
	if ( sig != UNM_CAM_RAM_DMESG_SIG_MAGIC ) {
		DBGC ( phantom, "Warning: bad signature %08x (want %08lx)\n",
		       sig, UNM_CAM_RAM_DMESG_SIG_MAGIC );
	}

	/* Locate start of last (max_lines) lines */
	for ( offset = tail ; offset > head ; offset-- ) {
		if ( ( byte = phantom_read_test_mem ( phantom,
						      ( offset - 1 ) ) ) < 0 )
			return byte;
		if ( ( byte == '\n' ) && ( max_lines-- == 0 ) )
			break;
	}

	/* Print lines */
	for ( ; offset < tail ; offset++ ) {
		if ( ( byte = phantom_read_test_mem ( phantom, offset ) ) < 0 )
			return byte;
		DBG ( "%c", byte );
	}
	DBG ( "\n" );
	return 0;
}

/**
 * Dump Phantom firmware dmesg logs
 *
 * @v phantom		Phantom NIC
 * @v max_lines		Maximum number of lines to show, or -1 to show all
 */
static void __attribute__ (( unused ))
phantom_dmesg_all ( struct phantom_nic *phantom, unsigned int max_lines ) {
	unsigned int i;

	for ( i = 0 ; i < UNM_CAM_RAM_NUM_DMESG_BUFFERS ; i++ )
		phantom_dmesg ( phantom, i, max_lines );
}

/***************************************************************************
 *
 * Firmware interface
 *
 */

/**
 * Wait for firmware to accept command
 *
 * @v phantom		Phantom NIC
 * @ret rc		Return status code
 */
static int phantom_wait_for_cmd ( struct phantom_nic *phantom ) {
	unsigned int retries;
	uint32_t cdrp;

	for ( retries = 0 ; retries < PHN_ISSUE_CMD_TIMEOUT_MS ; retries++ ) {
		mdelay ( 1 );
		cdrp = phantom_readl ( phantom, UNM_NIC_REG_NX_CDRP );
		if ( NX_CDRP_IS_RSP ( cdrp ) ) {
			switch ( NX_CDRP_FORM_RSP ( cdrp ) ) {
			case NX_CDRP_RSP_OK:
				return 0;
			case NX_CDRP_RSP_FAIL:
				return -EIO;
			case NX_CDRP_RSP_TIMEOUT:
				return -ETIMEDOUT;
			default:
				return -EPROTO;
			}
		}
	}

	DBGC ( phantom, "Phantom %p timed out waiting for firmware to accept "
	       "command\n", phantom );
	return -ETIMEDOUT;
}

/**
 * Issue command to firmware
 *
 * @v phantom		Phantom NIC
 * @v command		Firmware command
 * @v arg1		Argument 1
 * @v arg2		Argument 2
 * @v arg3		Argument 3
 * @ret rc		Return status code
 */
static int phantom_issue_cmd ( struct phantom_nic *phantom,
			       uint32_t command, uint32_t arg1, uint32_t arg2,
			       uint32_t arg3 ) {
	uint32_t signature;
	int rc;

	/* Issue command */
	signature = NX_CDRP_SIGNATURE_MAKE ( phantom->port,
					     NXHAL_VERSION );
	DBGC2 ( phantom, "Phantom %p issuing command %08x (%08x, %08x, "
		"%08x)\n", phantom, command, arg1, arg2, arg3 );
	phantom_writel ( phantom, signature, UNM_NIC_REG_NX_SIGN );
	phantom_writel ( phantom, arg1, UNM_NIC_REG_NX_ARG1 );
	phantom_writel ( phantom, arg2, UNM_NIC_REG_NX_ARG2 );
	phantom_writel ( phantom, arg3, UNM_NIC_REG_NX_ARG3 );
	phantom_writel ( phantom, NX_CDRP_FORM_CMD ( command ),
			 UNM_NIC_REG_NX_CDRP );

	/* Wait for command to be accepted */
	if ( ( rc = phantom_wait_for_cmd ( phantom ) ) != 0 ) {
		DBGC ( phantom, "Phantom %p could not issue command: %s\n",
		       phantom, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Issue buffer-format command to firmware
 *
 * @v phantom		Phantom NIC
 * @v command		Firmware command
 * @v buffer		Buffer to pass to firmware
 * @v len		Length of buffer
 * @ret rc		Return status code
 */
static int phantom_issue_buf_cmd ( struct phantom_nic *phantom,
				   uint32_t command, void *buffer,
				   size_t len ) {
	uint64_t physaddr;

	physaddr = virt_to_bus ( buffer );
	return phantom_issue_cmd ( phantom, command, ( physaddr >> 32 ),
				   ( physaddr & 0xffffffffUL ), len );
}

/**
 * Create Phantom RX context
 *
 * @v phantom		Phantom NIC
 * @ret rc		Return status code
 */
static int phantom_create_rx_ctx ( struct phantom_nic *phantom ) {
	struct phantom_create_rx_ctx_rqrsp *buf;
	int rc;

	/* Allocate context creation buffer */
	buf = malloc_dma ( sizeof ( *buf ), UNM_DMA_BUFFER_ALIGN );
	if ( ! buf ) {
		rc = -ENOMEM;
		goto out;
	}
	memset ( buf, 0, sizeof ( *buf ) );
	
	/* Prepare request */
	buf->hostrq.rx_ctx.host_rsp_dma_addr =
		cpu_to_le64 ( virt_to_bus ( &buf->cardrsp ) );
	buf->hostrq.rx_ctx.capabilities[0] =
		cpu_to_le32 ( NX_CAP0_LEGACY_CONTEXT | NX_CAP0_LEGACY_MN );
	buf->hostrq.rx_ctx.host_int_crb_mode =
		cpu_to_le32 ( NX_HOST_INT_CRB_MODE_SHARED );
	buf->hostrq.rx_ctx.host_rds_crb_mode =
		cpu_to_le32 ( NX_HOST_RDS_CRB_MODE_UNIQUE );
	buf->hostrq.rx_ctx.rds_ring_offset = cpu_to_le32 ( 0 );
	buf->hostrq.rx_ctx.sds_ring_offset =
		cpu_to_le32 ( sizeof ( buf->hostrq.rds ) );
	buf->hostrq.rx_ctx.num_rds_rings = cpu_to_le16 ( 1 );
	buf->hostrq.rx_ctx.num_sds_rings = cpu_to_le16 ( 1 );
	buf->hostrq.rds.host_phys_addr =
		cpu_to_le64 ( virt_to_bus ( phantom->desc->rds ) );
	buf->hostrq.rds.buff_size = cpu_to_le64 ( PHN_RX_BUFSIZE );
	buf->hostrq.rds.ring_size = cpu_to_le32 ( PHN_NUM_RDS );
	buf->hostrq.rds.ring_kind = cpu_to_le32 ( NX_RDS_RING_TYPE_NORMAL );
	buf->hostrq.sds.host_phys_addr =
		cpu_to_le64 ( virt_to_bus ( phantom->desc->sds ) );
	buf->hostrq.sds.ring_size = cpu_to_le32 ( PHN_NUM_SDS );

	DBGC ( phantom, "Phantom %p creating RX context\n", phantom );
	DBGC2_HDA ( phantom, virt_to_bus ( &buf->hostrq ),
		    &buf->hostrq, sizeof ( buf->hostrq ) );

	/* Issue request */
	if ( ( rc = phantom_issue_buf_cmd ( phantom,
					    NX_CDRP_CMD_CREATE_RX_CTX,
					    &buf->hostrq,
					    sizeof ( buf->hostrq ) ) ) != 0 ) {
		DBGC ( phantom, "Phantom %p could not create RX context: "
		       "%s\n", phantom, strerror ( rc ) );
		DBGC ( phantom, "Request:\n" );
		DBGC_HDA ( phantom, virt_to_bus ( &buf->hostrq ),
			   &buf->hostrq, sizeof ( buf->hostrq ) );
		DBGC ( phantom, "Response:\n" );
		DBGC_HDA ( phantom, virt_to_bus ( &buf->cardrsp ),
			   &buf->cardrsp, sizeof ( buf->cardrsp ) );
		goto out;
	}

	/* Retrieve context parameters */
	phantom->rx_context_id =
		le16_to_cpu ( buf->cardrsp.rx_ctx.context_id );
	phantom->rds_producer_crb =
		( UNM_CAM_RAM +
		  le32_to_cpu ( buf->cardrsp.rds.host_producer_crb ) );
	phantom->sds_consumer_crb =
		( UNM_CAM_RAM +
		  le32_to_cpu ( buf->cardrsp.sds.host_consumer_crb ) );
	phantom->sds_irq_mask_crb =
		( UNM_CAM_RAM +
		  le32_to_cpu ( buf->cardrsp.sds.interrupt_crb ) );

	DBGC ( phantom, "Phantom %p created RX context (id %04x, port phys "
	       "%02x virt %02x)\n", phantom, phantom->rx_context_id,
	       buf->cardrsp.rx_ctx.phys_port, buf->cardrsp.rx_ctx.virt_port );
	DBGC2_HDA ( phantom, virt_to_bus ( &buf->cardrsp ),
		    &buf->cardrsp, sizeof ( buf->cardrsp ) );
	DBGC ( phantom, "Phantom %p RDS producer CRB is %08lx\n",
	       phantom, phantom->rds_producer_crb );
	DBGC ( phantom, "Phantom %p SDS consumer CRB is %08lx\n",
	       phantom, phantom->sds_consumer_crb );
	DBGC ( phantom, "Phantom %p SDS interrupt mask CRB is %08lx\n",
	       phantom, phantom->sds_irq_mask_crb );

 out:
	free_dma ( buf, sizeof ( *buf ) );
	return rc;
}

/**
 * Destroy Phantom RX context
 *
 * @v phantom		Phantom NIC
 * @ret rc		Return status code
 */
static void phantom_destroy_rx_ctx ( struct phantom_nic *phantom ) {
	int rc;
	
	DBGC ( phantom, "Phantom %p destroying RX context (id %04x)\n",
	       phantom, phantom->rx_context_id );

	/* Issue request */
	if ( ( rc = phantom_issue_cmd ( phantom,
					NX_CDRP_CMD_DESTROY_RX_CTX,
					phantom->rx_context_id,
					NX_DESTROY_CTX_RESET, 0 ) ) != 0 ) {
		DBGC ( phantom, "Phantom %p could not destroy RX context: "
		       "%s\n", phantom, strerror ( rc ) );
		/* We're probably screwed */
		return;
	}

	/* Clear context parameters */
	phantom->rx_context_id = 0;
	phantom->rds_producer_crb = 0;
	phantom->sds_consumer_crb = 0;

	/* Reset software counters */
	phantom->rds_producer_idx = 0;
	phantom->rds_consumer_idx = 0;
	phantom->sds_consumer_idx = 0;
}

/**
 * Create Phantom TX context
 *
 * @v phantom		Phantom NIC
 * @ret rc		Return status code
 */
static int phantom_create_tx_ctx ( struct phantom_nic *phantom ) {
	struct phantom_create_tx_ctx_rqrsp *buf;
	int rc;

	/* Allocate context creation buffer */
	buf = malloc_dma ( sizeof ( *buf ), UNM_DMA_BUFFER_ALIGN );
	if ( ! buf ) {
		rc = -ENOMEM;
		goto out;
	}
	memset ( buf, 0, sizeof ( *buf ) );

	/* Prepare request */
	buf->hostrq.tx_ctx.host_rsp_dma_addr =
		cpu_to_le64 ( virt_to_bus ( &buf->cardrsp ) );
	buf->hostrq.tx_ctx.cmd_cons_dma_addr =
		cpu_to_le64 ( virt_to_bus ( &phantom->desc->cmd_cons ) );
	buf->hostrq.tx_ctx.capabilities[0] =
		cpu_to_le32 ( NX_CAP0_LEGACY_CONTEXT | NX_CAP0_LEGACY_MN );
	buf->hostrq.tx_ctx.host_int_crb_mode =
		cpu_to_le32 ( NX_HOST_INT_CRB_MODE_SHARED );
	buf->hostrq.tx_ctx.cds_ring.host_phys_addr =
		cpu_to_le64 ( virt_to_bus ( phantom->desc->cds ) );
	buf->hostrq.tx_ctx.cds_ring.ring_size = cpu_to_le32 ( PHN_NUM_CDS );

	DBGC ( phantom, "Phantom %p creating TX context\n", phantom );
	DBGC2_HDA ( phantom, virt_to_bus ( &buf->hostrq ),
		    &buf->hostrq, sizeof ( buf->hostrq ) );

	/* Issue request */
	if ( ( rc = phantom_issue_buf_cmd ( phantom,
					    NX_CDRP_CMD_CREATE_TX_CTX,
					    &buf->hostrq,
					    sizeof ( buf->hostrq ) ) ) != 0 ) {
		DBGC ( phantom, "Phantom %p could not create TX context: "
		       "%s\n", phantom, strerror ( rc ) );
		DBGC ( phantom, "Request:\n" );
		DBGC_HDA ( phantom, virt_to_bus ( &buf->hostrq ),
			   &buf->hostrq, sizeof ( buf->hostrq ) );
		DBGC ( phantom, "Response:\n" );
		DBGC_HDA ( phantom, virt_to_bus ( &buf->cardrsp ),
			   &buf->cardrsp, sizeof ( buf->cardrsp ) );
		goto out;
	}

	/* Retrieve context parameters */
	phantom->tx_context_id =
		le16_to_cpu ( buf->cardrsp.tx_ctx.context_id );
	phantom->cds_producer_crb =
		( UNM_CAM_RAM +
		  le32_to_cpu(buf->cardrsp.tx_ctx.cds_ring.host_producer_crb));

	DBGC ( phantom, "Phantom %p created TX context (id %04x, port phys "
	       "%02x virt %02x)\n", phantom, phantom->tx_context_id,
	       buf->cardrsp.tx_ctx.phys_port, buf->cardrsp.tx_ctx.virt_port );
	DBGC2_HDA ( phantom, virt_to_bus ( &buf->cardrsp ),
		    &buf->cardrsp, sizeof ( buf->cardrsp ) );
	DBGC ( phantom, "Phantom %p CDS producer CRB is %08lx\n",
	       phantom, phantom->cds_producer_crb );

 out:
	free_dma ( buf, sizeof ( *buf ) );
	return rc;
}

/**
 * Destroy Phantom TX context
 *
 * @v phantom		Phantom NIC
 * @ret rc		Return status code
 */
static void phantom_destroy_tx_ctx ( struct phantom_nic *phantom ) {
	int rc;
	
	DBGC ( phantom, "Phantom %p destroying TX context (id %04x)\n",
	       phantom, phantom->tx_context_id );

	/* Issue request */
	if ( ( rc = phantom_issue_cmd ( phantom,
					NX_CDRP_CMD_DESTROY_TX_CTX,
					phantom->tx_context_id,
					NX_DESTROY_CTX_RESET, 0 ) ) != 0 ) {
		DBGC ( phantom, "Phantom %p could not destroy TX context: "
		       "%s\n", phantom, strerror ( rc ) );
		/* We're probably screwed */
		return;
	}

	/* Clear context parameters */
	phantom->tx_context_id = 0;
	phantom->cds_producer_crb = 0;

	/* Reset software counters */
	phantom->cds_producer_idx = 0;
	phantom->cds_consumer_idx = 0;
}

/***************************************************************************
 *
 * Descriptor ring management
 *
 */

/**
 * Allocate Phantom RX descriptor
 *
 * @v phantom		Phantom NIC
 * @ret index		RX descriptor index, or negative error
 */
static int phantom_alloc_rds ( struct phantom_nic *phantom ) {
	unsigned int rds_producer_idx;
	unsigned int next_rds_producer_idx;

	/* Check for space in the ring.  RX descriptors are consumed
	 * out of order, but they are *read* by the hardware in strict
	 * order.  We maintain a pessimistic consumer index, which is
	 * guaranteed never to be an overestimate of the number of
	 * descriptors read by the hardware.
	 */
	rds_producer_idx = phantom->rds_producer_idx;
	next_rds_producer_idx = ( ( rds_producer_idx + 1 ) % PHN_NUM_RDS );
	if ( next_rds_producer_idx == phantom->rds_consumer_idx ) {
		DBGC ( phantom, "Phantom %p RDS ring full (index %d not "
		       "consumed)\n", phantom, next_rds_producer_idx );
		return -ENOBUFS;
	}

	return rds_producer_idx;
}

/**
 * Post Phantom RX descriptor
 *
 * @v phantom		Phantom NIC
 * @v rds		RX descriptor
 */
static void phantom_post_rds ( struct phantom_nic *phantom,
			       struct phantom_rds *rds ) {
	unsigned int rds_producer_idx;
	unsigned int next_rds_producer_idx;
	struct phantom_rds *entry;

	/* Copy descriptor to ring */
	rds_producer_idx = phantom->rds_producer_idx;
	entry = &phantom->desc->rds[rds_producer_idx];
	memcpy ( entry, rds, sizeof ( *entry ) );
	DBGC2 ( phantom, "Phantom %p posting RDS %ld (slot %d):\n",
		phantom, NX_GET ( rds, handle ), rds_producer_idx );
	DBGC2_HDA ( phantom, virt_to_bus ( entry ), entry, sizeof ( *entry ) );

	/* Update producer index */
	next_rds_producer_idx = ( ( rds_producer_idx + 1 ) % PHN_NUM_RDS );
	phantom->rds_producer_idx = next_rds_producer_idx;
	wmb();
	phantom_writel ( phantom, phantom->rds_producer_idx,
			 phantom->rds_producer_crb );
}

/**
 * Allocate Phantom TX descriptor
 *
 * @v phantom		Phantom NIC
 * @ret index		TX descriptor index, or negative error
 */
static int phantom_alloc_cds ( struct phantom_nic *phantom ) {
	unsigned int cds_producer_idx;
	unsigned int next_cds_producer_idx;

	/* Check for space in the ring.  TX descriptors are consumed
	 * in strict order, so we just check for a collision against
	 * the consumer index.
	 */
	cds_producer_idx = phantom->cds_producer_idx;
	next_cds_producer_idx = ( ( cds_producer_idx + 1 ) % PHN_NUM_CDS );
	if ( next_cds_producer_idx == phantom->cds_consumer_idx ) {
		DBGC ( phantom, "Phantom %p CDS ring full (index %d not "
		       "consumed)\n", phantom, next_cds_producer_idx );
		return -ENOBUFS;
	}

	return cds_producer_idx;
}

/**
 * Post Phantom TX descriptor
 *
 * @v phantom		Phantom NIC
 * @v cds		TX descriptor
 */
static void phantom_post_cds ( struct phantom_nic *phantom,
			       union phantom_cds *cds ) {
	unsigned int cds_producer_idx;
	unsigned int next_cds_producer_idx;
	union phantom_cds *entry;

	/* Copy descriptor to ring */
	cds_producer_idx = phantom->cds_producer_idx;
	entry = &phantom->desc->cds[cds_producer_idx];
	memcpy ( entry, cds, sizeof ( *entry ) );
	DBGC2 ( phantom, "Phantom %p posting CDS %d:\n",
		phantom, cds_producer_idx );
	DBGC2_HDA ( phantom, virt_to_bus ( entry ), entry, sizeof ( *entry ) );

	/* Update producer index */
	next_cds_producer_idx = ( ( cds_producer_idx + 1 ) % PHN_NUM_CDS );
	phantom->cds_producer_idx = next_cds_producer_idx;
	wmb();
	phantom_writel ( phantom, phantom->cds_producer_idx,
			 phantom->cds_producer_crb );
}

/***************************************************************************
 *
 * MAC address management
 *
 */

/**
 * Add/remove MAC address
 *
 * @v phantom		Phantom NIC
 * @v ll_addr		MAC address to add or remove
 * @v opcode		MAC request opcode
 * @ret rc		Return status code
 */
static int phantom_update_macaddr ( struct phantom_nic *phantom,
				    const uint8_t *ll_addr,
				    unsigned int opcode ) {
	union phantom_cds cds;
	int index;

	/* Get descriptor ring entry */
	index = phantom_alloc_cds ( phantom );
	if ( index < 0 )
		return index;

	/* Fill descriptor ring entry */
	memset ( &cds, 0, sizeof ( cds ) );
	NX_FILL_1 ( &cds, 0,
		    nic_request.common.opcode, UNM_NIC_REQUEST );
	NX_FILL_2 ( &cds, 1,
		    nic_request.header.opcode, UNM_MAC_EVENT,
		    nic_request.header.context_id, phantom->port );
	NX_FILL_7 ( &cds, 2,
		    nic_request.body.mac_request.opcode, opcode,
		    nic_request.body.mac_request.mac_addr_0, ll_addr[0],
		    nic_request.body.mac_request.mac_addr_1, ll_addr[1],
		    nic_request.body.mac_request.mac_addr_2, ll_addr[2],
		    nic_request.body.mac_request.mac_addr_3, ll_addr[3],
		    nic_request.body.mac_request.mac_addr_4, ll_addr[4],
		    nic_request.body.mac_request.mac_addr_5, ll_addr[5] );

	/* Post descriptor */
	phantom_post_cds ( phantom, &cds );

	return 0;
}

/**
 * Add MAC address
 *
 * @v phantom		Phantom NIC
 * @v ll_addr		MAC address to add or remove
 * @ret rc		Return status code
 */
static inline int phantom_add_macaddr ( struct phantom_nic *phantom,
					const uint8_t *ll_addr ) {

	DBGC ( phantom, "Phantom %p adding MAC address %s\n",
	       phantom, eth_ntoa ( ll_addr ) );

	return phantom_update_macaddr ( phantom, ll_addr, UNM_MAC_ADD );
}

/**
 * Remove MAC address
 *
 * @v phantom		Phantom NIC
 * @v ll_addr		MAC address to add or remove
 * @ret rc		Return status code
 */
static inline int phantom_del_macaddr ( struct phantom_nic *phantom,
					const uint8_t *ll_addr ) {

	DBGC ( phantom, "Phantom %p removing MAC address %s\n",
	       phantom, eth_ntoa ( ll_addr ) );

	return phantom_update_macaddr ( phantom, ll_addr, UNM_MAC_DEL );
}

/***************************************************************************
 *
 * Link state detection
 *
 */

/**
 * Poll link state
 *
 * @v netdev		Network device
 */
static void phantom_poll_link_state ( struct net_device *netdev ) {
	struct phantom_nic *phantom = netdev_priv ( netdev );
	uint32_t xg_state_p3;
	unsigned int link;

	/* Read link state */
	xg_state_p3 = phantom_readl ( phantom, UNM_NIC_REG_XG_STATE_P3 );

	/* If there is no change, do nothing */
	if ( phantom->link_state == xg_state_p3 )
		return;

	/* Record new link state */
	DBGC ( phantom, "Phantom %p new link state %08x (was %08x)\n",
	       phantom, xg_state_p3, phantom->link_state );
	phantom->link_state = xg_state_p3;

	/* Indicate link state to iPXE */
	link = UNM_NIC_REG_XG_STATE_P3_LINK ( phantom->port,
					      phantom->link_state );
	switch ( link ) {
	case UNM_NIC_REG_XG_STATE_P3_LINK_UP:
		DBGC ( phantom, "Phantom %p link is up\n", phantom );
		netdev_link_up ( netdev );
		break;
	case UNM_NIC_REG_XG_STATE_P3_LINK_DOWN:
		DBGC ( phantom, "Phantom %p link is down\n", phantom );
		netdev_link_down ( netdev );
		break;
	default:
		DBGC ( phantom, "Phantom %p bad link state %d\n",
		       phantom, link );
		break;
	}
}

/***************************************************************************
 *
 * Main driver body
 *
 */

/**
 * Refill descriptor ring
 *
 * @v netdev		Net device
 */
static void phantom_refill_rx_ring ( struct net_device *netdev ) {
	struct phantom_nic *phantom = netdev_priv ( netdev );
	struct io_buffer *iobuf;
	struct phantom_rds rds;
	unsigned int handle;
	int index;

	for ( handle = 0 ; handle < PHN_RDS_MAX_FILL ; handle++ ) {

		/* Skip this index if the descriptor has not yet been
		 * consumed.
		 */
		if ( phantom->rds_iobuf[handle] != NULL )
			continue;

		/* Allocate descriptor ring entry */
		index = phantom_alloc_rds ( phantom );
		assert ( PHN_RDS_MAX_FILL < PHN_NUM_RDS );
		assert ( index >= 0 ); /* Guaranteed by MAX_FILL < NUM_RDS ) */

		/* Try to allocate an I/O buffer */
		iobuf = alloc_iob ( PHN_RX_BUFSIZE );
		if ( ! iobuf ) {
			/* Failure is non-fatal; we will retry later */
			netdev_rx_err ( netdev, NULL, -ENOMEM );
			break;
		}

		/* Fill descriptor ring entry */
		memset ( &rds, 0, sizeof ( rds ) );
		NX_FILL_2 ( &rds, 0,
			    handle, handle,
			    length, iob_len ( iobuf ) );
		NX_FILL_1 ( &rds, 1,
			    dma_addr, virt_to_bus ( iobuf->data ) );

		/* Record I/O buffer */
		assert ( phantom->rds_iobuf[handle] == NULL );
		phantom->rds_iobuf[handle] = iobuf;

		/* Post descriptor */
		phantom_post_rds ( phantom, &rds );
	}
}

/**
 * Open NIC
 *
 * @v netdev		Net device
 * @ret rc		Return status code
 */
static int phantom_open ( struct net_device *netdev ) {
	struct phantom_nic *phantom = netdev_priv ( netdev );
	int rc;

	/* Allocate and zero descriptor rings */
	phantom->desc = malloc_dma ( sizeof ( *(phantom->desc) ),
					  UNM_DMA_BUFFER_ALIGN );
	if ( ! phantom->desc ) {
		rc = -ENOMEM;
		goto err_alloc_desc;
	}
	memset ( phantom->desc, 0, sizeof ( *(phantom->desc) ) );

	/* Create RX context */
	if ( ( rc = phantom_create_rx_ctx ( phantom ) ) != 0 )
		goto err_create_rx_ctx;

	/* Create TX context */
	if ( ( rc = phantom_create_tx_ctx ( phantom ) ) != 0 )
		goto err_create_tx_ctx;

	/* Fill the RX descriptor ring */
	phantom_refill_rx_ring ( netdev );

	/* Add MAC addresses
	 *
	 * BUG5583
	 *
	 * We would like to be able to enable receiving all multicast
	 * packets (or, failing that, promiscuous mode), but the
	 * firmware doesn't currently support this.
	 */
	if ( ( rc = phantom_add_macaddr ( phantom,
					  netdev->ll_broadcast ) ) != 0 )
		goto err_add_macaddr_broadcast;
	if ( ( rc = phantom_add_macaddr ( phantom,
					  netdev->ll_addr ) ) != 0 )
		goto err_add_macaddr_unicast;

	return 0;

	phantom_del_macaddr ( phantom, netdev->ll_addr );
 err_add_macaddr_unicast:
	phantom_del_macaddr ( phantom, netdev->ll_broadcast );
 err_add_macaddr_broadcast:
	phantom_destroy_tx_ctx ( phantom );
 err_create_tx_ctx:
	phantom_destroy_rx_ctx ( phantom );
 err_create_rx_ctx:
	free_dma ( phantom->desc, sizeof ( *(phantom->desc) ) );
	phantom->desc = NULL;
 err_alloc_desc:
	return rc;
}

/**
 * Close NIC
 *
 * @v netdev		Net device
 */
static void phantom_close ( struct net_device *netdev ) {
	struct phantom_nic *phantom = netdev_priv ( netdev );
	struct io_buffer *iobuf;
	unsigned int i;

	/* Shut down the port */
	phantom_del_macaddr ( phantom, netdev->ll_addr );
	phantom_del_macaddr ( phantom, netdev->ll_broadcast );
	phantom_destroy_tx_ctx ( phantom );
	phantom_destroy_rx_ctx ( phantom );
	free_dma ( phantom->desc, sizeof ( *(phantom->desc) ) );
	phantom->desc = NULL;

	/* Flush any uncompleted descriptors */
	for ( i = 0 ; i < PHN_RDS_MAX_FILL ; i++ ) {
		iobuf = phantom->rds_iobuf[i];
		if ( iobuf ) {
			free_iob ( iobuf );
			phantom->rds_iobuf[i] = NULL;
		}
	}
	for ( i = 0 ; i < PHN_NUM_CDS ; i++ ) {
		iobuf = phantom->cds_iobuf[i];
		if ( iobuf ) {
			netdev_tx_complete_err ( netdev, iobuf, -ECANCELED );
			phantom->cds_iobuf[i] = NULL;
		}
	}
}

/** 
 * Transmit packet
 *
 * @v netdev	Network device
 * @v iobuf	I/O buffer
 * @ret rc	Return status code
 */
static int phantom_transmit ( struct net_device *netdev,
			      struct io_buffer *iobuf ) {
	struct phantom_nic *phantom = netdev_priv ( netdev );
	union phantom_cds cds;
	int index;

	/* Get descriptor ring entry */
	index = phantom_alloc_cds ( phantom );
	if ( index < 0 )
		return index;

	/* Fill descriptor ring entry */
	memset ( &cds, 0, sizeof ( cds ) );
	NX_FILL_3 ( &cds, 0,
		    tx.opcode, UNM_TX_ETHER_PKT,
		    tx.num_buffers, 1,
		    tx.length, iob_len ( iobuf ) );
	NX_FILL_2 ( &cds, 2,
		    tx.port, phantom->port,
		    tx.context_id, phantom->port );
	NX_FILL_1 ( &cds, 4,
		    tx.buffer1_dma_addr, virt_to_bus ( iobuf->data ) );
	NX_FILL_1 ( &cds, 5,
		    tx.buffer1_length, iob_len ( iobuf ) );

	/* Record I/O buffer */
	assert ( phantom->cds_iobuf[index] == NULL );
	phantom->cds_iobuf[index] = iobuf;

	/* Post descriptor */
	phantom_post_cds ( phantom, &cds );

	return 0;
}

/**
 * Poll for received packets
 *
 * @v netdev	Network device
 */
static void phantom_poll ( struct net_device *netdev ) {
	struct phantom_nic *phantom = netdev_priv ( netdev );
	struct io_buffer *iobuf;
	unsigned int irq_vector;
	unsigned int irq_state;
	unsigned int cds_consumer_idx;
	unsigned int raw_new_cds_consumer_idx;
	unsigned int new_cds_consumer_idx;
	unsigned int rds_consumer_idx;
	unsigned int sds_consumer_idx;
	struct phantom_sds *sds;
	unsigned int sds_handle;
	unsigned int sds_opcode;

	/* Occasionally poll the link state */
	if ( phantom->link_poll_timer-- == 0 ) {
		phantom_poll_link_state ( netdev );
		/* Reset the link poll timer */
		phantom->link_poll_timer = PHN_LINK_POLL_FREQUENCY;
	}

	/* Check for interrupts */
	if ( phantom->sds_irq_enabled ) {

		/* Do nothing unless an interrupt is asserted */
		irq_vector = phantom_readl ( phantom, UNM_PCIE_IRQ_VECTOR );
		if ( ! ( irq_vector & UNM_PCIE_IRQ_VECTOR_BIT( phantom->port )))
			return;

		/* Do nothing unless interrupt state machine has stabilised */
		irq_state = phantom_readl ( phantom, UNM_PCIE_IRQ_STATE );
		if ( ! UNM_PCIE_IRQ_STATE_TRIGGERED ( irq_state ) )
			return;

		/* Acknowledge interrupt */
		phantom_writel ( phantom, UNM_PCIE_IRQ_STATUS_MAGIC,
				 phantom_irq_status_reg[phantom->port] );
		phantom_readl ( phantom, UNM_PCIE_IRQ_VECTOR );
	}

	/* Check for TX completions */
	cds_consumer_idx = phantom->cds_consumer_idx;
	raw_new_cds_consumer_idx = phantom->desc->cmd_cons;
	new_cds_consumer_idx = le32_to_cpu ( raw_new_cds_consumer_idx );
	while ( cds_consumer_idx != new_cds_consumer_idx ) {
		DBGC2 ( phantom, "Phantom %p CDS %d complete\n",
			phantom, cds_consumer_idx );
		/* Completions may be for commands other than TX, so
		 * there may not always be an associated I/O buffer.
		 */
		if ( ( iobuf = phantom->cds_iobuf[cds_consumer_idx] ) ) {
			netdev_tx_complete ( netdev, iobuf );
			phantom->cds_iobuf[cds_consumer_idx] = NULL;
		}
		cds_consumer_idx = ( ( cds_consumer_idx + 1 ) % PHN_NUM_CDS );
		phantom->cds_consumer_idx = cds_consumer_idx;
	}

	/* Check for received packets */
	rds_consumer_idx = phantom->rds_consumer_idx;
	sds_consumer_idx = phantom->sds_consumer_idx;
	while ( 1 ) {
		sds = &phantom->desc->sds[sds_consumer_idx];
		if ( NX_GET ( sds, owner ) == 0 )
			break;

		DBGC2 ( phantom, "Phantom %p SDS %d status:\n",
			phantom, sds_consumer_idx );
		DBGC2_HDA ( phantom, virt_to_bus ( sds ), sds, sizeof (*sds) );

		/* Check received opcode */
		sds_opcode = NX_GET ( sds, opcode );
		if ( ( sds_opcode == UNM_RXPKT_DESC ) ||
		     ( sds_opcode == UNM_SYN_OFFLOAD ) ) {

			/* Sanity check: ensure that all of the SDS
			 * descriptor has been written.
			 */
			if ( NX_GET ( sds, total_length ) == 0 ) {
				DBGC ( phantom, "Phantom %p SDS %d "
				       "incomplete; deferring\n",
				       phantom, sds_consumer_idx );
				/* Leave for next poll() */
				break;
			}

			/* Process received packet */
			sds_handle = NX_GET ( sds, handle );
			iobuf = phantom->rds_iobuf[sds_handle];
			assert ( iobuf != NULL );
			iob_put ( iobuf, NX_GET ( sds, total_length ) );
			iob_pull ( iobuf, NX_GET ( sds, pkt_offset ) );
			DBGC2 ( phantom, "Phantom %p RDS %d complete\n",
				phantom, sds_handle );
			netdev_rx ( netdev, iobuf );
			phantom->rds_iobuf[sds_handle] = NULL;

			/* Update RDS consumer counter.  This is a
			 * lower bound for the number of descriptors
			 * that have been read by the hardware, since
			 * the hardware must have read at least one
			 * descriptor for each completion that we
			 * receive.
			 */
			rds_consumer_idx =
				( ( rds_consumer_idx + 1 ) % PHN_NUM_RDS );
			phantom->rds_consumer_idx = rds_consumer_idx;

		} else {

			DBGC ( phantom, "Phantom %p unexpected SDS opcode "
			       "%02x\n", phantom, sds_opcode );
			DBGC_HDA ( phantom, virt_to_bus ( sds ),
				   sds, sizeof ( *sds ) );
		}
			
		/* Clear status descriptor */
		memset ( sds, 0, sizeof ( *sds ) );

		/* Update SDS consumer index */
		sds_consumer_idx = ( ( sds_consumer_idx + 1 ) % PHN_NUM_SDS );
		phantom->sds_consumer_idx = sds_consumer_idx;
		wmb();
		phantom_writel ( phantom, phantom->sds_consumer_idx,
				 phantom->sds_consumer_crb );
	}

	/* Refill the RX descriptor ring */
	phantom_refill_rx_ring ( netdev );
}

/**
 * Enable/disable interrupts
 *
 * @v netdev	Network device
 * @v enable	Interrupts should be enabled
 */
static void phantom_irq ( struct net_device *netdev, int enable ) {
	struct phantom_nic *phantom = netdev_priv ( netdev );

	phantom_writel ( phantom, ( enable ? 1 : 0 ),
			 phantom->sds_irq_mask_crb );
	phantom_writel ( phantom, UNM_PCIE_IRQ_MASK_MAGIC,
			 phantom_irq_mask_reg[phantom->port] );
	phantom->sds_irq_enabled = enable;
}

/** Phantom net device operations */
static struct net_device_operations phantom_operations = {
	.open		= phantom_open,
	.close		= phantom_close,
	.transmit	= phantom_transmit,
	.poll		= phantom_poll,
	.irq		= phantom_irq,
};

/***************************************************************************
 *
 * CLP settings
 *
 */

/** Phantom CLP settings scope */
static const struct settings_scope phantom_settings_scope;

/** Phantom CLP data
 *
 */
union phantom_clp_data {
	/** Data bytes
	 *
	 * This field is right-aligned; if only N bytes are present
	 * then bytes[0]..bytes[7-N] should be zero, and the data
	 * should be in bytes[7-N+1] to bytes[7];
	 */
	uint8_t bytes[8];
	/** Dwords for the CLP interface */
	struct {
		/** High dword, in network byte order */
		uint32_t hi;
		/** Low dword, in network byte order */
		uint32_t lo;
	} dwords;
};
#define PHN_CLP_BLKSIZE ( sizeof ( union phantom_clp_data ) )

/**
 * Wait for Phantom CLP command to complete
 *
 * @v phantom		Phantom NIC
 * @ret rc		Return status code
 */
static int phantom_clp_wait ( struct phantom_nic *phantom ) {
	unsigned int retries;
	uint32_t status;

	for ( retries = 0 ; retries < PHN_CLP_CMD_TIMEOUT_MS ; retries++ ) {
		status = phantom_readl ( phantom, UNM_CAM_RAM_CLP_STATUS );
		if ( status & UNM_CAM_RAM_CLP_STATUS_DONE )
			return 0;
		mdelay ( 1 );
	}

	DBGC ( phantom, "Phantom %p timed out waiting for CLP command\n",
	       phantom );
	return -ETIMEDOUT;
}

/**
 * Issue Phantom CLP command
 *
 * @v phantom		Phantom NIC
 * @v port		Virtual port number
 * @v opcode		Opcode
 * @v data_in		Data in, or NULL
 * @v data_out		Data out, or NULL
 * @v offset		Offset within data
 * @v len		Data buffer length
 * @ret len		Total transfer length (for reads), or negative error
 */
static int phantom_clp_cmd ( struct phantom_nic *phantom, unsigned int port,
			     unsigned int opcode, const void *data_in,
			     void *data_out, size_t offset, size_t len ) {
	union phantom_clp_data data;
	unsigned int index = ( offset / sizeof ( data ) );
	unsigned int last = 0;
	size_t in_frag_len;
	uint8_t *in_frag;
	uint32_t command;
	uint32_t status;
	size_t read_len;
	unsigned int error;
	size_t out_frag_len;
	uint8_t *out_frag;
	int rc;

	/* Sanity checks */
	assert ( ( offset % sizeof ( data ) ) == 0 );
	if ( len > 255 ) {
		DBGC ( phantom, "Phantom %p invalid CLP length %zd\n",
		       phantom, len );
		return -EINVAL;
	}

	/* Check that CLP interface is ready */
	if ( ( rc = phantom_clp_wait ( phantom ) ) != 0 )
		return rc;

	/* Copy data in */
	memset ( &data, 0, sizeof ( data ) );
	if ( data_in ) {
		assert ( offset < len );
		in_frag_len = ( len - offset );
		if ( in_frag_len > sizeof ( data ) ) {
			in_frag_len = sizeof ( data );
		} else {
			last = 1;
		}
		in_frag = &data.bytes[ sizeof ( data ) - in_frag_len ];
		memcpy ( in_frag, ( data_in + offset ), in_frag_len );
		phantom_writel ( phantom, be32_to_cpu ( data.dwords.lo ),
				 UNM_CAM_RAM_CLP_DATA_LO );
		phantom_writel ( phantom, be32_to_cpu ( data.dwords.hi ),
				 UNM_CAM_RAM_CLP_DATA_HI );
	}

	/* Issue CLP command */
	command = ( ( index << 24 ) | ( ( data_in ? len : 0 ) << 16 ) |
		    ( port << 8 ) | ( last << 7 ) | ( opcode << 0 ) );
	phantom_writel ( phantom, command, UNM_CAM_RAM_CLP_COMMAND );
	mb();
	phantom_writel ( phantom, UNM_CAM_RAM_CLP_STATUS_START,
			 UNM_CAM_RAM_CLP_STATUS );

	/* Wait for command to complete */
	if ( ( rc = phantom_clp_wait ( phantom ) ) != 0 )
		return rc;

	/* Get command status */
	status = phantom_readl ( phantom, UNM_CAM_RAM_CLP_STATUS );
	read_len = ( ( status >> 16 ) & 0xff );
	error = ( ( status >> 8 ) & 0xff );
	if ( error ) {
		DBGC ( phantom, "Phantom %p CLP command error %02x\n",
		       phantom, error );
		return -EIO;
	}

	/* Copy data out */
	if ( data_out ) {
		data.dwords.lo = cpu_to_be32 ( phantom_readl ( phantom,
						  UNM_CAM_RAM_CLP_DATA_LO ) );
		data.dwords.hi = cpu_to_be32 ( phantom_readl ( phantom,
						  UNM_CAM_RAM_CLP_DATA_HI ) );
		out_frag_len = ( read_len - offset );
		if ( out_frag_len > sizeof ( data ) )
			out_frag_len = sizeof ( data );
		out_frag = &data.bytes[ sizeof ( data ) - out_frag_len ];
		if ( out_frag_len > ( len - offset ) )
			out_frag_len = ( len - offset );
		memcpy ( ( data_out + offset ), out_frag, out_frag_len );
	}

	return read_len;
}

/**
 * Store Phantom CLP setting
 *
 * @v phantom		Phantom NIC
 * @v port		Virtual port number
 * @v setting		Setting number
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int phantom_clp_store ( struct phantom_nic *phantom, unsigned int port,
			       unsigned int setting, const void *data,
			       size_t len ) {
	unsigned int opcode = setting;
	size_t offset;
	int rc;

	for ( offset = 0 ; offset < len ; offset += PHN_CLP_BLKSIZE ) {
		if ( ( rc = phantom_clp_cmd ( phantom, port, opcode, data,
					      NULL, offset, len ) ) < 0 )
			return rc;
	}
	return 0;
}

/**
 * Fetch Phantom CLP setting
 *
 * @v phantom		Phantom NIC
 * @v port		Virtual port number
 * @v setting		Setting number
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret len		Length of setting, or negative error
 */
static int phantom_clp_fetch ( struct phantom_nic *phantom, unsigned int port,
			       unsigned int setting, void *data, size_t len ) {
	unsigned int opcode = ( setting + 1 );
	size_t offset = 0;
	int read_len;

	while ( 1 ) {
		read_len = phantom_clp_cmd ( phantom, port, opcode, NULL,
					     data, offset, len );
		if ( read_len < 0 )
			return read_len;
		offset += PHN_CLP_BLKSIZE;
		if ( offset >= ( unsigned ) read_len )
			break;
		if ( offset >= len )
			break;
	}
	return read_len;
}

/** A Phantom CLP setting */
struct phantom_clp_setting {
	/** iPXE setting */
	const struct setting *setting;
	/** Setting number */
	unsigned int clp_setting;
};

/** Phantom CLP settings */
static struct phantom_clp_setting clp_settings[] = {
	{ &mac_setting, 0x01 },
};

/**
 * Find Phantom CLP setting
 *
 * @v setting		iPXE setting
 * @v clp_setting	Setting number, or 0 if not found
 */
static unsigned int
phantom_clp_setting ( struct phantom_nic *phantom,
		      const struct setting *setting ) {
	struct phantom_clp_setting *clp_setting;
	unsigned int i;

	/* Search the list of explicitly-defined settings */
	for ( i = 0 ; i < ( sizeof ( clp_settings ) /
			    sizeof ( clp_settings[0] ) ) ; i++ ) {
		clp_setting = &clp_settings[i];
		if ( setting_cmp ( setting, clp_setting->setting ) == 0 )
			return clp_setting->clp_setting;
	}

	/* Allow for use of numbered settings */
	if ( setting->scope == &phantom_settings_scope )
		return setting->tag;

	DBGC2 ( phantom, "Phantom %p has no \"%s\" setting\n",
		phantom, setting->name );

	return 0;
}

/**
 * Check applicability of Phantom CLP setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
static int phantom_setting_applies ( struct settings *settings,
				     const struct setting *setting ) {
	struct phantom_nic *phantom =
		container_of ( settings, struct phantom_nic, settings );
	unsigned int clp_setting;

	/* Find Phantom setting equivalent to iPXE setting */
	clp_setting = phantom_clp_setting ( phantom, setting );
	return ( clp_setting != 0 );
}

/**
 * Store Phantom CLP setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v data		Setting data, or NULL to clear setting
 * @v len		Length of setting data
 * @ret rc		Return status code
 */
static int phantom_store_setting ( struct settings *settings,
				   const struct setting *setting,
				   const void *data, size_t len ) {
	struct phantom_nic *phantom =
		container_of ( settings, struct phantom_nic, settings );
	unsigned int clp_setting;
	int rc;

	/* Find Phantom setting equivalent to iPXE setting */
	clp_setting = phantom_clp_setting ( phantom, setting );
	assert ( clp_setting != 0 );

	/* Store setting */
	if ( ( rc = phantom_clp_store ( phantom, phantom->port,
					clp_setting, data, len ) ) != 0 ) {
		DBGC ( phantom, "Phantom %p could not store setting \"%s\": "
		       "%s\n", phantom, setting->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Fetch Phantom CLP setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int phantom_fetch_setting ( struct settings *settings,
				   struct setting *setting,
				   void *data, size_t len ) {
	struct phantom_nic *phantom =
		container_of ( settings, struct phantom_nic, settings );
	unsigned int clp_setting;
	int read_len;
	int rc;

	/* Find Phantom setting equivalent to iPXE setting */
	clp_setting = phantom_clp_setting ( phantom, setting );
	assert ( clp_setting != 0 );

	/* Fetch setting */
	if ( ( read_len = phantom_clp_fetch ( phantom, phantom->port,
					      clp_setting, data, len ) ) < 0 ){
		rc = read_len;
		DBGC ( phantom, "Phantom %p could not fetch setting \"%s\": "
		       "%s\n", phantom, setting->name, strerror ( rc ) );
		return rc;
	}

	return read_len;
}

/** Phantom CLP settings operations */
static struct settings_operations phantom_settings_operations = {
	.applies	= phantom_setting_applies,
	.store		= phantom_store_setting,
	.fetch		= phantom_fetch_setting,
};

/***************************************************************************
 *
 * Initialisation
 *
 */

/**
 * Map Phantom CRB window
 *
 * @v phantom		Phantom NIC
 * @ret rc		Return status code
 */
static int phantom_map_crb ( struct phantom_nic *phantom,
			     struct pci_device *pci ) {
	unsigned long bar0_start;
	unsigned long bar0_size;

	bar0_start = pci_bar_start ( pci, PCI_BASE_ADDRESS_0 );
	bar0_size = pci_bar_size ( pci, PCI_BASE_ADDRESS_0 );
	DBGC ( phantom, "Phantom %p is " PCI_FMT " with BAR0 at %08lx+%lx\n",
	       phantom, PCI_ARGS ( pci ), bar0_start, bar0_size );

	if ( ! bar0_start ) {
		DBGC ( phantom, "Phantom %p BAR not assigned; ignoring\n",
		       phantom );
		return -EINVAL;
	}

	switch ( bar0_size ) {
	case ( 128 * 1024 * 1024 ) :
		DBGC ( phantom, "Phantom %p has 128MB BAR\n", phantom );
		phantom->crb_access = phantom_crb_access_128m;
		break;
	case ( 32 * 1024 * 1024 ) :
		DBGC ( phantom, "Phantom %p has 32MB BAR\n", phantom );
		phantom->crb_access = phantom_crb_access_32m;
		break;
	case ( 2 * 1024 * 1024 ) :
		DBGC ( phantom, "Phantom %p has 2MB BAR\n", phantom );
		phantom->crb_access = phantom_crb_access_2m;
		break;
	default:
		DBGC ( phantom, "Phantom %p has bad BAR size\n", phantom );
		return -EINVAL;
	}

	phantom->bar0 = ioremap ( bar0_start, bar0_size );
	if ( ! phantom->bar0 ) {
		DBGC ( phantom, "Phantom %p could not map BAR0\n", phantom );
		return -EIO;
	}

	/* Mark current CRB window as invalid, so that the first
	 * read/write will set the current window.
	 */
	phantom->crb_window = -1UL;

	return 0;
}

/**
 * Unhalt all PEGs
 *
 * @v phantom		Phantom NIC
 */
static void phantom_unhalt_pegs ( struct phantom_nic *phantom ) {
	uint32_t halt_status;

	halt_status = phantom_readl ( phantom, UNM_PEG_0_HALT_STATUS );
	phantom_writel ( phantom, halt_status, UNM_PEG_0_HALT_STATUS );
	halt_status = phantom_readl ( phantom, UNM_PEG_1_HALT_STATUS );
	phantom_writel ( phantom, halt_status, UNM_PEG_1_HALT_STATUS );
	halt_status = phantom_readl ( phantom, UNM_PEG_2_HALT_STATUS );
	phantom_writel ( phantom, halt_status, UNM_PEG_2_HALT_STATUS );
	halt_status = phantom_readl ( phantom, UNM_PEG_3_HALT_STATUS );
	phantom_writel ( phantom, halt_status, UNM_PEG_3_HALT_STATUS );
	halt_status = phantom_readl ( phantom, UNM_PEG_4_HALT_STATUS );
	phantom_writel ( phantom, halt_status, UNM_PEG_4_HALT_STATUS );
}

/**
 * Initialise the Phantom command PEG
 *
 * @v phantom		Phantom NIC
 * @ret rc		Return status code
 */
static int phantom_init_cmdpeg ( struct phantom_nic *phantom ) {
	uint32_t cold_boot;
	uint32_t sw_reset;
	unsigned int retries;
	uint32_t cmdpeg_state;
	uint32_t last_cmdpeg_state = 0;

	/* Check for a previous initialisation.  This could have
	 * happened if, for example, the BIOS used the UNDI API to
	 * drive the NIC prior to a full PXE boot.
	 */
	cmdpeg_state = phantom_readl ( phantom, UNM_NIC_REG_CMDPEG_STATE );
	if ( cmdpeg_state == UNM_NIC_REG_CMDPEG_STATE_INITIALIZE_ACK ) {
		DBGC ( phantom, "Phantom %p command PEG already initialized\n",
		       phantom );
		/* Unhalt the PEGs.  Previous firmware (e.g. BOFM) may
		 * have halted the PEGs to prevent internal bus
		 * collisions when the BIOS re-reads the expansion ROM.
		 */
		phantom_unhalt_pegs ( phantom );
		return 0;
	}

	/* If this was a cold boot, check that the hardware came up ok */
	cold_boot = phantom_readl ( phantom, UNM_CAM_RAM_COLD_BOOT );
	if ( cold_boot == UNM_CAM_RAM_COLD_BOOT_MAGIC ) {
		DBGC ( phantom, "Phantom %p coming up from cold boot\n",
		       phantom );
		sw_reset = phantom_readl ( phantom, UNM_ROMUSB_GLB_SW_RESET );
		if ( sw_reset != UNM_ROMUSB_GLB_SW_RESET_MAGIC ) {
			DBGC ( phantom, "Phantom %p reset failed: %08x\n",
			       phantom, sw_reset );
			return -EIO;
		}
	} else {
		DBGC ( phantom, "Phantom %p coming up from warm boot "
		       "(%08x)\n", phantom, cold_boot );
	}
	/* Clear cold-boot flag */
	phantom_writel ( phantom, 0, UNM_CAM_RAM_COLD_BOOT );

	/* Set port modes */
	phantom_writel ( phantom, UNM_CAM_RAM_PORT_MODE_AUTO_NEG_1G,
			 UNM_CAM_RAM_WOL_PORT_MODE );

	/* Pass dummy DMA area to card */
	phantom_write_hilo ( phantom, 0,
			     UNM_NIC_REG_DUMMY_BUF_ADDR_LO,
			     UNM_NIC_REG_DUMMY_BUF_ADDR_HI );
	phantom_writel ( phantom, UNM_NIC_REG_DUMMY_BUF_INIT,
			 UNM_NIC_REG_DUMMY_BUF );

	/* Tell the hardware that tuning is complete */
	phantom_writel ( phantom, UNM_ROMUSB_GLB_PEGTUNE_DONE_MAGIC,
			 UNM_ROMUSB_GLB_PEGTUNE_DONE );

	/* Wait for command PEG to finish initialising */
	DBGC ( phantom, "Phantom %p initialising command PEG (will take up to "
	       "%d seconds)...\n", phantom, PHN_CMDPEG_INIT_TIMEOUT_SEC );
	for ( retries = 0; retries < PHN_CMDPEG_INIT_TIMEOUT_SEC; retries++ ) {
		cmdpeg_state = phantom_readl ( phantom,
					       UNM_NIC_REG_CMDPEG_STATE );
		if ( cmdpeg_state != last_cmdpeg_state ) {
			DBGC ( phantom, "Phantom %p command PEG state is "
			       "%08x after %d seconds...\n",
			       phantom, cmdpeg_state, retries );
			last_cmdpeg_state = cmdpeg_state;
		}
		if ( cmdpeg_state == UNM_NIC_REG_CMDPEG_STATE_INITIALIZED ) {
			/* Acknowledge the PEG initialisation */
			phantom_writel ( phantom,
				       UNM_NIC_REG_CMDPEG_STATE_INITIALIZE_ACK,
				       UNM_NIC_REG_CMDPEG_STATE );
			return 0;
		}
		mdelay ( 1000 );
	}

	DBGC ( phantom, "Phantom %p timed out waiting for command PEG to "
	       "initialise (status %08x)\n", phantom, cmdpeg_state );
	return -ETIMEDOUT;
}

/**
 * Read Phantom MAC address
 *
 * @v phanton_port	Phantom NIC
 * @v hw_addr		Buffer to fill with MAC address
 */
static void phantom_get_macaddr ( struct phantom_nic *phantom,
				  uint8_t *hw_addr ) {
	union {
		uint8_t mac_addr[2][ETH_ALEN];
		uint32_t dwords[3];
	} u;
	unsigned long offset;
	int i;

	/* Read the three dwords that include this MAC address and one other */
	offset = ( UNM_CAM_RAM_MAC_ADDRS +
		   ( 12 * ( phantom->port / 2 ) ) );
	for ( i = 0 ; i < 3 ; i++, offset += 4 ) {
		u.dwords[i] = phantom_readl ( phantom, offset );
	}

	/* Copy out the relevant MAC address */
	for ( i = 0 ; i < ETH_ALEN ; i++ ) {
		hw_addr[ ETH_ALEN - i - 1 ] =
			u.mac_addr[ phantom->port & 1 ][i];
	}
	DBGC ( phantom, "Phantom %p MAC address is %s\n",
	       phantom, eth_ntoa ( hw_addr ) );
}

/**
 * Check Phantom is enabled for boot
 *
 * @v phanton_port	Phantom NIC
 * @ret rc		Return status code
 *
 * This is something of an ugly hack to accommodate an OEM
 * requirement.  The NIC has only one expansion ROM BAR, rather than
 * one per port.  To allow individual ports to be selectively
 * enabled/disabled for PXE boot (as required), we must therefore
 * leave the expansion ROM always enabled, and place the per-port
 * enable/disable logic within the iPXE driver.
 */
static int phantom_check_boot_enable ( struct phantom_nic *phantom ) {
	unsigned long boot_enable;

	boot_enable = phantom_readl ( phantom, UNM_CAM_RAM_BOOT_ENABLE );
	if ( ! ( boot_enable & ( 1 << phantom->port ) ) ) {
		DBGC ( phantom, "Phantom %p PXE boot is disabled\n",
		       phantom );
		return -ENOTSUP;
	}

	return 0;
}

/**
 * Initialise Phantom receive PEG
 *
 * @v phantom		Phantom NIC
 * @ret rc		Return status code
 */
static int phantom_init_rcvpeg ( struct phantom_nic *phantom ) {
	unsigned int retries;
	uint32_t rcvpeg_state;
	uint32_t last_rcvpeg_state = 0;

	DBGC ( phantom, "Phantom %p initialising receive PEG (will take up to "
	       "%d seconds)...\n", phantom, PHN_RCVPEG_INIT_TIMEOUT_SEC );
	for ( retries = 0; retries < PHN_RCVPEG_INIT_TIMEOUT_SEC; retries++ ) {
		rcvpeg_state = phantom_readl ( phantom,
					       UNM_NIC_REG_RCVPEG_STATE );
		if ( rcvpeg_state != last_rcvpeg_state ) {
			DBGC ( phantom, "Phantom %p receive PEG state is "
			       "%08x after %d seconds...\n",
			       phantom, rcvpeg_state, retries );
			last_rcvpeg_state = rcvpeg_state;
		}
		if ( rcvpeg_state == UNM_NIC_REG_RCVPEG_STATE_INITIALIZED )
			return 0;
		mdelay ( 1000 );
	}

	DBGC ( phantom, "Phantom %p timed out waiting for receive PEG to "
	       "initialise (status %08x)\n", phantom, rcvpeg_state );
	return -ETIMEDOUT;
}

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @v id		PCI ID
 * @ret rc		Return status code
 */
static int phantom_probe ( struct pci_device *pci ) {
	struct net_device *netdev;
	struct phantom_nic *phantom;
	struct settings *parent_settings;
	int rc;

	/* Allocate Phantom device */
	netdev = alloc_etherdev ( sizeof ( *phantom ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc_etherdev;
	}
	netdev_init ( netdev, &phantom_operations );
	phantom = netdev_priv ( netdev );
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;
	memset ( phantom, 0, sizeof ( *phantom ) );
	phantom->port = PCI_FUNC ( pci->busdevfn );
	assert ( phantom->port < PHN_MAX_NUM_PORTS );
	settings_init ( &phantom->settings,
			&phantom_settings_operations,
			&netdev->refcnt, &phantom_settings_scope );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Map CRB */
	if ( ( rc = phantom_map_crb ( phantom, pci ) ) != 0 )
		goto err_map_crb;

	/* BUG5945 - need to hack PCI config space on P3 B1 silicon.
	 * B2 will have this fixed; remove this hack when B1 is no
	 * longer in use.
	 */
	if ( PCI_FUNC ( pci->busdevfn ) == 0 ) {
		unsigned int i;
		for ( i = 0 ; i < 8 ; i++ ) {
			uint32_t temp;
			pci->busdevfn =
				PCI_BUSDEVFN ( PCI_BUS ( pci->busdevfn ),
					       PCI_SLOT ( pci->busdevfn ), i );
			pci_read_config_dword ( pci, 0xc8, &temp );
			pci_read_config_dword ( pci, 0xc8, &temp );
			pci_write_config_dword ( pci, 0xc8, 0xf1000 );
		}
		pci->busdevfn = PCI_BUSDEVFN ( PCI_BUS ( pci->busdevfn ),
					       PCI_SLOT ( pci->busdevfn ), 0 );
	}

	/* Initialise the command PEG */
	if ( ( rc = phantom_init_cmdpeg ( phantom ) ) != 0 )
		goto err_init_cmdpeg;

	/* Initialise the receive PEG */
	if ( ( rc = phantom_init_rcvpeg ( phantom ) ) != 0 )
		goto err_init_rcvpeg;

	/* Read MAC addresses */
	phantom_get_macaddr ( phantom, netdev->hw_addr );

	/* Skip if boot disabled on NIC */
	if ( ( rc = phantom_check_boot_enable ( phantom ) ) != 0 )
		goto err_check_boot_enable;

	/* Register network devices */
	if ( ( rc = register_netdev ( netdev ) ) != 0 ) {
		DBGC ( phantom, "Phantom %p could not register net device: "
		       "%s\n", phantom, strerror ( rc ) );
		goto err_register_netdev;
	}

	/* Register settings blocks */
	parent_settings = netdev_settings ( netdev );
	if ( ( rc = register_settings ( &phantom->settings,
					parent_settings, "clp" ) ) != 0 ) {
		DBGC ( phantom, "Phantom %p could not register settings: "
		       "%s\n", phantom, strerror ( rc ) );
		goto err_register_settings;
	}

	return 0;

	unregister_settings ( &phantom->settings );
 err_register_settings:
	unregister_netdev ( netdev );
 err_register_netdev:
 err_check_boot_enable:
 err_init_rcvpeg:
 err_init_cmdpeg:
 err_map_crb:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
 err_alloc_etherdev:
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci		PCI device
 */
static void phantom_remove ( struct pci_device *pci ) {
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct phantom_nic *phantom = netdev_priv ( netdev );

	unregister_settings ( &phantom->settings );
	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** Phantom PCI IDs */
static struct pci_device_id phantom_nics[] = {
	PCI_ROM ( 0x4040, 0x0100, "nx", "NX", 0 ),
};

/** Phantom PCI driver */
struct pci_driver phantom_driver __pci_driver = {
	.ids = phantom_nics,
	.id_count = ( sizeof ( phantom_nics ) / sizeof ( phantom_nics[0] ) ),
	.probe = phantom_probe,
	.remove = phantom_remove,
};
