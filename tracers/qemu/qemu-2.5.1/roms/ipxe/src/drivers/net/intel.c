/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/pci.h>
#include <ipxe/profile.h>
#include "intel.h"

/** @file
 *
 * Intel 10/100/1000 network card driver
 *
 */

/** VM transmit profiler */
static struct profiler intel_vm_tx_profiler __profiler =
	{ .name = "intel.vm_tx" };

/** VM receive refill profiler */
static struct profiler intel_vm_refill_profiler __profiler =
	{ .name = "intel.vm_refill" };

/** VM poll profiler */
static struct profiler intel_vm_poll_profiler __profiler =
	{ .name = "intel.vm_poll" };

/******************************************************************************
 *
 * EEPROM interface
 *
 ******************************************************************************
 */

/**
 * Read data from EEPROM
 *
 * @v nvs		NVS device
 * @v address		Address from which to read
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int intel_read_eeprom ( struct nvs_device *nvs, unsigned int address,
			       void *data, size_t len ) {
	struct intel_nic *intel =
		container_of ( nvs, struct intel_nic, eeprom );
	unsigned int i;
	uint32_t value;
	uint16_t *data_word = data;

	/* Sanity check.  We advertise a blocksize of one word, so
	 * should only ever receive single-word requests.
	 */
	assert ( len == sizeof ( *data_word ) );

	/* Initiate read */
	writel ( ( INTEL_EERD_START | ( address << intel->eerd_addr_shift ) ),
		 intel->regs + INTEL_EERD );

	/* Wait for read to complete */
	for ( i = 0 ; i < INTEL_EEPROM_MAX_WAIT_MS ; i++ ) {

		/* If read is not complete, delay 1ms and retry */
		value = readl ( intel->regs + INTEL_EERD );
		if ( ! ( value & intel->eerd_done ) ) {
			mdelay ( 1 );
			continue;
		}

		/* Extract data */
		*data_word = cpu_to_le16 ( INTEL_EERD_DATA ( value ) );
		return 0;
	}

	DBGC ( intel, "INTEL %p timed out waiting for EEPROM read\n", intel );
	return -ETIMEDOUT;
}

/**
 * Write data to EEPROM
 *
 * @v nvs		NVS device
 * @v address		Address to which to write
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int intel_write_eeprom ( struct nvs_device *nvs,
				unsigned int address __unused,
				const void *data __unused,
				size_t len __unused ) {
	struct intel_nic *intel =
		container_of ( nvs, struct intel_nic, eeprom );

	DBGC ( intel, "INTEL %p EEPROM write not supported\n", intel );
	return -ENOTSUP;
}

/**
 * Initialise EEPROM
 *
 * @v intel		Intel device
 * @ret rc		Return status code
 */
static int intel_init_eeprom ( struct intel_nic *intel ) {
	unsigned int i;
	uint32_t value;

	/* The NIC automatically detects the type of attached EEPROM.
	 * The EERD register provides access to only a single word at
	 * a time, so we pretend to have a single-word block size.
	 *
	 * The EEPROM size may be larger than the minimum size, but
	 * this doesn't matter to us since we access only the first
	 * few words.
	 */
	intel->eeprom.word_len_log2 = INTEL_EEPROM_WORD_LEN_LOG2;
	intel->eeprom.size = INTEL_EEPROM_MIN_SIZE_WORDS;
	intel->eeprom.block_size = 1;
	intel->eeprom.read = intel_read_eeprom;
	intel->eeprom.write = intel_write_eeprom;

	/* The layout of the EERD register was changed at some point
	 * to accommodate larger EEPROMs.  Read from address zero (for
	 * which the request layouts are compatible) to determine
	 * which type of register we have.
	 */
	writel ( INTEL_EERD_START, intel->regs + INTEL_EERD );
	for ( i = 0 ; i < INTEL_EEPROM_MAX_WAIT_MS ; i++ ) {
		value = readl ( intel->regs + INTEL_EERD );
		if ( value & INTEL_EERD_DONE_LARGE ) {
			DBGC ( intel, "INTEL %p has large-format EERD\n",
			       intel );
			intel->eerd_done = INTEL_EERD_DONE_LARGE;
			intel->eerd_addr_shift = INTEL_EERD_ADDR_SHIFT_LARGE;
			return 0;
		}
		if ( value & INTEL_EERD_DONE_SMALL ) {
			DBGC ( intel, "INTEL %p has small-format EERD\n",
			       intel );
			intel->eerd_done = INTEL_EERD_DONE_SMALL;
			intel->eerd_addr_shift = INTEL_EERD_ADDR_SHIFT_SMALL;
			return 0;
		}
		mdelay ( 1 );
	}

	DBGC ( intel, "INTEL %p timed out waiting for initial EEPROM read "
	       "(value %08x)\n", intel, value );
	return -ETIMEDOUT;
}

/******************************************************************************
 *
 * MAC address
 *
 ******************************************************************************
 */

/**
 * Fetch initial MAC address from EEPROM
 *
 * @v intel		Intel device
 * @v hw_addr		Hardware address to fill in
 * @ret rc		Return status code
 */
static int intel_fetch_mac_eeprom ( struct intel_nic *intel,
				    uint8_t *hw_addr ) {
	int rc;

	/* Initialise EEPROM */
	if ( ( rc = intel_init_eeprom ( intel ) ) != 0 )
		return rc;

	/* Read base MAC address from EEPROM */
	if ( ( rc = nvs_read ( &intel->eeprom, INTEL_EEPROM_MAC,
			       hw_addr, ETH_ALEN ) ) != 0 ) {
		DBGC ( intel, "INTEL %p could not read EEPROM base MAC "
		       "address: %s\n", intel, strerror ( rc ) );
		return rc;
	}

	/* Adjust MAC address for multi-port devices */
	hw_addr[ETH_ALEN-1] ^= intel->port;

	DBGC ( intel, "INTEL %p has EEPROM MAC address %s (port %d)\n",
	       intel, eth_ntoa ( hw_addr ), intel->port );
	return 0;
}

/**
 * Fetch initial MAC address
 *
 * @v intel		Intel device
 * @v hw_addr		Hardware address to fill in
 * @ret rc		Return status code
 */
static int intel_fetch_mac ( struct intel_nic *intel, uint8_t *hw_addr ) {
	union intel_receive_address mac;
	int rc;

	/* Read current address from RAL0/RAH0 */
	mac.reg.low = cpu_to_le32 ( readl ( intel->regs + INTEL_RAL0 ) );
	mac.reg.high = cpu_to_le32 ( readl ( intel->regs + INTEL_RAH0 ) );
	DBGC ( intel, "INTEL %p has autoloaded MAC address %s\n",
	       intel, eth_ntoa ( mac.raw ) );

	/* Use current address if valid */
	if ( is_valid_ether_addr ( mac.raw ) ) {
		memcpy ( hw_addr, mac.raw, ETH_ALEN );
		return 0;
	}

	/* Otherwise, try to read address from EEPROM */
	if ( ( rc = intel_fetch_mac_eeprom ( intel, hw_addr ) ) == 0 )
		return 0;

	DBGC ( intel, "INTEL %p has no MAC address to use\n", intel );
	return -ENOENT;
}

/******************************************************************************
 *
 * Device reset
 *
 ******************************************************************************
 */

/**
 * Reset hardware
 *
 * @v intel		Intel device
 * @ret rc		Return status code
 */
static int intel_reset ( struct intel_nic *intel ) {
	uint32_t pbs;
	uint32_t pba;
	uint32_t ctrl;
	uint32_t status;

	/* Force RX and TX packet buffer allocation, to work around an
	 * errata in ICH devices.
	 */
	if ( intel->flags & INTEL_PBS_ERRATA ) {
		DBGC ( intel, "INTEL %p WARNING: applying ICH PBS/PBA errata\n",
		       intel );
		pbs = readl ( intel->regs + INTEL_PBS );
		pba = readl ( intel->regs + INTEL_PBA );
		writel ( 0x08, intel->regs + INTEL_PBA );
		writel ( 0x10, intel->regs + INTEL_PBS );
		DBGC ( intel, "INTEL %p PBS %#08x->%#08x PBA %#08x->%#08x\n",
		       intel, pbs, readl ( intel->regs + INTEL_PBS ),
		       pba, readl ( intel->regs + INTEL_PBA ) );
	}

	/* Always reset MAC.  Required to reset the TX and RX rings. */
	ctrl = readl ( intel->regs + INTEL_CTRL );
	writel ( ( ctrl | INTEL_CTRL_RST ), intel->regs + INTEL_CTRL );
	mdelay ( INTEL_RESET_DELAY_MS );

	/* Set a sensible default configuration */
	ctrl |= ( INTEL_CTRL_SLU | INTEL_CTRL_ASDE );
	ctrl &= ~( INTEL_CTRL_LRST | INTEL_CTRL_FRCSPD | INTEL_CTRL_FRCDPLX );
	writel ( ctrl, intel->regs + INTEL_CTRL );
	mdelay ( INTEL_RESET_DELAY_MS );

	/* If link is already up, do not attempt to reset the PHY.  On
	 * some models (notably ICH), performing a PHY reset seems to
	 * drop the link speed to 10Mbps.
	 */
	status = readl ( intel->regs + INTEL_STATUS );
	if ( status & INTEL_STATUS_LU ) {
		DBGC ( intel, "INTEL %p MAC reset (ctrl %08x)\n",
		       intel, ctrl );
		return 0;
	}

	/* Reset PHY and MAC simultaneously */
	writel ( ( ctrl | INTEL_CTRL_RST | INTEL_CTRL_PHY_RST ),
		 intel->regs + INTEL_CTRL );
	mdelay ( INTEL_RESET_DELAY_MS );

	/* PHY reset is not self-clearing on all models */
	writel ( ctrl, intel->regs + INTEL_CTRL );
	mdelay ( INTEL_RESET_DELAY_MS );

	DBGC ( intel, "INTEL %p MAC+PHY reset (ctrl %08x)\n", intel, ctrl );
	return 0;
}

/******************************************************************************
 *
 * Link state
 *
 ******************************************************************************
 */

/**
 * Check link state
 *
 * @v netdev		Network device
 */
static void intel_check_link ( struct net_device *netdev ) {
	struct intel_nic *intel = netdev->priv;
	uint32_t status;

	/* Read link status */
	status = readl ( intel->regs + INTEL_STATUS );
	DBGC ( intel, "INTEL %p link status is %08x\n", intel, status );

	/* Update network device */
	if ( status & INTEL_STATUS_LU ) {
		netdev_link_up ( netdev );
	} else {
		netdev_link_down ( netdev );
	}
}

/******************************************************************************
 *
 * Descriptors
 *
 ******************************************************************************
 */

/**
 * Populate transmit descriptor
 *
 * @v tx		Transmit descriptor
 * @v addr		Data buffer address
 * @v len		Length of data
 */
void intel_describe_tx ( struct intel_descriptor *tx, physaddr_t addr,
			 size_t len ) {

	/* Populate transmit descriptor */
	tx->address = cpu_to_le64 ( addr );
	tx->length = cpu_to_le16 ( len );
	tx->flags = 0;
	tx->command = ( INTEL_DESC_CMD_RS | INTEL_DESC_CMD_IFCS |
			INTEL_DESC_CMD_EOP );
	tx->status = 0;
}

/**
 * Populate advanced transmit descriptor
 *
 * @v tx		Transmit descriptor
 * @v addr		Data buffer address
 * @v len		Length of data
 */
void intel_describe_tx_adv ( struct intel_descriptor *tx, physaddr_t addr,
			     size_t len ) {

	/* Populate advanced transmit descriptor */
	tx->address = cpu_to_le64 ( addr );
	tx->length = cpu_to_le16 ( len );
	tx->flags = INTEL_DESC_FL_DTYP_DATA;
	tx->command = ( INTEL_DESC_CMD_DEXT | INTEL_DESC_CMD_RS |
			INTEL_DESC_CMD_IFCS | INTEL_DESC_CMD_EOP );
	tx->status = cpu_to_le32 ( INTEL_DESC_STATUS_PAYLEN ( len ) );
}

/**
 * Populate receive descriptor
 *
 * @v rx		Receive descriptor
 * @v addr		Data buffer address
 * @v len		Length of data
 */
void intel_describe_rx ( struct intel_descriptor *rx, physaddr_t addr,
			 size_t len __unused ) {

	/* Populate transmit descriptor */
	rx->address = cpu_to_le64 ( addr );
	rx->length = 0;
	rx->status = 0;
}

/******************************************************************************
 *
 * Network device interface
 *
 ******************************************************************************
 */

/**
 * Create descriptor ring
 *
 * @v intel		Intel device
 * @v ring		Descriptor ring
 * @ret rc		Return status code
 */
int intel_create_ring ( struct intel_nic *intel, struct intel_ring *ring ) {
	physaddr_t address;
	uint32_t dctl;

	/* Allocate descriptor ring.  Align ring on its own size to
	 * prevent any possible page-crossing errors due to hardware
	 * errata.
	 */
	ring->desc = malloc_dma ( ring->len, ring->len );
	if ( ! ring->desc )
		return -ENOMEM;

	/* Initialise descriptor ring */
	memset ( ring->desc, 0, ring->len );

	/* Program ring address */
	address = virt_to_bus ( ring->desc );
	writel ( ( address & 0xffffffffUL ),
		 ( intel->regs + ring->reg + INTEL_xDBAL ) );
	if ( sizeof ( physaddr_t ) > sizeof ( uint32_t ) ) {
		writel ( ( ( ( uint64_t ) address ) >> 32 ),
			 ( intel->regs + ring->reg + INTEL_xDBAH ) );
	} else {
		writel ( 0, intel->regs + ring->reg + INTEL_xDBAH );
	}

	/* Program ring length */
	writel ( ring->len, ( intel->regs + ring->reg + INTEL_xDLEN ) );

	/* Reset head and tail pointers */
	writel ( 0, ( intel->regs + ring->reg + INTEL_xDH ) );
	writel ( 0, ( intel->regs + ring->reg + INTEL_xDT ) );

	/* Enable ring */
	dctl = readl ( intel->regs + ring->reg + INTEL_xDCTL );
	dctl |= INTEL_xDCTL_ENABLE;
	writel ( dctl, intel->regs + ring->reg + INTEL_xDCTL );

	DBGC ( intel, "INTEL %p ring %05x is at [%08llx,%08llx)\n",
	       intel, ring->reg, ( ( unsigned long long ) address ),
	       ( ( unsigned long long ) address + ring->len ) );

	return 0;
}

/**
 * Destroy descriptor ring
 *
 * @v intel		Intel device
 * @v ring		Descriptor ring
 */
void intel_destroy_ring ( struct intel_nic *intel, struct intel_ring *ring ) {

	/* Clear ring length */
	writel ( 0, ( intel->regs + ring->reg + INTEL_xDLEN ) );

	/* Clear ring address */
	writel ( 0, ( intel->regs + ring->reg + INTEL_xDBAL ) );
	writel ( 0, ( intel->regs + ring->reg + INTEL_xDBAH ) );

	/* Free descriptor ring */
	free_dma ( ring->desc, ring->len );
	ring->desc = NULL;
	ring->prod = 0;
	ring->cons = 0;
}

/**
 * Refill receive descriptor ring
 *
 * @v intel		Intel device
 */
void intel_refill_rx ( struct intel_nic *intel ) {
	struct intel_descriptor *rx;
	struct io_buffer *iobuf;
	unsigned int rx_idx;
	unsigned int rx_tail;
	physaddr_t address;
	unsigned int refilled = 0;

	/* Refill ring */
	while ( ( intel->rx.prod - intel->rx.cons ) < INTEL_RX_FILL ) {

		/* Allocate I/O buffer */
		iobuf = alloc_iob ( INTEL_RX_MAX_LEN );
		if ( ! iobuf ) {
			/* Wait for next refill */
			break;
		}

		/* Get next receive descriptor */
		rx_idx = ( intel->rx.prod++ % INTEL_NUM_RX_DESC );
		rx = &intel->rx.desc[rx_idx];

		/* Populate receive descriptor */
		address = virt_to_bus ( iobuf->data );
		intel->rx.describe ( rx, address, 0 );

		/* Record I/O buffer */
		assert ( intel->rx_iobuf[rx_idx] == NULL );
		intel->rx_iobuf[rx_idx] = iobuf;

		DBGC2 ( intel, "INTEL %p RX %d is [%llx,%llx)\n", intel, rx_idx,
			( ( unsigned long long ) address ),
			( ( unsigned long long ) address + INTEL_RX_MAX_LEN ) );
		refilled++;
	}

	/* Push descriptors to card, if applicable */
	if ( refilled ) {
		wmb();
		rx_tail = ( intel->rx.prod % INTEL_NUM_RX_DESC );
		profile_start ( &intel_vm_refill_profiler );
		writel ( rx_tail, intel->regs + intel->rx.reg + INTEL_xDT );
		profile_stop ( &intel_vm_refill_profiler );
		profile_exclude ( &intel_vm_refill_profiler );
	}
}

/**
 * Discard unused receive I/O buffers
 *
 * @v intel		Intel device
 */
void intel_empty_rx ( struct intel_nic *intel ) {
	unsigned int i;

	for ( i = 0 ; i < INTEL_NUM_RX_DESC ; i++ ) {
		if ( intel->rx_iobuf[i] )
			free_iob ( intel->rx_iobuf[i] );
		intel->rx_iobuf[i] = NULL;
	}
}

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int intel_open ( struct net_device *netdev ) {
	struct intel_nic *intel = netdev->priv;
	union intel_receive_address mac;
	uint32_t tctl;
	uint32_t rctl;
	int rc;

	/* Create transmit descriptor ring */
	if ( ( rc = intel_create_ring ( intel, &intel->tx ) ) != 0 )
		goto err_create_tx;

	/* Create receive descriptor ring */
	if ( ( rc = intel_create_ring ( intel, &intel->rx ) ) != 0 )
		goto err_create_rx;

	/* Program MAC address */
	memset ( &mac, 0, sizeof ( mac ) );
	memcpy ( mac.raw, netdev->ll_addr, sizeof ( mac.raw ) );
	writel ( le32_to_cpu ( mac.reg.low ), intel->regs + INTEL_RAL0 );
	writel ( ( le32_to_cpu ( mac.reg.high ) | INTEL_RAH0_AV ),
		 intel->regs + INTEL_RAH0 );

	/* Enable transmitter  */
	tctl = readl ( intel->regs + INTEL_TCTL );
	tctl &= ~( INTEL_TCTL_CT_MASK | INTEL_TCTL_COLD_MASK );
	tctl |= ( INTEL_TCTL_EN | INTEL_TCTL_PSP | INTEL_TCTL_CT_DEFAULT |
		  INTEL_TCTL_COLD_DEFAULT );
	writel ( tctl, intel->regs + INTEL_TCTL );

	/* Enable receiver */
	rctl = readl ( intel->regs + INTEL_RCTL );
	rctl &= ~( INTEL_RCTL_BSIZE_BSEX_MASK );
	rctl |= ( INTEL_RCTL_EN | INTEL_RCTL_UPE | INTEL_RCTL_MPE |
		  INTEL_RCTL_BAM | INTEL_RCTL_BSIZE_2048 | INTEL_RCTL_SECRC );
	writel ( rctl, intel->regs + INTEL_RCTL );

	/* Fill receive ring */
	intel_refill_rx ( intel );

	/* Update link state */
	intel_check_link ( netdev );

	/* Apply required errata */
	if ( intel->flags & INTEL_VMWARE ) {
		DBGC ( intel, "INTEL %p applying VMware errata workaround\n",
		       intel );
		intel->force_icr = INTEL_IRQ_RXT0;
	}

	return 0;

	intel_destroy_ring ( intel, &intel->rx );
 err_create_rx:
	intel_destroy_ring ( intel, &intel->tx );
 err_create_tx:
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void intel_close ( struct net_device *netdev ) {
	struct intel_nic *intel = netdev->priv;

	/* Disable receiver */
	writel ( 0, intel->regs + INTEL_RCTL );

	/* Disable transmitter  */
	writel ( 0, intel->regs + INTEL_TCTL );

	/* Destroy receive descriptor ring */
	intel_destroy_ring ( intel, &intel->rx );

	/* Discard any unused receive buffers */
	intel_empty_rx ( intel );

	/* Destroy transmit descriptor ring */
	intel_destroy_ring ( intel, &intel->tx );

	/* Reset the NIC, to flush the transmit and receive FIFOs */
	intel_reset ( intel );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
int intel_transmit ( struct net_device *netdev, struct io_buffer *iobuf ) {
	struct intel_nic *intel = netdev->priv;
	struct intel_descriptor *tx;
	unsigned int tx_idx;
	unsigned int tx_tail;
	physaddr_t address;
	size_t len;

	/* Get next transmit descriptor */
	if ( ( intel->tx.prod - intel->tx.cons ) >= INTEL_TX_FILL ) {
		DBGC ( intel, "INTEL %p out of transmit descriptors\n", intel );
		return -ENOBUFS;
	}
	tx_idx = ( intel->tx.prod++ % INTEL_NUM_TX_DESC );
	tx_tail = ( intel->tx.prod % INTEL_NUM_TX_DESC );
	tx = &intel->tx.desc[tx_idx];

	/* Populate transmit descriptor */
	address = virt_to_bus ( iobuf->data );
	len = iob_len ( iobuf );
	intel->tx.describe ( tx, address, len );
	wmb();

	/* Notify card that there are packets ready to transmit */
	profile_start ( &intel_vm_tx_profiler );
	writel ( tx_tail, intel->regs + intel->tx.reg + INTEL_xDT );
	profile_stop ( &intel_vm_tx_profiler );
	profile_exclude ( &intel_vm_tx_profiler );

	DBGC2 ( intel, "INTEL %p TX %d is [%llx,%llx)\n", intel, tx_idx,
		( ( unsigned long long ) address ),
		( ( unsigned long long ) address + len ) );

	return 0;
}

/**
 * Poll for completed packets
 *
 * @v netdev		Network device
 */
void intel_poll_tx ( struct net_device *netdev ) {
	struct intel_nic *intel = netdev->priv;
	struct intel_descriptor *tx;
	unsigned int tx_idx;

	/* Check for completed packets */
	while ( intel->tx.cons != intel->tx.prod ) {

		/* Get next transmit descriptor */
		tx_idx = ( intel->tx.cons % INTEL_NUM_TX_DESC );
		tx = &intel->tx.desc[tx_idx];

		/* Stop if descriptor is still in use */
		if ( ! ( tx->status & cpu_to_le32 ( INTEL_DESC_STATUS_DD ) ) )
			return;

		DBGC2 ( intel, "INTEL %p TX %d complete\n", intel, tx_idx );

		/* Complete TX descriptor */
		netdev_tx_complete_next ( netdev );
		intel->tx.cons++;
	}
}

/**
 * Poll for received packets
 *
 * @v netdev		Network device
 */
void intel_poll_rx ( struct net_device *netdev ) {
	struct intel_nic *intel = netdev->priv;
	struct intel_descriptor *rx;
	struct io_buffer *iobuf;
	unsigned int rx_idx;
	size_t len;

	/* Check for received packets */
	while ( intel->rx.cons != intel->rx.prod ) {

		/* Get next receive descriptor */
		rx_idx = ( intel->rx.cons % INTEL_NUM_RX_DESC );
		rx = &intel->rx.desc[rx_idx];

		/* Stop if descriptor is still in use */
		if ( ! ( rx->status & cpu_to_le32 ( INTEL_DESC_STATUS_DD ) ) )
			return;

		/* Populate I/O buffer */
		iobuf = intel->rx_iobuf[rx_idx];
		intel->rx_iobuf[rx_idx] = NULL;
		len = le16_to_cpu ( rx->length );
		iob_put ( iobuf, len );

		/* Hand off to network stack */
		if ( rx->status & cpu_to_le32 ( INTEL_DESC_STATUS_RXE ) ) {
			DBGC ( intel, "INTEL %p RX %d error (length %zd, "
			       "status %08x)\n", intel, rx_idx, len,
			       le32_to_cpu ( rx->status ) );
			netdev_rx_err ( netdev, iobuf, -EIO );
		} else {
			DBGC2 ( intel, "INTEL %p RX %d complete (length %zd)\n",
				intel, rx_idx, len );
			netdev_rx ( netdev, iobuf );
		}
		intel->rx.cons++;
	}
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void intel_poll ( struct net_device *netdev ) {
	struct intel_nic *intel = netdev->priv;
	uint32_t icr;

	/* Check for and acknowledge interrupts */
	profile_start ( &intel_vm_poll_profiler );
	icr = readl ( intel->regs + INTEL_ICR );
	profile_stop ( &intel_vm_poll_profiler );
	profile_exclude ( &intel_vm_poll_profiler );
	icr |= intel->force_icr;
	if ( ! icr )
		return;

	/* Poll for TX completions, if applicable */
	if ( icr & INTEL_IRQ_TXDW )
		intel_poll_tx ( netdev );

	/* Poll for RX completions, if applicable */
	if ( icr & ( INTEL_IRQ_RXT0 | INTEL_IRQ_RXO ) )
		intel_poll_rx ( netdev );

	/* Report receive overruns */
	if ( icr & INTEL_IRQ_RXO )
		netdev_rx_err ( netdev, NULL, -ENOBUFS );

	/* Check link state, if applicable */
	if ( icr & INTEL_IRQ_LSC )
		intel_check_link ( netdev );

	/* Check for unexpected interrupts */
	if ( icr & ~( INTEL_IRQ_TXDW | INTEL_IRQ_TXQE | INTEL_IRQ_LSC |
		      INTEL_IRQ_RXDMT0 | INTEL_IRQ_RXT0 | INTEL_IRQ_RXO ) ) {
		DBGC ( intel, "INTEL %p unexpected ICR %08x\n", intel, icr );
		/* Report as a TX error */
		netdev_tx_err ( netdev, NULL, -ENOTSUP );
	}

	/* Refill RX ring */
	intel_refill_rx ( intel );
}

/**
 * Enable or disable interrupts
 *
 * @v netdev		Network device
 * @v enable		Interrupts should be enabled
 */
static void intel_irq ( struct net_device *netdev, int enable ) {
	struct intel_nic *intel = netdev->priv;
	uint32_t mask;

	mask = ( INTEL_IRQ_TXDW | INTEL_IRQ_LSC | INTEL_IRQ_RXT0 );
	if ( enable ) {
		writel ( mask, intel->regs + INTEL_IMS );
	} else {
		writel ( mask, intel->regs + INTEL_IMC );
	}
}

/** Intel network device operations */
static struct net_device_operations intel_operations = {
	.open		= intel_open,
	.close		= intel_close,
	.transmit	= intel_transmit,
	.poll		= intel_poll,
	.irq		= intel_irq,
};

/******************************************************************************
 *
 * PCI interface
 *
 ******************************************************************************
 */

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 */
static int intel_probe ( struct pci_device *pci ) {
	struct net_device *netdev;
	struct intel_nic *intel;
	int rc;

	/* Allocate and initialise net device */
	netdev = alloc_etherdev ( sizeof ( *intel ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &intel_operations );
	intel = netdev->priv;
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;
	memset ( intel, 0, sizeof ( *intel ) );
	intel->port = PCI_FUNC ( pci->busdevfn );
	intel->flags = pci->id->driver_data;
	intel_init_ring ( &intel->tx, INTEL_NUM_TX_DESC, INTEL_TD,
			  intel_describe_tx );
	intel_init_ring ( &intel->rx, INTEL_NUM_RX_DESC, INTEL_RD,
			  intel_describe_rx );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Map registers */
	intel->regs = ioremap ( pci->membase, INTEL_BAR_SIZE );
	if ( ! intel->regs ) {
		rc = -ENODEV;
		goto err_ioremap;
	}

	/* Reset the NIC */
	if ( ( rc = intel_reset ( intel ) ) != 0 )
		goto err_reset;

	/* Fetch MAC address */
	if ( ( rc = intel_fetch_mac ( intel, netdev->hw_addr ) ) != 0 )
		goto err_fetch_mac;

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register_netdev;

	/* Set initial link state */
	intel_check_link ( netdev );

	return 0;

	unregister_netdev ( netdev );
 err_register_netdev:
 err_fetch_mac:
	intel_reset ( intel );
 err_reset:
	iounmap ( intel->regs );
 err_ioremap:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
 err_alloc:
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci		PCI device
 */
static void intel_remove ( struct pci_device *pci ) {
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct intel_nic *intel = netdev->priv;

	/* Unregister network device */
	unregister_netdev ( netdev );

	/* Reset the NIC */
	intel_reset ( intel );

	/* Free network device */
	iounmap ( intel->regs );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** Intel PCI device IDs */
static struct pci_device_id intel_nics[] = {
	PCI_ROM ( 0x8086, 0x0438, "dh8900cc", "DH8900CC", 0 ),
	PCI_ROM ( 0x8086, 0x043a, "dh8900cc-f", "DH8900CC Fiber", 0 ),
	PCI_ROM ( 0x8086, 0x043c, "dh8900cc-b", "DH8900CC Backplane", 0 ),
	PCI_ROM ( 0x8086, 0x0440, "dh8900cc-s", "DH8900CC SFP", 0 ),
	PCI_ROM ( 0x8086, 0x1000, "82542-f", "82542 (Fiber)", 0 ),
	PCI_ROM ( 0x8086, 0x1001, "82543gc-f", "82543GC (Fiber)", 0 ),
	PCI_ROM ( 0x8086, 0x1004, "82543gc", "82543GC (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x1008, "82544ei", "82544EI (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x1009, "82544ei-f", "82544EI (Fiber)", 0 ),
	PCI_ROM ( 0x8086, 0x100c, "82544gc", "82544GC (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x100d, "82544gc-l", "82544GC (LOM)", 0 ),
	PCI_ROM ( 0x8086, 0x100e, "82540em", "82540EM", 0 ),
	PCI_ROM ( 0x8086, 0x100f, "82545em", "82545EM (Copper)", INTEL_VMWARE ),
	PCI_ROM ( 0x8086, 0x1010, "82546eb", "82546EB (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x1011, "82545em-f", "82545EM (Fiber)", 0 ),
	PCI_ROM ( 0x8086, 0x1012, "82546eb-f", "82546EB (Fiber)", 0 ),
	PCI_ROM ( 0x8086, 0x1013, "82541ei", "82541EI", 0 ),
	PCI_ROM ( 0x8086, 0x1014, "82541er", "82541ER", 0 ),
	PCI_ROM ( 0x8086, 0x1015, "82540em-l", "82540EM (LOM)", 0 ),
	PCI_ROM ( 0x8086, 0x1016, "82540ep-m", "82540EP (Mobile)", 0 ),
	PCI_ROM ( 0x8086, 0x1017, "82540ep", "82540EP", 0 ),
	PCI_ROM ( 0x8086, 0x1018, "82541ei", "82541EI", 0 ),
	PCI_ROM ( 0x8086, 0x1019, "82547ei", "82547EI", 0 ),
	PCI_ROM ( 0x8086, 0x101a, "82547ei-m", "82547EI (Mobile)", 0 ),
	PCI_ROM ( 0x8086, 0x101d, "82546eb", "82546EB", 0 ),
	PCI_ROM ( 0x8086, 0x101e, "82540ep-m", "82540EP (Mobile)", 0 ),
	PCI_ROM ( 0x8086, 0x1026, "82545gm", "82545GM", 0 ),
	PCI_ROM ( 0x8086, 0x1027, "82545gm-1", "82545GM", 0 ),
	PCI_ROM ( 0x8086, 0x1028, "82545gm-2", "82545GM", 0 ),
	PCI_ROM ( 0x8086, 0x1049, "82566mm", "82566MM", INTEL_PBS_ERRATA ),
	PCI_ROM ( 0x8086, 0x104a, "82566dm", "82566DM", INTEL_PBS_ERRATA ),
	PCI_ROM ( 0x8086, 0x104b, "82566dc", "82566DC", INTEL_PBS_ERRATA ),
	PCI_ROM ( 0x8086, 0x104c, "82562v", "82562V", INTEL_PBS_ERRATA ),
	PCI_ROM ( 0x8086, 0x104d, "82566mc", "82566MC", INTEL_PBS_ERRATA ),
	PCI_ROM ( 0x8086, 0x105e, "82571eb", "82571EB", 0 ),
	PCI_ROM ( 0x8086, 0x105f, "82571eb-1", "82571EB", 0 ),
	PCI_ROM ( 0x8086, 0x1060, "82571eb-2", "82571EB", 0 ),
	PCI_ROM ( 0x8086, 0x1075, "82547gi", "82547GI", 0 ),
	PCI_ROM ( 0x8086, 0x1076, "82541gi", "82541GI", 0 ),
	PCI_ROM ( 0x8086, 0x1077, "82541gi-1", "82541GI", 0 ),
	PCI_ROM ( 0x8086, 0x1078, "82541er", "82541ER", 0 ),
	PCI_ROM ( 0x8086, 0x1079, "82546gb", "82546GB", 0 ),
	PCI_ROM ( 0x8086, 0x107a, "82546gb-1", "82546GB", 0 ),
	PCI_ROM ( 0x8086, 0x107b, "82546gb-2", "82546GB", 0 ),
	PCI_ROM ( 0x8086, 0x107c, "82541pi", "82541PI", 0 ),
	PCI_ROM ( 0x8086, 0x107d, "82572ei", "82572EI (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x107e, "82572ei-f", "82572EI (Fiber)", 0 ),
	PCI_ROM ( 0x8086, 0x107f, "82572ei", "82572EI", 0 ),
	PCI_ROM ( 0x8086, 0x108a, "82546gb-3", "82546GB", 0 ),
	PCI_ROM ( 0x8086, 0x108b, "82573v", "82573V (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x108c, "82573e", "82573E (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x1096, "80003es2lan", "80003ES2LAN (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x1098, "80003es2lan-s", "80003ES2LAN (Serdes)", 0 ),
	PCI_ROM ( 0x8086, 0x1099, "82546gb-4", "82546GB (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x109a, "82573l", "82573L", 0 ),
	PCI_ROM ( 0x8086, 0x10a4, "82571eb", "82571EB", 0 ),
	PCI_ROM ( 0x8086, 0x10a5, "82571eb", "82571EB (Fiber)", 0 ),
	PCI_ROM ( 0x8086, 0x10a7, "82575eb", "82575EB", 0 ),
	PCI_ROM ( 0x8086, 0x10a9, "82575eb", "82575EB Backplane", 0 ),
	PCI_ROM ( 0x8086, 0x10b5, "82546gb", "82546GB (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x10b9, "82572ei", "82572EI (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x10ba, "80003es2lan", "80003ES2LAN (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x10bb, "80003es2lan", "80003ES2LAN (Serdes)", 0 ),
	PCI_ROM ( 0x8086, 0x10bc, "82571eb", "82571EB (Copper)", 0 ),
	PCI_ROM ( 0x8086, 0x10bd, "82566dm-2", "82566DM-2", 0 ),
	PCI_ROM ( 0x8086, 0x10bf, "82567lf", "82567LF", 0 ),
	PCI_ROM ( 0x8086, 0x10c0, "82562v-2", "82562V-2", 0 ),
	PCI_ROM ( 0x8086, 0x10c2, "82562g-2", "82562G-2", 0 ),
	PCI_ROM ( 0x8086, 0x10c3, "82562gt-2", "82562GT-2", 0 ),
	PCI_ROM ( 0x8086, 0x10c4, "82562gt", "82562GT", INTEL_PBS_ERRATA ),
	PCI_ROM ( 0x8086, 0x10c5, "82562g", "82562G", INTEL_PBS_ERRATA ),
	PCI_ROM ( 0x8086, 0x10c9, "82576", "82576", 0 ),
	PCI_ROM ( 0x8086, 0x10cb, "82567v", "82567V", 0 ),
	PCI_ROM ( 0x8086, 0x10cc, "82567lm-2", "82567LM-2", 0 ),
	PCI_ROM ( 0x8086, 0x10cd, "82567lf-2", "82567LF-2", 0 ),
	PCI_ROM ( 0x8086, 0x10ce, "82567v-2", "82567V-2", 0 ),
	PCI_ROM ( 0x8086, 0x10d3, "82574l", "82574L", 0 ),
	PCI_ROM ( 0x8086, 0x10d5, "82571pt", "82571PT PT Quad", 0 ),
	PCI_ROM ( 0x8086, 0x10d6, "82575gb", "82575GB", 0 ),
	PCI_ROM ( 0x8086, 0x10d9, "82571eb-d", "82571EB Dual Mezzanine", 0 ),
	PCI_ROM ( 0x8086, 0x10da, "82571eb-q", "82571EB Quad Mezzanine", 0 ),
	PCI_ROM ( 0x8086, 0x10de, "82567lm-3", "82567LM-3", 0 ),
	PCI_ROM ( 0x8086, 0x10df, "82567lf-3", "82567LF-3", 0 ),
	PCI_ROM ( 0x8086, 0x10e5, "82567lm-4", "82567LM-4", 0 ),
	PCI_ROM ( 0x8086, 0x10e6, "82576", "82576", 0 ),
	PCI_ROM ( 0x8086, 0x10e7, "82576-2", "82576", 0 ),
	PCI_ROM ( 0x8086, 0x10e8, "82576-3", "82576", 0 ),
	PCI_ROM ( 0x8086, 0x10ea, "82577lm", "82577LM", 0 ),
	PCI_ROM ( 0x8086, 0x10eb, "82577lc", "82577LC", 0 ),
	PCI_ROM ( 0x8086, 0x10ef, "82578dm", "82578DM", 0 ),
	PCI_ROM ( 0x8086, 0x10f0, "82578dc", "82578DC", 0 ),
	PCI_ROM ( 0x8086, 0x10f5, "82567lm", "82567LM", 0 ),
	PCI_ROM ( 0x8086, 0x10f6, "82574l", "82574L", 0 ),
	PCI_ROM ( 0x8086, 0x1501, "82567v-3", "82567V-3", INTEL_PBS_ERRATA ),
	PCI_ROM ( 0x8086, 0x1502, "82579lm", "82579LM", 0 ),
	PCI_ROM ( 0x8086, 0x1503, "82579v", "82579V", 0 ),
	PCI_ROM ( 0x8086, 0x150a, "82576ns", "82576NS", 0 ),
	PCI_ROM ( 0x8086, 0x150c, "82583v", "82583V", 0 ),
	PCI_ROM ( 0x8086, 0x150d, "82576-4", "82576 Backplane", 0 ),
	PCI_ROM ( 0x8086, 0x150e, "82580", "82580", 0 ),
	PCI_ROM ( 0x8086, 0x150f, "82580-f", "82580 Fiber", 0 ),
	PCI_ROM ( 0x8086, 0x1510, "82580-b", "82580 Backplane", 0 ),
	PCI_ROM ( 0x8086, 0x1511, "82580-s", "82580 SFP", 0 ),
	PCI_ROM ( 0x8086, 0x1516, "82580-2", "82580", 0 ),
	PCI_ROM ( 0x8086, 0x1518, "82576ns", "82576NS SerDes", 0 ),
	PCI_ROM ( 0x8086, 0x1521, "i350", "I350", 0 ),
	PCI_ROM ( 0x8086, 0x1522, "i350-f", "I350 Fiber", 0 ),
	PCI_ROM ( 0x8086, 0x1523, "i350-b", "I350 Backplane", 0 ),
	PCI_ROM ( 0x8086, 0x1524, "i350-2", "I350", 0 ),
	PCI_ROM ( 0x8086, 0x1525, "82567v-4", "82567V-4", 0 ),
	PCI_ROM ( 0x8086, 0x1526, "82576-5", "82576", 0 ),
	PCI_ROM ( 0x8086, 0x1527, "82580-f2", "82580 Fiber", 0 ),
	PCI_ROM ( 0x8086, 0x1533, "i210", "I210", 0 ),
	PCI_ROM ( 0x8086, 0x153a, "i217lm", "I217-LM", 0 ),
	PCI_ROM ( 0x8086, 0x153b, "i217v", "I217-V", 0 ),
	PCI_ROM ( 0x8086, 0x1559, "i218v", "I218-V", 0),
	PCI_ROM ( 0x8086, 0x155a, "i218lm", "I218-LM", 0),
	PCI_ROM ( 0x8086, 0x15a0, "i218lm-2", "I218-LM", 0 ),
	PCI_ROM ( 0x8086, 0x15a1, "i218v-2", "I218-V", 0 ),
	PCI_ROM ( 0x8086, 0x15a2, "i218lm-3", "I218-LM", 0 ),
	PCI_ROM ( 0x8086, 0x15a3, "i218v-3", "I218-V", 0 ),
	PCI_ROM ( 0x8086, 0x294c, "82566dc-2", "82566DC-2", 0 ),
	PCI_ROM ( 0x8086, 0x2e6e, "cemedia", "CE Media Processor", 0 ),
};

/** Intel PCI driver */
struct pci_driver intel_driver __pci_driver = {
	.ids = intel_nics,
	.id_count = ( sizeof ( intel_nics ) / sizeof ( intel_nics[0] ) ),
	.probe = intel_probe,
	.remove = intel_remove,
};
