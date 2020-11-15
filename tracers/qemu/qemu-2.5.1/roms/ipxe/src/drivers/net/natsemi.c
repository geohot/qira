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
 */

FILE_LICENCE ( GPL2_OR_LATER );

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
#include <ipxe/nvs.h>
#include <ipxe/bitbash.h>
#include <ipxe/spi_bit.h>
#include <ipxe/threewire.h>
#include "natsemi.h"

/** @file
 *
 * National Semiconductor "MacPhyter" network card driver
 *
 * Based on the following datasheets:
 *
 *    http://www.ti.com/lit/ds/symlink/dp83820.pdf
 *    http://www.datasheets.org.uk/indexdl/Datasheet-03/DSA0041338.pdf
 *
 */

/******************************************************************************
 *
 * EEPROM interface
 *
 ******************************************************************************
 */

/** Pin mapping for SPI bit-bashing interface */
static const uint8_t natsemi_eeprom_bits[] = {
	[SPI_BIT_SCLK]	= NATSEMI_MEAR_EECLK,
	[SPI_BIT_MOSI]	= NATSEMI_MEAR_EEDI,
	[SPI_BIT_MISO]	= NATSEMI_MEAR_EEDO,
	[SPI_BIT_SS(0)]	= NATSEMI_MEAR_EESEL,
};

/**
 * Read input bit
 *
 * @v basher		Bit-bashing interface
 * @v bit_id		Bit number
 * @ret zero		Input is a logic 0
 * @ret non-zero	Input is a logic 1
 */
static int natsemi_spi_read_bit ( struct bit_basher *basher,
				  unsigned int bit_id ) {
	struct natsemi_nic *natsemi = container_of ( basher, struct natsemi_nic,
						     spibit.basher );
	uint32_t mask = natsemi_eeprom_bits[bit_id];
	uint32_t reg;

	DBG_DISABLE ( DBGLVL_IO );
	reg = readl ( natsemi->regs + NATSEMI_MEAR );
	DBG_ENABLE ( DBGLVL_IO );
	return ( reg & mask );
}

/**
 * Set/clear output bit
 *
 * @v basher		Bit-bashing interface
 * @v bit_id		Bit number
 * @v data		Value to write
 */
static void natsemi_spi_write_bit ( struct bit_basher *basher,
				    unsigned int bit_id, unsigned long data ) {
	struct natsemi_nic *natsemi = container_of ( basher, struct natsemi_nic,
						     spibit.basher );
	uint32_t mask = natsemi_eeprom_bits[bit_id];
	uint32_t reg;

	DBG_DISABLE ( DBGLVL_IO );
	reg = readl ( natsemi->regs + NATSEMI_MEAR );
	reg &= ~mask;
	reg |= ( data & mask );
	writel ( reg, natsemi->regs + NATSEMI_MEAR );
	DBG_ENABLE ( DBGLVL_IO );
}

/** SPI bit-bashing interface */
static struct bit_basher_operations natsemi_basher_ops = {
	.read = natsemi_spi_read_bit,
	.write = natsemi_spi_write_bit,
};

/**
 * Initialise EEPROM
 *
 * @v natsemi		National Semiconductor device
 */
static void natsemi_init_eeprom ( struct natsemi_nic *natsemi ) {

	/* Initialise SPI bit-bashing interface */
	natsemi->spibit.basher.op = &natsemi_basher_ops;
	natsemi->spibit.bus.mode = SPI_MODE_THREEWIRE;
	natsemi->spibit.endianness =
		( ( natsemi->flags & NATSEMI_EEPROM_LITTLE_ENDIAN ) ?
		  SPI_BIT_LITTLE_ENDIAN : SPI_BIT_BIG_ENDIAN );
	init_spi_bit_basher ( &natsemi->spibit );

	/* Initialise EEPROM device */
	init_at93c06 ( &natsemi->eeprom, 16 );
	natsemi->eeprom.bus = &natsemi->spibit.bus;
}

/**
 * Get hardware address from sane EEPROM data
 *
 * @v natsemi		National Semiconductor device
 * @v eeprom		EEPROM data
 * @v hw_addr		Hardware address to fill in
 */
static void natsemi_hwaddr_sane ( struct natsemi_nic *natsemi,
				  const uint16_t *eeprom, uint16_t *hw_addr ) {
	int i;

	/* Copy MAC address from EEPROM data */
	for ( i = ( ( ETH_ALEN / 2 ) - 1 ) ; i >= 0 ; i-- )
		*(hw_addr++) = eeprom[ NATSEMI_EEPROM_MAC_SANE + i ];

	DBGC ( natsemi, "NATSEMI %p has sane EEPROM layout\n", natsemi );
}

/**
 * Get hardware address from insane EEPROM data
 *
 * @v natsemi		National Semiconductor device
 * @v eeprom		EEPROM data
 * @v hw_addr		Hardware address to fill in
 */
static void natsemi_hwaddr_insane ( struct natsemi_nic *natsemi,
				    const uint16_t *eeprom,
				    uint16_t *hw_addr ) {
	unsigned int i;
	unsigned int offset;
	uint16_t word;

	/* Copy MAC address from EEPROM data */
	for ( i = 0 ; i < ( ETH_ALEN / 2 ) ; i++ ) {
		offset = ( NATSEMI_EEPROM_MAC_INSANE + i );
		word = ( ( le16_to_cpu ( eeprom[ offset ] ) >> 15 ) |
			 ( le16_to_cpu ( eeprom[ offset + 1 ] << 1 ) ) );
		hw_addr[i] = cpu_to_le16 ( word );
	}

	DBGC ( natsemi, "NATSEMI %p has insane EEPROM layout\n", natsemi );
}

/**
 * Get hardware address from EEPROM
 *
 * @v natsemi		National Semiconductor device
 * @v hw_addr		Hardware address to fill in
 * @ret rc		Return status code
 */
static int natsemi_hwaddr ( struct natsemi_nic *natsemi, void *hw_addr ) {
	uint16_t buf[NATSEMI_EEPROM_SIZE];
	void ( * extract ) ( struct natsemi_nic *natsemi,
			     const uint16_t *eeprom, uint16_t *hw_addr );
	int rc;

	/* Read EEPROM contents */
	if ( ( rc = nvs_read ( &natsemi->eeprom.nvs, 0, buf,
			       sizeof ( buf ) ) ) != 0 ) {
		DBGC ( natsemi, "NATSEMI %p could not read EEPROM: %s\n",
		       natsemi, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( natsemi, "NATSEMI %p EEPROM contents:\n", natsemi );
	DBGC2_HDA ( natsemi, 0, buf, sizeof ( buf ) );

	/* Extract MAC address from EEPROM contents */
	extract = ( ( natsemi->flags & NATSEMI_EEPROM_INSANE ) ?
		    natsemi_hwaddr_insane : natsemi_hwaddr_sane );
	extract ( natsemi, buf, hw_addr );

	return 0;
}

/******************************************************************************
 *
 * Device reset
 *
 ******************************************************************************
 */

/**
 * Reset controller chip
 *
 * @v natsemi		National Semiconductor device
 * @ret rc		Return status code
 */
static int natsemi_soft_reset ( struct natsemi_nic *natsemi ) {
	unsigned int i;

	/* Initiate reset */
	writel ( NATSEMI_CR_RST, natsemi->regs + NATSEMI_CR );

	/* Wait for reset to complete */
	for ( i = 0 ; i < NATSEMI_RESET_MAX_WAIT_MS ; i++ ) {

		/* If reset is not complete, delay 1ms and retry */
		if ( readl ( natsemi->regs + NATSEMI_CR ) & NATSEMI_CR_RST ) {
			mdelay ( 1 );
			continue;
		}

		return 0;
	}

	DBGC ( natsemi, "NATSEMI %p timed out waiting for reset\n", natsemi );
	return -ETIMEDOUT;
}

/**
 * Reload configuration from EEPROM
 *
 * @v natsemi		National Semiconductor device
 * @ret rc		Return status code
 */
static int natsemi_reload_config ( struct natsemi_nic *natsemi ) {
	unsigned int i;

	/* Initiate reload */
	writel ( NATSEMI_PTSCR_EELOAD_EN, natsemi->regs + NATSEMI_PTSCR );

	/* Wait for reload to complete */
	for ( i = 0 ; i < NATSEMI_EELOAD_MAX_WAIT_MS ; i++ ) {

		/* If reload is not complete, delay 1ms and retry */
		if ( readl ( natsemi->regs + NATSEMI_PTSCR ) &
		     NATSEMI_PTSCR_EELOAD_EN ) {
			mdelay ( 1 );
			continue;
		}

		return 0;
	}

	DBGC ( natsemi, "NATSEMI %p timed out waiting for configuration "
	       "reload\n", natsemi );
	return -ETIMEDOUT;
}

/**
 * Reset hardware
 *
 * @v natsemi		National Semiconductor device
 * @ret rc		Return status code
 */
static int natsemi_reset ( struct natsemi_nic *natsemi ) {
	uint32_t cfg;
	int rc;

	/* Perform soft reset */
	if ( ( rc = natsemi_soft_reset ( natsemi ) ) != 0 )
		return rc;

	/* Reload configuration from EEPROM */
	if ( ( rc = natsemi_reload_config ( natsemi ) ) != 0 )
		return rc;

	/* Configure 64-bit operation, if applicable */
	cfg = readl ( natsemi->regs + NATSEMI_CFG );
	if ( natsemi->flags & NATSEMI_64BIT ) {
		cfg |= ( NATSEMI_CFG_M64ADDR | NATSEMI_CFG_EXTSTS_EN );
		if ( ! ( cfg & NATSEMI_CFG_PCI64_DET ) )
			cfg &= ~NATSEMI_CFG_DATA64_EN;
	}
	writel ( cfg, natsemi->regs + NATSEMI_CFG );

	/* Invalidate link status cache to force an update */
	natsemi->cfg = ~cfg;

	DBGC ( natsemi, "NATSEMI %p using configuration %08x\n",
	       natsemi, cfg );
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
static void natsemi_check_link ( struct net_device *netdev ) {
	struct natsemi_nic *natsemi = netdev->priv;
	uint32_t cfg;

	/* Read link status */
	cfg = readl ( natsemi->regs + NATSEMI_CFG );

	/* Do nothing unless link status has changed */
	if ( cfg == natsemi->cfg )
		return;

	/* Set gigabit mode (if applicable) */
	if ( natsemi->flags & NATSEMI_1000 ) {
		cfg &= ~NATSEMI_CFG_MODE_1000;
		if ( ! ( cfg & NATSEMI_CFG_SPDSTS1 ) )
			cfg |= NATSEMI_CFG_MODE_1000;
		writel ( cfg, natsemi->regs + NATSEMI_CFG );
	}

	/* Update link status */
	natsemi->cfg = cfg;
	DBGC ( natsemi, "NATSEMI %p link status is %08x\n", natsemi, cfg );

	/* Update network device */
	if ( cfg & NATSEMI_CFG_LNKSTS ) {
		netdev_link_up ( netdev );
	} else {
		netdev_link_down ( netdev );
	}
}

/******************************************************************************
 *
 * Network device interface
 *
 ******************************************************************************
 */

/**
 * Set perfect match filter address
 *
 * @v natsemi		National Semiconductor device
 * @v mac		MAC address
 */
static void natsemi_pmatch ( struct natsemi_nic *natsemi, const void *mac ) {
	const uint16_t *pmatch = mac;
	uint32_t rfcr;
	unsigned int rfaddr;
	unsigned int i;

	for ( i = 0 ; i < ETH_ALEN ; i += sizeof ( *pmatch ) ) {

		/* Select receive filter register address */
		rfaddr = ( NATSEMI_RFADDR_PMATCH_BASE + i );
		rfcr = readl ( natsemi->regs + NATSEMI_RFCR );
		rfcr &= ~NATSEMI_RFCR_RFADDR_MASK;
		rfcr |= NATSEMI_RFCR_RFADDR ( rfaddr );
		writel ( rfcr, natsemi->regs + NATSEMI_RFCR );

		/* Write receive filter data */
		writel ( ( le16_to_cpu ( *(pmatch++) ) | NATSEMI_RFDR_BMASK ),
			 natsemi->regs + NATSEMI_RFDR );
	}
}

/**
 * Create descriptor ring
 *
 * @v natsemi		National Semiconductor device
 * @v ring		Descriptor ring
 * @ret rc		Return status code
 */
static int natsemi_create_ring ( struct natsemi_nic *natsemi,
				 struct natsemi_ring *ring ) {
	size_t len = ( ring->count * sizeof ( ring->desc[0] ) );
	union natsemi_descriptor *desc;
	union natsemi_descriptor *linked_desc;
	physaddr_t address;
	physaddr_t link;
	size_t offset;
	unsigned int i;
	int rc;

	/* Calculate descriptor offset */
	offset = ( ( natsemi->flags & NATSEMI_64BIT ) ? 0 :
		   offsetof ( typeof ( desc[i].d32pad ), d32 ) );

	/* Allocate descriptor ring.  Align ring on its own size to
	 * ensure that it can't possibly cross the boundary of 32-bit
	 * address space.
	 */
	ring->desc = malloc_dma ( len, len );
	if ( ! ring->desc ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	address = ( virt_to_bus ( ring->desc ) + offset );

	/* Check address is usable by card */
	if ( ! natsemi_address_ok ( natsemi, address ) ) {
		DBGC ( natsemi, "NATSEMI %p cannot support 64-bit ring "
		       "address\n", natsemi );
		rc = -ENOTSUP;
		goto err_64bit;
	}

	/* Initialise descriptor ring */
	memset ( ring->desc, 0, len );
	for ( i = 0 ; i < ring->count ; i++ ) {
		linked_desc = &ring->desc [ ( i + 1 ) % ring->count ];
		link = ( virt_to_bus ( linked_desc ) + offset );
		if ( natsemi->flags & NATSEMI_64BIT ) {
			ring->desc[i].d64.link = cpu_to_le64 ( link );
		} else {
			ring->desc[i].d32pad.d32.link = cpu_to_le32 ( link );
		}
	}

	/* Program ring address */
	writel ( ( address & 0xffffffffUL ), natsemi->regs + ring->reg );
	if ( natsemi->flags & NATSEMI_64BIT ) {
		if ( sizeof ( physaddr_t ) > sizeof ( uint32_t ) ) {
			writel ( ( ( ( uint64_t ) address ) >> 32 ),
				 natsemi->regs + ring->reg + 4 );
		} else {
			writel ( 0, natsemi->regs + ring->reg + 4 );
		}
	}

	DBGC ( natsemi, "NATSEMI %p ring %02x is at [%08llx,%08llx)\n",
	       natsemi, ring->reg,
	       ( ( unsigned long long ) virt_to_bus ( ring->desc ) ),
	       ( ( unsigned long long ) virt_to_bus ( ring->desc ) + len ) );

	return 0;

 err_64bit:
	free_dma ( ring->desc, len );
	ring->desc = NULL;
 err_alloc:
	return rc;
}

/**
 * Destroy descriptor ring
 *
 * @v natsemi		National Semiconductor device
 * @v ring		Descriptor ring
 */
static void natsemi_destroy_ring ( struct natsemi_nic *natsemi,
				   struct natsemi_ring *ring ) {
	size_t len = ( ring->count * sizeof ( ring->desc[0] ) );

	/* Clear ring address */
	writel ( 0, natsemi->regs + ring->reg );
	if ( natsemi->flags & NATSEMI_64BIT )
		writel ( 0, natsemi->regs + ring->reg + 4 );

	/* Free descriptor ring */
	free_dma ( ring->desc, len );
	ring->desc = NULL;
	ring->prod = 0;
	ring->cons = 0;
}

/**
 * Refill receive descriptor ring
 *
 * @v netdev		Network device
 */
static void natsemi_refill_rx ( struct net_device *netdev ) {
	struct natsemi_nic *natsemi = netdev->priv;
	union natsemi_descriptor *rx;
	struct io_buffer *iobuf;
	unsigned int rx_idx;
	physaddr_t address;

	while ( ( natsemi->rx.prod - natsemi->rx.cons ) < NATSEMI_NUM_RX_DESC ){

		/* Allocate I/O buffer */
		iobuf = alloc_iob ( NATSEMI_RX_MAX_LEN );
		if ( ! iobuf ) {
			/* Wait for next refill */
			return;
		}

		/* Check address is usable by card */
		address = virt_to_bus ( iobuf->data );
		if ( ! natsemi_address_ok ( natsemi, address ) ) {
			DBGC ( natsemi, "NATSEMI %p cannot support 64-bit RX "
			       "buffer address\n", natsemi );
			netdev_rx_err ( netdev, iobuf, -ENOTSUP );
			return;
		}

		/* Get next receive descriptor */
		rx_idx = ( natsemi->rx.prod++ % NATSEMI_NUM_RX_DESC );
		rx = &natsemi->rx.desc[rx_idx];

		/* Populate receive descriptor */
		if ( natsemi->flags & NATSEMI_64BIT ) {
			rx->d64.bufptr = cpu_to_le64 ( address );
		} else {
			rx->d32pad.d32.bufptr = cpu_to_le32 ( address );
		}
		wmb();
		rx->common.cmdsts = cpu_to_le32 ( NATSEMI_DESC_INTR |
						  NATSEMI_RX_MAX_LEN );
		wmb();

		/* Record I/O buffer */
		assert ( natsemi->rx_iobuf[rx_idx] == NULL );
		natsemi->rx_iobuf[rx_idx] = iobuf;

		/* Notify card that there are descriptors available */
		writel ( NATSEMI_CR_RXE, natsemi->regs + NATSEMI_CR );

		DBGC2 ( natsemi, "NATSEMI %p RX %d is [%llx,%llx)\n", natsemi,
			rx_idx, ( ( unsigned long long ) address ),
			( ( unsigned long long ) address + NATSEMI_RX_MAX_LEN));
	}
}

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int natsemi_open ( struct net_device *netdev ) {
	struct natsemi_nic *natsemi = netdev->priv;
	int rc;

	/* Set MAC address */
	natsemi_pmatch ( natsemi, netdev->ll_addr );

	/* Create transmit descriptor ring */
	if ( ( rc = natsemi_create_ring ( natsemi, &natsemi->tx ) ) != 0 )
		goto err_create_tx;

	/* Set transmit configuration */
	writel ( ( NATSEMI_TXCFG_CSI | NATSEMI_TXCFG_HBI | NATSEMI_TXCFG_ATP |
		   NATSEMI_TXCFG_ECRETRY | NATSEMI_TXCFG_MXDMA_DEFAULT |
		   NATSEMI_TXCFG_FLTH_DEFAULT | NATSEMI_TXCFG_DRTH_DEFAULT ),
		 ( natsemi->regs + ( ( natsemi->flags & NATSEMI_64BIT ) ?
				     NATSEMI_TXCFG_64 : NATSEMI_TXCFG_32 ) ) );

	/* Create receive descriptor ring */
	if ( ( rc = natsemi_create_ring ( natsemi, &natsemi->rx ) ) != 0 )
		goto err_create_rx;

	/* Set receive configuration */
	writel ( ( NATSEMI_RXCFG_ARP | NATSEMI_RXCFG_ATX | NATSEMI_RXCFG_ALP |
		   NATSEMI_RXCFG_MXDMA_DEFAULT | NATSEMI_RXCFG_DRTH_DEFAULT ),
		 ( natsemi->regs + ( ( natsemi->flags & NATSEMI_64BIT ) ?
				     NATSEMI_RXCFG_64 : NATSEMI_RXCFG_32 ) ) );

	/* Set receive filter configuration */
	writel ( ( NATSEMI_RFCR_RFEN | NATSEMI_RFCR_AAB | NATSEMI_RFCR_AAM |
		   NATSEMI_RFCR_AAU ), natsemi->regs + NATSEMI_RFCR );

	/* Fill receive ring */
	natsemi_refill_rx ( netdev );

	/* Unmask transmit and receive interrupts.  (Interrupts will
	 * not be generated unless enabled via the IER.)
	 */
	writel ( ( NATSEMI_IRQ_TXDESC | NATSEMI_IRQ_RXDESC ),
		 natsemi->regs + NATSEMI_IMR );

	/* Update link state */
	natsemi_check_link ( netdev );

	return 0;

	natsemi_destroy_ring ( natsemi, &natsemi->rx );
 err_create_rx:
	natsemi_destroy_ring ( natsemi, &natsemi->tx );
 err_create_tx:
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void natsemi_close ( struct net_device *netdev ) {
	struct natsemi_nic *natsemi = netdev->priv;
	unsigned int i;

	/* Mask transmit and receive interrupts */
	writel ( 0, natsemi->regs + NATSEMI_IMR );

	/* Reset and disable transmitter and receiver */
	writel ( ( NATSEMI_CR_RXR | NATSEMI_CR_TXR ),
		 natsemi->regs + NATSEMI_CR );

	/* Discard any unused receive buffers */
	for ( i = 0 ; i < NATSEMI_NUM_RX_DESC ; i++ ) {
		if ( natsemi->rx_iobuf[i] )
			free_iob ( natsemi->rx_iobuf[i] );
		natsemi->rx_iobuf[i] = NULL;
	}

	/* Destroy receive descriptor ring */
	natsemi_destroy_ring ( natsemi, &natsemi->rx );

	/* Destroy transmit descriptor ring */
	natsemi_destroy_ring ( natsemi, &natsemi->tx );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int natsemi_transmit ( struct net_device *netdev,
			       struct io_buffer *iobuf ) {
	struct natsemi_nic *natsemi = netdev->priv;
	union natsemi_descriptor *tx;
	unsigned int tx_idx;
	physaddr_t address;

	/* Check address is usable by card */
	address = virt_to_bus ( iobuf->data );
	if ( ! natsemi_address_ok ( natsemi, address ) ) {
		DBGC ( natsemi, "NATSEMI %p cannot support 64-bit TX buffer "
		       "address\n", natsemi );
		return -ENOTSUP;
	}

	/* Get next transmit descriptor */
	if ( ( natsemi->tx.prod - natsemi->tx.cons ) >= NATSEMI_NUM_TX_DESC ) {
		DBGC ( natsemi, "NATSEMI %p out of transmit descriptors\n",
		       natsemi );
		return -ENOBUFS;
	}
	tx_idx = ( natsemi->tx.prod++ % NATSEMI_NUM_TX_DESC );
	tx = &natsemi->tx.desc[tx_idx];

	/* Populate transmit descriptor */
	if ( natsemi->flags & NATSEMI_64BIT ) {
		tx->d64.bufptr = cpu_to_le64 ( address );
	} else {
		tx->d32pad.d32.bufptr = cpu_to_le32 ( address );
	}
	wmb();
	tx->common.cmdsts = cpu_to_le32 ( NATSEMI_DESC_OWN | NATSEMI_DESC_INTR |
					  iob_len ( iobuf ) );
	wmb();

	/* Notify card that there are packets ready to transmit */
	writel ( NATSEMI_CR_TXE, natsemi->regs + NATSEMI_CR );

	DBGC2 ( natsemi, "NATSEMI %p TX %d is [%llx,%llx)\n", natsemi, tx_idx,
		( ( unsigned long long ) address ),
		( ( unsigned long long ) address + iob_len ( iobuf ) ) );

	return 0;
}

/**
 * Poll for completed packets
 *
 * @v netdev		Network device
 */
static void natsemi_poll_tx ( struct net_device *netdev ) {
	struct natsemi_nic *natsemi = netdev->priv;
	union natsemi_descriptor *tx;
	unsigned int tx_idx;

	/* Check for completed packets */
	while ( natsemi->tx.cons != natsemi->tx.prod ) {

		/* Get next transmit descriptor */
		tx_idx = ( natsemi->tx.cons % NATSEMI_NUM_TX_DESC );
		tx = &natsemi->tx.desc[tx_idx];

		/* Stop if descriptor is still in use */
		if ( tx->common.cmdsts & cpu_to_le32 ( NATSEMI_DESC_OWN ) )
			return;

		/* Complete TX descriptor */
		if ( tx->common.cmdsts & cpu_to_le32 ( NATSEMI_DESC_OK ) ) {
			DBGC2 ( natsemi, "NATSEMI %p TX %d complete\n",
				natsemi, tx_idx );
			netdev_tx_complete_next ( netdev );
		} else {
			DBGC ( natsemi, "NATSEMI %p TX %d completion error "
			       "(%08x)\n", natsemi, tx_idx,
			       le32_to_cpu ( tx->common.cmdsts ) );
			netdev_tx_complete_next_err ( netdev, -EIO );
		}
		natsemi->tx.cons++;
	}
}

/**
 * Poll for received packets
 *
 * @v netdev		Network device
 */
static void natsemi_poll_rx ( struct net_device *netdev ) {
	struct natsemi_nic *natsemi = netdev->priv;
	union natsemi_descriptor *rx;
	struct io_buffer *iobuf;
	unsigned int rx_idx;
	size_t len;

	/* Check for received packets */
	while ( natsemi->rx.cons != natsemi->rx.prod ) {

		/* Get next receive descriptor */
		rx_idx = ( natsemi->rx.cons % NATSEMI_NUM_RX_DESC );
		rx = &natsemi->rx.desc[rx_idx];

		/* Stop if descriptor is still in use */
		if ( ! ( rx->common.cmdsts & NATSEMI_DESC_OWN ) )
			return;

		/* Populate I/O buffer */
		iobuf = natsemi->rx_iobuf[rx_idx];
		natsemi->rx_iobuf[rx_idx] = NULL;
		len = ( le32_to_cpu ( rx->common.cmdsts ) &
			NATSEMI_DESC_SIZE_MASK );
		iob_put ( iobuf, len - 4 /* strip CRC */ );

		/* Hand off to network stack */
		if ( rx->common.cmdsts & cpu_to_le32 ( NATSEMI_DESC_OK ) ) {
			DBGC2 ( natsemi, "NATSEMI %p RX %d complete (length "
				"%zd)\n", natsemi, rx_idx, len );
			netdev_rx ( netdev, iobuf );
		} else {
			DBGC ( natsemi, "NATSEMI %p RX %d error (length %zd, "
			       "status %08x)\n", natsemi, rx_idx, len,
			       le32_to_cpu ( rx->common.cmdsts ) );
			netdev_rx_err ( netdev, iobuf, -EIO );
		}
		natsemi->rx.cons++;
	}
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void natsemi_poll ( struct net_device *netdev ) {
	struct natsemi_nic *natsemi = netdev->priv;
	uint32_t isr;

	/* Poll for link state.  The PHY interrupt seems not to
	 * function as expected, and polling for the link state is
	 * only a single register read.
	 */
	natsemi_check_link ( netdev );

	/* Check for and acknowledge interrupts */
	isr = readl ( natsemi->regs + NATSEMI_ISR );
	if ( ! isr )
		return;

	/* Poll for TX completions, if applicable */
	if ( isr & NATSEMI_IRQ_TXDESC )
		natsemi_poll_tx ( netdev );

	/* Poll for RX completionsm, if applicable */
	if ( isr & NATSEMI_IRQ_RXDESC )
		natsemi_poll_rx ( netdev );

	/* Refill RX ring */
	natsemi_refill_rx ( netdev );
}

/**
 * Enable or disable interrupts
 *
 * @v netdev		Network device
 * @v enable		Interrupts should be enabled
 */
static void natsemi_irq ( struct net_device *netdev, int enable ) {
	struct natsemi_nic *natsemi = netdev->priv;

	/* Enable or disable interrupts */
	writel ( ( enable ? NATSEMI_IER_IE : 0 ), natsemi->regs + NATSEMI_IER );
}

/** National Semiconductor network device operations */
static struct net_device_operations natsemi_operations = {
	.open		= natsemi_open,
	.close		= natsemi_close,
	.transmit	= natsemi_transmit,
	.poll		= natsemi_poll,
	.irq		= natsemi_irq,
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
static int natsemi_probe ( struct pci_device *pci ) {
	struct net_device *netdev;
	struct natsemi_nic *natsemi;
	int rc;

	/* Allocate and initialise net device */
	netdev = alloc_etherdev ( sizeof ( *natsemi ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &natsemi_operations );
	natsemi = netdev->priv;
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;
	memset ( natsemi, 0, sizeof ( *natsemi ) );
	natsemi->flags = pci->id->driver_data;
	natsemi_init_ring ( &natsemi->tx, NATSEMI_NUM_TX_DESC, NATSEMI_TXDP );
	natsemi_init_ring ( &natsemi->rx, NATSEMI_NUM_RX_DESC, NATSEMI_RXDP );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Map registers */
	natsemi->regs = ioremap ( pci->membase, NATSEMI_BAR_SIZE );
	if ( ! natsemi->regs ) {
		rc = -ENODEV;
		goto err_ioremap;
	}

	/* Reset the NIC */
	if ( ( rc = natsemi_reset ( natsemi ) ) != 0 )
		goto err_reset;

	/* Initialise EEPROM */
	natsemi_init_eeprom ( natsemi );

	/* Read initial MAC address */
	if ( ( rc = natsemi_hwaddr ( natsemi, netdev->hw_addr ) ) != 0 )
		goto err_hwaddr;

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register_netdev;

	/* Set initial link state */
	natsemi_check_link ( netdev );

	return 0;

	unregister_netdev ( netdev );
 err_register_netdev:
 err_hwaddr:
	natsemi_reset ( natsemi );
 err_reset:
	iounmap ( natsemi->regs );
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
static void natsemi_remove ( struct pci_device *pci ) {
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct natsemi_nic *natsemi = netdev->priv;

	/* Unregister network device */
	unregister_netdev ( netdev );

	/* Reset card */
	natsemi_reset ( natsemi );

	/* Free network device */
	iounmap ( natsemi->regs );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** Flags for DP83815 */
#define DP83815_FLAGS ( NATSEMI_EEPROM_LITTLE_ENDIAN | NATSEMI_EEPROM_INSANE )

/** Flags for DP83820 */
#define DP83820_FLAGS ( NATSEMI_64BIT | NATSEMI_1000 )

/** National Semiconductor PCI device IDs */
static struct pci_device_id natsemi_nics[] = {
	PCI_ROM ( 0x100b, 0x0020, "dp83815", "DP83815", DP83815_FLAGS ),
	PCI_ROM ( 0x100b, 0x0022, "dp83820", "DP83820", DP83820_FLAGS ),
};

/** National Semiconductor PCI driver */
struct pci_driver natsemi_driver __pci_driver = {
	.ids = natsemi_nics,
	.id_count = ( sizeof ( natsemi_nics ) / sizeof ( natsemi_nics[0] ) ),
	.probe = natsemi_probe,
	.remove = natsemi_remove,
};
