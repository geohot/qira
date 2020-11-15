/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * (EEPROM code originally implemented for rtl8139.c)
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
#include <ipxe/nvs.h>
#include <ipxe/threewire.h>
#include <ipxe/bitbash.h>
#include <ipxe/mii.h>
#include "realtek.h"

/** @file
 *
 * Realtek 10/100/1000 network card driver
 *
 * Based on the following datasheets:
 *
 *    http://www.datasheetarchive.com/dl/Datasheets-8/DSA-153536.pdf
 *    http://www.datasheetarchive.com/indexdl/Datasheet-028/DSA00494723.pdf
 */

/******************************************************************************
 *
 * Debugging
 *
 ******************************************************************************
 */

/**
 * Dump all registers (for debugging)
 *
 * @v rtl		Realtek device
 */
static __attribute__ (( unused )) void realtek_dump ( struct realtek_nic *rtl ){
	uint8_t regs[256];
	unsigned int i;

	/* Do nothing unless debug output is enabled */
	if ( ! DBG_LOG )
		return;

	/* Dump registers (via byte accesses; may not work for all registers) */
	for ( i = 0 ; i < sizeof ( regs ) ; i++ )
		regs[i] = readb ( rtl->regs + i );
	DBGC ( rtl, "REALTEK %p register dump:\n", rtl );
	DBGC_HDA ( rtl, 0, regs, sizeof ( regs ) );
}

/******************************************************************************
 *
 * EEPROM interface
 *
 ******************************************************************************
 */

/** Pin mapping for SPI bit-bashing interface */
static const uint8_t realtek_eeprom_bits[] = {
	[SPI_BIT_SCLK]	= RTL_9346CR_EESK,
	[SPI_BIT_MOSI]	= RTL_9346CR_EEDI,
	[SPI_BIT_MISO]	= RTL_9346CR_EEDO,
	[SPI_BIT_SS(0)]	= RTL_9346CR_EECS,
};

/**
 * Open bit-bashing interface
 *
 * @v basher		Bit-bashing interface
 */
static void realtek_spi_open_bit ( struct bit_basher *basher ) {
	struct realtek_nic *rtl = container_of ( basher, struct realtek_nic,
						 spibit.basher );

	/* Enable EEPROM access */
	writeb ( RTL_9346CR_EEM_EEPROM, rtl->regs + RTL_9346CR );
	readb ( rtl->regs + RTL_9346CR ); /* Ensure write reaches chip */
}

/**
 * Close bit-bashing interface
 *
 * @v basher		Bit-bashing interface
 */
static void realtek_spi_close_bit ( struct bit_basher *basher ) {
	struct realtek_nic *rtl = container_of ( basher, struct realtek_nic,
						 spibit.basher );

	/* Disable EEPROM access */
	writeb ( RTL_9346CR_EEM_NORMAL, rtl->regs + RTL_9346CR );
	readb ( rtl->regs + RTL_9346CR ); /* Ensure write reaches chip */
}

/**
 * Read input bit
 *
 * @v basher		Bit-bashing interface
 * @v bit_id		Bit number
 * @ret zero		Input is a logic 0
 * @ret non-zero	Input is a logic 1
 */
static int realtek_spi_read_bit ( struct bit_basher *basher,
				  unsigned int bit_id ) {
	struct realtek_nic *rtl = container_of ( basher, struct realtek_nic,
						 spibit.basher );
	uint8_t mask = realtek_eeprom_bits[bit_id];
	uint8_t reg;

	DBG_DISABLE ( DBGLVL_IO );
	reg = readb ( rtl->regs + RTL_9346CR );
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
static void realtek_spi_write_bit ( struct bit_basher *basher,
				    unsigned int bit_id, unsigned long data ) {
	struct realtek_nic *rtl = container_of ( basher, struct realtek_nic,
						 spibit.basher );
	uint8_t mask = realtek_eeprom_bits[bit_id];
	uint8_t reg;

	DBG_DISABLE ( DBGLVL_IO );
	reg = readb ( rtl->regs + RTL_9346CR );
	reg &= ~mask;
	reg |= ( data & mask );
	writeb ( reg, rtl->regs + RTL_9346CR );
	readb ( rtl->regs + RTL_9346CR ); /* Ensure write reaches chip */
	DBG_ENABLE ( DBGLVL_IO );
}

/** SPI bit-bashing interface */
static struct bit_basher_operations realtek_basher_ops = {
	.open = realtek_spi_open_bit,
	.close = realtek_spi_close_bit,
	.read = realtek_spi_read_bit,
	.write = realtek_spi_write_bit,
};

/**
 * Initialise EEPROM
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int realtek_init_eeprom ( struct net_device *netdev ) {
	struct realtek_nic *rtl = netdev->priv;
	uint16_t id;
	int rc;

	/* Initialise SPI bit-bashing interface */
	rtl->spibit.basher.op = &realtek_basher_ops;
	rtl->spibit.bus.mode = SPI_MODE_THREEWIRE;
	init_spi_bit_basher ( &rtl->spibit );

	/* Detect EEPROM type and initialise three-wire device */
	if ( readl ( rtl->regs + RTL_RCR ) & RTL_RCR_9356SEL ) {
		DBGC ( rtl, "REALTEK %p EEPROM is a 93C56\n", rtl );
		init_at93c56 ( &rtl->eeprom, 16 );
	} else {
		DBGC ( rtl, "REALTEK %p EEPROM is a 93C46\n", rtl );
		init_at93c46 ( &rtl->eeprom, 16 );
	}

	/* Check for EEPROM presence.  Some onboard NICs will have no
	 * EEPROM connected, with the BIOS being responsible for
	 * programming the initial register values.
	 */
	if ( ( rc = nvs_read ( &rtl->eeprom.nvs, RTL_EEPROM_ID,
			       &id, sizeof ( id ) ) ) != 0 ) {
		DBGC ( rtl, "REALTEK %p could not read EEPROM ID: %s\n",
		       rtl, strerror ( rc ) );
		return rc;
	}
	if ( id != cpu_to_le16 ( RTL_EEPROM_ID_MAGIC ) ) {
		DBGC ( rtl, "REALTEK %p EEPROM ID incorrect (%#04x); assuming "
		       "no EEPROM\n", rtl, le16_to_cpu ( id ) );
		return -ENODEV;
	}

	/* Initialise space for non-volatile options, if available
	 *
	 * We use offset 0x40 (i.e. address 0x20), length 0x40.  This
	 * block is marked as VPD in the Realtek datasheets, so we use
	 * it only if we detect that the card is not supporting VPD.
	 */
	if ( readb ( rtl->regs + RTL_CONFIG1 ) & RTL_CONFIG1_VPD ) {
		DBGC ( rtl, "REALTEK %p EEPROM in use for VPD; cannot use "
		       "for options\n", rtl );
	} else {
		nvo_init ( &rtl->nvo, &rtl->eeprom.nvs, RTL_EEPROM_VPD,
			   RTL_EEPROM_VPD_LEN, NULL, &netdev->refcnt );
	}

	return 0;
}

/******************************************************************************
 *
 * MII interface
 *
 ******************************************************************************
 */

/**
 * Read from MII register
 *
 * @v mii		MII interface
 * @v reg		Register address
 * @ret value		Data read, or negative error
 */
static int realtek_mii_read ( struct mii_interface *mii, unsigned int reg ) {
	struct realtek_nic *rtl = container_of ( mii, struct realtek_nic, mii );
	unsigned int i;
	uint32_t value;

	/* Fail if PHYAR register is not present */
	if ( ! rtl->have_phy_regs )
		return -ENOTSUP;

	/* Initiate read */
	writel ( RTL_PHYAR_VALUE ( 0, reg, 0 ), rtl->regs + RTL_PHYAR );

	/* Wait for read to complete */
	for ( i = 0 ; i < RTL_MII_MAX_WAIT_US ; i++ ) {

		/* If read is not complete, delay 1us and retry */
		value = readl ( rtl->regs + RTL_PHYAR );
		if ( ! ( value & RTL_PHYAR_FLAG ) ) {
			udelay ( 1 );
			continue;
		}

		/* Return register value */
		return ( RTL_PHYAR_DATA ( value ) );
	}

	DBGC ( rtl, "REALTEK %p timed out waiting for MII read\n", rtl );
	return -ETIMEDOUT;
}

/**
 * Write to MII register
 *
 * @v mii		MII interface
 * @v reg		Register address
 * @v data		Data to write
 * @ret rc		Return status code
 */
static int realtek_mii_write ( struct mii_interface *mii, unsigned int reg,
			       unsigned int data) {
	struct realtek_nic *rtl = container_of ( mii, struct realtek_nic, mii );
	unsigned int i;

	/* Fail if PHYAR register is not present */
	if ( ! rtl->have_phy_regs )
		return -ENOTSUP;

	/* Initiate write */
	writel ( RTL_PHYAR_VALUE ( RTL_PHYAR_FLAG, reg, data ),
		 rtl->regs + RTL_PHYAR );

	/* Wait for write to complete */
	for ( i = 0 ; i < RTL_MII_MAX_WAIT_US ; i++ ) {

		/* If write is not complete, delay 1us and retry */
		if ( readl ( rtl->regs + RTL_PHYAR ) & RTL_PHYAR_FLAG ) {
			udelay ( 1 );
			continue;
		}

		return 0;
	}

	DBGC ( rtl, "REALTEK %p timed out waiting for MII write\n", rtl );
	return -ETIMEDOUT;
}

/** Realtek MII operations */
static struct mii_operations realtek_mii_operations = {
	.read = realtek_mii_read,
	.write = realtek_mii_write,
};

/******************************************************************************
 *
 * Device reset
 *
 ******************************************************************************
 */

/**
 * Reset hardware
 *
 * @v rtl		Realtek device
 * @ret rc		Return status code
 */
static int realtek_reset ( struct realtek_nic *rtl ) {
	unsigned int i;

	/* Issue reset */
	writeb ( RTL_CR_RST, rtl->regs + RTL_CR );

	/* Wait for reset to complete */
	for ( i = 0 ; i < RTL_RESET_MAX_WAIT_MS ; i++ ) {

		/* If reset is not complete, delay 1ms and retry */
		if ( readb ( rtl->regs + RTL_CR ) & RTL_CR_RST ) {
			mdelay ( 1 );
			continue;
		}

		return 0;
	}

	DBGC ( rtl, "REALTEK %p timed out waiting for reset\n", rtl );
	return -ETIMEDOUT;
}

/**
 * Configure PHY for Gigabit operation
 *
 * @v rtl		Realtek device
 * @ret rc		Return status code
 */
static int realtek_phy_speed ( struct realtek_nic *rtl ) {
	int ctrl1000;
	int rc;

	/* Read CTRL1000 register */
	ctrl1000 = mii_read ( &rtl->mii, MII_CTRL1000 );
	if ( ctrl1000 < 0 ) {
		rc = ctrl1000;
		DBGC ( rtl, "REALTEK %p could not read CTRL1000: %s\n",
		       rtl, strerror ( rc ) );
		return rc;
	}

	/* Advertise 1000Mbps speeds */
	ctrl1000 |= ( ADVERTISE_1000FULL | ADVERTISE_1000HALF );
	if ( ( rc = mii_write ( &rtl->mii, MII_CTRL1000, ctrl1000 ) ) != 0 ) {
		DBGC ( rtl, "REALTEK %p could not write CTRL1000: %s\n",
		       rtl, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Reset PHY
 *
 * @v rtl		Realtek device
 * @ret rc		Return status code
 */
static int realtek_phy_reset ( struct realtek_nic *rtl ) {
	int rc;

	/* Do nothing if we have no separate PHY register access */
	if ( ! rtl->have_phy_regs )
		return 0;

	/* Perform MII reset */
	if ( ( rc = mii_reset ( &rtl->mii ) ) != 0 ) {
		DBGC ( rtl, "REALTEK %p could not reset MII: %s\n",
		       rtl, strerror ( rc ) );
		return rc;
	}

	/* Some cards (e.g. RTL8169SC) do not advertise Gigabit by
	 * default.  Try to enable advertisement of Gigabit speeds.
	 */
	if ( ( rc = realtek_phy_speed ( rtl ) ) != 0 ) {
		/* Ignore failures, since the register may not be
		 * present on non-Gigabit PHYs (e.g. RTL8101).
		 */
	}

	/* Restart autonegotiation */
	if ( ( rc = mii_restart ( &rtl->mii ) ) != 0 ) {
		DBGC ( rtl, "REALTEK %p could not restart MII: %s\n",
		       rtl, strerror ( rc ) );
		return rc;
	}

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
static void realtek_check_link ( struct net_device *netdev ) {
	struct realtek_nic *rtl = netdev->priv;
	uint8_t phystatus;
	uint8_t msr;
	int link_up;

	/* Determine link state */
	if ( rtl->have_phy_regs ) {
		mii_dump ( &rtl->mii );
		phystatus = readb ( rtl->regs + RTL_PHYSTATUS );
		link_up = ( phystatus & RTL_PHYSTATUS_LINKSTS );
		DBGC ( rtl, "REALTEK %p PHY status is %02x (%s%s%s%s%s%s, "
		       "Link%s, %sDuplex)\n", rtl, phystatus,
		       ( ( phystatus & RTL_PHYSTATUS_ENTBI ) ? "TBI" : "GMII" ),
		       ( ( phystatus & RTL_PHYSTATUS_TXFLOW ) ?
			 ", TxFlow" : "" ),
		       ( ( phystatus & RTL_PHYSTATUS_RXFLOW ) ?
			 ", RxFlow" : "" ),
		       ( ( phystatus & RTL_PHYSTATUS_1000MF ) ?
			 ", 1000Mbps" : "" ),
		       ( ( phystatus & RTL_PHYSTATUS_100M ) ?
			 ", 100Mbps" : "" ),
		       ( ( phystatus & RTL_PHYSTATUS_10M ) ?
			 ", 10Mbps" : "" ),
		       ( ( phystatus & RTL_PHYSTATUS_LINKSTS ) ?
			 "Up" : "Down" ),
		       ( ( phystatus & RTL_PHYSTATUS_FULLDUP ) ?
			 "Full" : "Half" ) );
	} else {
		msr = readb ( rtl->regs + RTL_MSR );
		link_up = ( ! ( msr & RTL_MSR_LINKB ) );
		DBGC ( rtl, "REALTEK %p media status is %02x (Link%s, "
		       "%dMbps%s%s%s%s%s)\n", rtl, msr,
		       ( ( msr & RTL_MSR_LINKB ) ? "Down" : "Up" ),
		       ( ( msr & RTL_MSR_SPEED_10 ) ? 10 : 100 ),
		       ( ( msr & RTL_MSR_TXFCE ) ? ", TxFlow" : "" ),
		       ( ( msr & RTL_MSR_RXFCE ) ? ", RxFlow" : "" ),
		       ( ( msr & RTL_MSR_AUX_STATUS ) ? ", AuxPwr" : "" ),
		       ( ( msr & RTL_MSR_TXPF ) ? ", TxPause" : "" ),
		       ( ( msr & RTL_MSR_RXPF ) ? ", RxPause" : "" ) );
	}

	/* Report link state */
	if ( link_up ) {
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
 * Create receive buffer (legacy mode)
 *
 * @v rtl		Realtek device
 * @ret rc		Return status code
 */
static int realtek_create_buffer ( struct realtek_nic *rtl ) {
	size_t len = ( RTL_RXBUF_LEN + RTL_RXBUF_PAD );
	physaddr_t address;
	int rc;

	/* Do nothing unless in legacy mode */
	if ( ! rtl->legacy )
		return 0;

	/* Allocate buffer */
	rtl->rx_buffer = malloc_dma ( len, RTL_RXBUF_ALIGN );
	if ( ! rtl->rx_buffer ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	address = virt_to_bus ( rtl->rx_buffer );

	/* Check that card can support address */
	if ( address & ~0xffffffffULL ) {
		DBGC ( rtl, "REALTEK %p cannot support 64-bit RX buffer "
		       "address\n", rtl );
		rc = -ENOTSUP;
		goto err_64bit;
	}

	/* Program buffer address */
	writel ( address, rtl->regs + RTL_RBSTART );
	DBGC ( rtl, "REALTEK %p receive buffer is at [%08llx,%08llx,%08llx)\n",
	       rtl, ( ( unsigned long long ) address ),
	       ( ( unsigned long long ) address + RTL_RXBUF_LEN ),
	       ( ( unsigned long long ) address + len ) );

	return 0;

 err_64bit:
	free_dma ( rtl->rx_buffer, len );
	rtl->rx_buffer = NULL;
 err_alloc:
	return rc;
}

/**
 * Destroy receive buffer (legacy mode)
 *
 * @v rtl		Realtek device
 */
static void realtek_destroy_buffer ( struct realtek_nic *rtl ) {
	size_t len = ( RTL_RXBUF_LEN + RTL_RXBUF_PAD );

	/* Do nothing unless in legacy mode */
	if ( ! rtl->legacy )
		return;

	/* Clear buffer address */
	writel ( 0, rtl->regs + RTL_RBSTART );

	/* Free buffer */
	free_dma ( rtl->rx_buffer, len );
	rtl->rx_buffer = NULL;
	rtl->rx_offset = 0;
}

/**
 * Create descriptor ring
 *
 * @v rtl		Realtek device
 * @v ring		Descriptor ring
 * @ret rc		Return status code
 */
static int realtek_create_ring ( struct realtek_nic *rtl,
				 struct realtek_ring *ring ) {
	physaddr_t address;

	/* Do nothing in legacy mode */
	if ( rtl->legacy )
		return 0;

	/* Allocate descriptor ring */
	ring->desc = malloc_dma ( ring->len, RTL_RING_ALIGN );
	if ( ! ring->desc )
		return -ENOMEM;

	/* Initialise descriptor ring */
	memset ( ring->desc, 0, ring->len );

	/* Program ring address */
	address = virt_to_bus ( ring->desc );
	writel ( ( ( ( uint64_t ) address ) >> 32 ),
		 rtl->regs + ring->reg + 4 );
	writel ( ( address & 0xffffffffUL ), rtl->regs + ring->reg );
	DBGC ( rtl, "REALTEK %p ring %02x is at [%08llx,%08llx)\n",
	       rtl, ring->reg, ( ( unsigned long long ) address ),
	       ( ( unsigned long long ) address + ring->len ) );

	return 0;
}

/**
 * Destroy descriptor ring
 *
 * @v rtl		Realtek device
 * @v ring		Descriptor ring
 */
static void realtek_destroy_ring ( struct realtek_nic *rtl,
				   struct realtek_ring *ring ) {

	/* Reset producer and consumer counters */
	ring->prod = 0;
	ring->cons = 0;

	/* Do nothing more if in legacy mode */
	if ( rtl->legacy )
		return;

	/* Clear ring address */
	writel ( 0, rtl->regs + ring->reg );
	writel ( 0, rtl->regs + ring->reg + 4 );

	/* Free descriptor ring */
	free_dma ( ring->desc, ring->len );
	ring->desc = NULL;
}

/**
 * Refill receive descriptor ring
 *
 * @v rtl		Realtek device
 */
static void realtek_refill_rx ( struct realtek_nic *rtl ) {
	struct realtek_descriptor *rx;
	struct io_buffer *iobuf;
	unsigned int rx_idx;
	physaddr_t address;
	int is_last;

	/* Do nothing in legacy mode */
	if ( rtl->legacy )
		return;

	while ( ( rtl->rx.prod - rtl->rx.cons ) < RTL_NUM_RX_DESC ) {

		/* Allocate I/O buffer */
		iobuf = alloc_iob ( RTL_RX_MAX_LEN );
		if ( ! iobuf ) {
			/* Wait for next refill */
			return;
		}

		/* Get next receive descriptor */
		rx_idx = ( rtl->rx.prod++ % RTL_NUM_RX_DESC );
		is_last = ( rx_idx == ( RTL_NUM_RX_DESC - 1 ) );
		rx = &rtl->rx.desc[rx_idx];

		/* Populate receive descriptor */
		address = virt_to_bus ( iobuf->data );
		rx->address = cpu_to_le64 ( address );
		rx->length = cpu_to_le16 ( RTL_RX_MAX_LEN );
		wmb();
		rx->flags = ( cpu_to_le16 ( RTL_DESC_OWN ) |
			      ( is_last ? cpu_to_le16 ( RTL_DESC_EOR ) : 0 ) );
		wmb();

		/* Record I/O buffer */
		assert ( rtl->rx_iobuf[rx_idx] == NULL );
		rtl->rx_iobuf[rx_idx] = iobuf;

		DBGC2 ( rtl, "REALTEK %p RX %d is [%llx,%llx)\n", rtl, rx_idx,
			( ( unsigned long long ) address ),
			( ( unsigned long long ) address + RTL_RX_MAX_LEN ) );
	}
}

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int realtek_open ( struct net_device *netdev ) {
	struct realtek_nic *rtl = netdev->priv;
	uint32_t tcr;
	uint32_t rcr;
	int rc;

	/* Create transmit descriptor ring */
	if ( ( rc = realtek_create_ring ( rtl, &rtl->tx ) ) != 0 )
		goto err_create_tx;

	/* Create receive descriptor ring */
	if ( ( rc = realtek_create_ring ( rtl, &rtl->rx ) ) != 0 )
		goto err_create_rx;

	/* Create receive buffer */
	if ( ( rc = realtek_create_buffer ( rtl ) ) != 0 )
		goto err_create_buffer;

	/* Accept all packets */
	writel ( 0xffffffffUL, rtl->regs + RTL_MAR0 );
	writel ( 0xffffffffUL, rtl->regs + RTL_MAR4 );

	/* Enable transmitter and receiver.  RTL8139 requires that
	 * this happens before writing to RCR.
	 */
	writeb ( ( RTL_CR_TE | RTL_CR_RE ), rtl->regs + RTL_CR );

	/* Configure transmitter */
	tcr = readl ( rtl->regs + RTL_TCR );
	tcr &= ~RTL_TCR_MXDMA_MASK;
	tcr |= RTL_TCR_MXDMA_DEFAULT;
	writel ( tcr, rtl->regs + RTL_TCR );

	/* Configure receiver */
	rcr = readl ( rtl->regs + RTL_RCR );
	rcr &= ~( RTL_RCR_STOP_WORKING | RTL_RCR_RXFTH_MASK |
		  RTL_RCR_RBLEN_MASK | RTL_RCR_MXDMA_MASK );
	rcr |= ( RTL_RCR_RXFTH_DEFAULT | RTL_RCR_RBLEN_DEFAULT |
		 RTL_RCR_MXDMA_DEFAULT | RTL_RCR_WRAP | RTL_RCR_AB |
		 RTL_RCR_AM | RTL_RCR_APM | RTL_RCR_AAP );
	writel ( rcr, rtl->regs + RTL_RCR );

	/* Fill receive ring */
	realtek_refill_rx ( rtl );

	/* Update link state */
	realtek_check_link ( netdev );

	return 0;

	realtek_destroy_buffer ( rtl );
 err_create_buffer:
	realtek_destroy_ring ( rtl, &rtl->rx );
 err_create_rx:
	realtek_destroy_ring ( rtl, &rtl->tx );
 err_create_tx:
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void realtek_close ( struct net_device *netdev ) {
	struct realtek_nic *rtl = netdev->priv;
	unsigned int i;

	/* Disable receiver and transmitter */
	writeb ( 0, rtl->regs + RTL_CR );

	/* Destroy receive buffer */
	realtek_destroy_buffer ( rtl );

	/* Destroy receive descriptor ring */
	realtek_destroy_ring ( rtl, &rtl->rx );

	/* Discard any unused receive buffers */
	for ( i = 0 ; i < RTL_NUM_RX_DESC ; i++ ) {
		if ( rtl->rx_iobuf[i] )
			free_iob ( rtl->rx_iobuf[i] );
		rtl->rx_iobuf[i] = NULL;
	}

	/* Destroy transmit descriptor ring */
	realtek_destroy_ring ( rtl, &rtl->tx );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int realtek_transmit ( struct net_device *netdev,
			      struct io_buffer *iobuf ) {
	struct realtek_nic *rtl = netdev->priv;
	struct realtek_descriptor *tx;
	unsigned int tx_idx;
	physaddr_t address;
	int is_last;

	/* Get next transmit descriptor */
	if ( ( rtl->tx.prod - rtl->tx.cons ) >= RTL_NUM_TX_DESC ) {
		netdev_tx_defer ( netdev, iobuf );
		return 0;
	}
	tx_idx = ( rtl->tx.prod++ % RTL_NUM_TX_DESC );

	/* Transmit packet */
	if ( rtl->legacy ) {

		/* Pad and align packet */
		iob_pad ( iobuf, ETH_ZLEN );
		address = virt_to_bus ( iobuf->data );

		/* Check that card can support address */
		if ( address & ~0xffffffffULL ) {
			DBGC ( rtl, "REALTEK %p cannot support 64-bit TX "
			       "buffer address\n", rtl );
			return -ENOTSUP;
		}

		/* Add to transmit ring */
		writel ( address, rtl->regs + RTL_TSAD ( tx_idx ) );
		writel ( ( RTL_TSD_ERTXTH_DEFAULT | iob_len ( iobuf ) ),
			 rtl->regs + RTL_TSD ( tx_idx ) );

	} else {

		/* Populate transmit descriptor */
		address = virt_to_bus ( iobuf->data );
		is_last = ( tx_idx == ( RTL_NUM_TX_DESC - 1 ) );
		tx = &rtl->tx.desc[tx_idx];
		tx->address = cpu_to_le64 ( address );
		tx->length = cpu_to_le16 ( iob_len ( iobuf ) );
		wmb();
		tx->flags = ( cpu_to_le16 ( RTL_DESC_OWN | RTL_DESC_FS |
					    RTL_DESC_LS ) |
			      ( is_last ? cpu_to_le16 ( RTL_DESC_EOR ) : 0 ) );
		wmb();

		/* Notify card that there are packets ready to transmit */
		writeb ( RTL_TPPOLL_NPQ, rtl->regs + rtl->tppoll );
	}

	DBGC2 ( rtl, "REALTEK %p TX %d is [%llx,%llx)\n", rtl, tx_idx,
		( ( unsigned long long ) virt_to_bus ( iobuf->data ) ),
		( ( ( unsigned long long ) virt_to_bus ( iobuf->data ) ) +
		  iob_len ( iobuf ) ) );

	return 0;
}

/**
 * Poll for completed packets
 *
 * @v netdev		Network device
 */
static void realtek_poll_tx ( struct net_device *netdev ) {
	struct realtek_nic *rtl = netdev->priv;
	struct realtek_descriptor *tx;
	unsigned int tx_idx;

	/* Check for completed packets */
	while ( rtl->tx.cons != rtl->tx.prod ) {

		/* Get next transmit descriptor */
		tx_idx = ( rtl->tx.cons % RTL_NUM_TX_DESC );

		/* Stop if descriptor is still in use */
		if ( rtl->legacy ) {

			/* Check ownership bit in transmit status register */
			if ( ! ( readl ( rtl->regs + RTL_TSD ( tx_idx ) ) &
				 RTL_TSD_OWN ) )
				return;

		} else {

			/* Check ownership bit in descriptor */
			tx = &rtl->tx.desc[tx_idx];
			if ( tx->flags & cpu_to_le16 ( RTL_DESC_OWN ) )
				return;
		}

		DBGC2 ( rtl, "REALTEK %p TX %d complete\n", rtl, tx_idx );

		/* Complete TX descriptor */
		rtl->tx.cons++;
		netdev_tx_complete_next ( netdev );
	}
}

/**
 * Poll for received packets (legacy mode)
 *
 * @v netdev		Network device
 */
static void realtek_legacy_poll_rx ( struct net_device *netdev ) {
	struct realtek_nic *rtl = netdev->priv;
	struct realtek_legacy_header *rx;
	struct io_buffer *iobuf;
	size_t len;

	/* Check for received packets */
	while ( ! ( readb ( rtl->regs + RTL_CR ) & RTL_CR_BUFE ) ) {

		/* Extract packet from receive buffer */
		rx = ( rtl->rx_buffer + rtl->rx_offset );
		len = le16_to_cpu ( rx->length );
		if ( rx->status & cpu_to_le16 ( RTL_STAT_ROK ) ) {

			DBGC2 ( rtl, "REALTEK %p RX offset %x+%zx\n",
				rtl, rtl->rx_offset, len );

			/* Allocate I/O buffer */
			iobuf = alloc_iob ( len );
			if ( ! iobuf ) {
				netdev_rx_err ( netdev, NULL, -ENOMEM );
				/* Leave packet for next poll */
				break;
			}

			/* Copy data to I/O buffer */
			memcpy ( iob_put ( iobuf, len ), rx->data, len );
			iob_unput ( iobuf, 4 /* strip CRC */ );

			/* Hand off to network stack */
			netdev_rx ( netdev, iobuf );

		} else {

			DBGC ( rtl, "REALTEK %p RX offset %x+%zx error %04x\n",
			       rtl, rtl->rx_offset, len,
			       le16_to_cpu ( rx->status ) );
			netdev_rx_err ( netdev, NULL, -EIO );
		}

		/* Update buffer offset */
		rtl->rx_offset = ( rtl->rx_offset + sizeof ( *rx ) + len );
		rtl->rx_offset = ( ( rtl->rx_offset + 3 ) & ~3 );
		rtl->rx_offset = ( rtl->rx_offset % RTL_RXBUF_LEN );
		writew ( ( rtl->rx_offset - 16 ), rtl->regs + RTL_CAPR );

		/* Give chip time to react before rechecking RTL_CR */
		readw ( rtl->regs + RTL_CAPR );
	}
}

/**
 * Poll for received packets
 *
 * @v netdev		Network device
 */
static void realtek_poll_rx ( struct net_device *netdev ) {
	struct realtek_nic *rtl = netdev->priv;
	struct realtek_descriptor *rx;
	struct io_buffer *iobuf;
	unsigned int rx_idx;
	size_t len;

	/* Poll receive buffer if in legacy mode */
	if ( rtl->legacy ) {
		realtek_legacy_poll_rx ( netdev );
		return;
	}

	/* Check for received packets */
	while ( rtl->rx.cons != rtl->rx.prod ) {

		/* Get next receive descriptor */
		rx_idx = ( rtl->rx.cons % RTL_NUM_RX_DESC );
		rx = &rtl->rx.desc[rx_idx];

		/* Stop if descriptor is still in use */
		if ( rx->flags & cpu_to_le16 ( RTL_DESC_OWN ) )
			return;

		/* Populate I/O buffer */
		iobuf = rtl->rx_iobuf[rx_idx];
		rtl->rx_iobuf[rx_idx] = NULL;
		len = ( le16_to_cpu ( rx->length ) & RTL_DESC_SIZE_MASK );
		iob_put ( iobuf, ( len - 4 /* strip CRC */ ) );

		/* Hand off to network stack */
		if ( rx->flags & cpu_to_le16 ( RTL_DESC_RES ) ) {
			DBGC ( rtl, "REALTEK %p RX %d error (length %zd, "
			       "flags %04x)\n", rtl, rx_idx, len,
			       le16_to_cpu ( rx->flags ) );
			netdev_rx_err ( netdev, iobuf, -EIO );
		} else {
			DBGC2 ( rtl, "REALTEK %p RX %d complete (length "
				"%zd)\n", rtl, rx_idx, len );
			netdev_rx ( netdev, iobuf );
		}
		rtl->rx.cons++;
	}
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void realtek_poll ( struct net_device *netdev ) {
	struct realtek_nic *rtl = netdev->priv;
	uint16_t isr;

	/* Check for and acknowledge interrupts */
	isr = readw ( rtl->regs + RTL_ISR );
	if ( ! isr )
		return;
	writew ( isr, rtl->regs + RTL_ISR );

	/* Poll for TX completions, if applicable */
	if ( isr & ( RTL_IRQ_TER | RTL_IRQ_TOK ) )
		realtek_poll_tx ( netdev );

	/* Poll for RX completionsm, if applicable */
	if ( isr & ( RTL_IRQ_RER | RTL_IRQ_ROK ) )
		realtek_poll_rx ( netdev );

	/* Check link state, if applicable */
	if ( isr & RTL_IRQ_PUN_LINKCHG )
		realtek_check_link ( netdev );

	/* Refill RX ring */
	realtek_refill_rx ( rtl );
}

/**
 * Enable or disable interrupts
 *
 * @v netdev		Network device
 * @v enable		Interrupts should be enabled
 */
static void realtek_irq ( struct net_device *netdev, int enable ) {
	struct realtek_nic *rtl = netdev->priv;
	uint16_t imr;

	/* Set interrupt mask */
	imr = ( enable ? ( RTL_IRQ_PUN_LINKCHG | RTL_IRQ_TER | RTL_IRQ_TOK |
			   RTL_IRQ_RER | RTL_IRQ_ROK ) : 0 );
	writew ( imr, rtl->regs + RTL_IMR );
}

/** Realtek network device operations */
static struct net_device_operations realtek_operations = {
	.open		= realtek_open,
	.close		= realtek_close,
	.transmit	= realtek_transmit,
	.poll		= realtek_poll,
	.irq		= realtek_irq,
};

/******************************************************************************
 *
 * PCI interface
 *
 ******************************************************************************
 */

/**
 * Detect device type
 *
 * @v rtl		Realtek device
 */
static void realtek_detect ( struct realtek_nic *rtl ) {
	uint16_t rms;
	uint16_t check_rms;
	uint16_t cpcr;
	uint16_t check_cpcr;

	/* The RX Packet Maximum Size register is present only on
	 * 8169.  Try to set to our intended MTU.
	 */
	rms = RTL_RX_MAX_LEN;
	writew ( rms, rtl->regs + RTL_RMS );
	check_rms = readw ( rtl->regs + RTL_RMS );

	/* The C+ Command register is present only on 8169 and 8139C+.
	 * Try to enable C+ mode and PCI Dual Address Cycle (for
	 * 64-bit systems), if supported.
	 *
	 * Note that enabling DAC seems to cause bizarre behaviour
	 * (lockups, garbage data on the wire) on some systems, even
	 * if only 32-bit addresses are used.
	 */
	cpcr = readw ( rtl->regs + RTL_CPCR );
	cpcr |= ( RTL_CPCR_MULRW | RTL_CPCR_CPRX | RTL_CPCR_CPTX );
	if ( sizeof ( physaddr_t ) > sizeof ( uint32_t ) )
		cpcr |= RTL_CPCR_DAC;
	writew ( cpcr, rtl->regs + RTL_CPCR );
	check_cpcr = readw ( rtl->regs + RTL_CPCR );

	/* Detect device type */
	if ( check_rms == rms ) {
		DBGC ( rtl, "REALTEK %p appears to be an RTL8169\n", rtl );
		rtl->have_phy_regs = 1;
		rtl->tppoll = RTL_TPPOLL_8169;
	} else {
		if ( ( check_cpcr == cpcr ) && ( cpcr != 0xffff ) ) {
			DBGC ( rtl, "REALTEK %p appears to be an RTL8139C+\n",
			       rtl );
			rtl->tppoll = RTL_TPPOLL_8139CP;
		} else {
			DBGC ( rtl, "REALTEK %p appears to be an RTL8139\n",
			       rtl );
			rtl->legacy = 1;
		}
		rtl->eeprom.bus = &rtl->spibit.bus;
	}
}

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 */
static int realtek_probe ( struct pci_device *pci ) {
	struct net_device *netdev;
	struct realtek_nic *rtl;
	unsigned int i;
	int rc;

	/* Allocate and initialise net device */
	netdev = alloc_etherdev ( sizeof ( *rtl ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &realtek_operations );
	rtl = netdev->priv;
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;
	memset ( rtl, 0, sizeof ( *rtl ) );
	realtek_init_ring ( &rtl->tx, RTL_NUM_TX_DESC, RTL_TNPDS );
	realtek_init_ring ( &rtl->rx, RTL_NUM_RX_DESC, RTL_RDSAR );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Map registers */
	rtl->regs = ioremap ( pci->membase, RTL_BAR_SIZE );
	if ( ! rtl->regs ) {
		rc = -ENODEV;
		goto err_ioremap;
	}

	/* Reset the NIC */
	if ( ( rc = realtek_reset ( rtl ) ) != 0 )
		goto err_reset;

	/* Detect device type */
	realtek_detect ( rtl );

	/* Initialise EEPROM */
	if ( rtl->eeprom.bus &&
	     ( ( rc = realtek_init_eeprom ( netdev ) ) == 0 ) ) {

		/* Read MAC address from EEPROM */
		if ( ( rc = nvs_read ( &rtl->eeprom.nvs, RTL_EEPROM_MAC,
				       netdev->hw_addr, ETH_ALEN ) ) != 0 ) {
			DBGC ( rtl, "REALTEK %p could not read MAC address: "
			       "%s\n", rtl, strerror ( rc ) );
			goto err_nvs_read;
		}

	} else {

		/* EEPROM not present.  Fall back to reading the
		 * current ID register value, which will hopefully
		 * have been programmed by the platform firmware.
		 */
		for ( i = 0 ; i < ETH_ALEN ; i++ )
			netdev->hw_addr[i] = readb ( rtl->regs + RTL_IDR0 + i );
	}

	/* Initialise and reset MII interface */
	mii_init ( &rtl->mii, &realtek_mii_operations );
	if ( ( rc = realtek_phy_reset ( rtl ) ) != 0 )
		goto err_phy_reset;

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register_netdev;

	/* Set initial link state */
	realtek_check_link ( netdev );

	/* Register non-volatile options, if applicable */
	if ( rtl->nvo.nvs ) {
		if ( ( rc = register_nvo ( &rtl->nvo,
					   netdev_settings ( netdev ) ) ) != 0)
			goto err_register_nvo;
	}

	return 0;

 err_register_nvo:
	unregister_netdev ( netdev );
 err_register_netdev:
 err_phy_reset:
 err_nvs_read:
	realtek_reset ( rtl );
 err_reset:
	iounmap ( rtl->regs );
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
static void realtek_remove ( struct pci_device *pci ) {
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct realtek_nic *rtl = netdev->priv;

	/* Unregister non-volatile options, if applicable */
	if ( rtl->nvo.nvs )
		unregister_nvo ( &rtl->nvo );

	/* Unregister network device */
	unregister_netdev ( netdev );

	/* Reset card */
	realtek_reset ( rtl );

	/* Free network device */
	iounmap ( rtl->regs );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** Realtek PCI device IDs */
static struct pci_device_id realtek_nics[] = {
	PCI_ROM ( 0x0001, 0x8168, "clone8169",	"Cloned 8169", 0 ),
	PCI_ROM ( 0x018a, 0x0106, "fpc0106tx",	"LevelOne FPC-0106TX", 0 ),
	PCI_ROM ( 0x021b, 0x8139, "hne300",	"Compaq HNE-300", 0 ),
	PCI_ROM ( 0x02ac, 0x1012, "s1012",	"SpeedStream 1012", 0 ),
	PCI_ROM ( 0x0357, 0x000a, "ttpmon",	"TTTech TTP-Monitoring", 0 ),
	PCI_ROM ( 0x10ec, 0x8129, "rtl8129",	"RTL-8129", 0 ),
	PCI_ROM ( 0x10ec, 0x8136, "rtl8136",	"RTL8101E/RTL8102E", 0 ),
	PCI_ROM ( 0x10ec, 0x8138, "rtl8138",	"RT8139 (B/C)", 0 ),
	PCI_ROM ( 0x10ec, 0x8139, "rtl8139",	"RTL-8139/8139C/8139C+", 0 ),
	PCI_ROM ( 0x10ec, 0x8167, "rtl8167",	"RTL-8110SC/8169SC", 0 ),
	PCI_ROM ( 0x10ec, 0x8168, "rtl8168",	"RTL8111/8168B", 0 ),
	PCI_ROM ( 0x10ec, 0x8169, "rtl8169",	"RTL-8169", 0 ),
	PCI_ROM ( 0x1113, 0x1211, "smc1211",	"SMC2-1211TX", 0 ),
	PCI_ROM ( 0x1186, 0x1300, "dfe538",	"DFE530TX+/DFE538TX", 0 ),
	PCI_ROM ( 0x1186, 0x1340, "dfe690",	"DFE-690TXD", 0 ),
	PCI_ROM ( 0x1186, 0x4300, "dge528t",	"DGE-528T", 0 ),
	PCI_ROM ( 0x11db, 0x1234, "sega8139",	"Sega Enterprises 8139", 0 ),
	PCI_ROM ( 0x1259, 0xa117, "allied8139",	"Allied Telesyn 8139", 0 ),
	PCI_ROM ( 0x1259, 0xa11e, "allied81xx",	"Allied Telesyn 81xx", 0 ),
	PCI_ROM ( 0x1259, 0xc107, "allied8169",	"Allied Telesyn 8169", 0 ),
	PCI_ROM ( 0x126c, 0x1211, "northen8139","Northern Telecom 8139", 0 ),
	PCI_ROM ( 0x13d1, 0xab06, "fe2000vx",	"Abocom FE2000VX", 0 ),
	PCI_ROM ( 0x1432, 0x9130, "edi8139",	"Edimax 8139", 0 ),
	PCI_ROM ( 0x14ea, 0xab06, "fnw3603tx",	"Planex FNW-3603-TX", 0 ),
	PCI_ROM ( 0x14ea, 0xab07, "fnw3800tx",	"Planex FNW-3800-TX", 0 ),
	PCI_ROM ( 0x1500, 0x1360, "delta8139",	"Delta Electronics 8139", 0 ),
	PCI_ROM ( 0x16ec, 0x0116, "usr997902",	"USR997902", 0 ),
	PCI_ROM ( 0x1737, 0x1032, "linksys8169","Linksys 8169", 0 ),
	PCI_ROM ( 0x1743, 0x8139, "rolf100",	"Peppercorn ROL/F-100", 0 ),
	PCI_ROM ( 0x4033, 0x1360, "addron8139",	"Addtron 8139", 0 ),
	PCI_ROM ( 0xffff, 0x8139, "clonse8139",	"Cloned 8139", 0 ),
};

/** Realtek PCI driver */
struct pci_driver realtek_driver __pci_driver = {
	.ids = realtek_nics,
	.id_count = ( sizeof ( realtek_nics ) / sizeof ( realtek_nics[0] ) ),
	.probe = realtek_probe,
	.remove = realtek_remove,
};
