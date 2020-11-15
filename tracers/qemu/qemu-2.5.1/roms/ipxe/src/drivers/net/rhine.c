/*
 * Copyright (C) 2012 Adrian Jamroz <adrian.jamroz@gmail.com>
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
#include <ipxe/mii.h>
#include "rhine.h"

/** @file
 *
 * VIA Rhine network driver
 *
 */

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
static int rhine_mii_read ( struct mii_interface *mii, unsigned int reg ) {
	struct rhine_nic *rhn = container_of ( mii, struct rhine_nic, mii );
	unsigned int timeout = RHINE_TIMEOUT_US;
	uint8_t cr;

	DBGC2 ( rhn, "RHINE %p MII read reg %d\n", rhn, reg );

	/* Initiate read */
	writeb ( reg, rhn->regs + RHINE_MII_ADDR );
	cr = readb ( rhn->regs + RHINE_MII_CR );
	writeb ( ( cr | RHINE_MII_CR_RDEN ), rhn->regs + RHINE_MII_CR );

	/* Wait for read to complete */
	while ( timeout-- ) {
		udelay ( 1 );
		cr = readb ( rhn->regs + RHINE_MII_CR );
		if ( ! ( cr & RHINE_MII_CR_RDEN ) )
			return readw ( rhn->regs + RHINE_MII_RDWR );
	}

	DBGC ( rhn, "RHINE %p MII read timeout\n", rhn );
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
static int rhine_mii_write ( struct mii_interface *mii, unsigned int reg,
                             unsigned int data ) {
	struct rhine_nic *rhn = container_of ( mii, struct rhine_nic, mii );
	unsigned int timeout = RHINE_TIMEOUT_US;
	uint8_t cr;

	DBGC2 ( rhn, "RHINE %p MII write reg %d data 0x%04x\n",
	        rhn, reg, data );

	/* Initiate write */
	writeb ( reg, rhn->regs + RHINE_MII_ADDR );
	writew ( data, rhn->regs + RHINE_MII_RDWR );
	cr = readb ( rhn->regs + RHINE_MII_CR );
	writeb ( ( cr | RHINE_MII_CR_WREN ), rhn->regs + RHINE_MII_CR );

	/* Wait for write to complete */
	while ( timeout-- ) {
		udelay ( 1 );
		cr = readb ( rhn->regs + RHINE_MII_CR );
		if ( ! ( cr & RHINE_MII_CR_WREN ) )
			return 0;
	}

	DBGC ( rhn, "RHINE %p MII write timeout\n", rhn );
	return -ETIMEDOUT;
}

/** Rhine MII operations */
static struct mii_operations rhine_mii_operations = {
	.read = rhine_mii_read,
	.write = rhine_mii_write,
};

/**
 * Enable auto-polling
 *
 * @v rhn		Rhine device
 * @ret rc		Return status code
 *
 * This is voodoo.  There seems to be no documentation on exactly what
 * we are waiting for, or why we have to do anything other than simply
 * turn the feature on.
 */
static int rhine_mii_autopoll ( struct rhine_nic *rhn ) {
	unsigned int timeout = RHINE_TIMEOUT_US;
	uint8_t addr;

	/* Initiate auto-polling */
	writeb ( MII_BMSR, rhn->regs + RHINE_MII_ADDR );
	writeb ( RHINE_MII_CR_AUTOPOLL, rhn->regs + RHINE_MII_CR );

	/* Wait for auto-polling to complete */
	while ( timeout-- ) {
		udelay ( 1 );
		addr = readb ( rhn->regs + RHINE_MII_ADDR );
		if ( ! ( addr & RHINE_MII_ADDR_MDONE ) ) {
			writeb ( ( MII_BMSR | RHINE_MII_ADDR_MSRCEN ),
				 rhn->regs + RHINE_MII_ADDR );
			return 0;
		}
	}

	DBGC ( rhn, "RHINE %p MII auto-poll timeout\n", rhn );
	return -ETIMEDOUT;
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
 * @v rhn		Rhine device
 * @ret rc		Return status code
 *
 * We're using PIO because this might reset the MMIO enable bit.
 */
static int rhine_reset ( struct rhine_nic *rhn ) {
	unsigned int timeout = RHINE_TIMEOUT_US;
	uint8_t cr1;

	DBGC ( rhn, "RHINE %p reset\n", rhn );

	/* Initiate reset */
	outb ( RHINE_CR1_RESET, rhn->ioaddr + RHINE_CR1 );

	/* Wait for reset to complete */
	while ( timeout-- ) {
		udelay ( 1 );
		cr1 = inb ( rhn->ioaddr + RHINE_CR1 );
		if ( ! ( cr1 & RHINE_CR1_RESET ) )
			return 0;
	}

	DBGC ( rhn, "RHINE %p reset timeout\n", rhn );
	return -ETIMEDOUT;
}

/**
 * Enable MMIO register access
 *
 * @v rhn		Rhine device
 * @v revision		Card revision
 */
static void rhine_enable_mmio ( struct rhine_nic *rhn, int revision ) {
	uint8_t conf;

	if ( revision < RHINE_REVISION_OLD ) {
		conf = inb ( rhn->ioaddr + RHINE_CHIPCFG_A );
		outb ( ( conf | RHINE_CHIPCFG_A_MMIO ),
		       rhn->ioaddr + RHINE_CHIPCFG_A );
	} else {
		conf = inb ( rhn->ioaddr + RHINE_CHIPCFG_D );
		outb ( ( conf | RHINE_CHIPCFG_D_MMIO ),
		       rhn->ioaddr + RHINE_CHIPCFG_D );
	}
}

/**
 * Reload EEPROM contents
 *
 * @v rhn		Rhine device
 * @ret rc		Return status code
 *
 * We're using PIO because this might reset the MMIO enable bit.
 */
static int rhine_reload_eeprom ( struct rhine_nic *rhn ) {
	unsigned int timeout = RHINE_TIMEOUT_US;
	uint8_t eeprom;

	/* Initiate reload */
	eeprom = inb ( rhn->ioaddr + RHINE_EEPROM_CTRL );
	outb ( ( eeprom | RHINE_EEPROM_CTRL_RELOAD ),
	       rhn->ioaddr + RHINE_EEPROM_CTRL );

	/* Wait for reload to complete */
	while ( timeout-- ) {
		udelay ( 1 );
		eeprom = inb ( rhn->ioaddr + RHINE_EEPROM_CTRL );
		if ( ! ( eeprom & RHINE_EEPROM_CTRL_RELOAD ) )
			return 0;
	}

	DBGC ( rhn, "RHINE %p EEPROM reload timeout\n", rhn );
	return -ETIMEDOUT;
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
static void rhine_check_link ( struct net_device *netdev ) {
	struct rhine_nic *rhn = netdev->priv;
	uint8_t mii_sr;

	/* Read MII status register */
	mii_sr = readb ( rhn->regs + RHINE_MII_SR );
	DBGC ( rhn, "RHINE %p link status %02x\n", rhn, mii_sr );

	/* Report link state */
	if ( ! ( mii_sr & RHINE_MII_SR_LINKPOLL ) ) {
		netdev_link_up ( netdev );
	} else if ( mii_sr & RHINE_MII_SR_PHYERR ) {
		netdev_link_err ( netdev, -EIO );
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
 * Create descriptor ring
 *
 * @v rhn		Rhine device
 * @v ring		Descriptor ring
 * @ret rc		Return status code
 */
static int rhine_create_ring ( struct rhine_nic *rhn,
			       struct rhine_ring *ring ) {
	size_t len = ( ring->count * sizeof ( ring->desc[0] ) );
	struct rhine_descriptor *next;
	physaddr_t address;
	unsigned int i;

	/* Allocate descriptors */
	ring->desc = malloc_dma ( len, RHINE_RING_ALIGN );
	if ( ! ring->desc )
		return -ENOMEM;

	/* Initialise descriptor ring */
	memset ( ring->desc, 0, len );
	for ( i = 0 ; i < ring->count ; i++ ) {
		next = &ring->desc[ ( i + 1 ) % ring->count ];
		ring->desc[i].next = cpu_to_le32 ( virt_to_bus ( next ) );
	}

	/* Program ring address */
	address = virt_to_bus ( ring->desc );
	writel ( address, rhn->regs + ring->reg );

	DBGC ( rhn, "RHINE %p ring %02x is at [%08llx,%08llx)\n",
	       rhn, ring->reg, ( ( unsigned long long ) address ),
	       ( ( unsigned long long ) address + len ) );

	return 0;
}

/**
 * Destroy descriptor ring
 *
 * @v rhn		Rhine device
 * @v ring		Descriptor ring
 */
static void rhine_destroy_ring ( struct rhine_nic *rhn,
				 struct rhine_ring *ring ) {
	size_t len = ( ring->count * sizeof ( ring->desc[0] ) );

	/* Clear ring address */
	writel ( 0, rhn->regs + ring->reg );

	/* Free descriptor ring */
	free_dma ( ring->desc, len );
	ring->desc = NULL;
	ring->prod = 0;
	ring->cons = 0;
}

/**
 * Refill RX descriptor ring
 *
 * @v rhn		Rhine device
 */
static void rhine_refill_rx ( struct rhine_nic *rhn ) {
	struct rhine_descriptor *desc;
	struct io_buffer *iobuf;
	unsigned int rx_idx;
	physaddr_t address;

	while ( ( rhn->rx.prod - rhn->rx.cons ) < RHINE_RXDESC_NUM ) {

		/* Allocate I/O buffer */
		iobuf = alloc_iob ( RHINE_RX_MAX_LEN );
		if ( ! iobuf ) {
			/* Wait for next refill */
			return;
		}

		/* Populate next receive descriptor */
		rx_idx = ( rhn->rx.prod++ % RHINE_RXDESC_NUM );
		desc = &rhn->rx.desc[rx_idx];
		address = virt_to_bus ( iobuf->data );
		desc->buffer = cpu_to_le32 ( address );
		desc->des1 =
			cpu_to_le32 ( RHINE_DES1_SIZE ( RHINE_RX_MAX_LEN - 1) |
				      RHINE_DES1_CHAIN | RHINE_DES1_IC );
		wmb();
		desc->des0 = cpu_to_le32 ( RHINE_DES0_OWN );

		/* Record I/O buffer */
		rhn->rx_iobuf[rx_idx] = iobuf;

		DBGC2 ( rhn, "RHINE %p RX %d is [%llx,%llx)\n", rhn, rx_idx,
			( ( unsigned long long ) address ),
			( ( unsigned long long ) address + RHINE_RX_MAX_LEN ) );
	}
}

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int rhine_open ( struct net_device *netdev ) {
	struct rhine_nic *rhn = netdev->priv;
	int rc;

	/* Create transmit ring */
	if ( ( rc = rhine_create_ring ( rhn, &rhn->tx ) ) != 0 )
		goto err_create_tx;

	/* Create receive ring */
	if ( ( rc = rhine_create_ring ( rhn, &rhn->rx ) ) != 0 )
		goto err_create_rx;

	/* Set receive configuration */
	writeb ( ( RHINE_RCR_PHYS_ACCEPT | RHINE_RCR_BCAST_ACCEPT |
		   RHINE_RCR_RUNT_ACCEPT ), rhn->regs + RHINE_RCR );

	/* Enable link status monitoring */
	if ( ( rc = rhine_mii_autopoll ( rhn ) ) != 0 )
		goto err_mii_autopoll;

	/* Some cards need an extra delay(observed with VT6102) */
	mdelay ( 10 );

	/* Enable RX/TX of packets */
	writeb ( ( RHINE_CR0_STARTNIC | RHINE_CR0_RXEN | RHINE_CR0_TXEN ),
		 rhn->regs + RHINE_CR0 );

	/* Enable auto polling and full duplex operation */
	rhn->cr1 = RHINE_CR1_FDX;
	writeb ( rhn->cr1, rhn->regs + RHINE_CR1 );

	/* Refill RX ring */
	rhine_refill_rx ( rhn );

	/* Update link state */
	rhine_check_link ( netdev );

	return 0;

 err_mii_autopoll:
	rhine_destroy_ring ( rhn, &rhn->rx );
 err_create_rx:
	rhine_destroy_ring ( rhn, &rhn->tx );
 err_create_tx:
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void rhine_close ( struct net_device *netdev ) {
	struct rhine_nic *rhn = netdev->priv;
	unsigned int i;

	/* Disable interrupts */
	writeb ( 0, RHINE_IMR0 );
	writeb ( 0, RHINE_IMR1 );

	/* Stop card, clear RXON and TXON bits */
	writeb ( RHINE_CR0_STOPNIC, rhn->regs + RHINE_CR0 );

	/* Destroy receive ring */
	rhine_destroy_ring ( rhn, &rhn->rx );

	/* Discard any unused receive buffers */
	for ( i = 0 ; i < RHINE_RXDESC_NUM ; i++ ) {
		if ( rhn->rx_iobuf[i] )
			free_iob ( rhn->rx_iobuf[i] );
		rhn->rx_iobuf[i] = NULL;
	}

	/* Destroy transmit ring */
	rhine_destroy_ring ( rhn, &rhn->tx );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int rhine_transmit ( struct net_device *netdev,
                            struct io_buffer *iobuf ) {
	struct rhine_nic *rhn = netdev->priv;
	struct rhine_descriptor *desc;
	physaddr_t address;
	unsigned int tx_idx;

	/* Get next transmit descriptor */
	if ( ( rhn->tx.prod - rhn->tx.cons ) >= RHINE_TXDESC_NUM )
		return -ENOBUFS;
	tx_idx = ( rhn->tx.prod++ % RHINE_TXDESC_NUM );
	desc = &rhn->tx.desc[tx_idx];

	/* Pad and align packet */
	iob_pad ( iobuf, ETH_ZLEN );
	address = virt_to_bus ( iobuf->data );

	/* Populate transmit descriptor */
	desc->buffer = cpu_to_le32 ( address );
	desc->des1 = cpu_to_le32 ( RHINE_DES1_IC | RHINE_TDES1_STP |
				   RHINE_TDES1_EDP | RHINE_DES1_CHAIN |
				   RHINE_DES1_SIZE ( iob_len ( iobuf ) ) );
	wmb();
	desc->des0 = cpu_to_le32 ( RHINE_DES0_OWN );
	wmb();

	/* Notify card that there are packets ready to transmit */
	writeb ( ( rhn->cr1 | RHINE_CR1_TXPOLL ), rhn->regs + RHINE_CR1 );

	DBGC2 ( rhn, "RHINE %p TX %d is [%llx,%llx)\n", rhn, tx_idx,
		( ( unsigned long long ) address ),
		( ( unsigned long long ) address + iob_len ( iobuf ) ) );

	return 0;
}

/**
 * Poll for completed packets
 *
 * @v netdev		Network device
 */
static void rhine_poll_tx ( struct net_device *netdev ) {
	struct rhine_nic *rhn = netdev->priv;
	struct rhine_descriptor *desc;
	unsigned int tx_idx;
	uint32_t des0;

	/* Check for completed packets */
	while ( rhn->tx.cons != rhn->tx.prod ) {

		/* Get next transmit descriptor */
		tx_idx = ( rhn->tx.cons % RHINE_TXDESC_NUM );
		desc = &rhn->tx.desc[tx_idx];

		/* Stop if descriptor is still in use */
		if ( desc->des0 & cpu_to_le32 ( RHINE_DES0_OWN ) )
			return;

		/* Complete TX descriptor */
		des0 = le32_to_cpu ( desc->des0 );
		if ( des0 & RHINE_TDES0_TERR ) {
			DBGC ( rhn, "RHINE %p TX %d error (DES0 %08x)\n",
			       rhn, tx_idx, des0 );
			netdev_tx_complete_next_err ( netdev, -EIO );
		} else {
			DBGC2 ( rhn, "RHINE %p TX %d complete\n", rhn, tx_idx );
			netdev_tx_complete_next ( netdev );
		}
		rhn->tx.cons++;
	}
}

/**
 * Poll for received packets
 *
 * @v netdev		Network device
 */
static void rhine_poll_rx ( struct net_device *netdev ) {
	struct rhine_nic *rhn = netdev->priv;
	struct rhine_descriptor *desc;
	struct io_buffer *iobuf;
	unsigned int rx_idx;
	uint32_t des0;
	size_t len;

	/* Check for received packets */
	while ( rhn->rx.cons != rhn->rx.prod ) {

		/* Get next receive descriptor */
		rx_idx = ( rhn->rx.cons % RHINE_RXDESC_NUM );
		desc = &rhn->rx.desc[rx_idx];

		/* Stop if descriptor is still in use */
		if ( desc->des0 & cpu_to_le32 ( RHINE_DES0_OWN ) )
			return;

		/* Populate I/O buffer */
		iobuf = rhn->rx_iobuf[rx_idx];
		rhn->rx_iobuf[rx_idx] = NULL;
		des0 = le32_to_cpu ( desc->des0 );
		len = ( RHINE_DES0_GETSIZE ( des0 ) - 4 /* strip CRC */ );
		iob_put ( iobuf, len );

		/* Hand off to network stack */
		if ( des0 & RHINE_RDES0_RXOK ) {
			DBGC2 ( rhn, "RHINE %p RX %d complete (length %zd)\n",
				rhn, rx_idx, len );
			netdev_rx ( netdev, iobuf );
		} else {
			DBGC ( rhn, "RHINE %p RX %d error (length %zd, DES0 "
			       "%08x)\n", rhn, rx_idx, len, des0 );
			netdev_rx_err ( netdev, iobuf, -EIO );
		}
		rhn->rx.cons++;
	}
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void rhine_poll ( struct net_device *netdev ) {
	struct rhine_nic *rhn = netdev->priv;
	uint8_t isr0;
	uint8_t isr1;

	/* Read and acknowledge interrupts */
	isr0 = readb ( rhn->regs + RHINE_ISR0 );
	isr1 = readb ( rhn->regs + RHINE_ISR1 );
	if ( isr0 )
		writeb ( isr0, rhn->regs + RHINE_ISR0 );
	if ( isr1 )
		writeb ( isr1, rhn->regs + RHINE_ISR1 );

	/* Report unexpected errors */
	if ( ( isr0 & ( RHINE_ISR0_MIBOVFL | RHINE_ISR0_PCIERR |
			RHINE_ISR0_RXRINGERR | RHINE_ISR0_TXRINGERR ) ) ||
	     ( isr1 & ( RHINE_ISR1_GPI | RHINE_ISR1_TXABORT |
			RHINE_ISR1_RXFIFOOVFL | RHINE_ISR1_RXFIFOUNFL |
			RHINE_ISR1_TXFIFOUNFL ) ) ) {
		DBGC ( rhn, "RHINE %p unexpected ISR0 %02x ISR1 %02x\n",
		       rhn, isr0, isr1 );
		/* Report as a TX error */
		netdev_tx_err ( netdev, NULL, -EIO );
	}

	/* Poll for TX completions, if applicable */
	if ( isr0 & ( RHINE_ISR0_TXDONE | RHINE_ISR0_TXERR ) )
		rhine_poll_tx ( netdev );

	/* Poll for RX completions, if applicable */
	if ( isr0 & ( RHINE_ISR0_RXDONE | RHINE_ISR0_RXERR ) )
		rhine_poll_rx ( netdev );

	/* Handle RX buffer exhaustion */
	if ( isr1 & RHINE_ISR1_RXNOBUF ) {
		rhine_poll_rx ( netdev );
		netdev_rx_err ( netdev, NULL, -ENOBUFS );
	}

	/* Check link state, if applicable */
	if ( isr1 & RHINE_ISR1_PORTSTATE )
		rhine_check_link ( netdev );

	/* Refill RX ring */
	rhine_refill_rx ( rhn );
}

/**
 * Enable or disable interrupts
 *
 * @v netdev		Network device
 * @v enable		Interrupts should be enabled
 */
static void rhine_irq ( struct net_device *netdev, int enable ) {
	struct rhine_nic *nic = netdev->priv;

	if ( enable ) {
		/* Enable interrupts */
		writeb ( 0xff, nic->regs + RHINE_IMR0 );
		writeb ( 0xff, nic->regs + RHINE_IMR1 );
	} else {
		/* Disable interrupts */
		writeb ( 0, nic->regs + RHINE_IMR0 );
		writeb ( 0, nic->regs + RHINE_IMR1 );
	}
}

/** Rhine network device operations */
static struct net_device_operations rhine_operations = {
	.open		= rhine_open,
	.close		= rhine_close,
	.transmit	= rhine_transmit,
	.poll		= rhine_poll,
	.irq		= rhine_irq,
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
static int rhine_probe ( struct pci_device *pci ) {
	struct net_device *netdev;
	struct rhine_nic *rhn;
	uint8_t revision;
	unsigned int i;
	int rc;

	/* Allocate and initialise net device */
	netdev = alloc_etherdev ( sizeof ( *rhn ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &rhine_operations );
	rhn = netdev->priv;
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;
	memset ( rhn, 0, sizeof ( *rhn ) );
	rhine_init_ring ( &rhn->tx, RHINE_TXDESC_NUM, RHINE_TXQUEUE_BASE );
	rhine_init_ring ( &rhn->rx, RHINE_RXDESC_NUM, RHINE_RXQUEUE_BASE );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Map registers */
	rhn->regs = ioremap ( pci->membase, RHINE_BAR_SIZE );
	rhn->ioaddr = pci->ioaddr;
	DBGC ( rhn, "RHINE %p regs at %08lx, I/O at %04lx\n", rhn,
	       pci->membase, pci->ioaddr );

	/* Reset the NIC */
	if ( ( rc = rhine_reset ( rhn ) ) != 0 )
		goto err_reset;

	/* Reload EEPROM */
	if ( ( rc = rhine_reload_eeprom ( rhn ) ) != 0 )
		goto err_reload_eeprom;

	/* Read card revision and enable MMIO */
	pci_read_config_byte ( pci, PCI_REVISION, &revision );
	DBGC ( rhn, "RHINE %p revision %#02x detected\n", rhn, revision );
	rhine_enable_mmio ( rhn, revision );

	/* Read MAC address */
	for ( i = 0 ; i < ETH_ALEN ; i++ )
		netdev->hw_addr[i] = readb ( rhn->regs + RHINE_MAC + i );

	/* Initialise and reset MII interface */
	mii_init ( &rhn->mii, &rhine_mii_operations );
	if ( ( rc = mii_reset ( &rhn->mii ) ) != 0 ) {
		DBGC ( rhn, "RHINE %p could not reset MII: %s\n",
		       rhn, strerror ( rc ) );
		goto err_mii_reset;
	}
	DBGC ( rhn, "RHINE PHY vendor %04x device %04x\n",
	       rhine_mii_read ( &rhn->mii, 0x02 ),
	       rhine_mii_read ( &rhn->mii, 0x03 ) );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register_netdev;

	/* Set initial link state */
	rhine_check_link ( netdev );

	return 0;

 err_register_netdev:
 err_mii_reset:
 err_reload_eeprom:
	rhine_reset ( rhn );
 err_reset:
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
static void rhine_remove ( struct pci_device *pci ) {
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct rhine_nic *nic = netdev->priv;

	/* Unregister network device */
	unregister_netdev ( netdev );

	/* Reset card */
	rhine_reset ( nic );

	/* Free network device */
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** Rhine PCI device IDs */
static struct pci_device_id rhine_nics[] = {
	PCI_ROM ( 0x1106, 0x3065, "dlink-530tx", "VIA VT6102", 0 ),
	PCI_ROM ( 0x1106, 0x3106, "vt6105", "VIA VT6105", 0 ),
	PCI_ROM ( 0x1106, 0x3043, "dlink-530tx-old", "VIA VT3043", 0 ),
	PCI_ROM ( 0x1106, 0x3053, "vt6105m", "VIA VT6105M", 0 ),
	PCI_ROM ( 0x1106, 0x6100, "via-rhine-old", "VIA 86C100A", 0 )
};

/** Rhine PCI driver */
struct pci_driver rhine_driver __pci_driver = {
	.ids = rhine_nics,
	.id_count = ( sizeof ( rhine_nics ) / sizeof ( rhine_nics[0] ) ),
	.probe = rhine_probe,
	.remove = rhine_remove,
};
