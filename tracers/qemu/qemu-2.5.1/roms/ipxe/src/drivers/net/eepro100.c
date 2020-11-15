/*
 * eepro100.c -- This is a driver for Intel Fast Ethernet Controllers
 * (ifec).
 *
 * Originally written for Etherboot by:
 *
 *   Copyright (C) AW Computer Systems.
 *   written by R.E.Wolff -- R.E.Wolff@BitWizard.nl
 *
 *   AW Computer Systems is contributing to the free software community
 *   by paying for this driver and then putting the result under GPL.
 *
 *   If you need a Linux device driver, please contact BitWizard for a
 *   quote.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
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
 *
 *              date       version  by      what
 *  Written:    May 29 1997  V0.10  REW     Initial revision.
 * changes:     May 31 1997  V0.90  REW     Works!
 *              Jun 1  1997  V0.91  REW     Cleanup
 *              Jun 2  1997  V0.92  REW     Add some code documentation
 *              Jul 25 1997  V1.00  REW     Tested by AW to work in a PROM
 *                                          Cleanup for publication
 *              Dez 11 2004  V1.10  Kiszka  Add RX ring buffer support
 *              Jun    2008  v2.0   mdeck   Updated to iPXE. Changed much.
 *
 * Cleanups and fixes by Thomas Miletich<thomas.miletich@gmail.com>
 *
 * This is the etherboot intel etherexpress Pro/100B driver.
 *
 * It was written from scratch, with Donald Beckers eepro100.c kernel
 * driver as a guideline. Mostly the 82557 related definitions and the
 * lower level routines have been cut-and-pasted into this source.
 *
 * The driver was finished before Intel got the NDA out of the closet.
 *
 * Datasheet is now published and available from 
 * ftp://download.intel.com/design/network/manuals/8255X_OpenSDM.pdf
 *    - Michael Brown
 * */

FILE_LICENCE ( GPL2_OR_LATER );

/*
 * General Theory of Operation
 *
 * Initialization
 *
 * ifec_pci_probe() is called by iPXE during initialization. Typical NIC
 * initialization is performed.  EEPROM data is read.
 *
 * Network Boot
 *
 * ifec_net_open() is called by iPXE before attempting to network boot from the
 * card.  Here, the Command Unit & Receive Unit are initialized.  The tx & rx
 * rings are setup.  The MAC address is programmed and the card is configured.
 *
 * Transmit
 *
 * ifec_net_transmit() enqueues a packet in the tx ring - active::tcbs[]  The tx
 * ring is composed of TCBs linked to each other into a ring.  A tx request
 * fills out the next available TCB with a pointer to the packet data.
 * The last enqueued tx is always at active::tcb_head.  Thus, a tx request fills
 * out the TCB following tcb_head.
 * active::tcb_tail points to the TCB we're awaiting completion of.
 * ifec_tx_process() checks tcb_tail, and once complete,
 * blindly increments tcb_tail to the next ring TCB.
 *
 * Receive
 *
 * priv::rfds[] is an array of Receive Frame Descriptors. The RFDs are linked
 * together to form a ring.
 * ifec_net_poll() calls ifec_rx_process(), which checks the next RFD for
 * data.  If we received a packet, we allocate a new io_buffer and copy the
 * packet data into it. If alloc_iob() fails, we don't touch the RFD and try
 * again on the next poll.
 */

/*
 * Debugging levels:
 *	- DBG() is for any errors, i.e. failed alloc_iob(), malloc_dma(),
 *	  TX overflow, corrupted packets, ...
 *	- DBG2() is for successful events, like packet received,
 *	  packet transmitted, and other general notifications.
 *	- DBGP() prints the name of each called function on entry
 */

#include <stdint.h>
#include <byteswap.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/pci.h>
#include <ipxe/spi_bit.h>
#include <ipxe/timer.h>
#include <ipxe/nvs.h>
#include <ipxe/threewire.h>
#include <ipxe/netdevice.h>
#include "eepro100.h"

/****************************** Global data **********************************/

/*
 * This is the default configuration command data. The values were copied from
 * the Linux kernel initialization for the eepro100.
 */
static struct ifec_cfg ifec_cfg = {
	.status  = 0,
	.command = CmdConfigure | CmdSuspend,
	.link    = 0,        /* Filled in later */
	.byte = { 22,        /* How many bytes in this array */
	          ( TX_FIFO << 4 ) | RX_FIFO,  /* Rx & Tx FIFO limits */
	          0, 0,                        /* Adaptive Interframe Spacing */
	          RX_DMA_COUNT,                /* Rx DMA max byte count */
	          TX_DMA_COUNT + 0x80,         /* Tx DMA max byte count */
	          0x32,      /* Many bits. */
	          0x03,      /* Discard short receive & Underrun retries */
	          1,         /* 1=Use MII  0=Use AUI */
	          0,
	          0x2E,      /* NSAI, Preamble length, & Loopback*/
	          0,         /* Linear priority */
	          0x60,      /* L PRI MODE & Interframe spacing */
	          0, 0xf2,
	          0x48,      /* Promiscuous, Broadcast disable, CRS & CDT */
	          0, 0x40,
	          0xf2,      /* Stripping, Padding, Receive CRC Transfer */
	          0x80,      /* 0x40=Force full-duplex, 0x80=Allowfull-duplex*/
	          0x3f,      /* Multiple IA */
	          0x0D }     /* Multicast all */
};

static struct net_device_operations ifec_operations = {
	.open     = ifec_net_open,
	.close    = ifec_net_close,
	.transmit = ifec_net_transmit,
	.poll     = ifec_net_poll,
	.irq      = ifec_net_irq
};

/******************* iPXE PCI Device Driver API functions ********************/

/*
 * Initialize the PCI device.
 *
 * @v pci 		The device's associated pci_device structure.
 * @v id  		The PCI device + vendor id.
 * @ret rc		Returns zero if successfully initialized.
 *
 * This function is called very early on, while iPXE is initializing.
 * This is a iPXE PCI Device Driver API function.
 */
static int ifec_pci_probe ( struct pci_device *pci )
{
	struct net_device *netdev;
	struct ifec_private *priv;
	int rc;

	DBGP ( "ifec_pci_probe: " );

	if ( pci->ioaddr == 0 )
		return -EINVAL;

	netdev = alloc_etherdev ( sizeof(*priv) );
	if ( !netdev )
		return -ENOMEM;

	netdev_init ( netdev, &ifec_operations );
	priv = netdev->priv;

	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;

	/* enable bus master, etc */
	adjust_pci_device( pci );

	DBGP ( "pci " );

	memset ( priv, 0, sizeof(*priv) );
	priv->ioaddr = pci->ioaddr;

	ifec_reset ( netdev );
	DBGP ( "reset " );

	ifec_init_eeprom ( netdev );

	/* read MAC address */
	nvs_read ( &priv->eeprom.nvs, EEPROM_ADDR_MAC_0, netdev->hw_addr,
		   ETH_ALEN );
	/* read mdio_register */
	nvs_read ( &priv->eeprom.nvs, EEPROM_ADDR_MDIO_REGISTER,
		   &priv->mdio_register, 2 );

	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto error;

	netdev_link_up ( netdev );

	DBGP ( "ints\n" );

	return 0;

error:
	ifec_reset     ( netdev );
	netdev_nullify ( netdev );
	netdev_put     ( netdev );

	return rc;
}

/*
 * Remove a device from the PCI device list.
 *
 * @v pci		PCI device to remove.
 *
 * This is a PCI Device Driver API function.
 */
static void ifec_pci_remove ( struct pci_device *pci )
{
	struct net_device *netdev = pci_get_drvdata ( pci );

	DBGP ( "ifec_pci_remove\n" );

	unregister_netdev ( netdev );
	ifec_reset        ( netdev );
	netdev_nullify    ( netdev );
	netdev_put        ( netdev );
}

/****************** iPXE Network Device Driver API functions *****************/

/*
 * Close a network device.
 *
 * @v netdev		Device to close.
 *
 * This is a iPXE Network Device Driver API function.
 */
static void ifec_net_close ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	unsigned long ioaddr = priv->ioaddr;
	unsigned short intr_status;

	DBGP ( "ifec_net_close\n" );

	/* disable interrupts */
	ifec_net_irq ( netdev, 0 );

	/* Ack & clear ints */
	intr_status = inw ( ioaddr + SCBStatus );
	outw ( intr_status, ioaddr + SCBStatus );
	inw ( ioaddr + SCBStatus );

	ifec_reset ( netdev );

	/* Free any resources */
	ifec_free ( netdev );
}

/* Interrupts to be masked */
#define INTERRUPT_MASK	( SCBMaskEarlyRx | SCBMaskFlowCtl )

/*
 * Enable or disable IRQ masking.
 *
 * @v netdev		Device to control.
 * @v enable		Zero to mask off IRQ, non-zero to enable IRQ.
 *
 * This is a iPXE Network Driver API function.
 */
static void ifec_net_irq ( struct net_device *netdev, int enable )
{
	struct ifec_private *priv = netdev->priv;
	unsigned long ioaddr = priv->ioaddr;

	DBGP ( "ifec_net_irq\n" );

	outw ( enable ? INTERRUPT_MASK : SCBMaskAll, ioaddr + SCBCmd );
}

/*
 * Opens a network device.
 *
 * @v netdev		Device to be opened.
 * @ret rc  		Non-zero if failed to open.
 *
 * This enables tx and rx on the device.
 * This is a iPXE Network Device Driver API function.
 */
static int ifec_net_open ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	struct ifec_ias *ias = NULL;
	struct ifec_cfg *cfg = NULL;
	int i, options;
	int rc = -ENOMEM;

	DBGP ( "ifec_net_open: " );

	/* Ensure interrupts are disabled. */
	ifec_net_irq ( netdev, 0 );

	/* Initialize Command Unit and Receive Unit base addresses. */
	ifec_scb_cmd ( netdev, 0, RUAddrLoad );
	ifec_scb_cmd ( netdev, virt_to_bus ( &priv->stats ), CUStatsAddr );
	ifec_scb_cmd ( netdev, 0, CUCmdBase );

	/* Initialize both rings */
	if ( ( rc = ifec_rx_setup ( netdev ) ) != 0 )
		goto error;
	if ( ( rc = ifec_tx_setup ( netdev ) ) != 0 )
		goto error;

	/* Initialize MDIO */
	options = 0x00; /* 0x40 = 10mbps half duplex, 0x00 = Autosense */
	ifec_mdio_setup ( netdev, options );

	/* Prepare MAC address w/ Individual Address Setup (ias) command.*/
	ias = malloc_dma ( sizeof ( *ias ), CB_ALIGN );
	if ( !ias ) {
		rc = -ENOMEM;
		goto error;
	}
	ias->command      = CmdIASetup;
	ias->status       = 0;
	memcpy ( ias->ia, netdev->ll_addr, ETH_ALEN );

	/* Prepare operating parameters w/ a configure command. */
	cfg = malloc_dma ( sizeof ( *cfg ), CB_ALIGN );
	if ( !cfg ) {
		rc = -ENOMEM;
		goto error;
	}
	memcpy ( cfg, &ifec_cfg, sizeof ( *cfg ) );
	cfg->link     = virt_to_bus ( priv->tcbs );
	cfg->byte[19] = ( options & 0x10 ) ? 0xC0 : 0x80;
	ias->link     = virt_to_bus ( cfg );

	/* Issue the ias and configure commands. */
	ifec_scb_cmd ( netdev, virt_to_bus ( ias ), CUStart );
	ifec_scb_cmd_wait ( netdev );
	priv->configured = 1;

	/* Wait up to 10 ms for configuration to initiate */
	for ( i = 10; i && !cfg->status; i-- )
		mdelay ( 1 );
	if ( ! cfg->status ) {
		DBG ( "Failed to initiate!\n" );
		goto error;
	}
	free_dma ( ias, sizeof ( *ias ) );
	free_dma ( cfg, sizeof ( *cfg ) );
	DBG2 ( "cfg " );

	/* Enable rx by sending ring address to card */
	if ( priv->rfds[0] != NULL ) {
		ifec_scb_cmd ( netdev, virt_to_bus( priv->rfds[0] ), RUStart );
		ifec_scb_cmd_wait ( netdev );
	}
	DBG2 ( "rx_start\n" );

	return 0;

error:
	free_dma ( cfg, sizeof ( *cfg ) );
	free_dma ( ias, sizeof ( *ias ) );
	ifec_free ( netdev );
	ifec_reset ( netdev );
	return rc;
}

/*
 * This function allows a driver to process events during operation.
 *
 * @v netdev		Device being polled.
 *
 * This is called periodically by iPXE to let the driver check the status of
 * transmitted packets and to allow the driver to check for received packets.
 * This is a iPXE Network Device Driver API function.
 */
static void ifec_net_poll ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	unsigned short intr_status;

	DBGP ( "ifec_net_poll\n" );

	/* acknowledge interrupts ASAP */
	intr_status = inw ( priv->ioaddr + SCBStatus );
	outw ( intr_status, priv->ioaddr + SCBStatus );
	inw ( priv->ioaddr + SCBStatus );

	DBG2 ( "poll - status: 0x%04X\n", intr_status );

	/* anything to do here? */
	if ( ( intr_status & ( ~INTERRUPT_MASK ) ) == 0 )
		return;

	/* process received and transmitted packets */
	ifec_tx_process ( netdev );
	ifec_rx_process ( netdev );

	ifec_check_ru_status ( netdev, intr_status );

	return;
}

/*
 * This transmits a packet.
 *
 * @v netdev		Device to transmit from.
 * @v iobuf 		Data to transmit.
 * @ret rc  		Non-zero if failed to transmit.
 *
 * This is a iPXE Network Driver API function.
 */
static int ifec_net_transmit ( struct net_device *netdev,
                               struct io_buffer *iobuf )
{
	struct ifec_private *priv = netdev->priv;
	struct ifec_tcb *tcb = priv->tcb_head->next;
	unsigned long ioaddr = priv->ioaddr;

	DBGP ( "ifec_net_transmit\n" );

	/* Wait for TCB to become available. */
	if ( tcb->status || tcb->iob ) {
		DBG ( "TX overflow\n" );
		return -ENOBUFS;
	}

	DBG2 ( "transmitting packet (%zd bytes). status = %hX, cmd=%hX\n",
		iob_len ( iobuf ), tcb->status, inw ( ioaddr + SCBCmd ) );

	tcb->command   = CmdSuspend | CmdTx | CmdTxFlex;
	tcb->count     = 0x01208000;
	tcb->tbd_addr0 = virt_to_bus ( iobuf->data );
	tcb->tbd_size0 = 0x3FFF & iob_len ( iobuf );
	tcb->iob = iobuf;

	ifec_tx_wake ( netdev );

	/* Append to end of ring. */
	priv->tcb_head = tcb;

	return 0;
}

/*************************** Local support functions *************************/

/* Define what each GPIO Pin does */
static const uint16_t ifec_ee_bits[] = {
	[SPI_BIT_SCLK]	= EE_SHIFT_CLK,
	[SPI_BIT_MOSI]	= EE_DATA_WRITE,
	[SPI_BIT_MISO]	= EE_DATA_READ,
	[SPI_BIT_SS(0)]	= EE_ENB,
};

/*
 * Read a single bit from the GPIO pins used for SPI.
 * should be called by SPI bitbash functions only
 *
 * @v basher		Bitbash device
 * @v bit_id		Line to be read
 */
static int ifec_spi_read_bit ( struct bit_basher *basher,
			       unsigned int bit_id )
{
	struct ifec_private *priv =
		container_of ( basher, struct ifec_private, spi.basher );
	unsigned long ee_addr = priv->ioaddr + CSREeprom;
	unsigned int ret = 0;
	uint16_t mask;

	DBGP ( "ifec_spi_read_bit\n" );

	mask = ifec_ee_bits[bit_id];
	ret = inw (ee_addr);

	return ( ret & mask ) ? 1 : 0;
}

/*
 * Write a single bit to the GPIO pins used for SPI.
 * should be called by SPI bitbash functions only
 *
 * @v basher		Bitbash device
 * @v bit_id		Line to write to
 * @v data		Value to write
 */
static void ifec_spi_write_bit ( struct bit_basher *basher,
				 unsigned int bit_id,
				 unsigned long data )
{
	struct ifec_private *priv =
		container_of ( basher, struct ifec_private, spi.basher );
	unsigned long ee_addr = priv->ioaddr + CSREeprom;
	short val;
	uint16_t mask = ifec_ee_bits[bit_id];

	DBGP ( "ifec_spi_write_bit\n" );

	val = inw ( ee_addr );
	val &= ~mask;
	val |= data & mask;

	outw ( val, ee_addr );
}

/* set function pointer to SPI read- and write-bit functions */
static struct bit_basher_operations ifec_basher_ops = {
	.read = ifec_spi_read_bit,
	.write = ifec_spi_write_bit,
};

/*
 * Initialize the eeprom stuff
 *
 * @v netdev		Network device
 */
static void ifec_init_eeprom ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;

	DBGP ( "ifec_init_eeprom\n" );

	priv->spi.basher.op = &ifec_basher_ops;
	priv->spi.bus.mode = SPI_MODE_THREEWIRE;
	init_spi_bit_basher ( &priv->spi );

	priv->eeprom.bus = &priv->spi.bus;

	/* init as 93c46(93c14 compatible) first, to set the command len,
	 * block size and word len. Needs to be set for address len detection.
	 */
	init_at93c46 ( &priv->eeprom, 16 );

	/* detect address length, */
	threewire_detect_address_len ( &priv->eeprom );

	/* address len == 8 means 93c66 instead of 93c46 */
	if ( priv->eeprom.address_len == 8 )
		init_at93c66 ( &priv->eeprom, 16 );
}

/*
 * Support function: ifec_mdio_read
 *
 * This probably reads a register in the "physical media interface chip".
 * -- REW
 */
static int ifec_mdio_read ( struct net_device *netdev, int phy_id,
                                                       int location )
{
	struct ifec_private *priv = netdev->priv;
	unsigned long ioaddr = priv->ioaddr;
	int val;
	int boguscnt = 64*4;     /* <64 usec. to complete, typ 27 ticks */

	DBGP ( "ifec_mdio_read\n" );

	outl ( 0x08000000 | ( location << 16 ) | ( phy_id << 21 ),
	       ioaddr + CSRCtrlMDI );
	do {
		udelay ( 16 );

		val = inl ( ioaddr + CSRCtrlMDI );

		if ( --boguscnt < 0 ) {
			DBG ( " ifec_mdio_read() time out with val = %X.\n",
			         val );
			break;
		}
	} while (! ( val & 0x10000000 ) );
	return val & 0xffff;
}

/*
 * Initializes MDIO.
 *
 * @v netdev 		Network device
 * @v options		MDIO options
 */
static void ifec_mdio_setup ( struct net_device *netdev, int options )
{
	struct ifec_private *priv = netdev->priv;
	unsigned short mdio_register = priv->mdio_register;

	DBGP ( "ifec_mdio_setup\n" );

	if (   ( (mdio_register>>8) & 0x3f ) == DP83840
	    || ( (mdio_register>>8) & 0x3f ) == DP83840A ) {
		int mdi_reg23 = ifec_mdio_read ( netdev, mdio_register
						  & 0x1f, 23 ) | 0x0422;
		if (CONGENB)
			mdi_reg23 |= 0x0100;
		DBG2 ( "DP83840 specific setup, setting register 23 to "
		                                         "%hX.\n", mdi_reg23 );
		ifec_mdio_write ( netdev, mdio_register & 0x1f, 23, mdi_reg23 );
	}
	DBG2 ( "dp83840 " );
	if ( options != 0 ) {
		ifec_mdio_write ( netdev, mdio_register & 0x1f, 0,
		                           ( (options & 0x20) ? 0x2000 : 0 ) |
		                           ( (options & 0x10) ? 0x0100 : 0 ) );
		DBG2 ( "set mdio_register. " );
	}
}

/*
 * Support function: ifec_mdio_write
 *
 * This probably writes to the "physical media interface chip".
 * -- REW
 */
static int ifec_mdio_write ( struct net_device *netdev,
                             int phy_id, int location, int value )
{
	struct ifec_private *priv = netdev->priv;
	unsigned long ioaddr = priv->ioaddr;
	int val;
	int boguscnt = 64*4;     /* <64 usec. to complete, typ 27 ticks */

	DBGP ( "ifec_mdio_write\n" );

	outl ( 0x04000000 | ( location << 16 ) | ( phy_id << 21 ) | value,
	       ioaddr + CSRCtrlMDI );
	do {
		udelay ( 16 );

		val = inl ( ioaddr + CSRCtrlMDI );
		if ( --boguscnt < 0 ) {
			DBG ( " ifec_mdio_write() time out with val = %X.\n",
			      val );
			break;
		}
	} while (! ( val & 0x10000000 ) );
	return val & 0xffff;
}

/*
 * Resets the hardware.
 *
 * @v netdev		Network device
 */
static void ifec_reset ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	unsigned long ioaddr = priv->ioaddr;

	DBGP ( "ifec_reset\n" );

	/* do partial reset first */
	outl ( PortPartialReset, ioaddr + CSRPort );
	inw ( ioaddr + SCBStatus );
	udelay ( 20 );

	/* full reset */
	outl ( PortReset, ioaddr + CSRPort );
	inw ( ioaddr + SCBStatus );
	udelay ( 20 );

	/* disable interrupts again */
	ifec_net_irq ( netdev, 0 );
}

/*
 * free()s the tx/rx rings.
 *
 * @v netdev		Network device
 */
static void ifec_free ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev_priv ( netdev );
	int i;

	DBGP ( "ifec_free\n" );

	/* free all allocated receive io_buffers */
	for ( i = 0; i < RFD_COUNT; i++ ) {
		free_iob ( priv->rx_iobs[i] );
		priv->rx_iobs[i] = NULL;
		priv->rfds[i] = NULL;
	}

	/* free TX ring buffer */
	free_dma ( priv->tcbs, TX_RING_BYTES );

	priv->tcbs = NULL;
}

/*
 * Initializes an RFD.
 *
 * @v rfd    		RFD struct to initialize
 * @v command		Command word
 * @v link   		Link value
 */
static void ifec_rfd_init ( struct ifec_rfd *rfd, s16 command, u32 link )
{
	DBGP ( "ifec_rfd_init\n" );

	rfd->status      = 0;
	rfd->command     = command;
	rfd->rx_buf_addr = 0xFFFFFFFF;
	rfd->count       = 0;
	rfd->size        = RFD_PACKET_LEN;
	rfd->link        = link;
}

/*
 * Send address of new RFD to card
 *
 * @v netdev		Network device
 */
static void ifec_reprime_ru ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	int cur_rx = priv->cur_rx;
	
	DBGP ( "ifec_reprime_ru\n" );
	
	if ( priv->rfds[cur_rx] != NULL ) {
		ifec_scb_cmd ( netdev, virt_to_bus ( priv->rfds[cur_rx] ),
			       RUStart );
		ifec_scb_cmd_wait ( netdev );
	}
}

/*
 * Check if reprime of RU needed
 *
 * @v netdev		Network device
 */
static void ifec_check_ru_status ( struct net_device *netdev,
				   unsigned short intr_status )
{
	struct ifec_private *priv = netdev->priv;

	DBGP ( "ifec_check_ru_status\n" );

	/*
	* The chip may have suspended reception for various reasons.
	* Check for that, and re-prime it should this be the case.
	*/
	switch ( ( intr_status >> 2 ) & 0xf ) {
		case 0:  /* Idle */
		case 4:  /* Ready */
			break;
		case 1:  /* Suspended */
		case 2:  /* No resources (RFDs) */
		case 9:  /* Suspended with no more RBDs */
		case 10: /* No resources due to no RBDs */
		case 12: /* Ready with no RBDs */
			DBG ( "ifec_net_poll: RU reprimed.\n" );
			ifec_reprime_ru ( netdev );
			break;
		default:
			/* reserved values */
			DBG ( "ifec_net_poll: RU state anomaly: %i\n",
			      ( inw ( priv->ioaddr + SCBStatus ) >> 2 ) & 0xf );
			break;
	}
}

#define RFD_STATUS ( RFD_OK | RFDRxCol | RFDRxErr | RFDShort | \
		     RFDDMAOverrun | RFDNoBufs | RFDCRCError )
/*
 * Looks for received packets in the rx ring, reports success or error to
 * the core accordingly. Starts reallocation of rx ring.
 *
 * @v netdev		Network device
 */
static void ifec_rx_process ( struct net_device *netdev )
{
	struct ifec_private *priv   = netdev->priv;
	int cur_rx = priv->cur_rx;
	struct io_buffer *iob = priv->rx_iobs[cur_rx];
	struct ifec_rfd *rfd = priv->rfds[cur_rx];
	unsigned int rx_len;
	s16 status;

	DBGP ( "ifec_rx_process\n" );

	/* Process any received packets */
	while ( iob && rfd && ( status = rfd->status ) ) {
		rx_len = rfd->count & RFDMaskCount;

		DBG2 ( "Got a packet: Len = %d, cur_rx = %d.\n", rx_len,
		       cur_rx );
		DBGIO_HD ( (void*)rfd->packet, 0x30 );

		if ( ( status & ( RFD_STATUS & ~RFDShort ) ) != RFD_OK ) {
			DBG ( "Corrupted packet received. "
			      "Status = %#08hx\n", status );
			netdev_rx_err ( netdev, iob, -EINVAL );
		} else {
			/* Hand off the packet to the network subsystem */
			iob_put ( iob, rx_len );
			DBG2 ( "Received packet: %p, len: %d\n", iob, rx_len );
			netdev_rx ( netdev, iob );
		}

		/* make sure we don't reuse this RFD */
		priv->rx_iobs[cur_rx] = NULL;
		priv->rfds[cur_rx] = NULL;

		/* Next RFD */
		priv->cur_rx = ( cur_rx + 1 ) % RFD_COUNT;
		cur_rx = priv->cur_rx;
		iob = priv->rx_iobs[cur_rx];
		rfd = priv->rfds[cur_rx];
	}

	ifec_refill_rx_ring ( netdev );
}

/*
 * Allocates io_buffer, set pointers in ifec_private structure accordingly,
 * reserves space for RFD header in io_buffer.
 *
 * @v netdev		Network device
 * @v cur		Descriptor number to work on
 * @v cmd		Value to set cmd field in RFD to
 * @v link		Pointer to ned RFD
 * @ret rc		0 on success, negative on failure
 */
static int ifec_get_rx_desc ( struct net_device *netdev, int cur, int cmd,
			      int link )
{
	struct ifec_private *priv = netdev->priv;
	struct ifec_rfd *rfd  = priv->rfds[cur];

	DBGP ( "ifec_get_rx_desc\n" );

	priv->rx_iobs[cur] = alloc_iob ( sizeof ( *rfd ) );
	if ( ! priv->rx_iobs[cur] ) {
		DBG ( "alloc_iob failed. desc. nr: %d\n", cur );
		priv->rfds[cur] = NULL;
		return -ENOMEM;
	}

	/* Initialize new tail. */
	priv->rfds[cur] = priv->rx_iobs[cur]->data;
	ifec_rfd_init ( priv->rfds[cur], cmd, link );
	iob_reserve ( priv->rx_iobs[cur], RFD_HEADER_LEN );

	return 0;
}

/*
 * Allocate new descriptor entries and initialize them if needed
 *
 * @v netdev		Network device
 */
static void ifec_refill_rx_ring ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	int i, cur_rx;
	unsigned short intr_status;

	DBGP ( "ifec_refill_rx_ring\n" );

	for ( i = 0; i < RFD_COUNT; i++ ) {
		cur_rx = ( priv->cur_rx + i ) % RFD_COUNT;
		/* only refill if empty */
		if ( priv->rfds[cur_rx] != NULL ||
		     priv->rx_iobs[cur_rx] != NULL )
			continue;

		DBG2 ( "refilling RFD %d\n", cur_rx );

		if ( ifec_get_rx_desc ( netdev, cur_rx,
		     CmdSuspend | CmdEndOfList, 0 ) == 0 ) {
			if ( i > 0 ) {
				int prev_rx = ( ( ( cur_rx + RFD_COUNT ) - 1 )
						% RFD_COUNT );
				struct ifec_rfd *rfd = priv->rfds[prev_rx];

				rfd->command = 0;
				rfd->link = virt_to_bus ( priv->rfds[cur_rx] );
			}
		}
	}

	intr_status = inw ( priv->ioaddr + SCBStatus );
	ifec_check_ru_status ( netdev, intr_status );
}

/*
 * Initial allocation & initialization of the rx ring.
 *
 * @v netdev  		Device of rx ring.
 * @ret rc    		Non-zero if error occurred
 */
static int ifec_rx_setup ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	int i;

	DBGP ( "ifec_rx_setup\n" );

	priv->cur_rx = 0;

	/* init values for ifec_refill_rx_ring() */
	for ( i = 0; i < RFD_COUNT; i++ ) {
		priv->rfds[i] = NULL;
		priv->rx_iobs[i] = NULL;
	}
	ifec_refill_rx_ring ( netdev );

	return 0;
}

/*
 * Initiates a SCB command.
 *
 * @v netdev		Network device
 * @v ptr   		General pointer value for command.
 * @v cmd   		Command to issue.
 * @ret rc  		Non-zero if command not issued.
 */
static int ifec_scb_cmd ( struct net_device *netdev, u32 ptr, u8 cmd )
{
	struct ifec_private *priv = netdev->priv;
	unsigned long ioaddr = priv->ioaddr;
	int rc;

	DBGP ( "ifec_scb_cmd\n" );

	rc = ifec_scb_cmd_wait ( netdev );	/* Wait until ready */
	if ( !rc ) {
		outl ( ptr, ioaddr + SCBPointer );
		outb ( cmd, ioaddr + SCBCmd );		/* Issue command */
	}
	return rc;
}

/*
 * Wait for command unit to accept a command.
 *
 * @v cmd_ioaddr	I/O address of command register.
 * @ret rc      	Non-zero if command timed out.
 */
static int ifec_scb_cmd_wait ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	unsigned long cmd_ioaddr = priv->ioaddr + SCBCmd;
	int rc, wait = CU_CMD_TIMEOUT;

	DBGP ( "ifec_scb_cmd_wait\n" );

	for ( ; wait && ( rc = inb ( cmd_ioaddr ) ); wait-- )
		udelay ( 1 );

	if ( !wait )
		DBG ( "ifec_scb_cmd_wait timeout!\n" );
	return rc;
}

/*
 * Check status of transmitted packets & perform tx completions.
 *
 * @v netdev    	Network device.
 */
static void ifec_tx_process ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	struct ifec_tcb *tcb = priv->tcb_tail;
	s16 status;

	DBGP ( "ifec_tx_process\n" );

	/* Check status of transmitted packets */
	while ( ( status = tcb->status ) && tcb->iob ) {
		if ( status & TCB_U ) {
			/* report error to iPXE */
			DBG ( "ifec_tx_process : tx error!\n " );
			netdev_tx_complete_err ( netdev, tcb->iob, -EINVAL );
		} else {
			/* report successful transmit */
			netdev_tx_complete ( netdev, tcb->iob );
		}
		DBG2 ( "tx completion\n" );

		tcb->iob = NULL;
		tcb->status = 0;

		priv->tcb_tail = tcb->next;	/* Next TCB */
		tcb = tcb->next;
	}
}

/*
 * Allocates & initialize tx resources.
 *
 * @v netdev    	Network device.
 * @ret rc      	Non-zero if error occurred.
 */
static int ifec_tx_setup ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	struct ifec_tcb *tcb;
	int i;

	DBGP ( "ifec_tx_setup\n" );

	/* allocate tx ring */
	priv->tcbs = malloc_dma ( TX_RING_BYTES, CB_ALIGN );
	if ( !priv->tcbs ) {
		DBG ( "TX-ring allocation failed\n" );
		return -ENOMEM;
	}

	tcb = priv->tcb_tail = priv->tcbs;
	priv->tx_curr = priv->tx_tail = 0;
	priv->tx_cnt = 0;

	for ( i = 0; i < TCB_COUNT; i++, tcb++ ) {
		tcb->status    = 0;
		tcb->count     = 0x01208000;
		tcb->iob       = NULL;
		tcb->tbda_addr = virt_to_bus ( &tcb->tbd_addr0 );
		tcb->link      = virt_to_bus ( tcb + 1 );
		tcb->next      = tcb + 1;
	}
	/* We point tcb_head at the last TCB, so the first ifec_net_transmit()
	 * will use the first (head->next) TCB to transmit. */
	priv->tcb_head = --tcb;
	tcb->link = virt_to_bus ( priv->tcbs );
	tcb->next = priv->tcbs;
	
	return 0;
}

/*
 * Wake up the Command Unit and issue a Resume/Start.
 *
 * @v netdev		Network device containing Command Unit
 *
 * The time between clearing the S bit and issuing Resume must be as short as
 * possible to prevent a race condition. As noted in linux eepro100.c :
 *   Note: Watch out for the potential race condition here: imagine
 *	erasing the previous suspend
 *		the chip processes the previous command
 *		the chip processes the final command, and suspends
 *	doing the CU_RESUME
 *		the chip processes the next-yet-valid post-final-command.
 *   So blindly sending a CU_RESUME is only safe if we do it immediately after
 *   erasing the previous CmdSuspend, without the possibility of an intervening
 *   delay.
 */
void ifec_tx_wake ( struct net_device *netdev )
{
	struct ifec_private *priv = netdev->priv;
	unsigned long ioaddr = priv->ioaddr;
	struct ifec_tcb *tcb = priv->tcb_head->next;

	DBGP ( "ifec_tx_wake\n" );

	/* For the special case of the first transmit, we issue a START. The
	 * card won't RESUME after the configure command. */
	if ( priv->configured ) {
		priv->configured = 0;
		ifec_scb_cmd ( netdev, virt_to_bus ( tcb ), CUStart );
		ifec_scb_cmd_wait ( netdev );
		return;
	}

	/* Resume if suspended. */
	switch ( ( inw ( ioaddr + SCBStatus ) >> 6 ) & 0x3 ) {
	case 0:  /* Idle - We should not reach this state. */
		DBG2 ( "ifec_tx_wake: tx idle!\n" );
		ifec_scb_cmd ( netdev, virt_to_bus ( tcb ), CUStart );
		ifec_scb_cmd_wait ( netdev );
		return;
	case 1:  /* Suspended */
		DBG2 ( "s" );
		break;
	default: /* Active */
		DBG2 ( "a" );
	}
	ifec_scb_cmd_wait ( netdev );
	outl ( 0, ioaddr + SCBPointer );
	priv->tcb_head->command &= ~CmdSuspend;
	/* Immediately issue Resume command */
	outb ( CUResume, ioaddr + SCBCmd );
	ifec_scb_cmd_wait ( netdev );
}

/*********************************************************************/

static struct pci_device_id ifec_nics[] = {
PCI_ROM(0x8086, 0x1029, "id1029",        "Intel EtherExpressPro100 ID1029", 0),
PCI_ROM(0x8086, 0x1030, "id1030",        "Intel EtherExpressPro100 ID1030", 0),
PCI_ROM(0x8086, 0x1031, "82801cam",      "Intel 82801CAM (ICH3) Chipset Ethernet Controller", 0),
PCI_ROM(0x8086, 0x1032, "eepro100-1032", "Intel PRO/100 VE Network Connection", 0),
PCI_ROM(0x8086, 0x1033, "eepro100-1033", "Intel PRO/100 VM Network Connection", 0),
PCI_ROM(0x8086, 0x1034, "eepro100-1034", "Intel PRO/100 VM Network Connection", 0),
PCI_ROM(0x8086, 0x1035, "eepro100-1035", "Intel 82801CAM (ICH3) Chipset Ethernet Controller", 0),
PCI_ROM(0x8086, 0x1036, "eepro100-1036", "Intel 82801CAM (ICH3) Chipset Ethernet Controller", 0),
PCI_ROM(0x8086, 0x1037, "eepro100-1037", "Intel 82801CAM (ICH3) Chipset Ethernet Controller", 0),
PCI_ROM(0x8086, 0x1038, "id1038",        "Intel PRO/100 VM Network Connection", 0),
PCI_ROM(0x8086, 0x1039, "82562et",       "Intel PRO100 VE 82562ET", 0),
PCI_ROM(0x8086, 0x103a, "id103a",        "Intel Corporation 82559 InBusiness 10/100", 0),
PCI_ROM(0x8086, 0x103b, "82562etb",      "Intel PRO100 VE 82562ETB", 0),
PCI_ROM(0x8086, 0x103c, "eepro100-103c", "Intel PRO/100 VM Network Connection", 0),
PCI_ROM(0x8086, 0x103d, "eepro100-103d", "Intel PRO/100 VE Network Connection", 0),
PCI_ROM(0x8086, 0x103e, "eepro100-103e", "Intel PRO/100 VM Network Connection", 0),
PCI_ROM(0x8086, 0x1051, "prove",         "Intel PRO/100 VE Network Connection", 0),
PCI_ROM(0x8086, 0x1059, "82551qm",       "Intel PRO/100 M Mobile Connection", 0),
PCI_ROM(0x8086, 0x1209, "82559er",       "Intel EtherExpressPro100 82559ER", 0),
PCI_ROM(0x8086, 0x1227, "82865",         "Intel 82865 EtherExpress PRO/100A", 0),
PCI_ROM(0x8086, 0x1228, "82556",         "Intel 82556 EtherExpress PRO/100 Smart", 0),
PCI_ROM(0x8086, 0x1229, "eepro100",      "Intel EtherExpressPro100", 0),
PCI_ROM(0x8086, 0x2449, "82562em",       "Intel EtherExpressPro100 82562EM", 0),
PCI_ROM(0x8086, 0x2459, "82562-1",       "Intel 82562 based Fast Ethernet Connection", 0),
PCI_ROM(0x8086, 0x245d, "82562-2",       "Intel 82562 based Fast Ethernet Connection", 0),
PCI_ROM(0x8086, 0x1050, "82562ez",       "Intel 82562EZ Network Connection", 0),
PCI_ROM(0x8086, 0x1065, "82562-3",       "Intel 82562 based Fast Ethernet Connection", 0),
PCI_ROM(0x8086, 0x5200, "eepro100-5200", "Intel EtherExpress PRO/100 Intelligent Server", 0),
PCI_ROM(0x8086, 0x5201, "eepro100-5201", "Intel EtherExpress PRO/100 Intelligent Server", 0),
PCI_ROM(0x8086, 0x1092, "82562-3",       "Intel Pro/100 VE Network", 0),
PCI_ROM(0x8086, 0x27dc, "eepro100-27dc", "Intel 82801G (ICH7) Chipset Ethernet Controller", 0),
PCI_ROM(0x8086, 0x10fe, "82552",         "Intel 82552 10/100 Network Connection", 0),
};

/* Cards with device ids 0x1030 to 0x103F, 0x2449, 0x2459 or 0x245D might need
 * a workaround for hardware bug on 10 mbit half duplex (see linux driver eepro100.c)
 * 2003/03/17 gbaum */

struct pci_driver ifec_driver __pci_driver = {
	.ids      = ifec_nics,
	.id_count = ( sizeof (ifec_nics) / sizeof (ifec_nics[0]) ),
	.probe    = ifec_pci_probe,
	.remove   = ifec_pci_remove
};

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
