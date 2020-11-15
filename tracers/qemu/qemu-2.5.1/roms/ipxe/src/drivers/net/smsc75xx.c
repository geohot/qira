/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/ethernet.h>
#include <ipxe/usb.h>
#include <ipxe/usbnet.h>
#include <ipxe/profile.h>
#include "smsc75xx.h"

/** @file
 *
 * SMSC LAN75xx USB Ethernet driver
 *
 */

/** Interrupt completion profiler */
static struct profiler smsc75xx_intr_profiler __profiler =
	{ .name = "smsc75xx.intr" };

/** Bulk IN completion profiler */
static struct profiler smsc75xx_in_profiler __profiler =
	{ .name = "smsc75xx.in" };

/** Bulk OUT profiler */
static struct profiler smsc75xx_out_profiler __profiler =
	{ .name = "smsc75xx.out" };

/******************************************************************************
 *
 * Register access
 *
 ******************************************************************************
 */

/**
 * Write register (without byte-swapping)
 *
 * @v smsc75xx		SMSC75xx device
 * @v address		Register address
 * @v value		Register value
 * @ret rc		Return status code
 */
static int smsc75xx_raw_writel ( struct smsc75xx_device *smsc75xx,
				 unsigned int address, uint32_t value ) {
	int rc;

	/* Write register */
	if ( ( rc = usb_control ( smsc75xx->usb, SMSC75XX_REGISTER_WRITE, 0,
				  address, &value, sizeof ( value ) ) ) != 0 ) {
		DBGC ( smsc75xx, "SMSC75XX %p could not write %03x: %s\n",
		       smsc75xx, address, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Write register
 *
 * @v smsc75xx		SMSC75xx device
 * @v address		Register address
 * @v value		Register value
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
smsc75xx_writel ( struct smsc75xx_device *smsc75xx, unsigned int address,
		  uint32_t value ) {
	int rc;

	/* Write register */
	if ( ( rc = smsc75xx_raw_writel ( smsc75xx, address,
					  cpu_to_le32 ( value ) ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Read register (without byte-swapping)
 *
 * @v smsc75xx		SMSC75xx device
 * @v address		Register address
 * @ret value		Register value
 * @ret rc		Return status code
 */
static int smsc75xx_raw_readl ( struct smsc75xx_device *smsc75xx,
				unsigned int address, uint32_t *value ) {
	int rc;

	/* Read register */
	if ( ( rc = usb_control ( smsc75xx->usb, SMSC75XX_REGISTER_READ, 0,
				  address, value, sizeof ( *value ) ) ) != 0 ) {
		DBGC ( smsc75xx, "SMSC75XX %p could not read %03x: %s\n",
		       smsc75xx, address, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Read register
 *
 * @v smsc75xx		SMSC75xx device
 * @v address		Register address
 * @ret value		Register value
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
smsc75xx_readl ( struct smsc75xx_device *smsc75xx, unsigned int address,
		 uint32_t *value ) {
	int rc;

	/* Read register */
	if ( ( rc = smsc75xx_raw_readl ( smsc75xx, address, value ) ) != 0 )
		return rc;
	le32_to_cpus ( value );

	return 0;
}

/******************************************************************************
 *
 * EEPROM access
 *
 ******************************************************************************
 */

/**
 * Wait for EEPROM to become idle
 *
 * @v smsc75xx		SMSC75xx device
 * @ret rc		Return status code
 */
static int smsc75xx_eeprom_wait ( struct smsc75xx_device *smsc75xx ) {
	uint32_t e2p_cmd;
	unsigned int i;
	int rc;

	/* Wait for EPC_BSY to become clear */
	for ( i = 0 ; i < SMSC75XX_EEPROM_MAX_WAIT_MS ; i++ ) {

		/* Read E2P_CMD and check EPC_BSY */
		if ( ( rc = smsc75xx_readl ( smsc75xx, SMSC75XX_E2P_CMD,
					     &e2p_cmd ) ) != 0 )
			return rc;
		if ( ! ( e2p_cmd & SMSC75XX_E2P_CMD_EPC_BSY ) )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( smsc75xx, "SMSC75XX %p timed out waiting for EEPROM\n",
	       smsc75xx );
	return -ETIMEDOUT;
}

/**
 * Read byte from EEPROM
 *
 * @v smsc75xx		SMSC75xx device
 * @v address		EEPROM address
 * @ret byte		Byte read, or negative error
 */
static int smsc75xx_eeprom_read_byte ( struct smsc75xx_device *smsc75xx,
				       unsigned int address ) {
	uint32_t e2p_cmd;
	uint32_t e2p_data;
	int rc;

	/* Wait for EEPROM to become idle */
	if ( ( rc = smsc75xx_eeprom_wait ( smsc75xx ) ) != 0 )
		return rc;

	/* Initiate read command */
	e2p_cmd = ( SMSC75XX_E2P_CMD_EPC_BSY | SMSC75XX_E2P_CMD_EPC_CMD_READ |
		    SMSC75XX_E2P_CMD_EPC_ADDR ( address ) );
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_E2P_CMD,
				      e2p_cmd ) ) != 0 )
		return rc;

	/* Wait for command to complete */
	if ( ( rc = smsc75xx_eeprom_wait ( smsc75xx ) ) != 0 )
		return rc;

	/* Read EEPROM data */
	if ( ( rc = smsc75xx_readl ( smsc75xx, SMSC75XX_E2P_DATA,
				     &e2p_data ) ) != 0 )
		return rc;

	return SMSC75XX_E2P_DATA_GET ( e2p_data );
}

/**
 * Read data from EEPROM
 *
 * @v smsc75xx		SMSC75xx device
 * @v address		EEPROM address
 * @v data		Data buffer
 * @v len		Length of data
 * @ret rc		Return status code
 */
static int smsc75xx_eeprom_read ( struct smsc75xx_device *smsc75xx,
				  unsigned int address, void *data,
				  size_t len ) {
	uint8_t *bytes;
	int byte;

	/* Read bytes */
	for ( bytes = data ; len-- ; address++, bytes++ ) {
		byte = smsc75xx_eeprom_read_byte ( smsc75xx, address );
		if ( byte < 0 )
			return byte;
		*bytes = byte;
	}

	return 0;
}

/******************************************************************************
 *
 * MII access
 *
 ******************************************************************************
 */

/**
 * Wait for MII to become idle
 *
 * @v smsc75xx		SMSC75xx device
 * @ret rc		Return status code
 */
static int smsc75xx_mii_wait ( struct smsc75xx_device *smsc75xx ) {
	uint32_t mii_access;
	unsigned int i;
	int rc;

	/* Wait for MIIBZY to become clear */
	for ( i = 0 ; i < SMSC75XX_MII_MAX_WAIT_MS ; i++ ) {

		/* Read MII_ACCESS and check MIIBZY */
		if ( ( rc = smsc75xx_readl ( smsc75xx, SMSC75XX_MII_ACCESS,
					     &mii_access ) ) != 0 )
			return rc;
		if ( ! ( mii_access & SMSC75XX_MII_ACCESS_MIIBZY ) )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( smsc75xx, "SMSC75XX %p timed out waiting for MII\n",
	       smsc75xx );
	return -ETIMEDOUT;
}

/**
 * Read from MII register
 *
 * @v mii		MII interface
 * @v reg		Register address
 * @ret value		Data read, or negative error
 */
static int smsc75xx_mii_read ( struct mii_interface *mii, unsigned int reg ) {
	struct smsc75xx_device *smsc75xx =
		container_of ( mii, struct smsc75xx_device, mii );
	uint32_t mii_access;
	uint32_t mii_data;
	int rc;

	/* Wait for MII to become idle */
	if ( ( rc = smsc75xx_mii_wait ( smsc75xx ) ) != 0 )
		return rc;

	/* Initiate read command */
	mii_access = ( SMSC75XX_MII_ACCESS_PHY_ADDRESS |
		       SMSC75XX_MII_ACCESS_MIIRINDA ( reg ) |
		       SMSC75XX_MII_ACCESS_MIIBZY );
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_MII_ACCESS,
				      mii_access ) ) != 0 )
		return rc;

	/* Wait for command to complete */
	if ( ( rc = smsc75xx_mii_wait ( smsc75xx ) ) != 0 )
		return rc;

	/* Read MII data */
	if ( ( rc = smsc75xx_readl ( smsc75xx, SMSC75XX_MII_DATA,
				     &mii_data ) ) != 0 )
		return rc;

	return SMSC75XX_MII_DATA_GET ( mii_data );
}

/**
 * Write to MII register
 *
 * @v mii		MII interface
 * @v reg		Register address
 * @v data		Data to write
 * @ret rc		Return status code
 */
static int smsc75xx_mii_write ( struct mii_interface *mii, unsigned int reg,
				unsigned int data ) {
	struct smsc75xx_device *smsc75xx =
		container_of ( mii, struct smsc75xx_device, mii );
	uint32_t mii_access;
	uint32_t mii_data;
	int rc;

	/* Wait for MII to become idle */
	if ( ( rc = smsc75xx_mii_wait ( smsc75xx ) ) != 0 )
		return rc;

	/* Write MII data */
	mii_data = SMSC75XX_MII_DATA_SET ( data );
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_MII_DATA,
				      mii_data ) ) != 0 )
		return rc;

	/* Initiate write command */
	mii_access = ( SMSC75XX_MII_ACCESS_PHY_ADDRESS |
		       SMSC75XX_MII_ACCESS_MIIRINDA ( reg ) |
		       SMSC75XX_MII_ACCESS_MIIWNR |
		       SMSC75XX_MII_ACCESS_MIIBZY );
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_MII_ACCESS,
				      mii_access ) ) != 0 )
		return rc;

	/* Wait for command to complete */
	if ( ( rc = smsc75xx_mii_wait ( smsc75xx ) ) != 0 )
		return rc;

	return 0;
}

/** MII operations */
static struct mii_operations smsc75xx_mii_operations = {
	.read = smsc75xx_mii_read,
	.write = smsc75xx_mii_write,
};

/**
 * Check link status
 *
 * @v smsc75xx		SMSC75xx device
 * @ret rc		Return status code
 */
static int smsc75xx_check_link ( struct smsc75xx_device *smsc75xx ) {
	struct net_device *netdev = smsc75xx->netdev;
	int intr;
	int rc;

	/* Read PHY interrupt source */
	intr = mii_read ( &smsc75xx->mii, SMSC75XX_MII_PHY_INTR_SOURCE );
	if ( intr < 0 ) {
		rc = intr;
		DBGC ( smsc75xx, "SMSC75XX %p could not get PHY interrupt "
		       "source: %s\n", smsc75xx, strerror ( rc ) );
		return rc;
	}

	/* Acknowledge PHY interrupt */
	if ( ( rc = mii_write ( &smsc75xx->mii, SMSC75XX_MII_PHY_INTR_SOURCE,
				intr ) ) != 0 ) {
		DBGC ( smsc75xx, "SMSC75XX %p could not acknowledge PHY "
		       "interrupt: %s\n", smsc75xx, strerror ( rc ) );
		return rc;
	}

	/* Check link status */
	if ( ( rc = mii_check_link ( &smsc75xx->mii, netdev ) ) != 0 ) {
		DBGC ( smsc75xx, "SMSC75XX %p could not check link: %s\n",
		       smsc75xx, strerror ( rc ) );
		return rc;
	}

	DBGC ( smsc75xx, "SMSC75XX %p link %s (intr %#04x)\n",
	       smsc75xx, ( netdev_link_ok ( netdev ) ? "up" : "down" ), intr );
	return 0;
}

/******************************************************************************
 *
 * Statistics (for debugging)
 *
 ******************************************************************************
 */

/**
 * Get statistics
 *
 * @v smsc75xx		SMSC75xx device
 * @v stats		Statistics to fill in
 * @ret rc		Return status code
 */
static int smsc75xx_get_statistics ( struct smsc75xx_device *smsc75xx,
				     struct smsc75xx_statistics *stats ) {
	int rc;

	/* Get statistics */
	if ( ( rc = usb_control ( smsc75xx->usb, SMSC75XX_GET_STATISTICS, 0, 0,
				  stats, sizeof ( *stats ) ) ) != 0 ) {
		DBGC ( smsc75xx, "SMSC75XX %p could not get statistics: %s\n",
		       smsc75xx, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Dump statistics (for debugging)
 *
 * @v smsc75xx		SMSC75xx device
 * @ret rc		Return status code
 */
static int smsc75xx_dump_statistics ( struct smsc75xx_device *smsc75xx ) {
	struct smsc75xx_statistics stats;
	int rc;

	/* Do nothing unless debugging is enabled */
	if ( ! DBG_LOG )
		return 0;

	/* Get statistics */
	if ( ( rc = smsc75xx_get_statistics ( smsc75xx, &stats ) ) != 0 )
		return rc;

	/* Dump statistics */
	DBGC ( smsc75xx, "SMSC75XX %p RXE fcs %d aln %d frg %d jab %d und %d "
	       "ovr %d drp %d\n", smsc75xx, le32_to_cpu ( stats.rx.err.fcs ),
	       le32_to_cpu ( stats.rx.err.alignment ),
	       le32_to_cpu ( stats.rx.err.fragment ),
	       le32_to_cpu ( stats.rx.err.jabber ),
	       le32_to_cpu ( stats.rx.err.undersize ),
	       le32_to_cpu ( stats.rx.err.oversize ),
	       le32_to_cpu ( stats.rx.err.dropped ) );
	DBGC ( smsc75xx, "SMSC75XX %p RXB ucast %d bcast %d mcast %d\n",
	       smsc75xx, le32_to_cpu ( stats.rx.byte.unicast ),
	       le32_to_cpu ( stats.rx.byte.broadcast ),
	       le32_to_cpu ( stats.rx.byte.multicast ) );
	DBGC ( smsc75xx, "SMSC75XX %p RXF ucast %d bcast %d mcast %d pause "
	       "%d\n", smsc75xx, le32_to_cpu ( stats.rx.frame.unicast ),
	       le32_to_cpu ( stats.rx.frame.broadcast ),
	       le32_to_cpu ( stats.rx.frame.multicast ),
	       le32_to_cpu ( stats.rx.frame.pause ) );
	DBGC ( smsc75xx, "SMSC75XX %p TXE fcs %d def %d car %d cnt %d sgl %d "
	       "mul %d exc %d lat %d\n", smsc75xx,
	       le32_to_cpu ( stats.tx.err.fcs ),
	       le32_to_cpu ( stats.tx.err.deferral ),
	       le32_to_cpu ( stats.tx.err.carrier ),
	       le32_to_cpu ( stats.tx.err.count ),
	       le32_to_cpu ( stats.tx.err.single ),
	       le32_to_cpu ( stats.tx.err.multiple ),
	       le32_to_cpu ( stats.tx.err.excessive ),
	       le32_to_cpu ( stats.tx.err.late ) );
	DBGC ( smsc75xx, "SMSC75XX %p TXB ucast %d bcast %d mcast %d\n",
	       smsc75xx, le32_to_cpu ( stats.tx.byte.unicast ),
	       le32_to_cpu ( stats.tx.byte.broadcast ),
	       le32_to_cpu ( stats.tx.byte.multicast ) );
	DBGC ( smsc75xx, "SMSC75XX %p TXF ucast %d bcast %d mcast %d pause "
	       "%d\n", smsc75xx, le32_to_cpu ( stats.tx.frame.unicast ),
	       le32_to_cpu ( stats.tx.frame.broadcast ),
	       le32_to_cpu ( stats.tx.frame.multicast ),
	       le32_to_cpu ( stats.tx.frame.pause ) );

	return 0;
}

/******************************************************************************
 *
 * Device reset
 *
 ******************************************************************************
 */

/**
 * Reset device
 *
 * @v smsc75xx		SMSC75xx device
 * @ret rc		Return status code
 */
static int smsc75xx_reset ( struct smsc75xx_device *smsc75xx ) {
	uint32_t hw_cfg;
	int rc;

	/* Reset device */
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_HW_CFG,
				      SMSC75XX_HW_CFG_LRST ) ) != 0 )
		return rc;

	/* Wait for reset to complete */
	udelay ( SMSC75XX_RESET_DELAY_US );

	/* Check that reset has completed */
	if ( ( rc = smsc75xx_readl ( smsc75xx, SMSC75XX_HW_CFG,
				     &hw_cfg ) ) != 0 )
		return rc;
	if ( hw_cfg & SMSC75XX_HW_CFG_LRST ) {
		DBGC ( smsc75xx, "SMSC75XX %p failed to reset\n", smsc75xx );
		return -ETIMEDOUT;
	}

	return 0;
}

/******************************************************************************
 *
 * Endpoint operations
 *
 ******************************************************************************
 */

/**
 * Complete interrupt transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void smsc75xx_intr_complete ( struct usb_endpoint *ep,
				     struct io_buffer *iobuf, int rc ) {
	struct smsc75xx_device *smsc75xx =
		container_of ( ep, struct smsc75xx_device, usbnet.intr );
	struct net_device *netdev = smsc75xx->netdev;
	struct smsc75xx_interrupt *intr;

	/* Profile completions */
	profile_start ( &smsc75xx_intr_profiler );

	/* Ignore packets cancelled when the endpoint closes */
	if ( ! ep->open )
		goto done;

	/* Record USB errors against the network device */
	if ( rc != 0 ) {
		DBGC ( smsc75xx, "SMSC75XX %p interrupt failed: %s\n",
		       smsc75xx, strerror ( rc ) );
		DBGC_HDA ( smsc75xx, 0, iobuf->data, iob_len ( iobuf ) );
		netdev_rx_err ( netdev, NULL, rc );
		goto done;
	}

	/* Extract interrupt data */
	if ( iob_len ( iobuf ) != sizeof ( *intr ) ) {
		DBGC ( smsc75xx, "SMSC75XX %p malformed interrupt\n",
		       smsc75xx );
		DBGC_HDA ( smsc75xx, 0, iobuf->data, iob_len ( iobuf ) );
		netdev_rx_err ( netdev, NULL, rc );
		goto done;
	}
	intr = iobuf->data;

	/* Record interrupt status */
	smsc75xx->int_sts = le32_to_cpu ( intr->int_sts );
	profile_stop ( &smsc75xx_intr_profiler );

 done:
	/* Free I/O buffer */
	free_iob ( iobuf );
}

/** Interrupt endpoint operations */
static struct usb_endpoint_driver_operations smsc75xx_intr_operations = {
	.complete = smsc75xx_intr_complete,
};

/**
 * Complete bulk IN transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void smsc75xx_in_complete ( struct usb_endpoint *ep,
				   struct io_buffer *iobuf, int rc ) {
	struct smsc75xx_device *smsc75xx =
		container_of ( ep, struct smsc75xx_device, usbnet.in );
	struct net_device *netdev = smsc75xx->netdev;
	struct smsc75xx_rx_header *header;

	/* Profile completions */
	profile_start ( &smsc75xx_in_profiler );

	/* Ignore packets cancelled when the endpoint closes */
	if ( ! ep->open ) {
		free_iob ( iobuf );
		return;
	}

	/* Record USB errors against the network device */
	if ( rc != 0 ) {
		DBGC ( smsc75xx, "SMSC75XX %p bulk IN failed: %s\n",
		       smsc75xx, strerror ( rc ) );
		goto err;
	}

	/* Sanity check */
	if ( iob_len ( iobuf ) < ( sizeof ( *header ) ) ) {
		DBGC ( smsc75xx, "SMSC75XX %p underlength bulk IN\n",
		       smsc75xx );
		DBGC_HDA ( smsc75xx, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto err;
	}

	/* Strip header */
	header = iobuf->data;
	iob_pull ( iobuf, sizeof ( *header ) );

	/* Check for errors */
	if ( header->command & cpu_to_le32 ( SMSC75XX_RX_RED ) ) {
		DBGC ( smsc75xx, "SMSC75XX %p receive error (%08x):\n",
		       smsc75xx, le32_to_cpu ( header->command ) );
		DBGC_HDA ( smsc75xx, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EIO;
		goto err;
	}

	/* Hand off to network stack */
	netdev_rx ( netdev, iob_disown ( iobuf ) );

	profile_stop ( &smsc75xx_in_profiler );
	return;

 err:
	/* Hand off to network stack */
	netdev_rx_err ( netdev, iob_disown ( iobuf ), rc );
}

/** Bulk IN endpoint operations */
static struct usb_endpoint_driver_operations smsc75xx_in_operations = {
	.complete = smsc75xx_in_complete,
};

/**
 * Transmit packet
 *
 * @v smsc75xx		SMSC75xx device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int smsc75xx_out_transmit ( struct smsc75xx_device *smsc75xx,
				   struct io_buffer *iobuf ) {
	struct smsc75xx_tx_header *header;
	size_t len = iob_len ( iobuf );
	int rc;

	/* Profile transmissions */
	profile_start ( &smsc75xx_out_profiler );

	/* Prepend header */
	if ( ( rc = iob_ensure_headroom ( iobuf, sizeof ( *header ) ) ) != 0 )
		return rc;
	header = iob_push ( iobuf, sizeof ( *header ) );
	header->command = cpu_to_le32 ( SMSC75XX_TX_FCS | len );
	header->tag = 0;
	header->mss = 0;

	/* Enqueue I/O buffer */
	if ( ( rc = usb_stream ( &smsc75xx->usbnet.out, iobuf, 0 ) ) != 0 )
		return rc;

	profile_stop ( &smsc75xx_out_profiler );
	return 0;
}

/**
 * Complete bulk OUT transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void smsc75xx_out_complete ( struct usb_endpoint *ep,
				    struct io_buffer *iobuf, int rc ) {
	struct smsc75xx_device *smsc75xx =
		container_of ( ep, struct smsc75xx_device, usbnet.out );
	struct net_device *netdev = smsc75xx->netdev;

	/* Report TX completion */
	netdev_tx_complete_err ( netdev, iobuf, rc );
}

/** Bulk OUT endpoint operations */
static struct usb_endpoint_driver_operations smsc75xx_out_operations = {
	.complete = smsc75xx_out_complete,
};

/******************************************************************************
 *
 * Network device interface
 *
 ******************************************************************************
 */

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int smsc75xx_open ( struct net_device *netdev ) {
	struct smsc75xx_device *smsc75xx = netdev->priv;
	union smsc75xx_mac mac;
	int rc;

	/* Clear stored interrupt status */
	smsc75xx->int_sts = 0;

	/* Copy MAC address */
	memset ( &mac, 0, sizeof ( mac ) );
	memcpy ( mac.raw, netdev->ll_addr, ETH_ALEN );

	/* Configure bulk IN empty response */
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_HW_CFG,
				      SMSC75XX_HW_CFG_BIR ) ) != 0 )
		goto err_hw_cfg;

	/* Open USB network device */
	if ( ( rc = usbnet_open ( &smsc75xx->usbnet ) ) != 0 ) {
		DBGC ( smsc75xx, "SMSC75XX %p could not open: %s\n",
		       smsc75xx, strerror ( rc ) );
		goto err_open;
	}

	/* Configure interrupt endpoint */
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_INT_EP_CTL,
				      ( SMSC75XX_INT_EP_CTL_RDFO_EN |
					SMSC75XX_INT_EP_CTL_PHY_EN ) ) ) != 0 )
		goto err_int_ep_ctl;

	/* Configure bulk IN delay */
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_BULK_IN_DLY,
				      SMSC75XX_BULK_IN_DLY_SET ( 0 ) ) ) != 0 )
		goto err_bulk_in_dly;

	/* Configure receive filters */
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_RFE_CTL,
				      ( SMSC75XX_RFE_CTL_AB |
					SMSC75XX_RFE_CTL_AM |
					SMSC75XX_RFE_CTL_AU ) ) ) != 0 )
		goto err_rfe_ctl;

	/* Configure receive FIFO */
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_FCT_RX_CTL,
				      ( SMSC75XX_FCT_RX_CTL_EN |
					SMSC75XX_FCT_RX_CTL_BAD ) ) ) != 0 )
		goto err_fct_rx_ctl;

	/* Configure transmit FIFO */
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_FCT_TX_CTL,
				      SMSC75XX_FCT_TX_CTL_EN ) ) != 0 )
		goto err_fct_tx_ctl;

	/* Configure receive datapath */
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_MAC_RX,
				      ( SMSC75XX_MAC_RX_MAX_SIZE_DEFAULT |
					SMSC75XX_MAC_RX_FCS |
					SMSC75XX_MAC_RX_EN ) ) ) != 0 )
		goto err_mac_rx;

	/* Configure transmit datapath */
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_MAC_TX,
				      SMSC75XX_MAC_TX_EN ) ) != 0 )
		goto err_mac_tx;

	/* Write MAC address high register */
	if ( ( rc = smsc75xx_raw_writel ( smsc75xx, SMSC75XX_RX_ADDRH,
					  mac.addr.h ) ) != 0 )
		goto err_rx_addrh;

	/* Write MAC address low register */
	if ( ( rc = smsc75xx_raw_writel ( smsc75xx, SMSC75XX_RX_ADDRL,
					  mac.addr.l ) ) != 0 )
		goto err_rx_addrl;

	/* Write MAC address perfect filter high register */
	mac.addr.h |= cpu_to_le32 ( SMSC75XX_ADDR_FILTH_VALID );
	if ( ( rc = smsc75xx_raw_writel ( smsc75xx, SMSC75XX_ADDR_FILTH ( 0 ),
					  mac.addr.h ) ) != 0 )
		goto err_addr_filth;

	/* Write MAC address perfect filter low register */
	if ( ( rc = smsc75xx_raw_writel ( smsc75xx, SMSC75XX_ADDR_FILTL ( 0 ),
					  mac.addr.l ) ) != 0 )
		goto err_addr_filtl;

	/* Enable PHY interrupts */
	if ( ( rc = mii_write ( &smsc75xx->mii, SMSC75XX_MII_PHY_INTR_MASK,
				( SMSC75XX_PHY_INTR_ANEG_DONE |
				  SMSC75XX_PHY_INTR_LINK_DOWN ) ) ) != 0 ) {
		DBGC ( smsc75xx, "SMSC75XX %p could not set PHY interrupt "
		       "mask: %s\n", smsc75xx, strerror ( rc ) );
		goto err_phy_intr_mask;
	}

	/* Update link status */
	smsc75xx_check_link ( smsc75xx );

	return 0;

 err_phy_intr_mask:
 err_addr_filtl:
 err_addr_filth:
 err_rx_addrl:
 err_rx_addrh:
 err_mac_tx:
 err_mac_rx:
 err_fct_tx_ctl:
 err_fct_rx_ctl:
 err_rfe_ctl:
 err_bulk_in_dly:
 err_int_ep_ctl:
	usbnet_close ( &smsc75xx->usbnet );
 err_open:
 err_hw_cfg:
	smsc75xx_reset ( smsc75xx );
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void smsc75xx_close ( struct net_device *netdev ) {
	struct smsc75xx_device *smsc75xx = netdev->priv;

	/* Close USB network device */
	usbnet_close ( &smsc75xx->usbnet );

	/* Dump statistics (for debugging) */
	smsc75xx_dump_statistics ( smsc75xx );

	/* Reset device */
	smsc75xx_reset ( smsc75xx );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int smsc75xx_transmit ( struct net_device *netdev,
			       struct io_buffer *iobuf ) {
	struct smsc75xx_device *smsc75xx = netdev->priv;
	int rc;

	/* Transmit packet */
	if ( ( rc = smsc75xx_out_transmit ( smsc75xx, iobuf ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void smsc75xx_poll ( struct net_device *netdev ) {
	struct smsc75xx_device *smsc75xx = netdev->priv;
	uint32_t int_sts;
	int rc;

	/* Poll USB bus */
	usb_poll ( smsc75xx->bus );

	/* Refill endpoints */
	if ( ( rc = usbnet_refill ( &smsc75xx->usbnet ) ) != 0 )
		netdev_rx_err ( netdev, NULL, rc );

	/* Do nothing more unless there are interrupts to handle */
	int_sts = smsc75xx->int_sts;
	if ( ! int_sts )
		return;

	/* Check link status if applicable */
	if ( int_sts & SMSC75XX_INT_STS_PHY_INT ) {
		smsc75xx_check_link ( smsc75xx );
		int_sts &= ~SMSC75XX_INT_STS_PHY_INT;
	}

	/* Record RX FIFO overflow if applicable */
	if ( int_sts & SMSC75XX_INT_STS_RDFO_INT ) {
		DBGC2 ( smsc75xx, "SMSC75XX %p RX FIFO overflowed\n",
			smsc75xx );
		netdev_rx_err ( netdev, NULL, -ENOBUFS );
		int_sts &= ~SMSC75XX_INT_STS_RDFO_INT;
	}

	/* Check for unexpected interrupts */
	if ( int_sts ) {
		DBGC ( smsc75xx, "SMSC75XX %p unexpected interrupt %#08x\n",
		       smsc75xx, int_sts );
		netdev_rx_err ( netdev, NULL, -ENOTTY );
	}

	/* Clear interrupts */
	if ( ( rc = smsc75xx_writel ( smsc75xx, SMSC75XX_INT_STS,
				      smsc75xx->int_sts ) ) != 0 )
		netdev_rx_err ( netdev, NULL, rc );
	smsc75xx->int_sts = 0;
}

/** SMSC75xx network device operations */
static struct net_device_operations smsc75xx_operations = {
	.open		= smsc75xx_open,
	.close		= smsc75xx_close,
	.transmit	= smsc75xx_transmit,
	.poll		= smsc75xx_poll,
};

/******************************************************************************
 *
 * USB interface
 *
 ******************************************************************************
 */

/**
 * Probe device
 *
 * @v func		USB function
 * @v config		Configuration descriptor
 * @ret rc		Return status code
 */
static int smsc75xx_probe ( struct usb_function *func,
			    struct usb_configuration_descriptor *config ) {
	struct usb_device *usb = func->usb;
	struct net_device *netdev;
	struct smsc75xx_device *smsc75xx;
	int rc;

	/* Allocate and initialise structure */
	netdev = alloc_etherdev ( sizeof ( *smsc75xx ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &smsc75xx_operations );
	netdev->dev = &func->dev;
	smsc75xx = netdev->priv;
	memset ( smsc75xx, 0, sizeof ( *smsc75xx ) );
	smsc75xx->usb = usb;
	smsc75xx->bus = usb->port->hub->bus;
	smsc75xx->netdev = netdev;
	usbnet_init ( &smsc75xx->usbnet, func, &smsc75xx_intr_operations,
		      &smsc75xx_in_operations, &smsc75xx_out_operations );
	usb_refill_init ( &smsc75xx->usbnet.intr, 0, SMSC75XX_INTR_MAX_FILL );
	usb_refill_init ( &smsc75xx->usbnet.in, SMSC75XX_IN_MTU,
			  SMSC75XX_IN_MAX_FILL );
	mii_init ( &smsc75xx->mii, &smsc75xx_mii_operations );
	DBGC ( smsc75xx, "SMSC75XX %p on %s\n", smsc75xx, func->name );

	/* Describe USB network device */
	if ( ( rc = usbnet_describe ( &smsc75xx->usbnet, config ) ) != 0 ) {
		DBGC ( smsc75xx, "SMSC75XX %p could not describe: %s\n",
		       smsc75xx, strerror ( rc ) );
		goto err_describe;
	}

	/* Reset device */
	if ( ( rc = smsc75xx_reset ( smsc75xx ) ) != 0 )
		goto err_reset;

	/* Read MAC address */
	if ( ( rc = smsc75xx_eeprom_read ( smsc75xx, SMSC75XX_EEPROM_MAC,
					   netdev->hw_addr, ETH_ALEN ) ) != 0 )
		goto err_eeprom_read;

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register;

	usb_func_set_drvdata ( func, netdev );
	return 0;

	unregister_netdev ( netdev );
 err_register:
 err_eeprom_read:
 err_reset:
 err_describe:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
 err_alloc:
	return rc;
}

/**
 * Remove device
 *
 * @v func		USB function
 */
static void smsc75xx_remove ( struct usb_function *func ) {
	struct net_device *netdev = usb_func_get_drvdata ( func );

	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** SMSC75xx device IDs */
static struct usb_device_id smsc75xx_ids[] = {
	{
		.name = "smsc7500",
		.vendor = 0x0424,
		.product = 0x7500,
		.class = { 0xff, 0x00, 0xff },
	},
	{
		.name = "smsc7505",
		.vendor = 0x0424,
		.product = 0x7505,
		.class = { 0xff, 0x00, 0xff },
	},
};

/** SMSC LAN75xx driver */
struct usb_driver smsc75xx_driver __usb_driver = {
	.ids = smsc75xx_ids,
	.id_count = ( sizeof ( smsc75xx_ids ) / sizeof ( smsc75xx_ids[0] ) ),
	.probe = smsc75xx_probe,
	.remove = smsc75xx_remove,
};
