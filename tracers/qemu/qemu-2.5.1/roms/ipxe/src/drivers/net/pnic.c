/**************************************************************************
Etherboot -  BOOTP/TFTP Bootstrap Program
Bochs Pseudo NIC driver for Etherboot
***************************************************************************/

/*
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
 * See pnic_api.h for an explanation of the Bochs Pseudo NIC.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdio.h>
#include <ipxe/io.h>
#include <errno.h>
#include <ipxe/pci.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>

#include "pnic_api.h"

struct pnic {
	unsigned short ioaddr;
};

/* 
 * Utility functions: issue a PNIC command, retrieve result.  Use
 * pnic_command_quiet if you don't want failure codes to be
 * automatically printed.  Returns the PNIC status code.
 * 
 * Set output_length to NULL only if you expect to receive exactly
 * output_max_length bytes, otherwise it'll complain that you didn't
 * get enough data (on the assumption that if you not interested in
 * discovering the output length then you're expecting a fixed amount
 * of data).
 */

static uint16_t pnic_command_quiet ( struct pnic *pnic, uint16_t command,
				     const void *input, uint16_t input_length,
				     void *output, uint16_t output_max_length,
				     uint16_t *output_length ) {
	uint16_t status;
	uint16_t _output_length;

	if ( input != NULL ) {
		/* Write input length */
		outw ( input_length, pnic->ioaddr + PNIC_REG_LEN );
		/* Write input data */
		outsb ( pnic->ioaddr + PNIC_REG_DATA, input, input_length );
	}
	/* Write command */
	outw ( command, pnic->ioaddr + PNIC_REG_CMD );
	/* Retrieve status */
	status = inw ( pnic->ioaddr + PNIC_REG_STAT );
	/* Retrieve output length */
	_output_length = inw ( pnic->ioaddr + PNIC_REG_LEN );
	if ( output_length == NULL ) {
		if ( _output_length != output_max_length ) {
			printf ( "pnic_command %#hx: wrong data length "
				 "returned (expected %d, got %d)\n", command,
				 output_max_length, _output_length );
		}
	} else {
		*output_length = _output_length;
	}
	if ( output != NULL ) {
		if ( _output_length > output_max_length ) {
			printf ( "pnic_command %#hx: output buffer too small "
				 "(have %d, need %d)\n", command,
				 output_max_length, _output_length );
			_output_length = output_max_length;
		}
		/* Retrieve output data */
		insb ( pnic->ioaddr + PNIC_REG_DATA, output, _output_length );
	}
	return status;
}

static uint16_t pnic_command ( struct pnic *pnic, uint16_t command,
			       const void *input, uint16_t input_length,
			       void *output, uint16_t output_max_length,
			       uint16_t *output_length ) {
	uint16_t status = pnic_command_quiet ( pnic, command,
					       input, input_length,
					       output, output_max_length,
					       output_length );
	if ( status == PNIC_STATUS_OK ) return status;
	printf ( "PNIC command %#hx (len %#hx) failed with status %#hx\n",
		 command, input_length, status );
	return status;
}

/* Check API version matches that of NIC */
static int pnic_api_check ( uint16_t api_version ) {
	if ( api_version != PNIC_API_VERSION ) {
		printf ( "Warning: API version mismatch! "
			 "(NIC's is %d.%d, ours is %d.%d)\n",
			 api_version >> 8, api_version & 0xff,
			 PNIC_API_VERSION >> 8, PNIC_API_VERSION & 0xff );
	}
	if ( api_version < PNIC_API_VERSION ) {
		printf ( "** You may need to update your copy of Bochs **\n" );
	}
	return ( api_version == PNIC_API_VERSION );
}

/**************************************************************************
POLL - Wait for a frame
***************************************************************************/
static void pnic_poll ( struct net_device *netdev ) {
	struct pnic *pnic = netdev->priv;
	struct io_buffer *iobuf;
	uint16_t length;
	uint16_t qlen;

	/* Fetch all available packets */
	while ( 1 ) {
		if ( pnic_command ( pnic, PNIC_CMD_RECV_QLEN, NULL, 0,
				    &qlen, sizeof ( qlen ), NULL )
		     != PNIC_STATUS_OK )
			return;
		if ( qlen == 0 )
			return;
		iobuf = alloc_iob ( ETH_FRAME_LEN );
		if ( ! iobuf ) {
			DBG ( "could not allocate buffer\n" );
			netdev_rx_err ( netdev, NULL, -ENOMEM );
			return;
		}
		if ( pnic_command ( pnic, PNIC_CMD_RECV, NULL, 0,
				    iobuf->data, ETH_FRAME_LEN, &length )
		     != PNIC_STATUS_OK ) {
			netdev_rx_err ( netdev, iobuf, -EIO );
			return;
		}
		iob_put ( iobuf, length );
		netdev_rx ( netdev, iobuf );
	}
}

/**************************************************************************
TRANSMIT - Transmit a frame
***************************************************************************/
static int pnic_transmit ( struct net_device *netdev, struct io_buffer *iobuf ) {
	struct pnic *pnic = netdev->priv;

	/* Pad the packet */
	iob_pad ( iobuf, ETH_ZLEN );

	/* Send packet */
	pnic_command ( pnic, PNIC_CMD_XMIT, iobuf->data, iob_len ( iobuf ),
		       NULL, 0, NULL );

	netdev_tx_complete ( netdev, iobuf );
	return 0;
}

/**************************************************************************
OPEN - Open network device
***************************************************************************/
static int pnic_open ( struct net_device *netdev __unused ) {
	/* Nothing to do */
	return 0;
}

/**************************************************************************
CLOSE - Close network device
***************************************************************************/
static void pnic_close ( struct net_device *netdev __unused ) {
	/* Nothing to do */
}

/**************************************************************************
IRQ - Enable/disable interrupts
***************************************************************************/
static void pnic_irq ( struct net_device *netdev, int enable ) {
	struct pnic *pnic = netdev->priv;
	uint8_t mask = ( enable ? 1 : 0 );
	
	pnic_command ( pnic, PNIC_CMD_MASK_IRQ, &mask, sizeof ( mask ),
		       NULL, 0, NULL );
}

/**************************************************************************
OPERATIONS TABLE
***************************************************************************/
static struct net_device_operations pnic_operations = {
	.open		= pnic_open,
	.close		= pnic_close,
	.transmit	= pnic_transmit,
	.poll		= pnic_poll,
	.irq   		= pnic_irq,
};

/**************************************************************************
DISABLE - Turn off ethernet interface
***************************************************************************/
static void pnic_remove ( struct pci_device *pci ) {
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct pnic *pnic = netdev->priv;

	unregister_netdev ( netdev );
	pnic_command ( pnic, PNIC_CMD_RESET, NULL, 0, NULL, 0, NULL );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/**************************************************************************
PROBE - Look for an adapter, this routine's visible to the outside
***************************************************************************/
static int pnic_probe ( struct pci_device *pci ) {
	struct net_device *netdev;
	struct pnic *pnic;
	uint16_t api_version;
	uint16_t status;
	int rc;

	/* Allocate net device */
	netdev = alloc_etherdev ( sizeof ( *pnic ) );
	if ( ! netdev )
		return -ENOMEM;
	netdev_init ( netdev, &pnic_operations );
	pnic = netdev->priv;
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;
	pnic->ioaddr = pci->ioaddr;

	/* Fix up PCI device */
	adjust_pci_device ( pci );
	
	/* API version check */
	status = pnic_command_quiet ( pnic, PNIC_CMD_API_VER, NULL, 0,
				      &api_version,
				      sizeof ( api_version ), NULL );
	if ( status != PNIC_STATUS_OK ) {
		printf ( "PNIC failed installation check, code %#hx\n",
			 status );
		rc = -EIO;
		goto err;
	}
	pnic_api_check ( api_version );

	/* Get MAC address */
	status = pnic_command ( pnic, PNIC_CMD_READ_MAC, NULL, 0,
				netdev->hw_addr, ETH_ALEN, NULL );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err;

	/* Mark as link up; PNIC has no concept of link state */
	netdev_link_up ( netdev );

	return 0;

 err:
	/* Free net device */
	netdev_nullify ( netdev );
	netdev_put ( netdev );
	return rc;
}

static struct pci_device_id pnic_nics[] = {
/* genrules.pl doesn't let us use macros for PCI IDs...*/
PCI_ROM ( 0xfefe, 0xefef, "pnic", "Bochs Pseudo NIC Adaptor", 0 ),
};

struct pci_driver pnic_driver __pci_driver = {
	.ids = pnic_nics,
	.id_count = ( sizeof ( pnic_nics ) / sizeof ( pnic_nics[0] ) ),
	.probe = pnic_probe,
	.remove = pnic_remove,
};
