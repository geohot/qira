/** @file
 *
 * PXE UNDI API
 *
 */

/*
 * Copyright (C) 2004 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <stdio.h>
#include <string.h>
#include <byteswap.h>
#include <basemem_packet.h>
#include <ipxe/netdevice.h>
#include <ipxe/iobuf.h>
#include <ipxe/device.h>
#include <ipxe/pci.h>
#include <ipxe/if_ether.h>
#include <ipxe/ip.h>
#include <ipxe/arp.h>
#include <ipxe/rarp.h>
#include <ipxe/profile.h>
#include "pxe.h"

/**
 * Count of outstanding transmitted packets
 *
 * This is incremented each time PXENV_UNDI_TRANSMIT is called, and
 * decremented each time that PXENV_UNDI_ISR is called with the TX
 * queue empty, stopping when the count reaches zero.  This allows us
 * to provide a pessimistic approximation of TX completion events to
 * the PXE NBP simply by monitoring the netdev's TX queue.
 */
static int undi_tx_count = 0;

struct net_device *pxe_netdev = NULL;

/** Transmit profiler */
static struct profiler undi_tx_profiler __profiler = { .name = "undi.tx" };

/**
 * Set network device as current PXE network device
 *
 * @v netdev		Network device, or NULL
 */
void pxe_set_netdev ( struct net_device *netdev ) {

	if ( pxe_netdev ) {
		netdev_rx_unfreeze ( pxe_netdev );
		netdev_put ( pxe_netdev );
	}

	pxe_netdev = NULL;

	if ( netdev )
		pxe_netdev = netdev_get ( netdev );
}

/**
 * Open PXE network device
 *
 * @ret rc		Return status code
 */
static int pxe_netdev_open ( void ) {
	int rc;

	assert ( pxe_netdev != NULL );

	if ( ( rc = netdev_open ( pxe_netdev ) ) != 0 )
		return rc;

	netdev_rx_freeze ( pxe_netdev );
	netdev_irq ( pxe_netdev, 1 );

	return 0;
}

/**
 * Close PXE network device
 *
 */
static void pxe_netdev_close ( void ) {

	assert ( pxe_netdev != NULL );
	netdev_rx_unfreeze ( pxe_netdev );
	netdev_irq ( pxe_netdev, 0 );
	netdev_close ( pxe_netdev );
	undi_tx_count = 0;
}

/**
 * Dump multicast address list
 *
 * @v mcast		PXE multicast address list
 */
static void pxe_dump_mcast_list ( struct s_PXENV_UNDI_MCAST_ADDRESS *mcast ) {
	struct ll_protocol *ll_protocol = pxe_netdev->ll_protocol;
	unsigned int i;

	for ( i = 0 ; i < mcast->MCastAddrCount ; i++ ) {
		DBGC ( &pxe_netdev, " %s",
		       ll_protocol->ntoa ( mcast->McastAddr[i] ) );
	}
}

/* PXENV_UNDI_STARTUP
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_startup ( struct s_PXENV_UNDI_STARTUP *undi_startup ) {
	DBGC ( &pxe_netdev, "PXENV_UNDI_STARTUP\n" );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_STARTUP called with no "
		       "network device\n" );
		undi_startup->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	undi_startup->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_CLEANUP
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_cleanup ( struct s_PXENV_UNDI_CLEANUP *undi_cleanup ) {
	DBGC ( &pxe_netdev, "PXENV_UNDI_CLEANUP\n" );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_CLEANUP called with no "
		       "network device\n" );
		undi_cleanup->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	/* Close network device */
	pxe_netdev_close();

	undi_cleanup->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_INITIALIZE
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_initialize ( struct s_PXENV_UNDI_INITIALIZE *undi_initialize ) {
	DBGC ( &pxe_netdev, "PXENV_UNDI_INITIALIZE protocolini %08x\n",
	       undi_initialize->ProtocolIni );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_INITIALIZE called with no "
		       "network device\n" );
		undi_initialize->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	undi_initialize->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_RESET_ADAPTER
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_reset_adapter ( struct s_PXENV_UNDI_RESET *undi_reset_adapter ) {
	int rc;

	DBGC ( &pxe_netdev, "PXENV_UNDI_RESET_ADAPTER" );
	pxe_dump_mcast_list ( &undi_reset_adapter->R_Mcast_Buf );
	DBGC ( &pxe_netdev, "\n" );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_RESET_ADAPTER called with no "
		       "network device\n" );
		undi_reset_adapter->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	/* Close and reopen network device */
	pxe_netdev_close();
	if ( ( rc = pxe_netdev_open() ) != 0 ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_RESET_ADAPTER could not "
		       "reopen %s: %s\n", pxe_netdev->name, strerror ( rc ) );
		undi_reset_adapter->Status = PXENV_STATUS ( rc );
		return PXENV_EXIT_FAILURE;
	}

	undi_reset_adapter->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_SHUTDOWN
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_shutdown ( struct s_PXENV_UNDI_SHUTDOWN *undi_shutdown ) {
	DBGC ( &pxe_netdev, "PXENV_UNDI_SHUTDOWN\n" );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_SHUTDOWN called with no "
		       "network device\n" );
		undi_shutdown->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	/* Close network device */
	pxe_netdev_close();

	undi_shutdown->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_OPEN
 *
 * Status: working
 */
static PXENV_EXIT_t pxenv_undi_open ( struct s_PXENV_UNDI_OPEN *undi_open ) {
	int rc;

	DBGC ( &pxe_netdev, "PXENV_UNDI_OPEN flag %04x filter %04x",
	       undi_open->OpenFlag, undi_open->PktFilter );
	pxe_dump_mcast_list ( &undi_open->R_Mcast_Buf );
	DBGC ( &pxe_netdev, "\n" );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_OPEN called with no "
		       "network device\n" );
		undi_open->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	/* Open network device */
	if ( ( rc = pxe_netdev_open() ) != 0 ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_OPEN could not open %s: %s\n",
		       pxe_netdev->name, strerror ( rc ) );
		undi_open->Status = PXENV_STATUS ( rc );
		return PXENV_EXIT_FAILURE;
	}

	undi_open->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_CLOSE
 *
 * Status: working
 */
static PXENV_EXIT_t pxenv_undi_close ( struct s_PXENV_UNDI_CLOSE *undi_close ) {
	DBGC ( &pxe_netdev, "PXENV_UNDI_CLOSE\n" );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_CLOSE called with no "
		       "network device\n" );
		undi_close->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	/* Close network device */
	pxe_netdev_close();

	undi_close->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_TRANSMIT
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_transmit ( struct s_PXENV_UNDI_TRANSMIT *undi_transmit ) {
	struct s_PXENV_UNDI_TBD tbd;
	struct DataBlk *datablk;
	struct io_buffer *iobuf;
	struct net_protocol *net_protocol;
	struct ll_protocol *ll_protocol;
	char destaddr[MAX_LL_ADDR_LEN];
	const void *ll_dest;
	size_t len;
	unsigned int i;
	int rc;

	/* Start profiling */
	profile_start ( &undi_tx_profiler );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_TRANSMIT called with no "
		       "network device\n" );
		undi_transmit->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	DBGC2 ( &pxe_netdev, "PXENV_UNDI_TRANSMIT" );

	/* Forcibly enable interrupts and freeze receive queue
	 * processing at this point, to work around callers that never
	 * call PXENV_UNDI_OPEN before attempting to use the UNDI API.
	 */
	if ( ! netdev_rx_frozen ( pxe_netdev ) ) {
		netdev_rx_freeze ( pxe_netdev );
		netdev_irq ( pxe_netdev, 1 );
	}

	/* Identify network-layer protocol */
	switch ( undi_transmit->Protocol ) {
	case P_IP:	net_protocol = &ipv4_protocol;	break;
	case P_ARP:	net_protocol = &arp_protocol;	break;
	case P_RARP:	net_protocol = &rarp_protocol;	break;
	case P_UNKNOWN:
		net_protocol = NULL;
		break;
	default:
		DBGC2 ( &pxe_netdev, " %02x invalid protocol\n",
			undi_transmit->Protocol );
		undi_transmit->Status = PXENV_STATUS_UNDI_INVALID_PARAMETER;
		return PXENV_EXIT_FAILURE;
	}
	DBGC2 ( &pxe_netdev, " %s",
		( net_protocol ? net_protocol->name : "RAW" ) );

	/* Calculate total packet length */
	copy_from_real ( &tbd, undi_transmit->TBD.segment,
			 undi_transmit->TBD.offset, sizeof ( tbd ) );
	len = tbd.ImmedLength;
	DBGC2 ( &pxe_netdev, " %04x:%04x+%x", tbd.Xmit.segment, tbd.Xmit.offset,
		tbd.ImmedLength );
	for ( i = 0 ; i < tbd.DataBlkCount ; i++ ) {
		datablk = &tbd.DataBlock[i];
		len += datablk->TDDataLen;
		DBGC2 ( &pxe_netdev, " %04x:%04x+%x",
			datablk->TDDataPtr.segment, datablk->TDDataPtr.offset,
			datablk->TDDataLen );
	}

	/* Allocate and fill I/O buffer */
	iobuf = alloc_iob ( MAX_LL_HEADER_LEN +
			    ( ( len > IOB_ZLEN ) ? len : IOB_ZLEN ) );
	if ( ! iobuf ) {
		DBGC2 ( &pxe_netdev, " could not allocate iobuf\n" );
		undi_transmit->Status = PXENV_STATUS_OUT_OF_RESOURCES;
		return PXENV_EXIT_FAILURE;
	}
	iob_reserve ( iobuf, MAX_LL_HEADER_LEN );
	copy_from_real ( iob_put ( iobuf, tbd.ImmedLength ), tbd.Xmit.segment,
			 tbd.Xmit.offset, tbd.ImmedLength );
	for ( i = 0 ; i < tbd.DataBlkCount ; i++ ) {
		datablk = &tbd.DataBlock[i];
		copy_from_real ( iob_put ( iobuf, datablk->TDDataLen ),
				 datablk->TDDataPtr.segment,
				 datablk->TDDataPtr.offset,
				 datablk->TDDataLen );
	}

	/* Add link-layer header, if required to do so */
	if ( net_protocol != NULL ) {

		/* Calculate destination address */
		ll_protocol = pxe_netdev->ll_protocol;
		if ( undi_transmit->XmitFlag == XMT_DESTADDR ) {
			copy_from_real ( destaddr,
					 undi_transmit->DestAddr.segment,
					 undi_transmit->DestAddr.offset,
					 ll_protocol->ll_addr_len );
			ll_dest = destaddr;
			DBGC2 ( &pxe_netdev, " DEST %s",
				ll_protocol->ntoa ( ll_dest ) );
		} else {
			ll_dest = pxe_netdev->ll_broadcast;
			DBGC2 ( &pxe_netdev, " BCAST" );
		}

		/* Add link-layer header */
		if ( ( rc = ll_protocol->push ( pxe_netdev, iobuf, ll_dest,
						pxe_netdev->ll_addr,
						net_protocol->net_proto ))!=0){
			DBGC2 ( &pxe_netdev, " could not add link-layer "
				"header: %s\n", strerror ( rc ) );
			free_iob ( iobuf );
			undi_transmit->Status = PXENV_STATUS ( rc );
			return PXENV_EXIT_FAILURE;
		}
	}

	/* Flag transmission as in-progress.  Do this before starting
	 * to transmit the packet, because the ISR may trigger before
	 * we return from netdev_tx().
	 */
	undi_tx_count++;

	/* Transmit packet */
	DBGC2 ( &pxe_netdev, "\n" );
	if ( ( rc = netdev_tx ( pxe_netdev, iobuf ) ) != 0 ) {
		DBGC2 ( &pxe_netdev, "PXENV_UNDI_TRANSMIT could not transmit: "
			"%s\n", strerror ( rc ) );
		undi_tx_count--;
		undi_transmit->Status = PXENV_STATUS ( rc );
		return PXENV_EXIT_FAILURE;
	}

	profile_stop ( &undi_tx_profiler );
	undi_transmit->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_SET_MCAST_ADDRESS
 *
 * Status: working (for NICs that support receive-all-multicast)
 */
static PXENV_EXIT_t
pxenv_undi_set_mcast_address ( struct s_PXENV_UNDI_SET_MCAST_ADDRESS
			       *undi_set_mcast_address ) {
	DBGC ( &pxe_netdev, "PXENV_UNDI_SET_MCAST_ADDRESS" );
	pxe_dump_mcast_list ( &undi_set_mcast_address->R_Mcast_Buf );
	DBGC ( &pxe_netdev, "\n" );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_SET_MCAST_ADDRESS called with "
		       "no network device\n" );
		undi_set_mcast_address->Status =
			PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	undi_set_mcast_address->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_SET_STATION_ADDRESS
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_set_station_address ( struct s_PXENV_UNDI_SET_STATION_ADDRESS
				 *undi_set_station_address ) {
	struct ll_protocol *ll_protocol;

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_SET_STATION_ADDRESS called "
		       "with no network device\n" );
		undi_set_station_address->Status =
			PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	ll_protocol = pxe_netdev->ll_protocol;
	DBGC ( &pxe_netdev, "PXENV_UNDI_SET_STATION_ADDRESS %s",
	       ll_protocol->ntoa ( undi_set_station_address->StationAddress ) );

	/* If adapter is open, the change will have no effect; return
	 * an error
	 */
	if ( netdev_is_open ( pxe_netdev ) ) {
		DBGC ( &pxe_netdev, " failed: netdev is open\n" );
		undi_set_station_address->Status =
			PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	/* Update MAC address */
	memcpy ( pxe_netdev->ll_addr,
		 &undi_set_station_address->StationAddress,
		 ll_protocol->ll_addr_len );

	DBGC ( &pxe_netdev, "\n" );
	undi_set_station_address->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_SET_PACKET_FILTER
 *
 * Status: won't implement (would require driver API changes for no
 * real benefit)
 */
static PXENV_EXIT_t
pxenv_undi_set_packet_filter ( struct s_PXENV_UNDI_SET_PACKET_FILTER
			       *undi_set_packet_filter ) {

	DBGC ( &pxe_netdev, "PXENV_UNDI_SET_PACKET_FILTER %02x\n",
	       undi_set_packet_filter->filter );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_SET_PACKET_FILTER called with "
		       "no network device\n" );
		undi_set_packet_filter->Status =
			PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	/* Pretend that we succeeded, otherwise the 3Com DOS UNDI
	 * driver refuses to load.  (We ignore the filter value in the
	 * PXENV_UNDI_OPEN call anyway.)
	 */
	undi_set_packet_filter->Status = PXENV_STATUS_SUCCESS;

	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_GET_INFORMATION
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_get_information ( struct s_PXENV_UNDI_GET_INFORMATION
			     *undi_get_information ) {
	struct device *dev;
	struct ll_protocol *ll_protocol;

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_GET_INFORMATION called with no "
		       "network device\n" );
		undi_get_information->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	DBGC ( &pxe_netdev, "PXENV_UNDI_GET_INFORMATION" );

	/* Fill in information */
	dev = pxe_netdev->dev;
	ll_protocol = pxe_netdev->ll_protocol;
	undi_get_information->BaseIo = dev->desc.ioaddr;
	undi_get_information->IntNumber =
		( netdev_irq_supported ( pxe_netdev ) ? dev->desc.irq : 0 );
	/* Cheat: assume all cards can cope with this */
	undi_get_information->MaxTranUnit = ETH_MAX_MTU;
	undi_get_information->HwType = ntohs ( ll_protocol->ll_proto );
	undi_get_information->HwAddrLen = ll_protocol->ll_addr_len;
	assert ( ll_protocol->ll_addr_len <=
		 sizeof ( undi_get_information->CurrentNodeAddress ) );
	memcpy ( &undi_get_information->CurrentNodeAddress,
		 pxe_netdev->ll_addr,
		 sizeof ( undi_get_information->CurrentNodeAddress ) );
	ll_protocol->init_addr ( pxe_netdev->hw_addr,
				 &undi_get_information->PermNodeAddress );
	undi_get_information->ROMAddress = 0;
		/* nic.rom_info->rom_segment; */
	/* We only provide the ability to receive or transmit a single
	 * packet at a time.  This is a bootloader, not an OS.
	 */
	undi_get_information->RxBufCt = 1;
	undi_get_information->TxBufCt = 1;

	DBGC ( &pxe_netdev, " io %04x irq %d mtu %d %s %s\n",
	       undi_get_information->BaseIo, undi_get_information->IntNumber,
	       undi_get_information->MaxTranUnit, ll_protocol->name,
	       ll_protocol->ntoa ( &undi_get_information->CurrentNodeAddress ));
	undi_get_information->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_GET_STATISTICS
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_get_statistics ( struct s_PXENV_UNDI_GET_STATISTICS
			    *undi_get_statistics ) {

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_GET_STATISTICS called with no "
		       "network device\n" );
		undi_get_statistics->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	DBGC ( &pxe_netdev, "PXENV_UNDI_GET_STATISTICS" );

	/* Report statistics */
	undi_get_statistics->XmtGoodFrames = pxe_netdev->tx_stats.good;
	undi_get_statistics->RcvGoodFrames = pxe_netdev->rx_stats.good;
	undi_get_statistics->RcvCRCErrors = pxe_netdev->rx_stats.bad;
	undi_get_statistics->RcvResourceErrors = pxe_netdev->rx_stats.bad;
	DBGC ( &pxe_netdev, " txok %d rxok %d rxcrc %d rxrsrc %d\n",
	       undi_get_statistics->XmtGoodFrames,
	       undi_get_statistics->RcvGoodFrames,
	       undi_get_statistics->RcvCRCErrors,
	       undi_get_statistics->RcvResourceErrors );

	undi_get_statistics->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_CLEAR_STATISTICS
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_clear_statistics ( struct s_PXENV_UNDI_CLEAR_STATISTICS
			      *undi_clear_statistics ) {
	DBGC ( &pxe_netdev, "PXENV_UNDI_CLEAR_STATISTICS\n" );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_CLEAR_STATISTICS called with "
		       "no network device\n" );
		undi_clear_statistics->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	/* Clear statistics */
	memset ( &pxe_netdev->tx_stats, 0, sizeof ( pxe_netdev->tx_stats ) );
	memset ( &pxe_netdev->rx_stats, 0, sizeof ( pxe_netdev->rx_stats ) );

	undi_clear_statistics->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_INITIATE_DIAGS
 *
 * Status: won't implement (would require driver API changes for no
 * real benefit)
 */
static PXENV_EXIT_t
pxenv_undi_initiate_diags ( struct s_PXENV_UNDI_INITIATE_DIAGS
			    *undi_initiate_diags ) {
	DBGC ( &pxe_netdev, "PXENV_UNDI_INITIATE_DIAGS failed: unsupported\n" );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_INITIATE_DIAGS called with no "
		       "network device\n" );
		undi_initiate_diags->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	undi_initiate_diags->Status = PXENV_STATUS_UNSUPPORTED;
	return PXENV_EXIT_FAILURE;
}

/* PXENV_UNDI_FORCE_INTERRUPT
 *
 * Status: won't implement (would require driver API changes for no
 * perceptible benefit)
 */
static PXENV_EXIT_t
pxenv_undi_force_interrupt ( struct s_PXENV_UNDI_FORCE_INTERRUPT
			     *undi_force_interrupt ) {
	DBGC ( &pxe_netdev,
	       "PXENV_UNDI_FORCE_INTERRUPT failed: unsupported\n" );

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_FORCE_INTERRUPT called with no "
		       "network device\n" );
		undi_force_interrupt->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	undi_force_interrupt->Status = PXENV_STATUS_UNSUPPORTED;
	return PXENV_EXIT_FAILURE;
}

/* PXENV_UNDI_GET_MCAST_ADDRESS
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_get_mcast_address ( struct s_PXENV_UNDI_GET_MCAST_ADDRESS
			       *undi_get_mcast_address ) {
	struct ll_protocol *ll_protocol;
	struct in_addr ip = { .s_addr = undi_get_mcast_address->InetAddr };
	int rc;

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_GET_MCAST_ADDRESS called with "
		       "no network device\n" );
		undi_get_mcast_address->Status =
			PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	DBGC ( &pxe_netdev, "PXENV_UNDI_GET_MCAST_ADDRESS %s",
	       inet_ntoa ( ip ) );

	/* Hash address using the network device's link-layer protocol */
	ll_protocol = pxe_netdev->ll_protocol;
	if ( ( rc = ll_protocol->mc_hash ( AF_INET, &ip,
				      undi_get_mcast_address->MediaAddr ))!=0){
		DBGC ( &pxe_netdev, " failed: %s\n", strerror ( rc ) );
		undi_get_mcast_address->Status = PXENV_STATUS ( rc );
		return PXENV_EXIT_FAILURE;
	}
	DBGC ( &pxe_netdev, "=>%s\n",
	       ll_protocol->ntoa ( undi_get_mcast_address->MediaAddr ) );

	undi_get_mcast_address->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_GET_NIC_TYPE
 *
 * Status: working
 */
static PXENV_EXIT_t pxenv_undi_get_nic_type ( struct s_PXENV_UNDI_GET_NIC_TYPE
					      *undi_get_nic_type ) {
	struct device *dev;

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_GET_NIC_TYPE called with "
		       "no network device\n" );
		undi_get_nic_type->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	DBGC ( &pxe_netdev, "PXENV_UNDI_GET_NIC_TYPE" );

	/* Fill in information */
	memset ( &undi_get_nic_type->info, 0,
		 sizeof ( undi_get_nic_type->info ) );
	dev = pxe_netdev->dev;
	switch ( dev->desc.bus_type ) {
	case BUS_TYPE_PCI: {
		struct pci_nic_info *info = &undi_get_nic_type->info.pci;

		undi_get_nic_type->NicType = PCI_NIC;
		info->Vendor_ID = dev->desc.vendor;
		info->Dev_ID = dev->desc.device;
		info->Base_Class = PCI_BASE_CLASS ( dev->desc.class );
		info->Sub_Class = PCI_SUB_CLASS ( dev->desc.class );
		info->Prog_Intf = PCI_PROG_INTF ( dev->desc.class );
		info->BusDevFunc = dev->desc.location;
		/* Earlier versions of the PXE specification do not
		 * have the SubVendor_ID and SubDevice_ID fields.  It
		 * is possible that some NBPs will not provide space
		 * for them, and so we must not fill them in.
		 */
		DBGC ( &pxe_netdev, " PCI %02x:%02x.%x %04x:%04x "
		       "('%04x:%04x') %02x%02x%02x rev %02x\n",
		       PCI_BUS ( info->BusDevFunc ),
		       PCI_SLOT ( info->BusDevFunc ),
		       PCI_FUNC ( info->BusDevFunc ), info->Vendor_ID,
		       info->Dev_ID, info->SubVendor_ID, info->SubDevice_ID,
		       info->Base_Class, info->Sub_Class, info->Prog_Intf,
		       info->Rev );
		break; }
	case BUS_TYPE_ISAPNP: {
		struct pnp_nic_info *info = &undi_get_nic_type->info.pnp;

		undi_get_nic_type->NicType = PnP_NIC;
		info->EISA_Dev_ID = ( ( dev->desc.vendor << 16 ) |
				      dev->desc.device );
		info->CardSelNum = dev->desc.location;
		/* Cheat: remaining fields are probably unnecessary,
		 * and would require adding extra code to isapnp.c.
		 */
		DBGC ( &pxe_netdev, " ISAPnP CSN %04x %08x %02x%02x%02x\n",
		       info->CardSelNum, info->EISA_Dev_ID,
		       info->Base_Class, info->Sub_Class, info->Prog_Intf );
		break; }
	default:
		DBGC ( &pxe_netdev, " failed: unknown bus type\n" );
		undi_get_nic_type->Status = PXENV_STATUS_FAILURE;
		return PXENV_EXIT_FAILURE;
	}

	undi_get_nic_type->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_GET_IFACE_INFO
 *
 * Status: working
 */
static PXENV_EXIT_t
pxenv_undi_get_iface_info ( struct s_PXENV_UNDI_GET_IFACE_INFO
			    *undi_get_iface_info ) {

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxe_netdev, "PXENV_UNDI_GET_IFACE_INFO called with "
		       "no network device\n" );
		undi_get_iface_info->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	DBGC ( &pxe_netdev, "PXENV_UNDI_GET_IFACE_INFO" );

	/* Just hand back some info, doesn't really matter what it is.
	 * Most PXE stacks seem to take this approach.
	 */
	snprintf ( ( char * ) undi_get_iface_info->IfaceType,
		   sizeof ( undi_get_iface_info->IfaceType ), "DIX+802.3" );
	undi_get_iface_info->LinkSpeed = 10000000; /* 10 Mbps */
	undi_get_iface_info->ServiceFlags =
		( SUPPORTED_BROADCAST | SUPPORTED_MULTICAST |
		  SUPPORTED_SET_STATION_ADDRESS | SUPPORTED_RESET |
		  SUPPORTED_OPEN_CLOSE );
	if ( netdev_irq_supported ( pxe_netdev ) )
		undi_get_iface_info->ServiceFlags |= SUPPORTED_IRQ;
	memset ( undi_get_iface_info->Reserved, 0,
		 sizeof(undi_get_iface_info->Reserved) );

	DBGC ( &pxe_netdev, " %s %dbps flags %08x\n",
	       undi_get_iface_info->IfaceType, undi_get_iface_info->LinkSpeed,
	       undi_get_iface_info->ServiceFlags );
	undi_get_iface_info->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/* PXENV_UNDI_GET_STATE
 *
 * Status: impossible due to opcode collision
 */

/* PXENV_UNDI_ISR
 *
 * Status: working
 */
static PXENV_EXIT_t pxenv_undi_isr ( struct s_PXENV_UNDI_ISR *undi_isr ) {
	struct io_buffer *iobuf;
	size_t len;
	struct ll_protocol *ll_protocol;
	const void *ll_dest;
	const void *ll_source;
	uint16_t net_proto;
	unsigned int flags;
	size_t ll_hlen;
	struct net_protocol *net_protocol;
	unsigned int prottype;
	int rc;

	/* Use a different debug colour, since UNDI ISR messages are
	 * likely to be interspersed amongst other UNDI messages.
	 */

	/* Sanity check */
	if ( ! pxe_netdev ) {
		DBGC ( &pxenv_undi_isr, "PXENV_UNDI_ISR called with "
		       "no network device\n" );
		undi_isr->Status = PXENV_STATUS_UNDI_INVALID_STATE;
		return PXENV_EXIT_FAILURE;
	}

	DBGC2 ( &pxenv_undi_isr, "PXENV_UNDI_ISR" );

	/* Just in case some idiot actually looks at these fields when
	 * we weren't meant to fill them in...
	 */
	undi_isr->BufferLength = 0;
	undi_isr->FrameLength = 0;
	undi_isr->FrameHeaderLength = 0;
	undi_isr->ProtType = 0;
	undi_isr->PktType = 0;

	switch ( undi_isr->FuncFlag ) {
	case PXENV_UNDI_ISR_IN_START :
		DBGC2 ( &pxenv_undi_isr, " START" );

		/* Call poll().  This should acknowledge the device
		 * interrupt and queue up any received packet.
		 */
		net_poll();

		/* A 100% accurate determination of "OURS" vs "NOT
		 * OURS" is difficult to achieve without invasive and
		 * unpleasant changes to the driver model.  We settle
		 * for always returning "OURS" if interrupts are
		 * currently enabled.
		 *
		 * Returning "NOT OURS" when interrupts are disabled
		 * allows us to avoid a potential interrupt storm when
		 * we are on a shared interrupt line; if we were to
		 * always return "OURS" then the other device's ISR
		 * may never be called.
		 */
		if ( netdev_irq_enabled ( pxe_netdev ) ) {
			DBGC2 ( &pxenv_undi_isr, " OURS" );
			undi_isr->FuncFlag = PXENV_UNDI_ISR_OUT_OURS;
		} else {
			DBGC2 ( &pxenv_undi_isr, " NOT OURS" );
			undi_isr->FuncFlag = PXENV_UNDI_ISR_OUT_NOT_OURS;
		}

		/* Disable interrupts */
		netdev_irq ( pxe_netdev, 0 );

		break;
	case PXENV_UNDI_ISR_IN_PROCESS :
	case PXENV_UNDI_ISR_IN_GET_NEXT :
		DBGC2 ( &pxenv_undi_isr, " %s",
			( ( undi_isr->FuncFlag == PXENV_UNDI_ISR_IN_PROCESS ) ?
			  "PROCESS" : "GET_NEXT" ) );

		/* Some dumb NBPs (e.g. emBoot's winBoot/i) never call
		 * PXENV_UNDI_ISR with FuncFlag=PXENV_UNDI_ISR_START;
		 * they just sit in a tight polling loop merrily
		 * violating the PXE spec with repeated calls to
		 * PXENV_UNDI_ISR_IN_PROCESS.  Force extra polls to
		 * cope with these out-of-spec clients.
		 */
		net_poll();

		/* If we have not yet marked a TX as complete, and the
		 * netdev TX queue is empty, report the TX completion.
		 */
		if ( undi_tx_count && list_empty ( &pxe_netdev->tx_queue ) ) {
			DBGC2 ( &pxenv_undi_isr, " TXC" );
			undi_tx_count--;
			undi_isr->FuncFlag = PXENV_UNDI_ISR_OUT_TRANSMIT;
			break;
		}

		/* Remove first packet from netdev RX queue */
		iobuf = netdev_rx_dequeue ( pxe_netdev );
		if ( ! iobuf ) {
			DBGC2 ( &pxenv_undi_isr, " DONE" );
			/* No more packets remaining */
			undi_isr->FuncFlag = PXENV_UNDI_ISR_OUT_DONE;
			/* Re-enable interrupts */
			netdev_irq ( pxe_netdev, 1 );
			break;
		}

		/* Copy packet to base memory buffer */
		len = iob_len ( iobuf );
		DBGC2 ( &pxenv_undi_isr, " RX" );
		if ( len > sizeof ( basemem_packet ) ) {
			/* Should never happen */
			DBGC2 ( &pxenv_undi_isr, " overlength (%zx)", len );
			len = sizeof ( basemem_packet );
		}
		memcpy ( basemem_packet, iobuf->data, len );

		/* Strip link-layer header */
		ll_protocol = pxe_netdev->ll_protocol;
		if ( ( rc = ll_protocol->pull ( pxe_netdev, iobuf, &ll_dest,
						&ll_source, &net_proto,
						&flags ) ) != 0 ) {
			/* Assume unknown net_proto and no ll_source */
			net_proto = 0;
			ll_source = NULL;
		}
		ll_hlen = ( len - iob_len ( iobuf ) );

		/* Determine network-layer protocol */
		switch ( net_proto ) {
		case htons ( ETH_P_IP ):
			net_protocol = &ipv4_protocol;
			prottype = P_IP;
			break;
		case htons ( ETH_P_ARP ):
			net_protocol = &arp_protocol;
			prottype = P_ARP;
			break;
		case htons ( ETH_P_RARP ):
			net_protocol = &rarp_protocol;
			prottype = P_RARP;
			break;
		default:
			net_protocol = NULL;
			prottype = P_UNKNOWN;
			break;
		}

		/* Fill in UNDI_ISR structure */
		undi_isr->FuncFlag = PXENV_UNDI_ISR_OUT_RECEIVE;
		undi_isr->BufferLength = len;
		undi_isr->FrameLength = len;
		undi_isr->FrameHeaderLength = ll_hlen;
		undi_isr->Frame.segment = rm_ds;
		undi_isr->Frame.offset = __from_data16 ( basemem_packet );
		undi_isr->ProtType = prottype;
		if ( flags & LL_BROADCAST ) {
			undi_isr->PktType = P_BROADCAST;
		} else if ( flags & LL_MULTICAST ) {
			undi_isr->PktType = P_MULTICAST;
		} else {
			undi_isr->PktType = P_DIRECTED;
		}
		DBGC2 ( &pxenv_undi_isr, " %04x:%04x+%x(%x) %s hlen %d",
			undi_isr->Frame.segment, undi_isr->Frame.offset,
			undi_isr->BufferLength, undi_isr->FrameLength,
			( net_protocol ? net_protocol->name : "RAW" ),
			undi_isr->FrameHeaderLength );

		/* Free packet */
		free_iob ( iobuf );
		break;
	default :
		DBGC2 ( &pxenv_undi_isr, " INVALID(%04x)\n",
			undi_isr->FuncFlag );

		/* Should never happen */
		undi_isr->FuncFlag = PXENV_UNDI_ISR_OUT_DONE;
		undi_isr->Status = PXENV_STATUS_UNDI_INVALID_PARAMETER;
		return PXENV_EXIT_FAILURE;
	}

	DBGC2 ( &pxenv_undi_isr, "\n" );
	undi_isr->Status = PXENV_STATUS_SUCCESS;
	return PXENV_EXIT_SUCCESS;
}

/** PXE UNDI API */
struct pxe_api_call pxe_undi_api[] __pxe_api_call = {
	PXE_API_CALL ( PXENV_UNDI_STARTUP, pxenv_undi_startup,
		       struct s_PXENV_UNDI_STARTUP ),
	PXE_API_CALL ( PXENV_UNDI_CLEANUP, pxenv_undi_cleanup,
		       struct s_PXENV_UNDI_CLEANUP ),
	PXE_API_CALL ( PXENV_UNDI_INITIALIZE, pxenv_undi_initialize,
		       struct s_PXENV_UNDI_INITIALIZE ),
	PXE_API_CALL ( PXENV_UNDI_RESET_ADAPTER, pxenv_undi_reset_adapter,
		       struct s_PXENV_UNDI_RESET ),
	PXE_API_CALL ( PXENV_UNDI_SHUTDOWN, pxenv_undi_shutdown,
		       struct s_PXENV_UNDI_SHUTDOWN ),
	PXE_API_CALL ( PXENV_UNDI_OPEN, pxenv_undi_open,
		       struct s_PXENV_UNDI_OPEN ),
	PXE_API_CALL ( PXENV_UNDI_CLOSE, pxenv_undi_close,
		       struct s_PXENV_UNDI_CLOSE ),
	PXE_API_CALL ( PXENV_UNDI_TRANSMIT, pxenv_undi_transmit,
		       struct s_PXENV_UNDI_TRANSMIT ),
	PXE_API_CALL ( PXENV_UNDI_SET_MCAST_ADDRESS,
		       pxenv_undi_set_mcast_address,
		       struct s_PXENV_UNDI_SET_MCAST_ADDRESS ),
	PXE_API_CALL ( PXENV_UNDI_SET_STATION_ADDRESS,
		       pxenv_undi_set_station_address,
		       struct s_PXENV_UNDI_SET_STATION_ADDRESS ),
	PXE_API_CALL ( PXENV_UNDI_SET_PACKET_FILTER,
		       pxenv_undi_set_packet_filter,
		       struct s_PXENV_UNDI_SET_PACKET_FILTER ),
	PXE_API_CALL ( PXENV_UNDI_GET_INFORMATION, pxenv_undi_get_information,
		       struct s_PXENV_UNDI_GET_INFORMATION ),
	PXE_API_CALL ( PXENV_UNDI_GET_STATISTICS, pxenv_undi_get_statistics,
		       struct s_PXENV_UNDI_GET_STATISTICS ),
	PXE_API_CALL ( PXENV_UNDI_CLEAR_STATISTICS, pxenv_undi_clear_statistics,
		       struct s_PXENV_UNDI_CLEAR_STATISTICS ),
	PXE_API_CALL ( PXENV_UNDI_INITIATE_DIAGS, pxenv_undi_initiate_diags,
		       struct s_PXENV_UNDI_INITIATE_DIAGS ),
	PXE_API_CALL ( PXENV_UNDI_FORCE_INTERRUPT, pxenv_undi_force_interrupt,
		       struct s_PXENV_UNDI_FORCE_INTERRUPT ),
	PXE_API_CALL ( PXENV_UNDI_GET_MCAST_ADDRESS,
		       pxenv_undi_get_mcast_address,
		       struct s_PXENV_UNDI_GET_MCAST_ADDRESS ),
	PXE_API_CALL ( PXENV_UNDI_GET_NIC_TYPE, pxenv_undi_get_nic_type,
		       struct s_PXENV_UNDI_GET_NIC_TYPE ),
	PXE_API_CALL ( PXENV_UNDI_GET_IFACE_INFO, pxenv_undi_get_iface_info,
		       struct s_PXENV_UNDI_GET_IFACE_INFO ),
	PXE_API_CALL ( PXENV_UNDI_ISR, pxenv_undi_isr,
		       struct s_PXENV_UNDI_ISR ),
};
