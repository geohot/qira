/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/netdevice.h>
#include <ipxe/iobuf.h>
#include <ipxe/in.h>
#include <ipxe/version.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_driver.h>
#include <ipxe/efi/efi_strings.h>
#include <ipxe/efi/efi_utils.h>
#include <ipxe/efi/efi_watchdog.h>
#include <ipxe/efi/efi_snp.h>
#include <usr/autoboot.h>
#include <config/general.h>

/** List of SNP devices */
static LIST_HEAD ( efi_snp_devices );

/** Network devices are currently claimed for use by iPXE */
static int efi_snp_claimed;

/* Downgrade user experience if configured to do so
 *
 * The default UEFI user experience for network boot is somewhat
 * excremental: only TFTP is available as a download protocol, and if
 * anything goes wrong the user will be shown just a dot on an
 * otherwise blank screen.  (Some programmer was clearly determined to
 * win a bet that they could outshine Apple at producing uninformative
 * error messages.)
 *
 * For comparison, the default iPXE user experience provides the
 * option to use protocols designed more recently than 1980 (such as
 * HTTP and iSCSI), and if anything goes wrong the the user will be
 * shown one of over 1200 different error messages, complete with a
 * link to a wiki page describing that specific error.
 *
 * We default to upgrading the user experience to match that available
 * in a "legacy" BIOS environment, by installing our own instance of
 * EFI_LOAD_FILE_PROTOCOL.
 *
 * Note that unfortunately we can't sensibly provide the choice of
 * both options to the user in the same build, because the UEFI boot
 * menu ignores the multitude of ways in which a network device handle
 * can be described and opaquely labels both menu entries as just "EFI
 * Network".
 */
#ifdef EFI_DOWNGRADE_UX
static EFI_GUID dummy_load_file_protocol_guid = {
	0x6f6c7323, 0x2077, 0x7523,
	{ 0x6e, 0x68, 0x65, 0x6c, 0x70, 0x66, 0x75, 0x6c }
};
#define efi_load_file_protocol_guid dummy_load_file_protocol_guid
#endif

/**
 * Set EFI SNP mode state
 *
 * @v snp		SNP interface
 */
static void efi_snp_set_state ( struct efi_snp_device *snpdev ) {
	struct net_device *netdev = snpdev->netdev;
	EFI_SIMPLE_NETWORK_MODE *mode = &snpdev->mode;

	/* Calculate state */
	if ( ! snpdev->started ) {
		/* Start() method not called; report as Stopped */
		mode->State = EfiSimpleNetworkStopped;
	} else if ( ! netdev_is_open ( netdev ) ) {
		/* Network device not opened; report as Started */
		mode->State = EfiSimpleNetworkStarted;
	} else if ( efi_snp_claimed ) {
		/* Network device opened but claimed for use by iPXE; report
		 * as Started to inhibit receive polling.
		 */
		mode->State = EfiSimpleNetworkStarted;
	} else {
		/* Network device opened and available for use via SNP; report
		 * as Initialized.
		 */
		mode->State = EfiSimpleNetworkInitialized;
	}
}

/**
 * Set EFI SNP mode based on iPXE net device parameters
 *
 * @v snp		SNP interface
 */
static void efi_snp_set_mode ( struct efi_snp_device *snpdev ) {
	struct net_device *netdev = snpdev->netdev;
	EFI_SIMPLE_NETWORK_MODE *mode = &snpdev->mode;
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	unsigned int ll_addr_len = ll_protocol->ll_addr_len;

	mode->HwAddressSize = ll_addr_len;
	mode->MediaHeaderSize = ll_protocol->ll_header_len;
	mode->MaxPacketSize = netdev->max_pkt_len;
	mode->ReceiveFilterMask = ( EFI_SIMPLE_NETWORK_RECEIVE_UNICAST |
				    EFI_SIMPLE_NETWORK_RECEIVE_MULTICAST |
				    EFI_SIMPLE_NETWORK_RECEIVE_BROADCAST );
	assert ( ll_addr_len <= sizeof ( mode->CurrentAddress ) );
	memcpy ( &mode->CurrentAddress, netdev->ll_addr, ll_addr_len );
	memcpy ( &mode->BroadcastAddress, netdev->ll_broadcast, ll_addr_len );
	ll_protocol->init_addr ( netdev->hw_addr, &mode->PermanentAddress );
	mode->IfType = ntohs ( ll_protocol->ll_proto );
	mode->MacAddressChangeable = TRUE;
	mode->MediaPresentSupported = TRUE;
	mode->MediaPresent = ( netdev_link_ok ( netdev ) ? TRUE : FALSE );
}

/**
 * Flush transmit ring and receive queue
 *
 * @v snpdev		SNP device
 */
static void efi_snp_flush ( struct efi_snp_device *snpdev ) {
	struct io_buffer *iobuf;
	struct io_buffer *tmp;

	/* Reset transmit completion ring */
	snpdev->tx_prod = 0;
	snpdev->tx_cons = 0;

	/* Discard any queued receive buffers */
	list_for_each_entry_safe ( iobuf, tmp, &snpdev->rx, list ) {
		list_del ( &iobuf->list );
		free_iob ( iobuf );
	}
}

/**
 * Poll net device and count received packets
 *
 * @v snpdev		SNP device
 */
static void efi_snp_poll ( struct efi_snp_device *snpdev ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct io_buffer *iobuf;

	/* Poll network device */
	netdev_poll ( snpdev->netdev );

	/* Retrieve any received packets */
	while ( ( iobuf = netdev_rx_dequeue ( snpdev->netdev ) ) ) {
		list_add_tail ( &iobuf->list, &snpdev->rx );
		snpdev->interrupts |= EFI_SIMPLE_NETWORK_RECEIVE_INTERRUPT;
		bs->SignalEvent ( &snpdev->snp.WaitForPacket );
	}
}

/**
 * Change SNP state from "stopped" to "started"
 *
 * @v snp		SNP interface
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_start ( EFI_SIMPLE_NETWORK_PROTOCOL *snp ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );

	DBGC2 ( snpdev, "SNPDEV %p START\n", snpdev );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	snpdev->started = 1;
	efi_snp_set_state ( snpdev );
	return 0;
}

/**
 * Change SNP state from "started" to "stopped"
 *
 * @v snp		SNP interface
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_stop ( EFI_SIMPLE_NETWORK_PROTOCOL *snp ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );

	DBGC2 ( snpdev, "SNPDEV %p STOP\n", snpdev );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	snpdev->started = 0;
	efi_snp_set_state ( snpdev );
	return 0;
}

/**
 * Open the network device
 *
 * @v snp		SNP interface
 * @v extra_rx_bufsize	Extra RX buffer size, in bytes
 * @v extra_tx_bufsize	Extra TX buffer size, in bytes
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_initialize ( EFI_SIMPLE_NETWORK_PROTOCOL *snp,
		     UINTN extra_rx_bufsize, UINTN extra_tx_bufsize ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );
	int rc;

	DBGC2 ( snpdev, "SNPDEV %p INITIALIZE (%ld extra RX, %ld extra TX)\n",
		snpdev, ( ( unsigned long ) extra_rx_bufsize ),
		( ( unsigned long ) extra_tx_bufsize ) );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	if ( ( rc = netdev_open ( snpdev->netdev ) ) != 0 ) {
		DBGC ( snpdev, "SNPDEV %p could not open %s: %s\n",
		       snpdev, snpdev->netdev->name, strerror ( rc ) );
		return EFIRC ( rc );
	}
	efi_snp_set_state ( snpdev );

	return 0;
}

/**
 * Reset the network device
 *
 * @v snp		SNP interface
 * @v ext_verify	Extended verification required
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_reset ( EFI_SIMPLE_NETWORK_PROTOCOL *snp, BOOLEAN ext_verify ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );
	int rc;

	DBGC2 ( snpdev, "SNPDEV %p RESET (%s extended verification)\n",
		snpdev, ( ext_verify ? "with" : "without" ) );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	netdev_close ( snpdev->netdev );
	efi_snp_set_state ( snpdev );
	efi_snp_flush ( snpdev );

	if ( ( rc = netdev_open ( snpdev->netdev ) ) != 0 ) {
		DBGC ( snpdev, "SNPDEV %p could not reopen %s: %s\n",
		       snpdev, snpdev->netdev->name, strerror ( rc ) );
		return EFIRC ( rc );
	}
	efi_snp_set_state ( snpdev );

	return 0;
}

/**
 * Shut down the network device
 *
 * @v snp		SNP interface
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_shutdown ( EFI_SIMPLE_NETWORK_PROTOCOL *snp ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );

	DBGC2 ( snpdev, "SNPDEV %p SHUTDOWN\n", snpdev );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	netdev_close ( snpdev->netdev );
	efi_snp_set_state ( snpdev );
	efi_snp_flush ( snpdev );

	return 0;
}

/**
 * Manage receive filters
 *
 * @v snp		SNP interface
 * @v enable		Receive filters to enable
 * @v disable		Receive filters to disable
 * @v mcast_reset	Reset multicast filters
 * @v mcast_count	Number of multicast filters
 * @v mcast		Multicast filters
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_receive_filters ( EFI_SIMPLE_NETWORK_PROTOCOL *snp, UINT32 enable,
			  UINT32 disable, BOOLEAN mcast_reset,
			  UINTN mcast_count, EFI_MAC_ADDRESS *mcast ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );
	unsigned int i;

	DBGC2 ( snpdev, "SNPDEV %p RECEIVE_FILTERS %08x&~%08x%s %ld mcast\n",
		snpdev, enable, disable, ( mcast_reset ? " reset" : "" ),
		( ( unsigned long ) mcast_count ) );
	for ( i = 0 ; i < mcast_count ; i++ ) {
		DBGC2_HDA ( snpdev, i, &mcast[i],
			    snpdev->netdev->ll_protocol->ll_addr_len );
	}

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	/* Lie through our teeth, otherwise MNP refuses to accept us */
	return 0;
}

/**
 * Set station address
 *
 * @v snp		SNP interface
 * @v reset		Reset to permanent address
 * @v new		New station address
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_station_address ( EFI_SIMPLE_NETWORK_PROTOCOL *snp, BOOLEAN reset,
			  EFI_MAC_ADDRESS *new ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );
	struct ll_protocol *ll_protocol = snpdev->netdev->ll_protocol;

	DBGC2 ( snpdev, "SNPDEV %p STATION_ADDRESS %s\n", snpdev,
		( reset ? "reset" : ll_protocol->ntoa ( new ) ) );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	/* Set the MAC address */
	if ( reset )
		new = &snpdev->mode.PermanentAddress;
	memcpy ( snpdev->netdev->ll_addr, new, ll_protocol->ll_addr_len );

	/* MAC address changes take effect only on netdev_open() */
	if ( netdev_is_open ( snpdev->netdev ) ) {
		DBGC ( snpdev, "SNPDEV %p MAC address changed while net "
		       "device open\n", snpdev );
	}

	return 0;
}

/**
 * Get (or reset) statistics
 *
 * @v snp		SNP interface
 * @v reset		Reset statistics
 * @v stats_len		Size of statistics table
 * @v stats		Statistics table
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_statistics ( EFI_SIMPLE_NETWORK_PROTOCOL *snp, BOOLEAN reset,
		     UINTN *stats_len, EFI_NETWORK_STATISTICS *stats ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );
	EFI_NETWORK_STATISTICS stats_buf;

	DBGC2 ( snpdev, "SNPDEV %p STATISTICS%s", snpdev,
		( reset ? " reset" : "" ) );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	/* Gather statistics */
	memset ( &stats_buf, 0, sizeof ( stats_buf ) );
	stats_buf.TxGoodFrames = snpdev->netdev->tx_stats.good;
	stats_buf.TxDroppedFrames = snpdev->netdev->tx_stats.bad;
	stats_buf.TxTotalFrames = ( snpdev->netdev->tx_stats.good +
				    snpdev->netdev->tx_stats.bad );
	stats_buf.RxGoodFrames = snpdev->netdev->rx_stats.good;
	stats_buf.RxDroppedFrames = snpdev->netdev->rx_stats.bad;
	stats_buf.RxTotalFrames = ( snpdev->netdev->rx_stats.good +
				    snpdev->netdev->rx_stats.bad );
	if ( *stats_len > sizeof ( stats_buf ) )
		*stats_len = sizeof ( stats_buf );
	if ( stats )
		memcpy ( stats, &stats_buf, *stats_len );

	/* Reset statistics if requested to do so */
	if ( reset ) {
		memset ( &snpdev->netdev->tx_stats, 0,
			 sizeof ( snpdev->netdev->tx_stats ) );
		memset ( &snpdev->netdev->rx_stats, 0,
			 sizeof ( snpdev->netdev->rx_stats ) );
	}

	return 0;
}

/**
 * Convert multicast IP address to MAC address
 *
 * @v snp		SNP interface
 * @v ipv6		Address is IPv6
 * @v ip		IP address
 * @v mac		MAC address
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_mcast_ip_to_mac ( EFI_SIMPLE_NETWORK_PROTOCOL *snp, BOOLEAN ipv6,
			  EFI_IP_ADDRESS *ip, EFI_MAC_ADDRESS *mac ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );
	struct ll_protocol *ll_protocol = snpdev->netdev->ll_protocol;
	const char *ip_str;
	int rc;

	ip_str = ( ipv6 ? "(IPv6)" /* FIXME when we have inet6_ntoa() */ :
		   inet_ntoa ( *( ( struct in_addr * ) ip ) ) );
	DBGC2 ( snpdev, "SNPDEV %p MCAST_IP_TO_MAC %s\n", snpdev, ip_str );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	/* Try to hash the address */
	if ( ( rc = ll_protocol->mc_hash ( ( ipv6 ? AF_INET6 : AF_INET ),
					   ip, mac ) ) != 0 ) {
		DBGC ( snpdev, "SNPDEV %p could not hash %s: %s\n",
		       snpdev, ip_str, strerror ( rc ) );
		return EFIRC ( rc );
	}

	return 0;
}

/**
 * Read or write non-volatile storage
 *
 * @v snp		SNP interface
 * @v read		Operation is a read
 * @v offset		Starting offset within NVRAM
 * @v len		Length of data buffer
 * @v data		Data buffer
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_nvdata ( EFI_SIMPLE_NETWORK_PROTOCOL *snp, BOOLEAN read,
		 UINTN offset, UINTN len, VOID *data ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );

	DBGC2 ( snpdev, "SNPDEV %p NVDATA %s %lx+%lx\n", snpdev,
		( read ? "read" : "write" ), ( ( unsigned long ) offset ),
		( ( unsigned long ) len ) );
	if ( ! read )
		DBGC2_HDA ( snpdev, offset, data, len );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	return EFI_UNSUPPORTED;
}

/**
 * Read interrupt status and TX recycled buffer status
 *
 * @v snp		SNP interface
 * @v interrupts	Interrupt status, or NULL
 * @v txbuf		Recycled transmit buffer address, or NULL
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_get_status ( EFI_SIMPLE_NETWORK_PROTOCOL *snp,
		     UINT32 *interrupts, VOID **txbuf ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );

	DBGC2 ( snpdev, "SNPDEV %p GET_STATUS", snpdev );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed ) {
		DBGC2 ( snpdev, "\n" );
		return EFI_NOT_READY;
	}

	/* Poll the network device */
	efi_snp_poll ( snpdev );

	/* Interrupt status.  In practice, this seems to be used only
	 * to detect TX completions.
	 */
	if ( interrupts ) {
		*interrupts = snpdev->interrupts;
		DBGC2 ( snpdev, " INTS:%02x", *interrupts );
		snpdev->interrupts = 0;
	}

	/* TX completions */
	if ( txbuf ) {
		if ( snpdev->tx_prod != snpdev->tx_cons ) {
			*txbuf = snpdev->tx[snpdev->tx_cons++ % EFI_SNP_NUM_TX];
		} else {
			*txbuf = NULL;
		}
		DBGC2 ( snpdev, " TX:%p", *txbuf );
	}

	DBGC2 ( snpdev, "\n" );
	return 0;
}

/**
 * Start packet transmission
 *
 * @v snp		SNP interface
 * @v ll_header_len	Link-layer header length, if to be filled in
 * @v len		Length of data buffer
 * @v data		Data buffer
 * @v ll_src		Link-layer source address, if specified
 * @v ll_dest		Link-layer destination address, if specified
 * @v net_proto		Network-layer protocol (in host order)
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_transmit ( EFI_SIMPLE_NETWORK_PROTOCOL *snp,
		   UINTN ll_header_len, UINTN len, VOID *data,
		   EFI_MAC_ADDRESS *ll_src, EFI_MAC_ADDRESS *ll_dest,
		   UINT16 *net_proto ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );
	struct ll_protocol *ll_protocol = snpdev->netdev->ll_protocol;
	struct io_buffer *iobuf;
	size_t payload_len;
	unsigned int tx_fill;
	int rc;

	DBGC2 ( snpdev, "SNPDEV %p TRANSMIT %p+%lx", snpdev, data,
		( ( unsigned long ) len ) );
	if ( ll_header_len ) {
		if ( ll_src ) {
			DBGC2 ( snpdev, " src %s",
				ll_protocol->ntoa ( ll_src ) );
		}
		if ( ll_dest ) {
			DBGC2 ( snpdev, " dest %s",
				ll_protocol->ntoa ( ll_dest ) );
		}
		if ( net_proto ) {
			DBGC2 ( snpdev, " proto %04x", *net_proto );
		}
	}
	DBGC2 ( snpdev, "\n" );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	/* Sanity checks */
	if ( ll_header_len ) {
		if ( ll_header_len != ll_protocol->ll_header_len ) {
			DBGC ( snpdev, "SNPDEV %p TX invalid header length "
			       "%ld\n", snpdev,
			       ( ( unsigned long ) ll_header_len ) );
			rc = -EINVAL;
			goto err_sanity;
		}
		if ( len < ll_header_len ) {
			DBGC ( snpdev, "SNPDEV %p invalid packet length %ld\n",
			       snpdev, ( ( unsigned long ) len ) );
			rc = -EINVAL;
			goto err_sanity;
		}
		if ( ! ll_dest ) {
			DBGC ( snpdev, "SNPDEV %p TX missing destination "
			       "address\n", snpdev );
			rc = -EINVAL;
			goto err_sanity;
		}
		if ( ! net_proto ) {
			DBGC ( snpdev, "SNPDEV %p TX missing network "
			       "protocol\n", snpdev );
			rc = -EINVAL;
			goto err_sanity;
		}
		if ( ! ll_src )
			ll_src = &snpdev->mode.CurrentAddress;
	}

	/* Allocate buffer */
	payload_len = ( len - ll_protocol->ll_header_len );
	iobuf = alloc_iob ( MAX_LL_HEADER_LEN + ( ( payload_len > IOB_ZLEN ) ?
						  payload_len : IOB_ZLEN ) );
	if ( ! iobuf ) {
		DBGC ( snpdev, "SNPDEV %p TX could not allocate %ld-byte "
		       "buffer\n", snpdev, ( ( unsigned long ) len ) );
		rc = -ENOMEM;
		goto err_alloc_iob;
	}
	iob_reserve ( iobuf, ( MAX_LL_HEADER_LEN -
			       ll_protocol->ll_header_len ) );
	memcpy ( iob_put ( iobuf, len ), data, len );

	/* Create link-layer header, if specified */
	if ( ll_header_len ) {
		iob_pull ( iobuf, ll_protocol->ll_header_len );
		if ( ( rc = ll_protocol->push ( snpdev->netdev,
						iobuf, ll_dest, ll_src,
						htons ( *net_proto ) )) != 0 ){
			DBGC ( snpdev, "SNPDEV %p TX could not construct "
			       "header: %s\n", snpdev, strerror ( rc ) );
			goto err_ll_push;
		}
	}

	/* Transmit packet */
	if ( ( rc = netdev_tx ( snpdev->netdev, iob_disown ( iobuf ) ) ) != 0){
		DBGC ( snpdev, "SNPDEV %p TX could not transmit: %s\n",
		       snpdev, strerror ( rc ) );
		goto err_tx;
	}

	/* Record in transmit completion ring.  If we run out of
	 * space, report the failure even though we have already
	 * transmitted the packet.
	 *
	 * This allows us to report completions only for packets for
	 * which we had reported successfully initiating transmission,
	 * while continuing to support clients that never poll for
	 * transmit completions.
	 */
	tx_fill = ( snpdev->tx_prod - snpdev->tx_cons );
	if ( tx_fill >= EFI_SNP_NUM_TX ) {
		DBGC ( snpdev, "SNPDEV %p TX completion ring full\n", snpdev );
		rc = -ENOBUFS;
		goto err_ring_full;
	}
	snpdev->tx[ snpdev->tx_prod++ % EFI_SNP_NUM_TX ] = data;
	snpdev->interrupts |= EFI_SIMPLE_NETWORK_TRANSMIT_INTERRUPT;

	return 0;

 err_ring_full:
 err_tx:
 err_ll_push:
	free_iob ( iobuf );
 err_alloc_iob:
 err_sanity:
	return EFIRC ( rc );
}

/**
 * Receive packet
 *
 * @v snp		SNP interface
 * @v ll_header_len	Link-layer header length, if to be filled in
 * @v len		Length of data buffer
 * @v data		Data buffer
 * @v ll_src		Link-layer source address, if specified
 * @v ll_dest		Link-layer destination address, if specified
 * @v net_proto		Network-layer protocol (in host order)
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_receive ( EFI_SIMPLE_NETWORK_PROTOCOL *snp,
		  UINTN *ll_header_len, UINTN *len, VOID *data,
		  EFI_MAC_ADDRESS *ll_src, EFI_MAC_ADDRESS *ll_dest,
		  UINT16 *net_proto ) {
	struct efi_snp_device *snpdev =
		container_of ( snp, struct efi_snp_device, snp );
	struct ll_protocol *ll_protocol = snpdev->netdev->ll_protocol;
	struct io_buffer *iobuf;
	const void *iob_ll_dest;
	const void *iob_ll_src;
	uint16_t iob_net_proto;
	unsigned int iob_flags;
	int rc;

	DBGC2 ( snpdev, "SNPDEV %p RECEIVE %p(+%lx)", snpdev, data,
		( ( unsigned long ) *len ) );

	/* Fail if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return EFI_NOT_READY;

	/* Poll the network device */
	efi_snp_poll ( snpdev );

	/* Dequeue a packet, if one is available */
	iobuf = list_first_entry ( &snpdev->rx, struct io_buffer, list );
	if ( ! iobuf ) {
		DBGC2 ( snpdev, "\n" );
		rc = -EAGAIN;
		goto out_no_packet;
	}
	list_del ( &iobuf->list );
	DBGC2 ( snpdev, "+%zx\n", iob_len ( iobuf ) );

	/* Return packet to caller */
	memcpy ( data, iobuf->data, iob_len ( iobuf ) );
	*len = iob_len ( iobuf );

	/* Attempt to decode link-layer header */
	if ( ( rc = ll_protocol->pull ( snpdev->netdev, iobuf, &iob_ll_dest,
					&iob_ll_src, &iob_net_proto,
					&iob_flags ) ) != 0 ) {
		DBGC ( snpdev, "SNPDEV %p could not parse header: %s\n",
		       snpdev, strerror ( rc ) );
		goto out_bad_ll_header;
	}

	/* Return link-layer header parameters to caller, if required */
	if ( ll_header_len )
		*ll_header_len = ll_protocol->ll_header_len;
	if ( ll_src )
		memcpy ( ll_src, iob_ll_src, ll_protocol->ll_addr_len );
	if ( ll_dest )
		memcpy ( ll_dest, iob_ll_dest, ll_protocol->ll_addr_len );
	if ( net_proto )
		*net_proto = ntohs ( iob_net_proto );

	rc = 0;

 out_bad_ll_header:
	free_iob ( iobuf );
 out_no_packet:
	return EFIRC ( rc );
}

/**
 * Poll event
 *
 * @v event		Event
 * @v context		Event context
 */
static VOID EFIAPI efi_snp_wait_for_packet ( EFI_EVENT event __unused,
					     VOID *context ) {
	struct efi_snp_device *snpdev = context;

	DBGCP ( snpdev, "SNPDEV %p WAIT_FOR_PACKET\n", snpdev );

	/* Do nothing unless the net device is open */
	if ( ! netdev_is_open ( snpdev->netdev ) )
		return;

	/* Do nothing if net device is currently claimed for use by iPXE */
	if ( efi_snp_claimed )
		return;

	/* Poll the network device */
	efi_snp_poll ( snpdev );
}

/** SNP interface */
static EFI_SIMPLE_NETWORK_PROTOCOL efi_snp_device_snp = {
	.Revision	= EFI_SIMPLE_NETWORK_PROTOCOL_REVISION,
	.Start		= efi_snp_start,
	.Stop		= efi_snp_stop,
	.Initialize	= efi_snp_initialize,
	.Reset		= efi_snp_reset,
	.Shutdown	= efi_snp_shutdown,
	.ReceiveFilters	= efi_snp_receive_filters,
	.StationAddress	= efi_snp_station_address,
	.Statistics	= efi_snp_statistics,
	.MCastIpToMac	= efi_snp_mcast_ip_to_mac,
	.NvData		= efi_snp_nvdata,
	.GetStatus	= efi_snp_get_status,
	.Transmit	= efi_snp_transmit,
	.Receive	= efi_snp_receive,
};

/******************************************************************************
 *
 * Component name protocol
 *
 ******************************************************************************
 */

/**
 * Look up driver name
 *
 * @v name2		Component name protocol
 * @v language		Language to use
 * @v driver_name	Driver name to fill in
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_get_driver_name ( EFI_COMPONENT_NAME2_PROTOCOL *name2,
			  CHAR8 *language __unused, CHAR16 **driver_name ) {
	struct efi_snp_device *snpdev =
		container_of ( name2, struct efi_snp_device, name2 );

	*driver_name = snpdev->driver_name;
	return 0;
}

/**
 * Look up controller name
 *
 * @v name2     		Component name protocol
 * @v device		Device
 * @v child		Child device, or NULL
 * @v language		Language to use
 * @v driver_name	Device name to fill in
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_get_controller_name ( EFI_COMPONENT_NAME2_PROTOCOL *name2,
			      EFI_HANDLE device __unused,
			      EFI_HANDLE child __unused,
			      CHAR8 *language __unused,
			      CHAR16 **controller_name ) {
	struct efi_snp_device *snpdev =
		container_of ( name2, struct efi_snp_device, name2 );

	*controller_name = snpdev->controller_name;
	return 0;
}

/******************************************************************************
 *
 * Load file protocol
 *
 ******************************************************************************
 */

/**
 * Load file
 *
 * @v loadfile		Load file protocol
 * @v path		File path
 * @v booting		Loading as part of a boot attempt
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_load_file ( EFI_LOAD_FILE_PROTOCOL *load_file,
		    EFI_DEVICE_PATH_PROTOCOL *path __unused,
		    BOOLEAN booting, UINTN *len __unused,
		    VOID *data __unused ) {
	struct efi_snp_device *snpdev =
		container_of ( load_file, struct efi_snp_device, load_file );
	struct net_device *netdev = snpdev->netdev;
	int rc;

	/* Fail unless this is a boot attempt */
	if ( ! booting ) {
		DBGC ( snpdev, "SNPDEV %p cannot load non-boot file\n",
		       snpdev );
		return EFI_UNSUPPORTED;
	}

	/* Claim network devices for use by iPXE */
	efi_snp_claim();

	/* Start watchdog holdoff timer */
	efi_watchdog_start();

	/* Boot from network device */
	if ( ( rc = ipxe ( netdev ) ) != 0 )
		goto err_ipxe;

 err_ipxe:
	efi_watchdog_stop();
	efi_snp_release();
	return EFIRC ( rc );
}

/** Load file protocol */
static EFI_LOAD_FILE_PROTOCOL efi_snp_load_file_protocol = {
	.LoadFile	= efi_snp_load_file,
};

/******************************************************************************
 *
 * iPXE network driver
 *
 ******************************************************************************
 */

/**
 * Locate SNP device corresponding to network device
 *
 * @v netdev		Network device
 * @ret snp		SNP device, or NULL if not found
 */
static struct efi_snp_device * efi_snp_demux ( struct net_device *netdev ) {
	struct efi_snp_device *snpdev;

	list_for_each_entry ( snpdev, &efi_snp_devices, list ) {
		if ( snpdev->netdev == netdev )
			return snpdev;
	}
	return NULL;
}

/**
 * Create SNP device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int efi_snp_probe ( struct net_device *netdev ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct efi_device *efidev;
	struct efi_snp_device *snpdev;
	union {
		EFI_DEVICE_PATH_PROTOCOL *path;
		void *interface;
	} path;
	EFI_DEVICE_PATH_PROTOCOL *path_end;
	MAC_ADDR_DEVICE_PATH *macpath;
	size_t path_prefix_len = 0;
	EFI_STATUS efirc;
	int rc;

	/* Find parent EFI device */
	efidev = efidev_parent ( netdev->dev );
	if ( ! efidev ) {
		DBG ( "SNP skipping non-EFI device %s\n", netdev->name );
		rc = 0;
		goto err_no_efidev;
	}

	/* Allocate the SNP device */
	snpdev = zalloc ( sizeof ( *snpdev ) );
	if ( ! snpdev ) {
		rc = -ENOMEM;
		goto err_alloc_snp;
	}
	snpdev->netdev = netdev_get ( netdev );
	snpdev->efidev = efidev;
	INIT_LIST_HEAD ( &snpdev->rx );

	/* Sanity check */
	if ( netdev->ll_protocol->ll_addr_len > sizeof ( EFI_MAC_ADDRESS ) ) {
		DBGC ( snpdev, "SNPDEV %p cannot support link-layer address "
		       "length %d for %s\n", snpdev,
		       netdev->ll_protocol->ll_addr_len, netdev->name );
		rc = -ENOTSUP;
		goto err_ll_addr_len;
	}

	/* Populate the SNP structure */
	memcpy ( &snpdev->snp, &efi_snp_device_snp, sizeof ( snpdev->snp ) );
	snpdev->snp.Mode = &snpdev->mode;
	if ( ( efirc = bs->CreateEvent ( EVT_NOTIFY_WAIT, TPL_NOTIFY,
					 efi_snp_wait_for_packet, snpdev,
					 &snpdev->snp.WaitForPacket ) ) != 0 ){
		rc = -EEFI ( efirc );
		DBGC ( snpdev, "SNPDEV %p could not create event: %s\n",
		       snpdev, strerror ( rc ) );
		goto err_create_event;
	}

	/* Populate the SNP mode structure */
	snpdev->mode.State = EfiSimpleNetworkStopped;
	efi_snp_set_mode ( snpdev );

	/* Populate the NII structure */
	snpdev->nii.Revision =
		EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL_REVISION;
	strncpy ( snpdev->nii.StringId, "iPXE",
		  sizeof ( snpdev->nii.StringId ) );

	/* Populate the component name structure */
	efi_snprintf ( snpdev->driver_name,
		       ( sizeof ( snpdev->driver_name ) /
			 sizeof ( snpdev->driver_name[0] ) ),
		       "%s %s", product_short_name, netdev->dev->driver_name );
	efi_snprintf ( snpdev->controller_name,
		       ( sizeof ( snpdev->controller_name ) /
			 sizeof ( snpdev->controller_name[0] ) ),
		       "%s %s (%s, %s)", product_short_name,
		       netdev->dev->driver_name, netdev->dev->name,
		       netdev_addr ( netdev ) );
	snpdev->name2.GetDriverName = efi_snp_get_driver_name;
	snpdev->name2.GetControllerName = efi_snp_get_controller_name;
	snpdev->name2.SupportedLanguages = "en";

	/* Populate the load file protocol structure */
	memcpy ( &snpdev->load_file, &efi_snp_load_file_protocol,
		 sizeof ( snpdev->load_file ) );

	/* Populate the device name */
	efi_snprintf ( snpdev->name, ( sizeof ( snpdev->name ) /
				       sizeof ( snpdev->name[0] ) ),
		       "%s", netdev->name );

	/* Get the parent device path */
	if ( ( efirc = bs->OpenProtocol ( efidev->device,
					  &efi_device_path_protocol_guid,
					  &path.interface, efi_image_handle,
					  efidev->device,
					  EFI_OPEN_PROTOCOL_GET_PROTOCOL ))!=0){
		rc = -EEFI ( efirc );
		DBGC ( snpdev, "SNPDEV %p cannot get %p %s device path: %s\n",
		       snpdev, efidev->device,
		       efi_handle_name ( efidev->device ), strerror ( rc ) );
		goto err_open_device_path;
	}

	/* Allocate the new device path */
	path_end = efi_devpath_end ( path.path );
	path_prefix_len = ( ( ( void * ) path_end ) - ( ( void * ) path.path ));
	snpdev->path = zalloc ( path_prefix_len + sizeof ( *macpath ) +
				sizeof ( *path_end ) );
	if ( ! snpdev->path ) {
		rc = -ENOMEM;
		goto err_alloc_device_path;
	}

	/* Populate the device path */
	memcpy ( snpdev->path, path.path, path_prefix_len );
	macpath = ( ( ( void * ) snpdev->path ) + path_prefix_len );
	path_end = ( ( void * ) ( macpath + 1 ) );
	memset ( macpath, 0, sizeof ( *macpath ) );
	macpath->Header.Type = MESSAGING_DEVICE_PATH;
	macpath->Header.SubType = MSG_MAC_ADDR_DP;
	macpath->Header.Length[0] = sizeof ( *macpath );
	memcpy ( &macpath->MacAddress, netdev->ll_addr,
		 sizeof ( macpath->MacAddress ) );
	macpath->IfType = ntohs ( netdev->ll_protocol->ll_proto );
	memset ( path_end, 0, sizeof ( *path_end ) );
	path_end->Type = END_DEVICE_PATH_TYPE;
	path_end->SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE;
	path_end->Length[0] = sizeof ( *path_end );

	/* Install the SNP */
	if ( ( efirc = bs->InstallMultipleProtocolInterfaces (
			&snpdev->handle,
			&efi_simple_network_protocol_guid, &snpdev->snp,
			&efi_device_path_protocol_guid, snpdev->path,
			&efi_nii_protocol_guid, &snpdev->nii,
			&efi_nii31_protocol_guid, &snpdev->nii,
			&efi_component_name2_protocol_guid, &snpdev->name2,
			&efi_load_file_protocol_guid, &snpdev->load_file,
			NULL ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( snpdev, "SNPDEV %p could not install protocols: "
		       "%s\n", snpdev, strerror ( rc ) );
		goto err_install_protocol_interface;
	}

	/* Add as child of EFI parent device */
	if ( ( rc = efi_child_add ( efidev->device, snpdev->handle ) ) != 0 ) {
		DBGC ( snpdev, "SNPDEV %p could not become child of %p %s: "
		       "%s\n", snpdev, efidev->device,
		       efi_handle_name ( efidev->device ), strerror ( rc ) );
		goto err_efi_child_add;
	}

	/* Install HII */
	if ( ( rc = efi_snp_hii_install ( snpdev ) ) != 0 ) {
		DBGC ( snpdev, "SNPDEV %p could not install HII: %s\n",
		       snpdev, strerror ( rc ) );
		/* HII fails on several platforms.  It's
		 * non-essential, so treat this as a non-fatal
		 * error.
		 */
	}

	/* Add to list of SNP devices */
	list_add ( &snpdev->list, &efi_snp_devices );

	/* Close device path */
	bs->CloseProtocol ( efidev->device, &efi_device_path_protocol_guid,
			    efi_image_handle, efidev->device );

	DBGC ( snpdev, "SNPDEV %p installed for %s as device %p %s\n",
	       snpdev, netdev->name, snpdev->handle,
	       efi_handle_name ( snpdev->handle ) );
	return 0;

	if ( snpdev->package_list )
		efi_snp_hii_uninstall ( snpdev );
	efi_child_del ( efidev->device, snpdev->handle );
 err_efi_child_add:
	bs->UninstallMultipleProtocolInterfaces (
			snpdev->handle,
			&efi_simple_network_protocol_guid, &snpdev->snp,
			&efi_device_path_protocol_guid, snpdev->path,
			&efi_nii_protocol_guid, &snpdev->nii,
			&efi_nii31_protocol_guid, &snpdev->nii,
			&efi_component_name2_protocol_guid, &snpdev->name2,
			&efi_load_file_protocol_guid, &snpdev->load_file,
			NULL );
 err_install_protocol_interface:
	free ( snpdev->path );
 err_alloc_device_path:
	bs->CloseProtocol ( efidev->device, &efi_device_path_protocol_guid,
			    efi_image_handle, efidev->device );
 err_open_device_path:
	bs->CloseEvent ( snpdev->snp.WaitForPacket );
 err_create_event:
 err_ll_addr_len:
	netdev_put ( netdev );
	free ( snpdev );
 err_alloc_snp:
 err_no_efidev:
	return rc;
}

/**
 * Handle SNP device or link state change
 *
 * @v netdev		Network device
 */
static void efi_snp_notify ( struct net_device *netdev ) {
	struct efi_snp_device *snpdev;

	/* Locate SNP device */
	snpdev = efi_snp_demux ( netdev );
	if ( ! snpdev ) {
		DBG ( "SNP skipping non-SNP device %s\n", netdev->name );
		return;
	}

	/* Update link state */
	snpdev->mode.MediaPresent =
		( netdev_link_ok ( netdev ) ? TRUE : FALSE );
	DBGC ( snpdev, "SNPDEV %p link is %s\n", snpdev,
	       ( snpdev->mode.MediaPresent ? "up" : "down" ) );

	/* Update mode state */
	efi_snp_set_state ( snpdev );
}

/**
 * Destroy SNP device
 *
 * @v netdev		Network device
 */
static void efi_snp_remove ( struct net_device *netdev ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct efi_snp_device *snpdev;

	/* Locate SNP device */
	snpdev = efi_snp_demux ( netdev );
	if ( ! snpdev ) {
		DBG ( "SNP skipping non-SNP device %s\n", netdev->name );
		return;
	}

	/* Uninstall the SNP */
	if ( snpdev->package_list )
		efi_snp_hii_uninstall ( snpdev );
	efi_child_del ( snpdev->efidev->device, snpdev->handle );
	list_del ( &snpdev->list );
	bs->UninstallMultipleProtocolInterfaces (
			snpdev->handle,
			&efi_simple_network_protocol_guid, &snpdev->snp,
			&efi_device_path_protocol_guid, snpdev->path,
			&efi_nii_protocol_guid, &snpdev->nii,
			&efi_nii31_protocol_guid, &snpdev->nii,
			&efi_component_name2_protocol_guid, &snpdev->name2,
			&efi_load_file_protocol_guid, &snpdev->load_file,
			NULL );
	free ( snpdev->path );
	bs->CloseEvent ( snpdev->snp.WaitForPacket );
	netdev_put ( snpdev->netdev );
	free ( snpdev );
}

/** SNP driver */
struct net_driver efi_snp_driver __net_driver = {
	.name = "SNP",
	.probe = efi_snp_probe,
	.notify = efi_snp_notify,
	.remove = efi_snp_remove,
};

/**
 * Find SNP device by EFI device handle
 *
 * @v handle		EFI device handle
 * @ret snpdev		SNP device, or NULL
 */
struct efi_snp_device * find_snpdev ( EFI_HANDLE handle ) {
	struct efi_snp_device *snpdev;

	list_for_each_entry ( snpdev, &efi_snp_devices, list ) {
		if ( snpdev->handle == handle )
			return snpdev;
	}
	return NULL;
}

/**
 * Get most recently opened SNP device
 *
 * @ret snpdev		Most recently opened SNP device, or NULL
 */
struct efi_snp_device * last_opened_snpdev ( void ) {
	struct net_device *netdev;

	netdev = last_opened_netdev();
	if ( ! netdev )
		return NULL;

	return efi_snp_demux ( netdev );
}

/**
 * Set SNP claimed/released state
 *
 * @v claimed		Network devices are claimed for use by iPXE
 */
void efi_snp_set_claimed ( int claimed ) {
	struct efi_snp_device *snpdev;

	/* Claim SNP devices */
	efi_snp_claimed = claimed;

	/* Update SNP mode state for each interface */
	list_for_each_entry ( snpdev, &efi_snp_devices, list )
		efi_snp_set_state ( snpdev );
}
