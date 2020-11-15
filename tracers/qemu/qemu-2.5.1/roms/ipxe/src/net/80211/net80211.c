/*
 * The iPXE 802.11 MAC layer.
 *
 * Copyright (c) 2009 Joshua Oreman <oremanj@rwcr.net>.
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

#include <string.h>
#include <byteswap.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ipxe/settings.h>
#include <ipxe/if_arp.h>
#include <ipxe/ethernet.h>
#include <ipxe/ieee80211.h>
#include <ipxe/netdevice.h>
#include <ipxe/net80211.h>
#include <ipxe/sec80211.h>
#include <ipxe/timer.h>
#include <ipxe/nap.h>
#include <ipxe/errortab.h>
#include <ipxe/net80211_err.h>

/** @file
 *
 * 802.11 device management
 */

/** List of 802.11 devices */
static struct list_head net80211_devices = LIST_HEAD_INIT ( net80211_devices );

/** Set of device operations that does nothing */
static struct net80211_device_operations net80211_null_ops;

/** Information associated with a received management packet
 *
 * This is used to keep beacon signal strengths in a parallel queue to
 * the beacons themselves.
 */
struct net80211_rx_info {
	int signal;
	struct list_head list;
};

/** Context for a probe operation */
struct net80211_probe_ctx {
	/** 802.11 device to probe on */
	struct net80211_device *dev;

	/** Value of keep_mgmt before probe was started */
	int old_keep_mgmt;

	/** If scanning actively, pointer to probe packet to send */
	struct io_buffer *probe;

	/** If non-"", the ESSID to limit ourselves to */
	const char *essid;

	/** Time probe was started */
	u32 ticks_start;

	/** Time last useful beacon was received */
	u32 ticks_beacon;

	/** Time channel was last changed */
	u32 ticks_channel;

	/** Time to stay on each channel */
	u32 hop_time;

	/** Channels to hop by when changing channel */
	int hop_step;

	/** List of best beacons for each network found so far */
	struct list_head *beacons;
};

/** Context for the association task */
struct net80211_assoc_ctx {
	/** Next authentication method to try using */
	int method;

	/** Time (in ticks) of the last sent association-related packet */
	int last_packet;

	/** Number of times we have tried sending it */
	int times_tried;
};

/**
 * Detect secure 802.11 network when security support is not available
 *
 * @return -ENOTSUP, always.
 */
__weak int sec80211_detect ( struct io_buffer *iob __unused,
			     enum net80211_security_proto *secprot __unused,
			     enum net80211_crypto_alg *crypt __unused ) {
	return -ENOTSUP;
}

/**
 * @defgroup net80211_netdev Network device interface functions
 * @{
 */
static int net80211_netdev_open ( struct net_device *netdev );
static void net80211_netdev_close ( struct net_device *netdev );
static int net80211_netdev_transmit ( struct net_device *netdev,
				      struct io_buffer *iobuf );
static void net80211_netdev_poll ( struct net_device *netdev );
static void net80211_netdev_irq ( struct net_device *netdev, int enable );
/** @} */

/**
 * @defgroup net80211_linklayer 802.11 link-layer protocol functions
 * @{
 */
static int net80211_ll_push ( struct net_device *netdev,
			      struct io_buffer *iobuf, const void *ll_dest,
			      const void *ll_source, uint16_t net_proto );
static int net80211_ll_pull ( struct net_device *netdev,
			      struct io_buffer *iobuf, const void **ll_dest,
			      const void **ll_source, uint16_t * net_proto,
			      unsigned int *flags );
/** @} */

/**
 * @defgroup net80211_help 802.11 helper functions
 * @{
 */
static void net80211_add_channels ( struct net80211_device *dev, int start,
				    int len, int txpower );
static void net80211_filter_hw_channels ( struct net80211_device *dev );
static void net80211_set_rtscts_rate ( struct net80211_device *dev );
static int net80211_process_capab ( struct net80211_device *dev,
				    u16 capab );
static int net80211_process_ie ( struct net80211_device *dev,
				 union ieee80211_ie *ie, void *ie_end );
static union ieee80211_ie *
net80211_marshal_request_info ( struct net80211_device *dev,
				union ieee80211_ie *ie );
/** @} */

/**
 * @defgroup net80211_assoc_ll 802.11 association handling functions
 * @{
 */
static void net80211_step_associate ( struct net80211_device *dev );
static void net80211_handle_auth ( struct net80211_device *dev,
				   struct io_buffer *iob );
static void net80211_handle_assoc_reply ( struct net80211_device *dev,
					  struct io_buffer *iob );
static int net80211_send_disassoc ( struct net80211_device *dev, int reason,
				    int deauth );
static void net80211_handle_mgmt ( struct net80211_device *dev,
				   struct io_buffer *iob, int signal );
/** @} */

/**
 * @defgroup net80211_frag 802.11 fragment handling functions
 * @{
 */
static void net80211_free_frags ( struct net80211_device *dev, int fcid );
static struct io_buffer *net80211_accum_frags ( struct net80211_device *dev,
						int fcid, int nfrags, int size );
static void net80211_rx_frag ( struct net80211_device *dev,
			       struct io_buffer *iob, int signal );
/** @} */

/**
 * @defgroup net80211_settings 802.11 settings handlers
 * @{
 */
static int net80211_check_settings_update ( void );

/** 802.11 settings applicator
 *
 * When the SSID is changed, this will cause any open devices to
 * re-associate; when the encryption key is changed, we similarly
 * update their state.
 */
struct settings_applicator net80211_applicator __settings_applicator = {
	.apply = net80211_check_settings_update,
};

/** The network name to associate with
 *
 * If this is blank, we scan for all networks and use the one with the
 * greatest signal strength.
 */
const struct setting net80211_ssid_setting __setting ( SETTING_NETDEV_EXTRA,
						       ssid ) = {
	.name = "ssid",
	.description = "Wireless SSID",
	.type = &setting_type_string,
};

/** Whether to use active scanning
 *
 * In order to associate with a hidden SSID, it's necessary to use an
 * active scan (send probe packets). If this setting is nonzero, an
 * active scan on the 2.4GHz band will be used to associate.
 */
const struct setting net80211_active_setting __setting ( SETTING_NETDEV_EXTRA,
							 active-scan ) = {
	.name = "active-scan",
	.description = "Actively scan for wireless networks",
	.type = &setting_type_int8,
};

/** The cryptographic key to use
 *
 * For hex WEP keys, as is common, this must be entered using the
 * normal iPXE method for entering hex settings; an ASCII string of
 * hex characters will not behave as expected.
 */
const struct setting net80211_key_setting __setting ( SETTING_NETDEV_EXTRA,
						      key ) = {
	.name = "key",
	.description = "Wireless encryption key",
	.type = &setting_type_string,
};

/** @} */


/* ---------- net_device wrapper ---------- */

/**
 * Open 802.11 device and start association
 *
 * @v netdev	Wrapping network device
 * @ret rc	Return status code
 *
 * This sets up a default conservative set of channels for probing,
 * and starts the auto-association task unless the @c
 * NET80211_NO_ASSOC flag is set in the wrapped 802.11 device's @c
 * state field.
 */
static int net80211_netdev_open ( struct net_device *netdev )
{
	struct net80211_device *dev = netdev->priv;
	int rc = 0;

	if ( dev->op == &net80211_null_ops )
		return -EFAULT;

	if ( dev->op->open )
		rc = dev->op->open ( dev );

	if ( rc < 0 )
		return rc;

	if ( ! ( dev->state & NET80211_NO_ASSOC ) )
		net80211_autoassociate ( dev );

	return 0;
}

/**
 * Close 802.11 device
 *
 * @v netdev	Wrapping network device.
 *
 * If the association task is running, this will stop it.
 */
static void net80211_netdev_close ( struct net_device *netdev )
{
	struct net80211_device *dev = netdev->priv;

	if ( dev->state & NET80211_WORKING )
		process_del ( &dev->proc_assoc );

	/* Send disassociation frame to AP, to be polite */
	if ( dev->state & NET80211_ASSOCIATED )
		net80211_send_disassoc ( dev, IEEE80211_REASON_LEAVING, 0 );

	if ( dev->handshaker && dev->handshaker->stop &&
	     dev->handshaker->started )
		dev->handshaker->stop ( dev );

	free ( dev->crypto );
	free ( dev->handshaker );
	dev->crypto = NULL;
	dev->handshaker = NULL;

	netdev_link_down ( netdev );
	dev->state = 0;

	if ( dev->op->close )
		dev->op->close ( dev );
}

/**
 * Transmit packet on 802.11 device
 *
 * @v netdev	Wrapping network device
 * @v iobuf	I/O buffer
 * @ret rc	Return status code
 *
 * If encryption is enabled for the currently associated network, the
 * packet will be encrypted prior to transmission.
 */
static int net80211_netdev_transmit ( struct net_device *netdev,
				      struct io_buffer *iobuf )
{
	struct net80211_device *dev = netdev->priv;
	struct ieee80211_frame *hdr = iobuf->data;
	int rc = -ENOSYS;

	if ( dev->crypto && ! ( hdr->fc & IEEE80211_FC_PROTECTED ) &&
	     ( ( hdr->fc & IEEE80211_FC_TYPE ) == IEEE80211_TYPE_DATA ) ) {
		struct io_buffer *niob = dev->crypto->encrypt ( dev->crypto,
								iobuf );
		if ( ! niob )
			return -ENOMEM;	/* only reason encryption could fail */

		/* Free the non-encrypted iob */
		netdev_tx_complete ( netdev, iobuf );

		/* Transmit the encrypted iob; the Protected flag is
		   set, so we won't recurse into here again */
		netdev_tx ( netdev, niob );

		/* Don't transmit the freed packet */
		return 0;
	}

	if ( dev->op->transmit )
		rc = dev->op->transmit ( dev, iobuf );

	return rc;
}

/**
 * Poll 802.11 device for received packets and completed transmissions
 *
 * @v netdev	Wrapping network device
 */
static void net80211_netdev_poll ( struct net_device *netdev )
{
	struct net80211_device *dev = netdev->priv;

	if ( dev->op->poll )
		dev->op->poll ( dev );
}

/**
 * Enable or disable interrupts for 802.11 device
 *
 * @v netdev	Wrapping network device
 * @v enable	Whether to enable interrupts
 */
static void net80211_netdev_irq ( struct net_device *netdev, int enable )
{
	struct net80211_device *dev = netdev->priv;

	if ( dev->op->irq )
		dev->op->irq ( dev, enable );
}

/** Network device operations for a wrapped 802.11 device */
static struct net_device_operations net80211_netdev_ops = {
	.open = net80211_netdev_open,
	.close = net80211_netdev_close,
	.transmit = net80211_netdev_transmit,
	.poll = net80211_netdev_poll,
	.irq = net80211_netdev_irq,
};


/* ---------- 802.11 link-layer protocol ---------- */

/**
 * Determine whether a transmission rate uses ERP/OFDM
 *
 * @v rate	Rate in 100 kbps units
 * @ret is_erp	TRUE if the rate is an ERP/OFDM rate
 *
 * 802.11b supports rates of 1.0, 2.0, 5.5, and 11.0 Mbps; any other
 * rate than these on the 2.4GHz spectrum is an ERP (802.11g) rate.
 */
static inline int net80211_rate_is_erp ( u16 rate )
{
	if ( rate == 10 || rate == 20 || rate == 55 || rate == 110 )
		return 0;
	return 1;
}


/**
 * Calculate one frame's contribution to 802.11 duration field
 *
 * @v dev	802.11 device
 * @v bytes	Amount of data to calculate duration for
 * @ret dur	Duration field in microseconds
 *
 * To avoid multiple stations attempting to transmit at once, 802.11
 * provides that every packet shall include a duration field
 * specifying a length of time for which the wireless medium will be
 * reserved after it is transmitted. The duration is measured in
 * microseconds and is calculated with respect to the current
 * physical-layer parameters of the 802.11 device.
 *
 * For an unfragmented data or management frame, or the last fragment
 * of a fragmented frame, the duration captures only the 10 data bytes
 * of one ACK; call once with bytes = 10.
 *
 * For a fragment of a data or management rame that will be followed
 * by more fragments, the duration captures an ACK, the following
 * fragment, and its ACK; add the results of three calls, two with
 * bytes = 10 and one with bytes set to the next fragment's size.
 *
 * For an RTS control frame, the duration captures the responding CTS,
 * the frame being sent, and its ACK; add the results of three calls,
 * two with bytes = 10 and one with bytes set to the next frame's size
 * (assuming unfragmented).
 *
 * For a CTS-to-self control frame, the duration captures the frame
 * being protected and its ACK; add the results of two calls, one with
 * bytes = 10 and one with bytes set to the next frame's size.
 *
 * No other frame types are currently supported by iPXE.
 */
u16 net80211_duration ( struct net80211_device *dev, int bytes, u16 rate )
{
	struct net80211_channel *chan = &dev->channels[dev->channel];
	u32 kbps = rate * 100;

	if ( chan->band == NET80211_BAND_5GHZ || net80211_rate_is_erp ( rate ) ) {
		/* OFDM encoding (802.11a/g) */
		int bits_per_symbol = ( kbps * 4 ) / 1000;	/* 4us/symbol */
		int bits = 22 + ( bytes << 3 );	/* 22-bit PLCP */
		int symbols = ( bits + bits_per_symbol - 1 ) / bits_per_symbol;

		return 16 + 20 + ( symbols * 4 ); /* 16us SIFS, 20us preamble */
	} else {
		/* CCK encoding (802.11b) */
		int phy_time = 144 + 48;	/* preamble + PLCP */
		int bits = bytes << 3;
		int data_time = ( bits * 1000 + kbps - 1 ) / kbps;

		if ( dev->phy_flags & NET80211_PHY_USE_SHORT_PREAMBLE )
			phy_time >>= 1;

		return 10 + phy_time + data_time; /* 10us SIFS */
	}
}

/**
 * Add 802.11 link-layer header
 *
 * @v netdev		Wrapping network device
 * @v iobuf		I/O buffer
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer source address
 * @v net_proto		Network-layer protocol, in network byte order
 * @ret rc		Return status code
 *
 * This adds both the 802.11 frame header and the 802.2 LLC/SNAP
 * header used on data packets.
 *
 * We also check here for state of the link that would make it invalid
 * to send a data packet; every data packet must pass through here,
 * and no non-data packet (e.g. management frame) should.
 */
static int net80211_ll_push ( struct net_device *netdev,
			      struct io_buffer *iobuf, const void *ll_dest,
			      const void *ll_source, uint16_t net_proto )
{
	struct net80211_device *dev = netdev->priv;
	struct ieee80211_frame *hdr = iob_push ( iobuf,
						 IEEE80211_LLC_HEADER_LEN +
						 IEEE80211_TYP_FRAME_HEADER_LEN );
	struct ieee80211_llc_snap_header *lhdr =
		( void * ) hdr + IEEE80211_TYP_FRAME_HEADER_LEN;

	/* We can't send data packets if we're not associated. */
	if ( ! ( dev->state & NET80211_ASSOCIATED ) ) {
		if ( dev->assoc_rc )
			return dev->assoc_rc;
		return -ENETUNREACH;
	}

	hdr->fc = IEEE80211_THIS_VERSION | IEEE80211_TYPE_DATA |
	    IEEE80211_STYPE_DATA | IEEE80211_FC_TODS;

	/* We don't send fragmented frames, so duration is the time
	   for an SIFS + 10-byte ACK. */
	hdr->duration = net80211_duration ( dev, 10, dev->rates[dev->rate] );

	memcpy ( hdr->addr1, dev->bssid, ETH_ALEN );
	memcpy ( hdr->addr2, ll_source, ETH_ALEN );
	memcpy ( hdr->addr3, ll_dest, ETH_ALEN );

	hdr->seq = IEEE80211_MAKESEQ ( ++dev->last_tx_seqnr, 0 );

	lhdr->dsap = IEEE80211_LLC_DSAP;
	lhdr->ssap = IEEE80211_LLC_SSAP;
	lhdr->ctrl = IEEE80211_LLC_CTRL;
	memset ( lhdr->oui, 0x00, 3 );
	lhdr->ethertype = net_proto;

	return 0;
}

/**
 * Remove 802.11 link-layer header
 *
 * @v netdev		Wrapping network device
 * @v iobuf		I/O buffer
 * @ret ll_dest		Link-layer destination address
 * @ret ll_source	Link-layer source
 * @ret net_proto	Network-layer protocol, in network byte order
 * @ret flags		Packet flags
 * @ret rc		Return status code
 *
 * This expects and removes both the 802.11 frame header and the 802.2
 * LLC/SNAP header that are used on data packets.
 */
static int net80211_ll_pull ( struct net_device *netdev __unused,
			      struct io_buffer *iobuf,
			      const void **ll_dest, const void **ll_source,
			      uint16_t * net_proto, unsigned int *flags )
{
	struct ieee80211_frame *hdr = iobuf->data;
	struct ieee80211_llc_snap_header *lhdr =
		( void * ) hdr + IEEE80211_TYP_FRAME_HEADER_LEN;

	/* Bunch of sanity checks */
	if ( iob_len ( iobuf ) < IEEE80211_TYP_FRAME_HEADER_LEN +
	     IEEE80211_LLC_HEADER_LEN ) {
		DBGC ( netdev->priv, "802.11 %p packet too short (%zd bytes)\n",
		       netdev->priv, iob_len ( iobuf ) );
		return -EINVAL_PKT_TOO_SHORT;
	}

	if ( ( hdr->fc & IEEE80211_FC_VERSION ) != IEEE80211_THIS_VERSION ) {
		DBGC ( netdev->priv, "802.11 %p packet invalid version %04x\n",
		       netdev->priv, hdr->fc & IEEE80211_FC_VERSION );
		return -EINVAL_PKT_VERSION;
	}

	if ( ( hdr->fc & IEEE80211_FC_TYPE ) != IEEE80211_TYPE_DATA ||
	     ( hdr->fc & IEEE80211_FC_SUBTYPE ) != IEEE80211_STYPE_DATA ) {
		DBGC ( netdev->priv, "802.11 %p packet not data/data (fc=%04x)\n",
		       netdev->priv, hdr->fc );
		return -EINVAL_PKT_NOT_DATA;
	}

	if ( ( hdr->fc & ( IEEE80211_FC_TODS | IEEE80211_FC_FROMDS ) ) !=
	     IEEE80211_FC_FROMDS ) {
		DBGC ( netdev->priv, "802.11 %p packet not from DS (fc=%04x)\n",
		       netdev->priv, hdr->fc );
		return -EINVAL_PKT_NOT_FROMDS;
	}

	if ( lhdr->dsap != IEEE80211_LLC_DSAP || lhdr->ssap != IEEE80211_LLC_SSAP ||
	     lhdr->ctrl != IEEE80211_LLC_CTRL || lhdr->oui[0] || lhdr->oui[1] ||
	     lhdr->oui[2] ) {
		DBGC ( netdev->priv, "802.11 %p LLC header is not plain EtherType "
		       "encapsulator: %02x->%02x [%02x] %02x:%02x:%02x %04x\n",
		       netdev->priv, lhdr->dsap, lhdr->ssap, lhdr->ctrl,
		       lhdr->oui[0], lhdr->oui[1], lhdr->oui[2], lhdr->ethertype );
		return -EINVAL_PKT_LLC_HEADER;
	}

	iob_pull ( iobuf, sizeof ( *hdr ) + sizeof ( *lhdr ) );

	*ll_dest = hdr->addr1;
	*ll_source = hdr->addr3;
	*net_proto = lhdr->ethertype;
	*flags = ( ( is_multicast_ether_addr ( hdr->addr1 ) ?
		     LL_MULTICAST : 0 ) |
		   ( is_broadcast_ether_addr ( hdr->addr1 ) ?
		     LL_BROADCAST : 0 ) );
	return 0;
}

/** 802.11 link-layer protocol */
static struct ll_protocol net80211_ll_protocol __ll_protocol = {
	.name = "802.11",
	.push = net80211_ll_push,
	.pull = net80211_ll_pull,
	.init_addr = eth_init_addr,
	.ntoa = eth_ntoa,
	.mc_hash = eth_mc_hash,
	.eth_addr = eth_eth_addr,
	.eui64 = eth_eui64,
	.ll_proto = htons ( ARPHRD_ETHER ),	/* "encapsulated Ethernet" */
	.hw_addr_len = ETH_ALEN,
	.ll_addr_len = ETH_ALEN,
	.ll_header_len = IEEE80211_TYP_FRAME_HEADER_LEN +
				IEEE80211_LLC_HEADER_LEN,
};


/* ---------- 802.11 network management API ---------- */

/**
 * Get 802.11 device from wrapping network device
 *
 * @v netdev	Wrapping network device
 * @ret dev	802.11 device wrapped by network device, or NULL
 *
 * Returns NULL if the network device does not wrap an 802.11 device.
 */
struct net80211_device * net80211_get ( struct net_device *netdev )
{
	struct net80211_device *dev;

	list_for_each_entry ( dev, &net80211_devices, list ) {
		if ( netdev->priv == dev )
			return netdev->priv;
	}

	return NULL;
}

/**
 * Set state of 802.11 device keeping management frames
 *
 * @v dev	802.11 device
 * @v enable	Whether to keep management frames
 * @ret oldenab	Whether management frames were enabled before this call
 *
 * If enable is TRUE, beacon, probe, and action frames will be kept
 * and may be retrieved by calling net80211_mgmt_dequeue().
 */
int net80211_keep_mgmt ( struct net80211_device *dev, int enable )
{
	int oldenab = dev->keep_mgmt;

	dev->keep_mgmt = enable;
	return oldenab;
}

/**
 * Get 802.11 management frame
 *
 * @v dev	802.11 device
 * @ret signal	Signal strength of returned management frame
 * @ret iob	I/O buffer, or NULL if no management frame is queued
 *
 * Frames will only be returned by this function if
 * net80211_keep_mgmt() has been previously called with enable set to
 * TRUE.
 *
 * The calling function takes ownership of the returned I/O buffer.
 */
struct io_buffer * net80211_mgmt_dequeue ( struct net80211_device *dev,
					   int *signal )
{
	struct io_buffer *iobuf;
	struct net80211_rx_info *rxi;

	list_for_each_entry ( rxi, &dev->mgmt_info_queue, list ) {
		list_del ( &rxi->list );
		if ( signal )
			*signal = rxi->signal;
		free ( rxi );

		assert ( ! list_empty ( &dev->mgmt_queue ) );
		iobuf = list_first_entry ( &dev->mgmt_queue, struct io_buffer,
					   list );
		list_del ( &iobuf->list );
		return iobuf;
	}

	return NULL;
}

/**
 * Transmit 802.11 management frame
 *
 * @v dev	802.11 device
 * @v fc	Frame Control flags for management frame
 * @v dest	Destination access point
 * @v iob	I/O buffer
 * @ret rc	Return status code
 *
 * The @a fc argument must contain at least an IEEE 802.11 management
 * subtype number (e.g. IEEE80211_STYPE_PROBE_REQ). If it contains
 * IEEE80211_FC_PROTECTED, the frame will be encrypted prior to
 * transmission.
 *
 * It is required that @a iob have at least 24 bytes of headroom
 * reserved before its data start.
 */
int net80211_tx_mgmt ( struct net80211_device *dev, u16 fc, u8 dest[6],
		       struct io_buffer *iob )
{
	struct ieee80211_frame *hdr = iob_push ( iob,
						 IEEE80211_TYP_FRAME_HEADER_LEN );

	hdr->fc = IEEE80211_THIS_VERSION | IEEE80211_TYPE_MGMT |
	    ( fc & ~IEEE80211_FC_PROTECTED );
	hdr->duration = net80211_duration ( dev, 10, dev->rates[dev->rate] );
	hdr->seq = IEEE80211_MAKESEQ ( ++dev->last_tx_seqnr, 0 );

	memcpy ( hdr->addr1, dest, ETH_ALEN );	/* DA = RA */
	memcpy ( hdr->addr2, dev->netdev->ll_addr, ETH_ALEN );	/* SA = TA */
	memcpy ( hdr->addr3, dest, ETH_ALEN );	/* BSSID */

	if ( fc & IEEE80211_FC_PROTECTED ) {
		if ( ! dev->crypto )
			return -EINVAL_CRYPTO_REQUEST;

		struct io_buffer *eiob = dev->crypto->encrypt ( dev->crypto,
								iob );
		free_iob ( iob );
		iob = eiob;
	}

	return netdev_tx ( dev->netdev, iob );
}


/* ---------- Driver API ---------- */

/** 802.11 association process descriptor */
static struct process_descriptor net80211_process_desc =
	PROC_DESC ( struct net80211_device, proc_assoc,
		    net80211_step_associate );

/**
 * Allocate 802.11 device
 *
 * @v priv_size		Size of driver-private allocation area
 * @ret dev		Newly allocated 802.11 device
 *
 * This function allocates a net_device with space in its private area
 * for both the net80211_device it will wrap and the driver-private
 * data space requested. It initializes the link-layer-specific parts
 * of the net_device, and links the net80211_device to the net_device
 * appropriately.
 */
struct net80211_device * net80211_alloc ( size_t priv_size )
{
	struct net80211_device *dev;
	struct net_device *netdev =
		alloc_netdev ( sizeof ( *dev ) + priv_size );

	if ( ! netdev )
		return NULL;

	netdev->ll_protocol = &net80211_ll_protocol;
	netdev->ll_broadcast = eth_broadcast;
	netdev->max_pkt_len = IEEE80211_MAX_DATA_LEN;
	netdev_init ( netdev, &net80211_netdev_ops );

	dev = netdev->priv;
	dev->netdev = netdev;
	dev->priv = ( u8 * ) dev + sizeof ( *dev );
	dev->op = &net80211_null_ops;

	process_init_stopped ( &dev->proc_assoc, &net80211_process_desc,
			       &netdev->refcnt );
	INIT_LIST_HEAD ( &dev->mgmt_queue );
	INIT_LIST_HEAD ( &dev->mgmt_info_queue );

	return dev;
}

/**
 * Register 802.11 device with network stack
 *
 * @v dev	802.11 device
 * @v ops	802.11 device operations
 * @v hw	802.11 hardware information
 *
 * This also registers the wrapping net_device with the higher network
 * layers.
 */
int net80211_register ( struct net80211_device *dev,
			struct net80211_device_operations *ops,
			struct net80211_hw_info *hw )
{
	dev->op = ops;
	dev->hw = malloc ( sizeof ( *hw ) );
	if ( ! dev->hw )
		return -ENOMEM;

	memcpy ( dev->hw, hw, sizeof ( *hw ) );
	memcpy ( dev->netdev->hw_addr, hw->hwaddr, ETH_ALEN );

	/* Set some sensible channel defaults for driver's open() function */
	memcpy ( dev->channels, dev->hw->channels,
		 NET80211_MAX_CHANNELS * sizeof ( dev->channels[0] ) );
	dev->channel = 0;

	/* Mark device as not supporting interrupts, if applicable */
	if ( ! ops->irq )
		dev->netdev->state |= NETDEV_IRQ_UNSUPPORTED;

	list_add_tail ( &dev->list, &net80211_devices );
	return register_netdev ( dev->netdev );
}

/**
 * Unregister 802.11 device from network stack
 *
 * @v dev	802.11 device
 *
 * After this call, the device operations are cleared so that they
 * will not be called.
 */
void net80211_unregister ( struct net80211_device *dev )
{
	unregister_netdev ( dev->netdev );
	list_del ( &dev->list );
	dev->op = &net80211_null_ops;
}

/**
 * Free 802.11 device
 *
 * @v dev	802.11 device
 *
 * The device should be unregistered before this function is called.
 */
void net80211_free ( struct net80211_device *dev )
{
	free ( dev->hw );
	rc80211_free ( dev->rctl );
	netdev_nullify ( dev->netdev );
	netdev_put ( dev->netdev );
}


/* ---------- 802.11 network management workhorse code ---------- */

/**
 * Set state of 802.11 device
 *
 * @v dev	802.11 device
 * @v clear	Bitmask of flags to clear
 * @v set	Bitmask of flags to set
 * @v status	Status or reason code for most recent operation
 *
 * If @a status represents a reason code, it should be OR'ed with
 * NET80211_IS_REASON.
 *
 * Clearing authentication also clears association; clearing
 * association also clears security handshaking state. Clearing
 * association removes the link-up flag from the wrapping net_device,
 * but setting it does not automatically set the flag; that is left to
 * the judgment of higher-level code.
 */
static inline void net80211_set_state ( struct net80211_device *dev,
					short clear, short set,
					u16 status )
{
	/* The conditions in this function are deliberately formulated
	   to be decidable at compile-time in most cases. Since clear
	   and set are generally passed as constants, the body of this
	   function can be reduced down to a few statements by the
	   compiler. */

	const int statmsk = NET80211_STATUS_MASK | NET80211_IS_REASON;

	if ( clear & NET80211_PROBED )
		clear |= NET80211_AUTHENTICATED;

	if ( clear & NET80211_AUTHENTICATED )
		clear |= NET80211_ASSOCIATED;

	if ( clear & NET80211_ASSOCIATED )
		clear |= NET80211_CRYPTO_SYNCED;

	dev->state = ( dev->state & ~clear ) | set;
	dev->state = ( dev->state & ~statmsk ) | ( status & statmsk );

	if ( clear & NET80211_ASSOCIATED )
		netdev_link_down ( dev->netdev );

	if ( ( clear | set ) & NET80211_ASSOCIATED )
		dev->op->config ( dev, NET80211_CFG_ASSOC );

	if ( status != 0 ) {
		if ( status & NET80211_IS_REASON )
			dev->assoc_rc = -E80211_REASON ( status );
		else
			dev->assoc_rc = -E80211_STATUS ( status );
		netdev_link_err ( dev->netdev, dev->assoc_rc );
	}
}

/**
 * Add channels to 802.11 device
 *
 * @v dev	802.11 device
 * @v start	First channel number to add
 * @v len	Number of channels to add
 * @v txpower	TX power (dBm) to allow on added channels
 *
 * To replace the current list of channels instead of adding to it,
 * set the nr_channels field of the 802.11 device to 0 before calling
 * this function.
 */
static void net80211_add_channels ( struct net80211_device *dev, int start,
				    int len, int txpower )
{
	int i, chan = start;

	for ( i = dev->nr_channels; len-- && i < NET80211_MAX_CHANNELS; i++ ) {
		dev->channels[i].channel_nr = chan;
		dev->channels[i].maxpower = txpower;
		dev->channels[i].hw_value = 0;

		if ( chan >= 1 && chan <= 14 ) {
			dev->channels[i].band = NET80211_BAND_2GHZ;
			if ( chan == 14 )
				dev->channels[i].center_freq = 2484;
			else
				dev->channels[i].center_freq = 2407 + 5 * chan;
			chan++;
		} else {
			dev->channels[i].band = NET80211_BAND_5GHZ;
			dev->channels[i].center_freq = 5000 + 5 * chan;
			chan += 4;
		}
	}

	dev->nr_channels = i;
}

/**
 * Filter 802.11 device channels for hardware capabilities
 *
 * @v dev	802.11 device
 *
 * Hardware may support fewer channels than regulatory restrictions
 * allow; this function filters out channels in dev->channels that are
 * not supported by the hardware list in dev->hwinfo. It also copies
 * over the net80211_channel::hw_value and limits maximum TX power
 * appropriately.
 *
 * Channels are matched based on center frequency, ignoring band and
 * channel number.
 *
 * If the driver specifies no supported channels, the effect will be
 * as though all were supported.
 */
static void net80211_filter_hw_channels ( struct net80211_device *dev )
{
	int delta = 0, i = 0;
	int old_freq = dev->channels[dev->channel].center_freq;
	struct net80211_channel *chan, *hwchan;

	if ( ! dev->hw->nr_channels )
		return;

	dev->channel = 0;
	for ( chan = dev->channels; chan < dev->channels + dev->nr_channels;
	      chan++, i++ ) {
		int ok = 0;
		for ( hwchan = dev->hw->channels;
		      hwchan < dev->hw->channels + dev->hw->nr_channels;
		      hwchan++ ) {
			if ( hwchan->center_freq == chan->center_freq ) {
				ok = 1;
				break;
			}
		}

		if ( ! ok )
			delta++;
		else {
			chan->hw_value = hwchan->hw_value;
			if ( hwchan->maxpower != 0 &&
			     chan->maxpower > hwchan->maxpower )
				chan->maxpower = hwchan->maxpower;
			if ( old_freq == chan->center_freq )
				dev->channel = i - delta;
			if ( delta )
				chan[-delta] = *chan;
		}
	}

	dev->nr_channels -= delta;

	if ( dev->channels[dev->channel].center_freq != old_freq )
		dev->op->config ( dev, NET80211_CFG_CHANNEL );
}

/**
 * Update 802.11 device state to reflect received capabilities field
 *
 * @v dev	802.11 device
 * @v capab	Capabilities field in beacon, probe, or association frame
 * @ret rc	Return status code
 */
static int net80211_process_capab ( struct net80211_device *dev,
				    u16 capab )
{
	u16 old_phy = dev->phy_flags;

	if ( ( capab & ( IEEE80211_CAPAB_MANAGED | IEEE80211_CAPAB_ADHOC ) ) !=
	     IEEE80211_CAPAB_MANAGED ) {
		DBGC ( dev, "802.11 %p cannot handle IBSS network\n", dev );
		return -ENOSYS;
	}

	dev->phy_flags &= ~( NET80211_PHY_USE_SHORT_PREAMBLE |
			     NET80211_PHY_USE_SHORT_SLOT );

	if ( capab & IEEE80211_CAPAB_SHORT_PMBL )
		dev->phy_flags |= NET80211_PHY_USE_SHORT_PREAMBLE;

	if ( capab & IEEE80211_CAPAB_SHORT_SLOT )
		dev->phy_flags |= NET80211_PHY_USE_SHORT_SLOT;

	if ( old_phy != dev->phy_flags )
		dev->op->config ( dev, NET80211_CFG_PHY_PARAMS );

	return 0;
}

/**
 * Update 802.11 device state to reflect received information elements
 *
 * @v dev	802.11 device
 * @v ie	Pointer to first information element
 * @v ie_end	Pointer to tail of packet I/O buffer
 * @ret rc	Return status code
 */
static int net80211_process_ie ( struct net80211_device *dev,
				 union ieee80211_ie *ie, void *ie_end )
{
	u16 old_rate = dev->rates[dev->rate];
	u16 old_phy = dev->phy_flags;
	int have_rates = 0, i;
	int ds_channel = 0;
	int changed = 0;
	int band = dev->channels[dev->channel].band;

	if ( ! ieee80211_ie_bound ( ie, ie_end ) )
		return 0;

	for ( ; ie; ie = ieee80211_next_ie ( ie, ie_end ) ) {
		switch ( ie->id ) {
		case IEEE80211_IE_SSID:
			if ( ie->len <= 32 ) {
				memcpy ( dev->essid, ie->ssid, ie->len );
				dev->essid[ie->len] = 0;
			}
			break;

		case IEEE80211_IE_RATES:
		case IEEE80211_IE_EXT_RATES:
			if ( ! have_rates ) {
				dev->nr_rates = 0;
				dev->basic_rates = 0;
				have_rates = 1;
			}
			for ( i = 0; i < ie->len &&
			      dev->nr_rates < NET80211_MAX_RATES; i++ ) {
				u8 rid = ie->rates[i];
				u16 rate = ( rid & 0x7f ) * 5;

				if ( rid & 0x80 )
					dev->basic_rates |=
						( 1 << dev->nr_rates );

				dev->rates[dev->nr_rates++] = rate;
			}

			break;

		case IEEE80211_IE_DS_PARAM:
			if ( dev->channel < dev->nr_channels && ds_channel ==
			     dev->channels[dev->channel].channel_nr )
				break;
			ds_channel = ie->ds_param.current_channel;
			net80211_change_channel ( dev, ds_channel );
			break;

		case IEEE80211_IE_COUNTRY:
			dev->nr_channels = 0;

			DBGC ( dev, "802.11 %p setting country regulations "
			       "for %c%c\n", dev, ie->country.name[0],
			       ie->country.name[1] );
			for ( i = 0; i < ( ie->len - 3 ) / 3; i++ ) {
				union ieee80211_ie_country_triplet *t =
					&ie->country.triplet[i];
				if ( t->first > 200 ) {
					DBGC ( dev, "802.11 %p ignoring regulatory "
					       "extension information\n", dev );
				} else {
					net80211_add_channels ( dev,
							t->band.first_channel,
							t->band.nr_channels,
							t->band.max_txpower );
				}
			}
			net80211_filter_hw_channels ( dev );
			break;

		case IEEE80211_IE_ERP_INFO:
			dev->phy_flags &= ~( NET80211_PHY_USE_PROTECTION |
					     NET80211_PHY_USE_SHORT_PREAMBLE );
			if ( ie->erp_info & IEEE80211_ERP_USE_PROTECTION )
				dev->phy_flags |= NET80211_PHY_USE_PROTECTION;
			if ( ! ( ie->erp_info & IEEE80211_ERP_BARKER_LONG ) )
				dev->phy_flags |= NET80211_PHY_USE_SHORT_PREAMBLE;
			break;
		}
	}

	if ( have_rates ) {
		/* Allow only those rates that are also supported by
		   the hardware. */
		int delta = 0, j;

		dev->rate = 0;
		for ( i = 0; i < dev->nr_rates; i++ ) {
			int ok = 0;
			for ( j = 0; j < dev->hw->nr_rates[band]; j++ ) {
				if ( dev->hw->rates[band][j] == dev->rates[i] ){
					ok = 1;
					break;
				}
			}

			if ( ! ok )
				delta++;
			else {
				dev->rates[i - delta] = dev->rates[i];
				if ( old_rate == dev->rates[i] )
					dev->rate = i - delta;
			}
		}

		dev->nr_rates -= delta;

		/* Sort available rates - sorted subclumps tend to already
		   exist, so insertion sort works well. */
		for ( i = 1; i < dev->nr_rates; i++ ) {
			u16 rate = dev->rates[i];
			u32 tmp, br, mask;

			for ( j = i - 1; j >= 0 && dev->rates[j] >= rate; j-- )
				dev->rates[j + 1] = dev->rates[j];
			dev->rates[j + 1] = rate;

			/* Adjust basic_rates to match by rotating the
			   bits from bit j+1 to bit i left one position. */
			mask = ( ( 1 << i ) - 1 ) & ~( ( 1 << ( j + 1 ) ) - 1 );
			br = dev->basic_rates;
			tmp = br & ( 1 << i );
			br = ( br & ~( mask | tmp ) ) | ( ( br & mask ) << 1 );
			br |= ( tmp >> ( i - j - 1 ) );
			dev->basic_rates = br;
		}

		net80211_set_rtscts_rate ( dev );

		if ( dev->rates[dev->rate] != old_rate )
			changed |= NET80211_CFG_RATE;
	}

	if ( dev->hw->flags & NET80211_HW_NO_SHORT_PREAMBLE )
		dev->phy_flags &= ~NET80211_PHY_USE_SHORT_PREAMBLE;
	if ( dev->hw->flags & NET80211_HW_NO_SHORT_SLOT )
		dev->phy_flags &= ~NET80211_PHY_USE_SHORT_SLOT;

	if ( old_phy != dev->phy_flags )
		changed |= NET80211_CFG_PHY_PARAMS;

	if ( changed )
		dev->op->config ( dev, changed );

	return 0;
}

/**
 * Create information elements for outgoing probe or association packet
 *
 * @v dev		802.11 device
 * @v ie		Pointer to start of information element area
 * @ret next_ie		Pointer to first byte after added information elements
 */
static union ieee80211_ie *
net80211_marshal_request_info ( struct net80211_device *dev,
				union ieee80211_ie *ie )
{
	int i;

	ie->id = IEEE80211_IE_SSID;
	ie->len = strlen ( dev->essid );
	memcpy ( ie->ssid, dev->essid, ie->len );

	ie = ieee80211_next_ie ( ie, NULL );

	ie->id = IEEE80211_IE_RATES;
	ie->len = dev->nr_rates;
	if ( ie->len > 8 )
		ie->len = 8;

	for ( i = 0; i < ie->len; i++ ) {
		ie->rates[i] = dev->rates[i] / 5;
		if ( dev->basic_rates & ( 1 << i ) )
			ie->rates[i] |= 0x80;
	}

	ie = ieee80211_next_ie ( ie, NULL );

	if ( dev->rsn_ie && dev->rsn_ie->id == IEEE80211_IE_RSN ) {
		memcpy ( ie, dev->rsn_ie, dev->rsn_ie->len + 2 );
		ie = ieee80211_next_ie ( ie, NULL );
	}

	if ( dev->nr_rates > 8 ) {
		/* 802.11 requires we use an Extended Basic Rates IE
		   for the rates beyond the eighth. */

		ie->id = IEEE80211_IE_EXT_RATES;
		ie->len = dev->nr_rates - 8;

		for ( ; i < dev->nr_rates; i++ ) {
			ie->rates[i - 8] = dev->rates[i] / 5;
			if ( dev->basic_rates & ( 1 << i ) )
				ie->rates[i - 8] |= 0x80;
		}

		ie = ieee80211_next_ie ( ie, NULL );
	}

	if ( dev->rsn_ie && dev->rsn_ie->id == IEEE80211_IE_VENDOR ) {
		memcpy ( ie, dev->rsn_ie, dev->rsn_ie->len + 2 );
		ie = ieee80211_next_ie ( ie, NULL );
	}

	return ie;
}

/** Seconds to wait after finding a network, to possibly find better APs for it
 *
 * This is used when a specific SSID to scan for is specified.
 */
#define NET80211_PROBE_GATHER    1

/** Seconds to wait after finding a network, to possibly find other networks
 *
 * This is used when an empty SSID is specified, to scan for all
 * networks.
 */
#define NET80211_PROBE_GATHER_ALL 2

/** Seconds to allow a probe to take if no network has been found */
#define NET80211_PROBE_TIMEOUT   6

/**
 * Begin probe of 802.11 networks
 *
 * @v dev	802.11 device
 * @v essid	SSID to probe for, or "" to accept any (may not be NULL)
 * @v active	Whether to use active scanning
 * @ret ctx	Probe context
 *
 * Active scanning may only be used on channels 1-11 in the 2.4GHz
 * band, due to iPXE's lack of a complete regulatory database. If
 * active scanning is used, probe packets will be sent on each
 * channel; this can allow association with hidden-SSID networks if
 * the SSID is properly specified.
 *
 * A @c NULL return indicates an out-of-memory condition.
 *
 * The returned context must be periodically passed to
 * net80211_probe_step() until that function returns zero.
 */
struct net80211_probe_ctx * net80211_probe_start ( struct net80211_device *dev,
						   const char *essid,
						   int active )
{
	struct net80211_probe_ctx *ctx = zalloc ( sizeof ( *ctx ) );

	if ( ! ctx )
		return NULL;

	assert ( netdev_is_open ( dev->netdev ) );

	ctx->dev = dev;
	ctx->old_keep_mgmt = net80211_keep_mgmt ( dev, 1 );
	ctx->essid = essid;
	if ( dev->essid != ctx->essid )
		strcpy ( dev->essid, ctx->essid );

	if ( active ) {
		struct ieee80211_probe_req *probe_req;
		union ieee80211_ie *ie;

		ctx->probe = alloc_iob ( 128 );
		iob_reserve ( ctx->probe, IEEE80211_TYP_FRAME_HEADER_LEN );
		probe_req = ctx->probe->data;

		ie = net80211_marshal_request_info ( dev,
						     probe_req->info_element );

		iob_put ( ctx->probe, ( void * ) ie - ctx->probe->data );
	}

	ctx->ticks_start = currticks();
	ctx->ticks_beacon = 0;
	ctx->ticks_channel = currticks();
	ctx->hop_time = ticks_per_sec() / ( active ? 2 : 6 );

	/*
	 * Channels on 2.4GHz overlap, and the most commonly used
	 * are 1, 6, and 11. We'll get a result faster if we check
	 * every 5 channels, but in order to hit all of them the
	 * number of channels must be relatively prime to 5. If it's
	 * not, tweak the hop.
	 */
	ctx->hop_step = 5;
	while ( dev->nr_channels % ctx->hop_step == 0 && ctx->hop_step > 1 )
		ctx->hop_step--;

	ctx->beacons = malloc ( sizeof ( *ctx->beacons ) );
	INIT_LIST_HEAD ( ctx->beacons );

	dev->channel = 0;
	dev->op->config ( dev, NET80211_CFG_CHANNEL );

	return ctx;
}

/**
 * Continue probe of 802.11 networks
 *
 * @v ctx	Probe context returned by net80211_probe_start()
 * @ret rc	Probe status
 *
 * The return code will be 0 if the probe is still going on (and this
 * function should be called again), a positive number if the probe
 * completed successfully, or a negative error code if the probe
 * failed for that reason.
 *
 * Whether the probe succeeded or failed, you must call
 * net80211_probe_finish_all() or net80211_probe_finish_best()
 * (depending on whether you want information on all networks or just
 * the best-signal one) in order to release the probe context. A
 * failed probe may still have acquired some valid data.
 */
int net80211_probe_step ( struct net80211_probe_ctx *ctx )
{
	struct net80211_device *dev = ctx->dev;
	u32 start_timeout = NET80211_PROBE_TIMEOUT * ticks_per_sec();
	u32 gather_timeout = ticks_per_sec();
	u32 now = currticks();
	struct io_buffer *iob;
	int signal;
	int rc;
	char ssid[IEEE80211_MAX_SSID_LEN + 1];

	gather_timeout *= ( ctx->essid[0] ? NET80211_PROBE_GATHER :
			    NET80211_PROBE_GATHER_ALL );

	/* Time out if necessary */
	if ( now >= ctx->ticks_start + start_timeout )
		return list_empty ( ctx->beacons ) ? -ETIMEDOUT : +1;

	if ( ctx->ticks_beacon > 0 && now >= ctx->ticks_start + gather_timeout )
		return +1;

	/* Change channels if necessary */
	if ( now >= ctx->ticks_channel + ctx->hop_time ) {
		dev->channel = ( dev->channel + ctx->hop_step )
			% dev->nr_channels;
		dev->op->config ( dev, NET80211_CFG_CHANNEL );
		udelay ( dev->hw->channel_change_time );

		ctx->ticks_channel = now;

		if ( ctx->probe ) {
			struct io_buffer *siob = ctx->probe; /* to send */

			/* make a copy for future use */
			iob = alloc_iob ( siob->tail - siob->head );
			iob_reserve ( iob, iob_headroom ( siob ) );
			memcpy ( iob_put ( iob, iob_len ( siob ) ),
				 siob->data, iob_len ( siob ) );

			ctx->probe = iob;
			rc = net80211_tx_mgmt ( dev, IEEE80211_STYPE_PROBE_REQ,
						eth_broadcast,
						iob_disown ( siob ) );
			if ( rc ) {
				DBGC ( dev, "802.11 %p send probe failed: "
				       "%s\n", dev, strerror ( rc ) );
				return rc;
			}
		}
	}

	/* Check for new management packets */
	while ( ( iob = net80211_mgmt_dequeue ( dev, &signal ) ) != NULL ) {
		struct ieee80211_frame *hdr;
		struct ieee80211_beacon *beacon;
		union ieee80211_ie *ie;
		struct net80211_wlan *wlan;
		u16 type;

		hdr = iob->data;
		type = hdr->fc & IEEE80211_FC_SUBTYPE;
		beacon = ( struct ieee80211_beacon * ) hdr->data;

		if ( type != IEEE80211_STYPE_BEACON &&
		     type != IEEE80211_STYPE_PROBE_RESP ) {
			DBGC2 ( dev, "802.11 %p probe: non-beacon\n", dev );
			goto drop;
		}

		if ( ( void * ) beacon->info_element >= iob->tail ) {
			DBGC ( dev, "802.11 %p probe: beacon with no IEs\n",
			       dev );
			goto drop;
		}

		ie = beacon->info_element;

		if ( ! ieee80211_ie_bound ( ie, iob->tail ) )
			ie = NULL;

		while ( ie && ie->id != IEEE80211_IE_SSID )
			ie = ieee80211_next_ie ( ie, iob->tail );

		if ( ! ie ) {
			DBGC ( dev, "802.11 %p probe: beacon with no SSID\n",
			       dev );
			goto drop;
		}

		memcpy ( ssid, ie->ssid, ie->len );
		ssid[ie->len] = 0;

		if ( ctx->essid[0] && strcmp ( ctx->essid, ssid ) != 0 ) {
			DBGC2 ( dev, "802.11 %p probe: beacon with wrong SSID "
				"(%s)\n", dev, ssid );
			goto drop;
		}

		/* See if we've got an entry for this network */
		list_for_each_entry ( wlan, ctx->beacons, list ) {
			if ( strcmp ( wlan->essid, ssid ) != 0 )
				continue;

			if ( signal < wlan->signal ) {
				DBGC2 ( dev, "802.11 %p probe: beacon for %s "
					"(%s) with weaker signal %d\n", dev,
					ssid, eth_ntoa ( hdr->addr3 ), signal );
				goto drop;
			}

			goto fill;
		}

		/* No entry yet - make one */
		wlan = zalloc ( sizeof ( *wlan ) );
		strcpy ( wlan->essid, ssid );
		list_add_tail ( &wlan->list, ctx->beacons );

		/* Whether we're using an old entry or a new one, fill
		   it with new data. */
	fill:
		memcpy ( wlan->bssid, hdr->addr3, ETH_ALEN );
		wlan->signal = signal;
		wlan->channel = dev->channels[dev->channel].channel_nr;

		/* Copy this I/O buffer into a new wlan->beacon; the
		 * iob we've got probably came from the device driver
		 * and may have the full 2.4k allocation, which we
		 * don't want to keep around wasting memory.
		 */
		free_iob ( wlan->beacon );
		wlan->beacon = alloc_iob ( iob_len ( iob ) );
		memcpy ( iob_put ( wlan->beacon, iob_len ( iob ) ),
			 iob->data, iob_len ( iob ) );

		if ( ( rc = sec80211_detect ( wlan->beacon, &wlan->handshaking,
					      &wlan->crypto ) ) == -ENOTSUP ) {
			struct ieee80211_beacon *beacon =
				( struct ieee80211_beacon * ) hdr->data;

			if ( beacon->capability & IEEE80211_CAPAB_PRIVACY ) {
				DBG ( "802.11 %p probe: secured network %s but "
				      "encryption support not compiled in\n",
				      dev, wlan->essid );
				wlan->handshaking = NET80211_SECPROT_UNKNOWN;
				wlan->crypto = NET80211_CRYPT_UNKNOWN;
			} else {
				wlan->handshaking = NET80211_SECPROT_NONE;
				wlan->crypto = NET80211_CRYPT_NONE;
			}
		} else if ( rc != 0 ) {
			DBGC ( dev, "802.11 %p probe warning: network "
			       "%s with unidentifiable security "
			       "settings: %s\n", dev, wlan->essid,
			       strerror ( rc ) );
		}

		ctx->ticks_beacon = now;

		DBGC2 ( dev, "802.11 %p probe: good beacon for %s (%s)\n",
			dev, wlan->essid, eth_ntoa ( wlan->bssid ) );

	drop:
		free_iob ( iob );
	}

	return 0;
}


/**
 * Finish probe of 802.11 networks, returning best-signal network found
 *
 * @v ctx	Probe context
 * @ret wlan	Best-signal network found, or @c NULL if none were found
 *
 * If net80211_probe_start() was called with a particular SSID
 * parameter as filter, only a network with that SSID (matching
 * case-sensitively) can be returned from this function.
 */
struct net80211_wlan *
net80211_probe_finish_best ( struct net80211_probe_ctx *ctx )
{
	struct net80211_wlan *best = NULL, *wlan;

	if ( ! ctx )
		return NULL;

	list_for_each_entry ( wlan, ctx->beacons, list ) {
		if ( ! best || best->signal < wlan->signal )
			best = wlan;
	}

	if ( best )
		list_del ( &best->list );
	else
		DBGC ( ctx->dev, "802.11 %p probe: found nothing for '%s'\n",
		       ctx->dev, ctx->essid );

	net80211_free_wlanlist ( ctx->beacons );

	net80211_keep_mgmt ( ctx->dev, ctx->old_keep_mgmt );

	if ( ctx->probe )
		free_iob ( ctx->probe );

	free ( ctx );

	return best;
}


/**
 * Finish probe of 802.11 networks, returning all networks found
 *
 * @v ctx	Probe context
 * @ret list	List of net80211_wlan detailing networks found
 *
 * If net80211_probe_start() was called with a particular SSID
 * parameter as filter, this will always return either an empty or a
 * one-element list.
 */
struct list_head *net80211_probe_finish_all ( struct net80211_probe_ctx *ctx )
{
	struct list_head *beacons = ctx->beacons;

	if ( ! ctx )
		return NULL;

	net80211_keep_mgmt ( ctx->dev, ctx->old_keep_mgmt );

	if ( ctx->probe )
		free_iob ( ctx->probe );

	free ( ctx );

	return beacons;
}


/**
 * Free WLAN structure
 *
 * @v wlan	WLAN structure to free
 */
void net80211_free_wlan ( struct net80211_wlan *wlan )
{
	if ( wlan ) {
		free_iob ( wlan->beacon );
		free ( wlan );
	}
}


/**
 * Free list of WLAN structures
 *
 * @v list	List of WLAN structures to free
 */
void net80211_free_wlanlist ( struct list_head *list )
{
	struct net80211_wlan *wlan, *tmp;

	if ( ! list )
		return;

	list_for_each_entry_safe ( wlan, tmp, list, list ) {
		list_del ( &wlan->list );
		net80211_free_wlan ( wlan );
	}

	free ( list );
}


/** Number of ticks to wait for replies to association management frames */
#define ASSOC_TIMEOUT	TICKS_PER_SEC

/** Number of times to try sending a particular association management frame */
#define ASSOC_RETRIES	2

/**
 * Step 802.11 association process
 *
 * @v dev	802.11 device
 */
static void net80211_step_associate ( struct net80211_device *dev )
{
	int rc = 0;
	int status = dev->state & NET80211_STATUS_MASK;

	/*
	 * We use a sort of state machine implemented using bits in
	 * the dev->state variable. At each call, we take the
	 * logically first step that has not yet succeeded; either it
	 * has not been tried yet, it's being retried, or it failed.
	 * If it failed, we return an error indication; otherwise we
	 * perform the step. If it succeeds, RX handling code will set
	 * the appropriate status bit for us.
	 *
	 * Probe works a bit differently, since we have to step it
	 * on every call instead of waiting for a packet to arrive
	 * that will set the completion bit for us.
	 */

	/* If we're waiting for a reply, check for timeout condition */
	if ( dev->state & NET80211_WAITING ) {
		/* Sanity check */
		if ( ! dev->associating )
			return;

		if ( currticks() - dev->ctx.assoc->last_packet > ASSOC_TIMEOUT ) {
			/* Timed out - fail if too many retries, or retry */
			dev->ctx.assoc->times_tried++;
			if ( ++dev->ctx.assoc->times_tried > ASSOC_RETRIES ) {
				rc = -ETIMEDOUT;
				goto fail;
			}
		} else {
			/* Didn't time out - let it keep going */
			return;
		}
	} else {
		if ( dev->state & NET80211_PROBED )
			dev->ctx.assoc->times_tried = 0;
	}

	if ( ! ( dev->state & NET80211_PROBED ) ) {
		/* state: probe */

		if ( ! dev->ctx.probe ) {
			/* start probe */
			int active = fetch_intz_setting ( NULL,
						&net80211_active_setting );
			int band = dev->hw->bands;

			if ( active )
				band &= ~NET80211_BAND_BIT_5GHZ;

			rc = net80211_prepare_probe ( dev, band, active );
			if ( rc )
				goto fail;

			dev->ctx.probe = net80211_probe_start ( dev, dev->essid,
								active );
			if ( ! dev->ctx.probe ) {
				dev->assoc_rc = -ENOMEM;
				goto fail;
			}
		}

		rc = net80211_probe_step ( dev->ctx.probe );
		if ( ! rc ) {
			return;	/* still going */
		}

		dev->associating = net80211_probe_finish_best ( dev->ctx.probe );
		dev->ctx.probe = NULL;
		if ( ! dev->associating ) {
			if ( rc > 0 ) /* "successful" probe found nothing */
				rc = -ETIMEDOUT;
			goto fail;
		}

		/* If we probed using a broadcast SSID, record that
		   fact for the settings applicator before we clobber
		   it with the specific SSID we've chosen. */
		if ( ! dev->essid[0] )
			dev->state |= NET80211_AUTO_SSID;

		DBGC ( dev, "802.11 %p found network %s (%s)\n", dev,
		       dev->associating->essid,
		       eth_ntoa ( dev->associating->bssid ) );

		dev->ctx.assoc = zalloc ( sizeof ( *dev->ctx.assoc ) );
		if ( ! dev->ctx.assoc ) {
			rc = -ENOMEM;
			goto fail;
		}

		dev->state |= NET80211_PROBED;
		dev->ctx.assoc->method = IEEE80211_AUTH_OPEN_SYSTEM;

		return;
	}

	/* Record time of sending the packet we're about to send, for timeout */
	dev->ctx.assoc->last_packet = currticks();

	if ( ! ( dev->state & NET80211_AUTHENTICATED ) ) {
		/* state: prepare and authenticate */

		if ( status != IEEE80211_STATUS_SUCCESS ) {
			/* we tried authenticating already, but failed */
			int method = dev->ctx.assoc->method;

			if ( method == IEEE80211_AUTH_OPEN_SYSTEM &&
			     ( status == IEEE80211_STATUS_AUTH_CHALL_INVALID ||
			       status == IEEE80211_STATUS_AUTH_ALGO_UNSUPP ) ) {
				/* Maybe this network uses Shared Key? */
				dev->ctx.assoc->method =
					IEEE80211_AUTH_SHARED_KEY;
			} else {
				goto fail;
			}
		}

		DBGC ( dev, "802.11 %p authenticating with method %d\n", dev,
		       dev->ctx.assoc->method );

		rc = net80211_prepare_assoc ( dev, dev->associating );
		if ( rc )
			goto fail;

		rc = net80211_send_auth ( dev, dev->associating,
					  dev->ctx.assoc->method );
		if ( rc )
			goto fail;

		return;
	}

	if ( ! ( dev->state & NET80211_ASSOCIATED ) ) {
		/* state: associate */

		if ( status != IEEE80211_STATUS_SUCCESS )
			goto fail;

		DBGC ( dev, "802.11 %p associating\n", dev );

		if ( dev->handshaker && dev->handshaker->start &&
		     ! dev->handshaker->started ) {
			rc = dev->handshaker->start ( dev );
			if ( rc < 0 )
				goto fail;
			dev->handshaker->started = 1;
		}

		rc = net80211_send_assoc ( dev, dev->associating );
		if ( rc )
			goto fail;

		return;
	}

	if ( ! ( dev->state & NET80211_CRYPTO_SYNCED ) ) {
		/* state: crypto sync */
		DBGC ( dev, "802.11 %p security handshaking\n", dev );

		if ( ! dev->handshaker || ! dev->handshaker->step ) {
			dev->state |= NET80211_CRYPTO_SYNCED;
			return;
		}

		rc = dev->handshaker->step ( dev );

		if ( rc < 0 ) {
			/* Only record the returned error if we're
			   still marked as associated, because an
			   asynchronous error will have already been
			   reported to net80211_deauthenticate() and
			   assoc_rc thereby set. */
			if ( dev->state & NET80211_ASSOCIATED )
				dev->assoc_rc = rc;
			rc = 0;
			goto fail;
		}

		if ( rc > 0 ) {
			dev->assoc_rc = 0;
			dev->state |= NET80211_CRYPTO_SYNCED;
		}
		return;
	}

	/* state: done! */
	netdev_link_up ( dev->netdev );
	dev->assoc_rc = 0;
	dev->state &= ~NET80211_WORKING;

	free ( dev->ctx.assoc );
	dev->ctx.assoc = NULL;

	net80211_free_wlan ( dev->associating );
	dev->associating = NULL;

	dev->rctl = rc80211_init ( dev );

	process_del ( &dev->proc_assoc );

	DBGC ( dev, "802.11 %p associated with %s (%s)\n", dev,
	       dev->essid, eth_ntoa ( dev->bssid ) );

	return;

 fail:
	dev->state &= ~( NET80211_WORKING | NET80211_WAITING );
	if ( rc )
		dev->assoc_rc = rc;

	netdev_link_err ( dev->netdev, dev->assoc_rc );

	/* We never reach here from the middle of a probe, so we don't
	   need to worry about freeing dev->ctx.probe. */

	if ( dev->state & NET80211_PROBED ) {
		free ( dev->ctx.assoc );
		dev->ctx.assoc = NULL;
	}

	net80211_free_wlan ( dev->associating );
	dev->associating = NULL;

	process_del ( &dev->proc_assoc );

	DBGC ( dev, "802.11 %p association failed (state=%04x): "
	       "%s\n", dev, dev->state, strerror ( dev->assoc_rc ) );

	/* Try it again: */
	net80211_autoassociate ( dev );
}

/**
 * Check for 802.11 SSID or key updates
 *
 * This acts as a settings applicator; if the user changes netX/ssid,
 * and netX is currently open, the association task will be invoked
 * again. If the user changes the encryption key, the current security
 * handshaker will be asked to update its state to match; if that is
 * impossible without reassociation, we reassociate.
 */
static int net80211_check_settings_update ( void )
{
	struct net80211_device *dev;
	char ssid[IEEE80211_MAX_SSID_LEN + 1];
	int key_reassoc;

	list_for_each_entry ( dev, &net80211_devices, list ) {
		if ( ! netdev_is_open ( dev->netdev ) )
			continue;

		key_reassoc = 0;
		if ( dev->handshaker && dev->handshaker->change_key &&
		     dev->handshaker->change_key ( dev ) < 0 )
			key_reassoc = 1;

		fetch_string_setting ( netdev_settings ( dev->netdev ),
				       &net80211_ssid_setting, ssid,
				       IEEE80211_MAX_SSID_LEN + 1 );

		if ( key_reassoc ||
		     ( ! ( ! ssid[0] && ( dev->state & NET80211_AUTO_SSID ) ) &&
		       strcmp ( ssid, dev->essid ) != 0 ) ) {
			DBGC ( dev, "802.11 %p updating association: "
			       "%s -> %s\n", dev, dev->essid, ssid );
			net80211_autoassociate ( dev );
		}
	}

	return 0;
}

/**
 * Start 802.11 association process
 *
 * @v dev	802.11 device
 *
 * If the association process is running, it will be restarted.
 */
void net80211_autoassociate ( struct net80211_device *dev )
{
	if ( ! ( dev->state & NET80211_WORKING ) ) {
		DBGC2 ( dev, "802.11 %p spawning association process\n", dev );
		process_add ( &dev->proc_assoc );
	} else {
		DBGC2 ( dev, "802.11 %p restarting association\n", dev );
	}

	/* Clean up everything an earlier association process might
	   have been in the middle of using */
	if ( dev->associating )
		net80211_free_wlan ( dev->associating );

	if ( ! ( dev->state & NET80211_PROBED ) )
		net80211_free_wlan (
			net80211_probe_finish_best ( dev->ctx.probe ) );
	else
		free ( dev->ctx.assoc );

	/* Reset to a clean state */
	fetch_string_setting ( netdev_settings ( dev->netdev ),
			       &net80211_ssid_setting, dev->essid,
			       IEEE80211_MAX_SSID_LEN + 1 );
	dev->ctx.probe = NULL;
	dev->associating = NULL;
	dev->assoc_rc = 0;
	net80211_set_state ( dev, NET80211_PROBED, NET80211_WORKING, 0 );
}

/**
 * Pick TX rate for RTS/CTS packets based on data rate
 *
 * @v dev	802.11 device
 *
 * The RTS/CTS rate is the fastest TX rate marked as "basic" that is
 * not faster than the data rate.
 */
static void net80211_set_rtscts_rate ( struct net80211_device *dev )
{
	u16 datarate = dev->rates[dev->rate];
	u16 rtsrate = 0;
	int rts_idx = -1;
	int i;

	for ( i = 0; i < dev->nr_rates; i++ ) {
		u16 rate = dev->rates[i];

		if ( ! ( dev->basic_rates & ( 1 << i ) ) || rate > datarate )
			continue;

		if ( rate > rtsrate ) {
			rtsrate = rate;
			rts_idx = i;
		}
	}

	/* If this is in initialization, we might not have any basic
	   rates; just use the first data rate in that case. */
	if ( rts_idx < 0 )
		rts_idx = 0;

	dev->rtscts_rate = rts_idx;
}

/**
 * Set data transmission rate for 802.11 device
 *
 * @v dev	802.11 device
 * @v rate	Rate to set, as index into @c dev->rates array
 */
void net80211_set_rate_idx ( struct net80211_device *dev, int rate )
{
	assert ( netdev_is_open ( dev->netdev ) );

	if ( rate >= 0 && rate < dev->nr_rates && rate != dev->rate ) {
		DBGC2 ( dev, "802.11 %p changing rate from %d->%d Mbps\n",
			dev, dev->rates[dev->rate] / 10,
			dev->rates[rate] / 10 );

		dev->rate = rate;
		net80211_set_rtscts_rate ( dev );
		dev->op->config ( dev, NET80211_CFG_RATE );
	}
}

/**
 * Configure 802.11 device to transmit on a certain channel
 *
 * @v dev	802.11 device
 * @v channel	Channel number (1-11 for 2.4GHz) to transmit on
 */
int net80211_change_channel ( struct net80211_device *dev, int channel )
{
	int i, oldchan = dev->channel;

	assert ( netdev_is_open ( dev->netdev ) );

	for ( i = 0; i < dev->nr_channels; i++ ) {
		if ( dev->channels[i].channel_nr == channel ) {
			dev->channel = i;
			break;
		}
	}

	if ( i == dev->nr_channels )
		return -ENOENT;

	if ( i != oldchan )
		return dev->op->config ( dev, NET80211_CFG_CHANNEL );

	return 0;
}

/**
 * Prepare 802.11 device channel and rate set for scanning
 *
 * @v dev	802.11 device
 * @v band	RF band(s) on which to prepare for scanning
 * @v active	Whether the scanning will be active
 * @ret rc	Return status code
 */
int net80211_prepare_probe ( struct net80211_device *dev, int band,
			     int active )
{
	assert ( netdev_is_open ( dev->netdev ) );

	if ( active && ( band & NET80211_BAND_BIT_5GHZ ) ) {
		DBGC ( dev, "802.11 %p cannot perform active scanning on "
		       "5GHz band\n", dev );
		return -EINVAL_ACTIVE_SCAN;
	}

	if ( band == 0 ) {
		/* This can happen for a 5GHz-only card with 5GHz
		   scanning masked out by an active request. */
		DBGC ( dev, "802.11 %p asked to prepare for scanning nothing\n",
		       dev );
		return -EINVAL_ACTIVE_SCAN;
	}

	dev->nr_channels = 0;

	if ( active )
		net80211_add_channels ( dev, 1, 11, NET80211_REG_TXPOWER );
	else {
		if ( band & NET80211_BAND_BIT_2GHZ )
			net80211_add_channels ( dev, 1, 14,
						NET80211_REG_TXPOWER );
		if ( band & NET80211_BAND_BIT_5GHZ )
			net80211_add_channels ( dev, 36, 8,
						NET80211_REG_TXPOWER );
	}

	net80211_filter_hw_channels ( dev );

	/* Use channel 1 for now */
	dev->channel = 0;
	dev->op->config ( dev, NET80211_CFG_CHANNEL );

	/* Always do active probes at lowest (presumably first) speed */
	dev->rate = 0;
	dev->nr_rates = 1;
	dev->rates[0] = dev->hw->rates[dev->channels[0].band][0];
	dev->op->config ( dev, NET80211_CFG_RATE );

	return 0;
}

/**
 * Prepare 802.11 device channel and rate set for communication
 *
 * @v dev	802.11 device
 * @v wlan	WLAN to prepare for communication with
 * @ret rc	Return status code
 */
int net80211_prepare_assoc ( struct net80211_device *dev,
			     struct net80211_wlan *wlan )
{
	struct ieee80211_frame *hdr = wlan->beacon->data;
	struct ieee80211_beacon *beacon =
		( struct ieee80211_beacon * ) hdr->data;
	struct net80211_handshaker *handshaker;
	int rc;

	assert ( netdev_is_open ( dev->netdev ) );

	net80211_set_state ( dev, NET80211_ASSOCIATED, 0, 0 );
	memcpy ( dev->bssid, wlan->bssid, ETH_ALEN );
	strcpy ( dev->essid, wlan->essid );

	free ( dev->rsn_ie );
	dev->rsn_ie = NULL;

	dev->last_beacon_timestamp = beacon->timestamp;
	dev->tx_beacon_interval = 1024 * beacon->beacon_interval;

	/* Barring an IE that tells us the channel outright, assume
	   the channel we heard this AP best on is the channel it's
	   communicating on. */
	net80211_change_channel ( dev, wlan->channel );

	rc = net80211_process_capab ( dev, beacon->capability );
	if ( rc )
		return rc;

	rc = net80211_process_ie ( dev, beacon->info_element,
				   wlan->beacon->tail );
	if ( rc )
		return rc;

	/* Associate at the lowest rate so we know it'll get through */
	dev->rate = 0;
	dev->op->config ( dev, NET80211_CFG_RATE );

	/* Free old handshaker and crypto, if they exist */
	if ( dev->handshaker && dev->handshaker->stop &&
	     dev->handshaker->started )
		dev->handshaker->stop ( dev );
	free ( dev->handshaker );
	dev->handshaker = NULL;
	free ( dev->crypto );
	free ( dev->gcrypto );
	dev->crypto = dev->gcrypto = NULL;

	/* Find new security handshaker to use */
	for_each_table_entry ( handshaker, NET80211_HANDSHAKERS ) {
		if ( handshaker->protocol == wlan->handshaking ) {
			dev->handshaker = zalloc ( sizeof ( *handshaker ) +
						   handshaker->priv_len );
			if ( ! dev->handshaker )
				return -ENOMEM;

			memcpy ( dev->handshaker, handshaker,
				 sizeof ( *handshaker ) );
			dev->handshaker->priv = ( ( void * ) dev->handshaker +
						  sizeof ( *handshaker ) );
			break;
		}
	}

	if ( ( wlan->handshaking != NET80211_SECPROT_NONE ) &&
	     ! dev->handshaker ) {
		DBGC ( dev, "802.11 %p no support for handshaking scheme %d\n",
		       dev, wlan->handshaking );
		return -( ENOTSUP | ( wlan->handshaking << 8 ) );
	}

	/* Initialize security handshaker */
	if ( dev->handshaker ) {
		rc = dev->handshaker->init ( dev );
		if ( rc < 0 )
			return rc;
	}

	return 0;
}

/**
 * Send 802.11 initial authentication frame
 *
 * @v dev	802.11 device
 * @v wlan	WLAN to authenticate with
 * @v method	Authentication method
 * @ret rc	Return status code
 *
 * @a method may be 0 for Open System authentication or 1 for Shared
 * Key authentication. Open System provides no security in association
 * whatsoever, relying on encryption for confidentiality, but Shared
 * Key actively introduces security problems and is very rarely used.
 */
int net80211_send_auth ( struct net80211_device *dev,
			 struct net80211_wlan *wlan, int method )
{
	struct io_buffer *iob = alloc_iob ( 64 );
	struct ieee80211_auth *auth;

	net80211_set_state ( dev, 0, NET80211_WAITING, 0 );
	iob_reserve ( iob, IEEE80211_TYP_FRAME_HEADER_LEN );
	auth = iob_put ( iob, sizeof ( *auth ) );
	auth->algorithm = method;
	auth->tx_seq = 1;
	auth->status = 0;

	return net80211_tx_mgmt ( dev, IEEE80211_STYPE_AUTH, wlan->bssid, iob );
}

/**
 * Handle receipt of 802.11 authentication frame
 *
 * @v dev	802.11 device
 * @v iob	I/O buffer
 *
 * If the authentication method being used is Shared Key, and the
 * frame that was received included challenge text, the frame is
 * encrypted using the cryptosystem currently in effect and sent back
 * to the AP to complete the authentication.
 */
static void net80211_handle_auth ( struct net80211_device *dev,
				   struct io_buffer *iob )
{
	struct ieee80211_frame *hdr = iob->data;
	struct ieee80211_auth *auth =
	    ( struct ieee80211_auth * ) hdr->data;

	if ( auth->tx_seq & 1 ) {
		DBGC ( dev, "802.11 %p authentication received improperly "
		       "directed frame (seq. %d)\n", dev, auth->tx_seq );
		net80211_set_state ( dev, NET80211_WAITING, 0,
				     IEEE80211_STATUS_FAILURE );
		return;
	}

	if ( auth->status != IEEE80211_STATUS_SUCCESS ) {
		DBGC ( dev, "802.11 %p authentication failed: status %d\n",
		       dev, auth->status );
		net80211_set_state ( dev, NET80211_WAITING, 0,
				     auth->status );
		return;
	}

	if ( auth->algorithm == IEEE80211_AUTH_SHARED_KEY && ! dev->crypto ) {
		DBGC ( dev, "802.11 %p can't perform shared-key authentication "
		       "without a cryptosystem\n", dev );
		net80211_set_state ( dev, NET80211_WAITING, 0,
				     IEEE80211_STATUS_FAILURE );
		return;
	}

	if ( auth->algorithm == IEEE80211_AUTH_SHARED_KEY &&
	     auth->tx_seq == 2 ) {
		/* Since the iob we got is going to be freed as soon
		   as we return, we can do some in-place
		   modification. */
		auth->tx_seq = 3;
		auth->status = 0;

		memcpy ( hdr->addr2, hdr->addr1, ETH_ALEN );
		memcpy ( hdr->addr1, hdr->addr3, ETH_ALEN );

		netdev_tx ( dev->netdev,
			    dev->crypto->encrypt ( dev->crypto, iob ) );
		return;
	}

	net80211_set_state ( dev, NET80211_WAITING, NET80211_AUTHENTICATED,
			     IEEE80211_STATUS_SUCCESS );

	return;
}

/**
 * Send 802.11 association frame
 *
 * @v dev	802.11 device
 * @v wlan	WLAN to associate with
 * @ret rc	Return status code
 */
int net80211_send_assoc ( struct net80211_device *dev,
			  struct net80211_wlan *wlan )
{
	struct io_buffer *iob = alloc_iob ( 128 );
	struct ieee80211_assoc_req *assoc;
	union ieee80211_ie *ie;

	net80211_set_state ( dev, 0, NET80211_WAITING, 0 );

	iob_reserve ( iob, IEEE80211_TYP_FRAME_HEADER_LEN );
	assoc = iob->data;

	assoc->capability = IEEE80211_CAPAB_MANAGED;
	if ( ! ( dev->hw->flags & NET80211_HW_NO_SHORT_PREAMBLE ) )
		assoc->capability |= IEEE80211_CAPAB_SHORT_PMBL;
	if ( ! ( dev->hw->flags & NET80211_HW_NO_SHORT_SLOT ) )
		assoc->capability |= IEEE80211_CAPAB_SHORT_SLOT;
	if ( wlan->crypto )
		assoc->capability |= IEEE80211_CAPAB_PRIVACY;

	assoc->listen_interval = 1;

	ie = net80211_marshal_request_info ( dev, assoc->info_element );

	DBGP ( "802.11 %p about to send association request:\n", dev );
	DBGP_HD ( iob->data, ( void * ) ie - iob->data );

	iob_put ( iob, ( void * ) ie - iob->data );

	return net80211_tx_mgmt ( dev, IEEE80211_STYPE_ASSOC_REQ,
				  wlan->bssid, iob );
}

/**
 * Handle receipt of 802.11 association reply frame
 *
 * @v dev	802.11 device
 * @v iob	I/O buffer
 */
static void net80211_handle_assoc_reply ( struct net80211_device *dev,
					  struct io_buffer *iob )
{
	struct ieee80211_frame *hdr = iob->data;
	struct ieee80211_assoc_resp *assoc =
		( struct ieee80211_assoc_resp * ) hdr->data;

	net80211_process_capab ( dev, assoc->capability );
	net80211_process_ie ( dev, assoc->info_element, iob->tail );

	if ( assoc->status != IEEE80211_STATUS_SUCCESS ) {
		DBGC ( dev, "802.11 %p association failed: status %d\n",
		       dev, assoc->status );
		net80211_set_state ( dev, NET80211_WAITING, 0,
				     assoc->status );
		return;
	}

	/* ESSID was filled before the association request was sent */
	memcpy ( dev->bssid, hdr->addr3, ETH_ALEN );
	dev->aid = assoc->aid;

	net80211_set_state ( dev, NET80211_WAITING, NET80211_ASSOCIATED,
			     IEEE80211_STATUS_SUCCESS );
}


/**
 * Send 802.11 disassociation frame
 *
 * @v dev	802.11 device
 * @v reason	Reason for disassociation
 * @v deauth	If TRUE, send deauthentication instead of disassociation
 * @ret rc	Return status code
 */
static int net80211_send_disassoc ( struct net80211_device *dev, int reason,
				    int deauth )
{
	struct io_buffer *iob = alloc_iob ( 64 );
	struct ieee80211_disassoc *disassoc;

	if ( ! ( dev->state & NET80211_ASSOCIATED ) )
		return -EINVAL;

	net80211_set_state ( dev, NET80211_ASSOCIATED, 0, 0 );
	iob_reserve ( iob, IEEE80211_TYP_FRAME_HEADER_LEN );
	disassoc = iob_put ( iob, sizeof ( *disassoc ) );
	disassoc->reason = reason;

	return net80211_tx_mgmt ( dev, deauth ? IEEE80211_STYPE_DEAUTH :
				  IEEE80211_STYPE_DISASSOC, dev->bssid, iob );
}


/**
 * Deauthenticate from current network and try again
 *
 * @v dev	802.11 device
 * @v rc	Return status code indicating reason
 *
 * The deauthentication will be sent using an 802.11 "unspecified
 * reason", as is common, but @a rc will be set as a link-up
 * error to aid the user in debugging.
 */
void net80211_deauthenticate ( struct net80211_device *dev, int rc )
{
	net80211_send_disassoc ( dev, IEEE80211_REASON_UNSPECIFIED, 1 );
	dev->assoc_rc = rc;
	netdev_link_err ( dev->netdev, rc );

	net80211_autoassociate ( dev );
}


/** Smoothing factor (1-7) for link quality calculation */
#define LQ_SMOOTH	7

/**
 * Update link quality information based on received beacon
 *
 * @v dev	802.11 device
 * @v iob	I/O buffer containing beacon
 * @ret rc	Return status code
 */
static void net80211_update_link_quality ( struct net80211_device *dev,
					   struct io_buffer *iob )
{
	struct ieee80211_frame *hdr = iob->data;
	struct ieee80211_beacon *beacon;
	u32 dt, rxi;

	if ( ! ( dev->state & NET80211_ASSOCIATED ) )
		return;

	beacon = ( struct ieee80211_beacon * ) hdr->data;
	dt = ( u32 ) ( beacon->timestamp - dev->last_beacon_timestamp );
	rxi = dev->rx_beacon_interval;

	rxi = ( LQ_SMOOTH * rxi ) + ( ( 8 - LQ_SMOOTH ) * dt );
	dev->rx_beacon_interval = rxi >> 3;

	dev->last_beacon_timestamp = beacon->timestamp;
}


/**
 * Handle receipt of 802.11 management frame
 *
 * @v dev	802.11 device
 * @v iob	I/O buffer
 * @v signal	Signal strength of received frame
 */
static void net80211_handle_mgmt ( struct net80211_device *dev,
				   struct io_buffer *iob, int signal )
{
	struct ieee80211_frame *hdr = iob->data;
	struct ieee80211_disassoc *disassoc;
	u16 stype = hdr->fc & IEEE80211_FC_SUBTYPE;
	int keep = 0;
	int is_deauth = ( stype == IEEE80211_STYPE_DEAUTH );

	if ( ( hdr->fc & IEEE80211_FC_TYPE ) != IEEE80211_TYPE_MGMT ) {
		free_iob ( iob );
		return;		/* only handle management frames */
	}

	switch ( stype ) {
		/* We reconnect on deauthentication and disassociation. */
	case IEEE80211_STYPE_DEAUTH:
	case IEEE80211_STYPE_DISASSOC:
		disassoc = ( struct ieee80211_disassoc * ) hdr->data;
		net80211_set_state ( dev, is_deauth ? NET80211_AUTHENTICATED :
				     NET80211_ASSOCIATED, 0,
				     NET80211_IS_REASON | disassoc->reason );
		DBGC ( dev, "802.11 %p %s: reason %d\n",
		       dev, is_deauth ? "deauthenticated" : "disassociated",
		       disassoc->reason );

		/* Try to reassociate, in case it's transient. */
		net80211_autoassociate ( dev );

		break;

		/* We handle authentication and association. */
	case IEEE80211_STYPE_AUTH:
		if ( ! ( dev->state & NET80211_AUTHENTICATED ) )
			net80211_handle_auth ( dev, iob );
		break;

	case IEEE80211_STYPE_ASSOC_RESP:
	case IEEE80211_STYPE_REASSOC_RESP:
		if ( ! ( dev->state & NET80211_ASSOCIATED ) )
			net80211_handle_assoc_reply ( dev, iob );
		break;

		/* We pass probes and beacons onto network scanning
		   code. Pass actions for future extensibility. */
	case IEEE80211_STYPE_BEACON:
		net80211_update_link_quality ( dev, iob );
		/* fall through */
	case IEEE80211_STYPE_PROBE_RESP:
	case IEEE80211_STYPE_ACTION:
		if ( dev->keep_mgmt ) {
			struct net80211_rx_info *rxinf;
			rxinf = zalloc ( sizeof ( *rxinf ) );
			if ( ! rxinf ) {
				DBGC ( dev, "802.11 %p out of memory\n", dev );
				break;
			}
			rxinf->signal = signal;
			list_add_tail ( &iob->list, &dev->mgmt_queue );
			list_add_tail ( &rxinf->list, &dev->mgmt_info_queue );
			keep = 1;
		}
		break;

	case IEEE80211_STYPE_PROBE_REQ:
		/* Some nodes send these broadcast. Ignore them. */
		break;

	case IEEE80211_STYPE_ASSOC_REQ:
	case IEEE80211_STYPE_REASSOC_REQ:
		/* We should never receive these, only send them. */
		DBGC ( dev, "802.11 %p received strange management request "
		       "(%04x)\n", dev, stype );
		break;

	default:
		DBGC ( dev, "802.11 %p received unimplemented management "
		       "packet (%04x)\n", dev, stype );
		break;
	}

	if ( ! keep )
		free_iob ( iob );
}

/* ---------- Packet handling functions ---------- */

/**
 * Free buffers used by 802.11 fragment cache entry
 *
 * @v dev	802.11 device
 * @v fcid	Fragment cache entry index
 *
 * After this function, the referenced entry will be marked unused.
 */
static void net80211_free_frags ( struct net80211_device *dev, int fcid )
{
	int j;
	struct net80211_frag_cache *frag = &dev->frags[fcid];

	for ( j = 0; j < 16; j++ ) {
		if ( frag->iob[j] ) {
			free_iob ( frag->iob[j] );
			frag->iob[j] = NULL;
		}
	}

	frag->seqnr = 0;
	frag->start_ticks = 0;
	frag->in_use = 0;
}

/**
 * Accumulate 802.11 fragments into one I/O buffer
 *
 * @v dev	802.11 device
 * @v fcid	Fragment cache entry index
 * @v nfrags	Number of fragments received
 * @v size	Sum of sizes of all fragments, including headers
 * @ret iob	I/O buffer containing reassembled packet
 *
 * This function does not free the fragment buffers.
 */
static struct io_buffer *net80211_accum_frags ( struct net80211_device *dev,
						int fcid, int nfrags, int size )
{
	struct net80211_frag_cache *frag = &dev->frags[fcid];
	int hdrsize = IEEE80211_TYP_FRAME_HEADER_LEN;
	int nsize = size - hdrsize * ( nfrags - 1 );
	int i;

	struct io_buffer *niob = alloc_iob ( nsize );
	struct ieee80211_frame *hdr;

	/* Add the header from the first one... */
	memcpy ( iob_put ( niob, hdrsize ), frag->iob[0]->data, hdrsize );

	/* ... and all the data from all of them. */
	for ( i = 0; i < nfrags; i++ ) {
		int len = iob_len ( frag->iob[i] ) - hdrsize;
		memcpy ( iob_put ( niob, len ),
			 frag->iob[i]->data + hdrsize, len );
	}

	/* Turn off the fragment bit. */
	hdr = niob->data;
	hdr->fc &= ~IEEE80211_FC_MORE_FRAG;

	return niob;
}

/**
 * Handle receipt of 802.11 fragment
 *
 * @v dev	802.11 device
 * @v iob	I/O buffer containing fragment
 * @v signal	Signal strength with which fragment was received
 */
static void net80211_rx_frag ( struct net80211_device *dev,
			       struct io_buffer *iob, int signal )
{
	struct ieee80211_frame *hdr = iob->data;
	int fragnr = IEEE80211_FRAG ( hdr->seq );

	if ( fragnr == 0 && ( hdr->fc & IEEE80211_FC_MORE_FRAG ) ) {
		/* start a frag cache entry */
		int i, newest = -1;
		u32 curr_ticks = currticks(), newest_ticks = 0;
		u32 timeout = ticks_per_sec() * NET80211_FRAG_TIMEOUT;

		for ( i = 0; i < NET80211_NR_CONCURRENT_FRAGS; i++ ) {
			if ( dev->frags[i].in_use == 0 )
				break;

			if ( dev->frags[i].start_ticks + timeout >=
			     curr_ticks ) {
				net80211_free_frags ( dev, i );
				break;
			}

			if ( dev->frags[i].start_ticks > newest_ticks ) {
				newest = i;
				newest_ticks = dev->frags[i].start_ticks;
			}
		}

		/* If we're being sent more concurrent fragmented
		   packets than we can handle, drop the newest so the
		   older ones have time to complete. */
		if ( i == NET80211_NR_CONCURRENT_FRAGS ) {
			i = newest;
			net80211_free_frags ( dev, i );
		}

		dev->frags[i].in_use = 1;
		dev->frags[i].seqnr = IEEE80211_SEQNR ( hdr->seq );
		dev->frags[i].start_ticks = currticks();
		dev->frags[i].iob[0] = iob;
		return;
	} else {
		int i;
		for ( i = 0; i < NET80211_NR_CONCURRENT_FRAGS; i++ ) {
			if ( dev->frags[i].in_use && dev->frags[i].seqnr ==
			     IEEE80211_SEQNR ( hdr->seq ) )
				break;
		}
		if ( i == NET80211_NR_CONCURRENT_FRAGS ) {
			/* Drop non-first not-in-cache fragments */
			DBGC ( dev, "802.11 %p dropped fragment fc=%04x "
			       "seq=%04x\n", dev, hdr->fc, hdr->seq );
			free_iob ( iob );
			return;
		}

		dev->frags[i].iob[fragnr] = iob;

		if ( ! ( hdr->fc & IEEE80211_FC_MORE_FRAG ) ) {
			int j, size = 0;
			for ( j = 0; j < fragnr; j++ ) {
				size += iob_len ( dev->frags[i].iob[j] );
				if ( dev->frags[i].iob[j] == NULL )
					break;
			}
			if ( j == fragnr ) {
				/* We've got everything */
				struct io_buffer *niob =
				    net80211_accum_frags ( dev, i, fragnr,
							   size );
				net80211_free_frags ( dev, i );
				net80211_rx ( dev, niob, signal, 0 );
			} else {
				DBGC ( dev, "802.11 %p dropping fragmented "
				       "packet due to out-of-order arrival, "
				       "fc=%04x seq=%04x\n", dev, hdr->fc,
				       hdr->seq );
				net80211_free_frags ( dev, i );
			}
		}
	}
}

/**
 * Handle receipt of 802.11 frame
 *
 * @v dev	802.11 device
 * @v iob	I/O buffer
 * @v signal	Received signal strength
 * @v rate	Bitrate at which frame was received, in 100 kbps units
 *
 * If the rate or signal is unknown, 0 should be passed.
 */
void net80211_rx ( struct net80211_device *dev, struct io_buffer *iob,
		   int signal, u16 rate )
{
	struct ieee80211_frame *hdr = iob->data;
	u16 type = hdr->fc & IEEE80211_FC_TYPE;
	if ( ( hdr->fc & IEEE80211_FC_VERSION ) != IEEE80211_THIS_VERSION )
		goto drop;	/* drop invalid-version packets */

	if ( type == IEEE80211_TYPE_CTRL )
		goto drop;	/* we don't handle control packets,
				   the hardware does */

	if ( dev->last_rx_seq == hdr->seq )
		goto drop;	/* avoid duplicate packet */
	dev->last_rx_seq = hdr->seq;

	if ( dev->hw->flags & NET80211_HW_RX_HAS_FCS ) {
		/* discard the FCS */
		iob_unput ( iob, 4 );
	}

	/* Only decrypt packets from our BSSID, to avoid spurious errors */
	if ( ( hdr->fc & IEEE80211_FC_PROTECTED ) &&
	     ! memcmp ( hdr->addr2, dev->bssid, ETH_ALEN ) ) {
		/* Decrypt packet; record and drop if it fails */
		struct io_buffer *niob;
		struct net80211_crypto *crypto = dev->crypto;

		if ( ! dev->crypto ) {
			DBGC ( dev, "802.11 %p cannot decrypt packet "
			       "without a cryptosystem\n", dev );
			goto drop_crypt;
		}

		if ( ( hdr->addr1[0] & 1 ) && dev->gcrypto ) {
			/* Use group decryption if needed */
			crypto = dev->gcrypto;
		}

		niob = crypto->decrypt ( crypto, iob );
		if ( ! niob ) {
			DBGC ( dev, "802.11 %p decryption error\n", dev );
			goto drop_crypt;
		}
		free_iob ( iob );
		iob = niob;
		hdr = iob->data;
	}

	dev->last_signal = signal;

	/* Fragments go into the frag cache or get dropped. */
	if ( IEEE80211_FRAG ( hdr->seq ) != 0
	     || ( hdr->fc & IEEE80211_FC_MORE_FRAG ) ) {
		net80211_rx_frag ( dev, iob, signal );
		return;
	}

	/* Management frames get handled, enqueued, or dropped. */
	if ( type == IEEE80211_TYPE_MGMT ) {
		net80211_handle_mgmt ( dev, iob, signal );
		return;
	}

	/* Data frames get dropped or sent to the net_device. */
	if ( ( hdr->fc & IEEE80211_FC_SUBTYPE ) != IEEE80211_STYPE_DATA )
		goto drop;	/* drop QoS, CFP, or null data packets */

	/* Update rate-control algorithm */
	if ( dev->rctl )
		rc80211_update_rx ( dev, hdr->fc & IEEE80211_FC_RETRY, rate );

	/* Pass packet onward */
	if ( dev->state & NET80211_ASSOCIATED ) {
		netdev_rx ( dev->netdev, iob );
		return;
	}

	/* No association? Drop it. */
	goto drop;

 drop_crypt:
	netdev_rx_err ( dev->netdev, NULL, EINVAL_CRYPTO_REQUEST );
 drop:
	DBGC2 ( dev, "802.11 %p dropped packet fc=%04x seq=%04x\n", dev,
		hdr->fc, hdr->seq );
	free_iob ( iob );
	return;
}

/** Indicate an error in receiving a packet
 *
 * @v dev	802.11 device
 * @v iob	I/O buffer with received packet, or NULL
 * @v rc	Error code
 *
 * This logs the error with the wrapping net_device, and frees iob if
 * it is passed.
 */
void net80211_rx_err ( struct net80211_device *dev,
		       struct io_buffer *iob, int rc )
{
	netdev_rx_err ( dev->netdev, iob, rc );
}

/** Indicate the completed transmission of a packet
 *
 * @v dev	802.11 device
 * @v iob	I/O buffer of transmitted packet
 * @v retries	Number of times this packet was retransmitted
 * @v rc	Error code, or 0 for success
 *
 * This logs an error with the wrapping net_device if one occurred,
 * and removes and frees the I/O buffer from its TX queue. The
 * provided retry information is used to tune our transmission rate.
 *
 * If the packet did not need to be retransmitted because it was
 * properly ACKed the first time, @a retries should be 0.
 */
void net80211_tx_complete ( struct net80211_device *dev,
			    struct io_buffer *iob, int retries, int rc )
{
	/* Update rate-control algorithm */
	if ( dev->rctl )
		rc80211_update_tx ( dev, retries, rc );

	/* Pass completion onward */
	netdev_tx_complete_err ( dev->netdev, iob, rc );
}

/** Common 802.11 errors */
struct errortab common_wireless_errors[] __errortab = {
	__einfo_errortab ( EINFO_EINVAL_CRYPTO_REQUEST ),
	__einfo_errortab ( EINFO_ECONNRESET_UNSPECIFIED ),
	__einfo_errortab ( EINFO_ECONNRESET_INACTIVITY ),
	__einfo_errortab ( EINFO_ECONNRESET_4WAY_TIMEOUT ),
	__einfo_errortab ( EINFO_ECONNRESET_8021X_FAILURE ),
	__einfo_errortab ( EINFO_ECONNREFUSED_FAILURE ),
	__einfo_errortab ( EINFO_ECONNREFUSED_ASSOC_DENIED ),
	__einfo_errortab ( EINFO_ECONNREFUSED_AUTH_ALGO_UNSUPP ),
};

/* Drag in objects via net80211_ll_protocol */
REQUIRING_SYMBOL ( net80211_ll_protocol );

/* Drag in 802.11 configuration */
REQUIRE_OBJECT ( config_net80211 );
