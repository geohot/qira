#ifndef _IPXE_NET80211_H
#define _IPXE_NET80211_H

#include <ipxe/process.h>
#include <ipxe/ieee80211.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/rc80211.h>

/** @file
 *
 * The iPXE 802.11 MAC layer.
 */

/*
 * Major things NOT YET supported:
 * - any type of security
 * - 802.11n
 *
 * Major things that probably will NEVER be supported, barring a
 * compelling use case and/or corporate sponsorship:
 * - QoS
 * - 802.1X authentication ("WPA Enterprise")
 * - Contention-free periods
 * - "ad-hoc" networks (IBSS), monitor mode, host AP mode
 * - hidden networks on the 5GHz band due to regulatory issues
 * - spectrum management on the 5GHz band (TPC and DFS), as required
 *   in some non-US regulatory domains
 * - Clause 14 PHYs (Frequency-Hopping Spread Spectrum on 2.4GHz)
 *   and Clause 16 PHYs (infrared) - I'm not aware of any real-world
 *   use of these.
 */

FILE_LICENCE ( GPL2_OR_LATER );

/* All 802.11 devices are handled using a generic "802.11 device"
   net_device, with a link in its `priv' field to a net80211_device
   which we use to handle 802.11-specific details. */


/** @defgroup net80211_band RF bands on which an 802.11 device can transmit */
/** @{ */

/** The 2.4 GHz ISM band, unlicensed in most countries */
#define NET80211_BAND_2GHZ	0
/** The band from 4.9 GHz to 5.7 GHz, which tends to be more restricted */
#define NET80211_BAND_5GHZ	1
/** Number of RF bands */
#define NET80211_NR_BANDS	2

/** Bitmask for the 2GHz band */
#define NET80211_BAND_BIT_2GHZ	(1 << 0)
/** Bitmask for the 5GHz band */
#define NET80211_BAND_BIT_5GHZ	(1 << 1)

/** @} */


/** @defgroup net80211_mode 802.11 operation modes supported by hardware */
/** @{ */

/** 802.11a: 54 Mbps operation using OFDM signaling on the 5GHz band */
#define NET80211_MODE_A		(1 << 0)

/** 802.11b: 1-11 Mbps operation using DSSS/CCK signaling on the 2.4GHz band */
#define NET80211_MODE_B		(1 << 1)

/** 802.11g: 54 Mbps operation using ERP/OFDM signaling on the 2.4GHz band */
#define NET80211_MODE_G		(1 << 2)

/** 802.11n: High-rate operation using MIMO technology on 2.4GHz or 5GHz */
#define NET80211_MODE_N		(1 << 3)

/** @} */


/** @defgroup net80211_cfg Constants for the net80211 config callback */
/** @{ */

/** Channel choice (@c dev->channel) or regulatory parameters have changed */
#define NET80211_CFG_CHANNEL	(1 << 0)

/** Requested transmission rate (@c dev->rate) has changed */
#define NET80211_CFG_RATE	(1 << 1)

/** Association has been established with a new BSS (@c dev->bssid) */
#define NET80211_CFG_ASSOC	(1 << 2)

/** Low-level link parameters (short preamble, protection, etc) have changed */
#define NET80211_CFG_PHY_PARAMS	(1 << 3)

/** @} */


/** An 802.11 security handshaking protocol */
enum net80211_security_proto {
	/** No security handshaking
	 *
	 * This might be used with an open network or with WEP, as
	 * WEP does not have a cryptographic handshaking phase.
	 */
	NET80211_SECPROT_NONE = 0,

	/** Pre-shared key handshaking
	 *
	 * This implements the "WPA Personal" handshake. 802.1X
	 * authentication is not performed -- the user supplies a
	 * pre-shared key directly -- but there is a 4-way handshake
	 * between client and AP to verify that both have the same key
	 * without revealing the contents of that key.
	 */
	NET80211_SECPROT_PSK = 1,

	/** Full EAP 802.1X handshaking
	 *
	 * This implements the "WPA Enterprise" handshake, connecting
	 * to an 802.1X authentication server to provide credentials
	 * and receive a pairwise master key (PMK), which is then used
	 * in the same 4-way handshake as the PSK method.
	 */
	NET80211_SECPROT_EAP = 2,

	/** Dummy value used when the handshaking type can't be detected */
	NET80211_SECPROT_UNKNOWN = 3,
};


/** An 802.11 data encryption algorithm */
enum net80211_crypto_alg {
	/** No security, an "Open" network */
	NET80211_CRYPT_NONE = 0,

	/** Network protected with WEP (awful RC4-based system)
	 *
	 * WEP uses a naive application of RC4, with a monotonically
	 * increasing initialization vector that is prepended to the
	 * key to initialize the RC4 keystream. It is highly insecure
	 * and can be completely cracked or subverted using automated,
	 * robust, freely available tools (aircrack-ng) in minutes.
	 *
	 * 40-bit and 104-bit WEP are differentiated only by the size
	 * of the key. They may be advertised as 64-bit and 128-bit,
	 * counting the non-random IV as part of the key bits.
	 */
	NET80211_CRYPT_WEP = 1,

	/** Network protected with TKIP (better RC4-based system)
	 *
	 * Usually known by its trade name of WPA (Wi-Fi Protected
	 * Access), TKIP implements a message integrity code (MIC)
	 * called Michael, a timestamp counter for replay prevention,
	 * and a key mixing function that together remove almost all
	 * the security problems with WEP. Countermeasures are
	 * implemented to prevent high data-rate attacks.
	 *
	 * There exists one known attack on TKIP, that allows one to
	 * send between 7 and 15 arbitrary short data packets on a
	 * QoS-enabled network given about an hour of data
	 * gathering. Since iPXE does not support QoS for 802.11
	 * networks, this is not a threat to us. The only other method
	 * is a brute-force passphrase attack.
	 */
	NET80211_CRYPT_TKIP = 2,

	/** Network protected with CCMP (AES-based system)
	 *
	 * Often called WPA2 in commerce, or RSNA (Robust Security
	 * Network Architecture) in the 802.11 standard, CCMP is
	 * highly secure and does not have any known attack vectors.
	 * Since it is based on a block cipher, the statistical
	 * correlation and "chopchop" attacks used with great success
	 * against WEP and minor success against TKIP fail.
	 */
	NET80211_CRYPT_CCMP = 3,

	/** Dummy value used when the cryptosystem can't be detected */
	NET80211_CRYPT_UNKNOWN = 4,
};


/** @defgroup net80211_state Bits for the 802.11 association state field */
/** @{ */

/** An error code indicating the failure mode, or 0 if successful */
#define NET80211_STATUS_MASK    0x7F

/** Whether the error code provided is a "reason" code, not a "status" code */
#define NET80211_IS_REASON	0x80

/** Whether we have found the network we will be associating with */
#define NET80211_PROBED		(1 << 8)

/** Whether we have successfully authenticated with the network
 *
 * This usually has nothing to do with actual security; it is a
 * holdover from older 802.11 implementation ideas.
 */
#define NET80211_AUTHENTICATED  (1 << 9)

/** Whether we have successfully associated with the network */
#define NET80211_ASSOCIATED     (1 << 10)

/** Whether we have completed security handshaking with the network
 *
 * Once this is set, we can send data packets. For that reason this
 * bit is set even in cases where no security handshaking is
 * required.
 */
#define NET80211_CRYPTO_SYNCED  (1 << 11)

/** Whether the auto-association task is running */
#define NET80211_WORKING        (1 << 12)

/** Whether the auto-association task is waiting for a reply from the AP */
#define NET80211_WAITING        (1 << 13)

/** Whether the auto-association task should be suppressed
 *
 * This is set by the `iwlist' command so that it can open the device
 * without starting another probe process that will interfere with its
 * own.
 */
#define NET80211_NO_ASSOC	(1 << 14)

/** Whether this association was performed using a broadcast SSID
 *
 * If the user opened this device without netX/ssid set, the device's
 * SSID will be set to that of the network it chooses to associate
 * with, but the netX/ssid setting will remain blank. If we don't
 * remember that we started from no specified SSID, it will appear
 * every time settings are updated (e.g. after DHCP) that we need to
 * reassociate due to the difference between the set SSID and our own.
 */
#define NET80211_AUTO_SSID	(1 << 15)


/** @} */


/** @defgroup net80211_phy 802.11 physical layer flags */
/** @{ */

/** Whether to use RTS/CTS or CTS-to-self protection for transmissions
 *
 * Since the RTS or CTS is transmitted using 802.11b signaling, and
 * includes a field indicating the amount of time that will be used by
 * transmission of the following packet, this serves as an effective
 * protection mechanism to avoid 802.11b clients interfering with
 * 802.11g clients on mixed networks.
 */
#define NET80211_PHY_USE_PROTECTION      (1 << 1)

/** Whether to use 802.11b short preamble operation
 *
 * Short-preamble operation can moderately increase throughput on
 * 802.11b networks operating between 2Mbps and 11Mbps. It is
 * irrelevant for 802.11g data rates, since they use a different
 * modulation scheme.
 */
#define NET80211_PHY_USE_SHORT_PREAMBLE  (1 << 2)

/** Whether to use 802.11g short slot operation
 *
 * This affects a low-level timing parameter of 802.11g transmissions.
 */
#define NET80211_PHY_USE_SHORT_SLOT      (1 << 3)

/** @} */


/** The maximum number of TX rates we allow to be configured simultaneously */
#define NET80211_MAX_RATES	16

/** The maximum number of channels we allow to be configured simultaneously */
#define NET80211_MAX_CHANNELS	40

/** Seconds we'll wait to get all fragments of a packet */
#define NET80211_FRAG_TIMEOUT	2

/** The number of fragments we can receive at once
 *
 * The 802.11 standard requires that this be at least 3.
 */
#define NET80211_NR_CONCURRENT_FRAGS 3

/** Maximum TX power to allow (dBm), if we don't get a regulatory hint */
#define NET80211_REG_TXPOWER	20


struct net80211_device;

/** Operations that must be implemented by an 802.11 driver */
struct net80211_device_operations {
	/** Open 802.11 device
	 *
	 * @v dev	802.11 device
	 * @ret rc	Return status code
	 *
	 * This method should allocate RX I/O buffers and enable the
	 * hardware to start transmitting and receiving packets on the
	 * channels its net80211_register() call indicated it could
	 * handle. It does not need to tune the antenna to receive
	 * packets on any particular channel.
	 */
	int ( * open ) ( struct net80211_device *dev );

	/** Close 802.11 network device
	 *
	 * @v dev	802.11 device
	 *
	 * This method should stop the flow of packets, and call
	 * net80211_tx_complete() for any packets remaining in the
	 * device's TX queue.
	 */
	void ( * close ) ( struct net80211_device *dev );

	/** Transmit packet on 802.11 network device
	 *
	 * @v dev	802.11 device
	 * @v iobuf	I/O buffer
	 * @ret rc	Return status code
	 *
	 * This method should cause the hardware to initiate
	 * transmission of the I/O buffer, using the channel and rate
	 * most recently indicated by an appropriate call to the
	 * @c config callback. The 802.11 layer guarantees that said
	 * channel and rate will be the same as those currently
	 * reflected in the fields of @a dev.
	 *
	 * If this method returns success, the I/O buffer remains
	 * owned by the network layer's TX queue, and the driver must
	 * eventually call net80211_tx_complete() to free the buffer
	 * whether transmission succeeded or not. If this method
	 * returns failure, it will be interpreted as "failure to
	 * enqueue buffer" and the I/O buffer will be immediately
	 * released.
	 *
	 * This method is guaranteed to be called only when the device
	 * is open.
	 */
	int ( * transmit ) ( struct net80211_device *dev,
			     struct io_buffer *iobuf );

	/** Poll for completed and received packets
	 *
	 * @v dev	802.11 device
	 *
	 * This method should cause the hardware to check for
	 * completed transmissions and received packets. Any received
	 * packets should be delivered via net80211_rx(), and
	 * completed transmissions should be indicated using
	 * net80211_tx_complete().
	 *
	 * This method is guaranteed to be called only when the device
	 * is open.
	 */
	void ( * poll ) ( struct net80211_device *dev );

	/** Enable or disable interrupts
	 *
	 * @v dev	802.11 device
	 * @v enable	If TRUE, interrupts should be enabled
	 */
	void ( * irq ) ( struct net80211_device *dev, int enable );

	/** Update hardware state to match 802.11 layer state
	 *
	 * @v dev	802.11 device
	 * @v changed	Set of flags indicating what may have changed
	 * @ret rc	Return status code
	 *
	 * This method should cause the hardware state to be
	 * reinitialized from the state indicated in fields of
	 * net80211_device, in the areas indicated by bits set in
	 * @a changed. If the hardware is unable to do so, this method
	 * may return an appropriate error indication.
	 *
	 * This method is guaranteed to be called only when the device
	 * is open.
	 */
	int ( * config ) ( struct net80211_device *dev, int changed );
};

/** An 802.11 RF channel. */
struct net80211_channel
{
	/** The band with which this channel is associated */
	u8 band;

	/** A channel number interpreted according to the band
	 *
	 * The 2.4GHz band uses channel numbers from 1-13 at 5MHz
	 * intervals such that channel 1 is 2407 MHz; channel 14,
	 * legal for use only in Japan, is defined separately as 2484
	 * MHz. Adjacent channels will overlap, since 802.11
	 * transmissions use a 20 MHz (4-channel) bandwidth. Most
	 * commonly, channels 1, 6, and 11 are used.
	 *
	 * The 5GHz band uses channel numbers derived directly from
	 * the frequency; channel 0 is 5000 MHz, and channels are
	 * always spaced 5 MHz apart. Channel numbers over 180 are
	 * relative to 4GHz instead of 5GHz, but these are rarely
	 * seen. Most channels are not legal for use.
	 */
	u8 channel_nr;

	/** The center frequency for this channel
	 *
	 * Currently a bandwidth of 20 MHz is assumed.
	 */
	u16 center_freq;

	/** Hardware channel value */
	u16 hw_value;

	/** Maximum allowable transmit power, in dBm
	 *
	 * This should be interpreted as EIRP, the power supplied to
	 * an ideal isotropic antenna in order to achieve the same
	 * average signal intensity as the real hardware at a
	 * particular distance.
	 *
	 * Currently no provision is made for directional antennas.
	 */
	u8 maxpower;
};

/** Information on the capabilities of an 802.11 hardware device
 *
 * In its probe callback, an 802.11 driver must read hardware
 * registers to determine the appropriate contents of this structure,
 * fill it, and pass it to net80211_register() so that the 802.11
 * layer knows how to treat the hardware and what to advertise as
 * supported to access points.
 */
struct net80211_hw_info
{
	/** Default hardware MAC address.
	 *
	 * The user may change this by setting the @c netX/mac setting
	 * before the driver's open function is called; in that case
	 * the driver must set the hardware MAC address to the address
	 * contained in the wrapping net_device's ll_addr field, or if
	 * that is impossible, set that ll_addr field back to the
	 * unchangeable hardware MAC address.
	 */
	u8 hwaddr[ETH_ALEN];

	/** A bitwise OR of the 802.11x modes supported by this device */
	int modes;

	/** A bitwise OR of the bands on which this device can communicate */
	int bands;

	/** A set of flags indicating peculiarities of this device. */
	enum {
		/** Received frames include a frame check sequence. */
		NET80211_HW_RX_HAS_FCS = (1 << 1),

		/** Hardware doesn't support 2.4GHz short preambles
		 *
		 * This is only relevant for 802.11b operation above
		 * 2Mbps. All 802.11g devices support short preambles.
		 */
		NET80211_HW_NO_SHORT_PREAMBLE = (1 << 2),

		/** Hardware doesn't support 802.11g short slot operation */
		NET80211_HW_NO_SHORT_SLOT = (1 << 3),
	} flags;

	/** Signal strength information that can be provided by the device
	 *
	 * Signal strength is passed to net80211_rx(), primarily to
	 * allow determination of the closest access point for a
	 * multi-AP network. The units are provided for completeness
	 * of status displays.
	 */
	enum {
		/** No signal strength information supported */
		NET80211_SIGNAL_NONE = 0,
		/** Signal strength in arbitrary units */
		NET80211_SIGNAL_ARBITRARY,
		/** Signal strength in decibels relative to arbitrary base */
		NET80211_SIGNAL_DB,
		/** Signal strength in decibels relative to 1mW */
		NET80211_SIGNAL_DBM,
	} signal_type;

	/** Maximum signal in arbitrary cases
	 *
	 * If signal_type is NET80211_SIGNAL_ARBITRARY or
	 * NET80211_SIGNAL_DB, the driver should report it on a scale
	 * from 0 to signal_max.
	 */
	unsigned signal_max;

	/** List of RF channels supported by the card */
	struct net80211_channel channels[NET80211_MAX_CHANNELS];

	/** Number of supported channels */
	int nr_channels;

	/** List of transmission rates supported by the card, indexed by band
	 *
	 * Rates should be in 100kbps increments (e.g. 11 Mbps would
	 * be represented as the number 110).
	 */
	u16 rates[NET80211_NR_BANDS][NET80211_MAX_RATES];

	/** Number of supported rates, indexed by band */
	int nr_rates[NET80211_NR_BANDS];

	/** Estimate of the time required to change channels, in microseconds
	 *
	 * If this is not known, a guess on the order of a few
	 * milliseconds (value of 1000-5000) is reasonable.
	 */
	unsigned channel_change_time;
};

/** Structure tracking received fragments for a packet
 *
 * We set up a fragment cache entry when we receive a packet marked as
 * fragment 0 with the "more fragments" bit set in its frame control
 * header. We are required by the 802.11 standard to track 3
 * fragmented packets arriving simultaneously; if we receive more we
 * may drop some. Upon receipt of a new fragment-0 packet, if no entry
 * is available or expired, we take over the most @e recent entry for
 * the new packet, since we don't want to starve old entries from ever
 * finishing at all. If we get a fragment after the zeroth with no
 * cache entry for its packet, we drop it.
 */
struct net80211_frag_cache
{
	/** Whether this cache entry is in use */
	u8 in_use;

	/** Sequence number of this MSDU (packet) */
	u16 seqnr;

	/** Timestamp from point at which first fragment was collected */
	u32 start_ticks;

	/** Buffers for each fragment */
	struct io_buffer *iob[16];
};


/** Interface to an 802.11 security handshaking protocol
 *
 * Security handshaking protocols handle parsing a user-specified key
 * into a suitable input to the encryption algorithm, and for WPA and
 * better systems, manage performing whatever authentication with the
 * network is necessary.
 *
 * At all times when any method in this structure is called with a
 * net80211_device argument @a dev, a dynamically allocated copy of
 * the handshaker structure itself with space for the requested amount
 * of private data may be accessed as @c dev->handshaker. The
 * structure will not be modified, and will only be freed during
 * reassociation and device closing after the @a stop method has been
 * called.
 */
struct net80211_handshaker
{
	/** The security handshaking protocol implemented */
	enum net80211_security_proto protocol;

	/** Initialize security handshaking protocol
	 *
	 * @v dev	802.11 device
	 * @ret rc	Return status code
	 *
	 * This method is expected to access @c netX/key or other
	 * applicable settings to determine the parameters for
	 * handshaking. If no handshaking is required, it should call
	 * sec80211_install() with the cryptosystem and key that are
	 * to be used, and @c start and @c step should be set to @c
	 * NULL.
	 *
	 * This is always called just before association is performed,
	 * but after its parameters have been set; in particular, you
	 * may rely on the contents of the @a essid field in @a dev.
	 */
	int ( * init ) ( struct net80211_device *dev );

	/** Start handshaking
	 *
	 * @v dev	802.11 device
	 * @ret rc	Return status code
	 *
	 * This method is expected to set up internal state so that
	 * packets sent immediately after association, before @a step
	 * can be called, will be handled appropriately.
	 *
	 * This is always called just before association is attempted.
	 */
	int ( * start ) ( struct net80211_device *dev );

	/** Process handshaking state
	 *
	 * @v dev	802.11 device
	 * @ret rc	Return status code, or positive if done
	 *
	 * This method is expected to perform as much progress on the
	 * protocol it implements as is possible without blocking. It
	 * should return 0 if it wishes to be called again, a negative
	 * return status code on error, or a positive value if
	 * handshaking is complete. In the case of a positive return,
	 * net80211_crypto_install() must have been called.
	 *
	 * If handshaking may require further action (e.g. an AP that
	 * might decide to rekey), handlers must be installed by this
	 * function that will act without further calls to @a step.
	 */
	int ( * step ) ( struct net80211_device *dev );

	/** Change cryptographic key based on setting
	 *
	 * @v dev	802.11 device
	 * @ret rc	Return status code
	 *
	 * This method is called whenever the @c netX/key setting
	 * @e may have been changed. It is expected to determine
	 * whether it did in fact change, and if so, to install the
	 * new key using net80211_crypto_install(). If it is not
	 * possible to do this immediately, this method should return
	 * an error; in that case the 802.11 stack will reassociate,
	 * following the usual init/start/step sequence.
	 *
	 * This method is only relevant when it is possible to
	 * associate successfully with an incorrect key. When it is
	 * not, a failed association will be retried until the user
	 * changes the key setting, and a successful association will
	 * not be dropped due to such a change. When association with
	 * an incorrect key is impossible, this function should return
	 * 0 after performing no action.
	 */
	int ( * change_key ) ( struct net80211_device *dev );

	/** Stop security handshaking handlers
	 *
	 * @v dev	802.11 device
	 *
	 * This method is called just before freeing a security
	 * handshaker; it could, for example, delete a process that @a
	 * start had created to manage the security of the connection.
	 * If not needed it may be set to NULL.
	 */
	void ( * stop ) ( struct net80211_device *dev );

	/** Amount of private data requested
	 *
	 * Before @c init is called for the first time, this structure's
	 * @c priv pointer will point to this many bytes of allocated
	 * data, where the allocation will be performed separately for
	 * each net80211_device.
	 */
	int priv_len;

	/** Whether @a start has been called
	 *
	 * Reset to 0 after @a stop is called.
	 */
	int started;

	/** Pointer to private data
	 *
	 * In initializing this structure statically for a linker
	 * table, set this to NULL.
	 */
	void *priv;
};

#define NET80211_HANDSHAKERS __table ( struct net80211_handshaker, \
				       "net80211_handshakers" )
#define __net80211_handshaker __table_entry ( NET80211_HANDSHAKERS, 01 )


/** Interface to an 802.11 cryptosystem
 *
 * Cryptosystems define a net80211_crypto structure statically, using
 * a iPXE linker table to make it available to the 802.11 layer. When
 * the cryptosystem needs to be used, the 802.11 code will allocate a
 * copy of the static definition plus whatever space the algorithm has
 * requested for private state, and point net80211_device::crypto or
 * net80211_device::gcrypto at it.
 */
struct net80211_crypto
{
	/** The cryptographic algorithm implemented */
	enum net80211_crypto_alg algorithm;

	/** Initialize cryptosystem using a given key
	 *
	 * @v crypto	802.11 cryptosystem
	 * @v key	Pointer to key bytes
	 * @v keylen	Number of key bytes
	 * @v rsc	Initial receive sequence counter, if applicable
	 * @ret rc	Return status code
	 *
	 * This method is passed the communication key provided by the
	 * security handshake handler, which will already be in the
	 * low-level form required. It may not store a pointer to the
	 * key after returning; it must copy it to its private storage.
	 */
	int ( * init ) ( struct net80211_crypto *crypto, const void *key,
			 int keylen, const void *rsc );

	/** Encrypt a frame using the cryptosystem
	 *
	 * @v crypto	802.11 cryptosystem
	 * @v iob	I/O buffer
	 * @ret eiob	Newly allocated I/O buffer with encrypted packet
	 *
	 * This method is called to encrypt a single frame. It is
	 * guaranteed that initialize() will have completed
	 * successfully before this method is called.
	 *
	 * The frame passed already has an 802.11 header prepended,
	 * but the PROTECTED bit in the frame control field will not
	 * be set; this method is responsible for setting it. The
	 * returned I/O buffer should contain a complete copy of @a
	 * iob, including the 802.11 header, but with the PROTECTED
	 * bit set, the data encrypted, and whatever encryption
	 * headers/trailers are necessary added.
	 *
	 * This method should never free the passed I/O buffer.
	 *
	 * Return NULL if the packet could not be encrypted, due to
	 * memory limitations or otherwise.
	 */
	struct io_buffer * ( * encrypt ) ( struct net80211_crypto *crypto,
					   struct io_buffer *iob );

	/** Decrypt a frame using the cryptosystem
	 *
	 * @v crypto	802.11 cryptosystem
	 * @v eiob	Encrypted I/O buffer
	 * @ret iob	Newly allocated I/O buffer with decrypted packet
	 *
	 * This method is called to decrypt a single frame. It is
	 * guaranteed that initialize() will have completed
	 * successfully before this method is called.
	 *
	 * Decryption follows the reverse of the pattern used for
	 * encryption: this method must copy the 802.11 header into
	 * the returned packet, decrypt the data stream, remove any
	 * encryption header or trailer, and clear the PROTECTED bit
	 * in the frame control header.
	 *
	 * This method should never free the passed I/O buffer.
	 *
	 * Return NULL if memory was not available for decryption, if
	 * a consistency or integrity check on the decrypted frame
	 * failed, or if the decrypted frame should not be processed
	 * by the network stack for any other reason.
	 */
	struct io_buffer * ( * decrypt ) ( struct net80211_crypto *crypto,
					   struct io_buffer *iob );

	/** Length of private data requested to be allocated */
	int priv_len;

	/** Private data for the algorithm to store key and state info */
	void *priv;
};

#define NET80211_CRYPTOS __table ( struct net80211_crypto, "net80211_cryptos" )
#define __net80211_crypto __table_entry ( NET80211_CRYPTOS, 01 )


struct net80211_probe_ctx;
struct net80211_assoc_ctx;


/** Structure encapsulating the complete state of an 802.11 device
 *
 * An 802.11 device is always wrapped by a network device, and this
 * network device is always pointed to by the @a netdev field. In
 * general, operations should never be performed by 802.11 code using
 * netdev functions directly. It is usually the case that the 802.11
 * layer might need to do some processing or bookkeeping on top of
 * what the netdevice code will do.
 */
struct net80211_device
{
	/** The net_device that wraps us. */
	struct net_device *netdev;

	/** List of 802.11 devices. */
	struct list_head list;

	/** 802.11 device operations */
	struct net80211_device_operations *op;

	/** Driver private data */
	void *priv;

	/** Information about the hardware, provided to net80211_register() */
	struct net80211_hw_info *hw;

	/* ---------- Channel and rate fields ---------- */

	/** A list of all possible channels we might use */
	struct net80211_channel channels[NET80211_MAX_CHANNELS];

	/** The number of channels in the channels array */
	u8 nr_channels;

	/** The channel currently in use, as an index into the channels array */
	u8 channel;

	/** A list of all possible TX rates we might use
	 *
	 * Rates are in units of 100 kbps.
	 */
	u16 rates[NET80211_MAX_RATES];

	/** The number of transmission rates in the rates array */
	u8 nr_rates;

	/** The rate currently in use, as an index into the rates array */
	u8 rate;

	/** The rate to use for RTS/CTS transmissions
	 *
	 * This is always the fastest basic rate that is not faster
	 * than the data rate in use. Also an index into the rates array.
	 */
	u8 rtscts_rate;

	/** Bitmask of basic rates
	 *
	 * If bit N is set in this value, with the LSB considered to
	 * be bit 0, then rate N in the rates array is a "basic" rate.
	 *
	 * We don't decide which rates are "basic"; our AP does, and
	 * we respect its wishes. We need to be able to identify basic
	 * rates in order to calculate the duration of a CTS packet
	 * used for 802.11 g/b interoperability.
	 */
	u32 basic_rates;

	/* ---------- Association fields ---------- */

	/** The asynchronous association process.
	 *
	 * When an 802.11 netdev is opened, or when the user changes
	 * the SSID setting on an open 802.11 device, an
	 * autoassociation task is started by net80211_autoassocate()
	 * to associate with the new best network. The association is
	 * asynchronous, but no packets can be transmitted until it is
	 * complete. If it is successful, the wrapping net_device is
	 * set as "link up". If it fails, @c assoc_rc will be set with
	 * an error indication.
	 */
	struct process proc_assoc;

	/** Network with which we are associating
	 *
	 * This will be NULL when we are not actively in the process
	 * of associating with a network we have already successfully
	 * probed for.
	 */
	struct net80211_wlan *associating;

	/** Context for the association process
	 *
	 * This is a probe_ctx if the @c PROBED flag is not set in @c
	 * state, and an assoc_ctx otherwise.
	 */
	union {
		struct net80211_probe_ctx *probe;
		struct net80211_assoc_ctx *assoc;
	} ctx;

	/** Security handshaker being used */
	struct net80211_handshaker *handshaker;

	/** State of our association to the network
	 *
	 * Since the association process happens asynchronously, it's
	 * necessary to have some channel of communication so the
	 * driver can say "I got an association reply and we're OK" or
	 * similar. This variable provides that link. It is a bitmask
	 * of any of NET80211_PROBED, NET80211_AUTHENTICATED,
	 * NET80211_ASSOCIATED, NET80211_CRYPTO_SYNCED to indicate how
	 * far along in associating we are; NET80211_WORKING if the
	 * association task is running; and NET80211_WAITING if a
	 * packet has been sent that we're waiting for a reply to. We
	 * can only be crypto-synced if we're associated, we can
	 * only be associated if we're authenticated, we can only be
	 * authenticated if we've probed.
	 *
	 * If an association process fails (that is, we receive a
	 * packet with an error indication), the error code is copied
	 * into bits 6-0 of this variable and bit 7 is set to specify
	 * what type of error code it is. An AP can provide either a
	 * "status code" (0-51 are defined) explaining why it refused
	 * an association immediately, or a "reason code" (0-45 are
	 * defined) explaining why it canceled an association after it
	 * had originally OK'ed it. Status and reason codes serve
	 * similar functions, but they use separate error message
	 * tables. A iPXE-formatted return status code (negative) is
	 * placed in @c assoc_rc.
	 *
	 * If the failure to associate is indicated by a status code,
	 * the NET80211_IS_REASON bit will be clear; if it is
	 * indicated by a reason code, the bit will be set. If we were
	 * successful, both zero status and zero reason mean success,
	 * so there is no ambiguity.
	 *
	 * To prevent association when opening the device, user code
	 * can set the NET80211_NO_ASSOC bit. The final bit in this
	 * variable, NET80211_AUTO_SSID, is used to remember whether
	 * we picked our SSID through automated probing as opposed to
	 * user specification; the distinction becomes relevant in the
	 * settings applicator.
	 */
	u16 state;

	/** Return status code associated with @c state */
	int assoc_rc;

	/** RSN or WPA information element to include with association
	 *
	 * If set to @c NULL, none will be included. It is expected
	 * that this will be set by the @a init function of a security
	 * handshaker if it is needed.
	 */
	union ieee80211_ie *rsn_ie;

	/* ---------- Parameters of currently associated network ---------- */

	/** 802.11 cryptosystem for our current network
	 *
	 * For an open network, this will be set to NULL.
	 */
	struct net80211_crypto *crypto;

	/** 802.11 cryptosystem for multicast and broadcast frames
	 *
	 * If this is NULL, the cryptosystem used for receiving
	 * unicast frames will also be used for receiving multicast
	 * and broadcast frames. Transmitted multicast and broadcast
	 * frames are always sent unicast to the AP, who multicasts
	 * them on our behalf; thus they always use the unicast
	 * cryptosystem.
	 */
	struct net80211_crypto *gcrypto;

	/** MAC address of the access point most recently associated */
	u8 bssid[ETH_ALEN];

	/** SSID of the access point we are or will be associated with
	 *
	 * Although the SSID field in 802.11 packets is generally not
	 * NUL-terminated, here and in net80211_wlan we add a NUL for
	 * convenience.
	 */
	char essid[IEEE80211_MAX_SSID_LEN+1];

	/** Association ID given to us by the AP */
	u16 aid;

	/** TSFT value for last beacon received, microseconds */
	u64 last_beacon_timestamp;

	/** Time between AP sending beacons, microseconds */
	u32 tx_beacon_interval;

	/** Smoothed average time between beacons, microseconds */
	u32 rx_beacon_interval;

	/* ---------- Physical layer information ---------- */

	/** Physical layer options
	 *
	 * These control the use of CTS protection, short preambles,
	 * and short-slot operation.
	 */
	int phy_flags;

	/** Signal strength of last received packet */
	int last_signal;

	/** Rate control state */
	struct rc80211_ctx *rctl;

	/* ---------- Packet handling state ---------- */

	/** Fragment reassembly state */
	struct net80211_frag_cache frags[NET80211_NR_CONCURRENT_FRAGS];

	/** The sequence number of the last packet we sent */
	u16 last_tx_seqnr;

	/** Packet duplication elimination state
	 *
	 * We are only required to handle immediate duplicates for
	 * each direct sender, and since we can only have one direct
	 * sender (the AP), we need only keep the sequence control
	 * field from the most recent packet we've received. Thus,
	 * this field stores the last sequence control field we've
	 * received for a packet from the AP.
	 */
	u16 last_rx_seq;

	/** RX management packet queue
	 *
	 * Sometimes we want to keep probe, beacon, and action packets
	 * that we receive, such as when we're scanning for networks.
	 * Ordinarily we drop them because they are sent at a large
	 * volume (ten beacons per second per AP, broadcast) and we
	 * have no need of them except when we're scanning.
	 *
	 * When keep_mgmt is TRUE, received probe, beacon, and action
	 * management packets will be stored in this queue.
	 */
	struct list_head mgmt_queue;

	/** RX management packet info queue
	 *
	 * We need to keep track of the signal strength for management
	 * packets we're keeping, because that provides the only way
	 * to distinguish between multiple APs for the same network.
	 * Since we can't extend io_buffer to store signal, this field
	 * heads a linked list of "RX packet info" structures that
	 * contain that signal strength field. Its entries always
	 * parallel the entries in mgmt_queue, because the two queues
	 * are always added to or removed from in parallel.
	 */
	struct list_head mgmt_info_queue;

	/** Whether to store management packets
	 *
	 * Received beacon, probe, and action packets will be added to
	 * mgmt_queue (and their signal strengths added to
	 * mgmt_info_queue) only when this variable is TRUE. It should
	 * be set by net80211_keep_mgmt() (which returns the old
	 * value) only when calling code is prepared to poll the
	 * management queue frequently, because packets will otherwise
	 * pile up and exhaust memory.
	 */
	int keep_mgmt;
};

/** Structure representing a probed network.
 *
 * This is returned from the net80211_probe_finish functions and
 * passed to the low-level association functions. At least essid,
 * bssid, channel, beacon, and security must be filled in if you want
 * to build this structure manually.
 */
struct net80211_wlan
{
	/** The human-readable ESSID (network name)
	 *
	 * Although the 802.11 SSID field is generally not
	 * NUL-terminated, the iPXE code adds an extra NUL (and
	 * expects one in this structure) for convenience.
	 */
	char essid[IEEE80211_MAX_SSID_LEN+1];

	/** MAC address of the strongest-signal access point for this ESSID */
	u8 bssid[ETH_ALEN];

	/** Signal strength of beacon frame from that access point */
	int signal;

	/** The channel on which that access point communicates
	 *
	 * This is a raw channel number (net80211_channel::channel_nr),
	 * so that it will not be affected by reconfiguration of the
	 * device channels array.
	 */
	int channel;

	/** The complete beacon or probe-response frame received */
	struct io_buffer *beacon;

	/** Security handshaking method used on the network */
	enum net80211_security_proto handshaking;

	/** Cryptographic algorithm used on the network */
	enum net80211_crypto_alg crypto;

	/** Link to allow chaining multiple structures into a list to
	    be returned from net80211_probe_finish_all(). */
	struct list_head list;
};


/** 802.11 encryption key setting */
extern const struct setting
net80211_key_setting __setting ( SETTING_NETDEV_EXTRA, key );


/**
 * @defgroup net80211_probe 802.11 network location API
 * @{
 */
int net80211_prepare_probe ( struct net80211_device *dev, int band,
			     int active );
struct net80211_probe_ctx * net80211_probe_start ( struct net80211_device *dev,
						   const char *essid,
						   int active );
int net80211_probe_step ( struct net80211_probe_ctx *ctx );
struct net80211_wlan *
net80211_probe_finish_best ( struct net80211_probe_ctx *ctx );
struct list_head *net80211_probe_finish_all ( struct net80211_probe_ctx *ctx );

void net80211_free_wlan ( struct net80211_wlan *wlan );
void net80211_free_wlanlist ( struct list_head *list );
/** @} */


/**
 * @defgroup net80211_mgmt 802.11 network management API
 * @{
 */
struct net80211_device * net80211_get ( struct net_device *netdev );
void net80211_autoassociate ( struct net80211_device *dev );

int net80211_change_channel ( struct net80211_device *dev, int channel );
void net80211_set_rate_idx ( struct net80211_device *dev, int rate );

int net80211_keep_mgmt ( struct net80211_device *dev, int enable );
struct io_buffer * net80211_mgmt_dequeue ( struct net80211_device *dev,
					   int *signal );
int net80211_tx_mgmt ( struct net80211_device *dev, u16 fc,
		       u8 bssid[ETH_ALEN], struct io_buffer *iob );
/** @} */


/**
 * @defgroup net80211_assoc 802.11 network association API
 * @{
 */
int net80211_prepare_assoc ( struct net80211_device *dev,
			     struct net80211_wlan *wlan );
int net80211_send_auth ( struct net80211_device *dev,
			 struct net80211_wlan *wlan, int method );
int net80211_send_assoc ( struct net80211_device *dev,
			  struct net80211_wlan *wlan );
void net80211_deauthenticate ( struct net80211_device *dev, int rc );
/** @} */


/**
 * @defgroup net80211_driver 802.11 driver interface API
 * @{
 */
struct net80211_device *net80211_alloc ( size_t priv_size );
int net80211_register ( struct net80211_device *dev,
			struct net80211_device_operations *ops,
			struct net80211_hw_info *hw );
u16 net80211_duration ( struct net80211_device *dev, int bytes, u16 rate );
void net80211_rx ( struct net80211_device *dev, struct io_buffer *iob,
		   int signal, u16 rate );
void net80211_rx_err ( struct net80211_device *dev,
		       struct io_buffer *iob, int rc );
void net80211_tx_complete ( struct net80211_device *dev,
			    struct io_buffer *iob, int retries, int rc );
void net80211_unregister ( struct net80211_device *dev );
void net80211_free ( struct net80211_device *dev );
/** @} */

/**
 * Calculate duration field for a CTS control frame
 *
 * @v dev	802.11 device
 * @v size	Size of the packet being cleared to send
 *
 * A CTS control frame's duration field captures the frame being
 * protected and its 10-byte ACK.
 */
static inline u16 net80211_cts_duration ( struct net80211_device *dev,
					  int size )
{
	return ( net80211_duration ( dev, 10,
				     dev->rates[dev->rtscts_rate] ) +
		 net80211_duration ( dev, size, dev->rates[dev->rate] ) );
}

#endif
