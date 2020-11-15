#ifndef _IPXE_IEEE80211_H
#define _IPXE_IEEE80211_H

#include <stddef.h>
#include <ipxe/if_ether.h>	/* for ETH_ALEN */
#include <endian.h>

/** @file
 * Constants and data structures defined in IEEE 802.11, subsetted
 * according to what iPXE knows how to use.
 */

FILE_LICENCE(GPL2_OR_LATER);

/* ---------- Maximum lengths of things ---------- */

/**
 * @defgroup ieee80211_maxlen Maximum lengths in the 802.11 protocol
 * @{
 */

/** Maximum length of frame payload
 *
 * This does not include cryptographic overhead, which can be up to 20
 * bytes, but it DOES include the 802.2 LLC/SNAP headers that are used
 * on data frames (but not management frames).
 */
#define IEEE80211_MAX_DATA_LEN          2304

/** Length of LLC/SNAP headers on data frames */
#define IEEE80211_LLC_HEADER_LEN	8

/** Maximum cryptographic overhead before encrypted data */
#define IEEE80211_MAX_CRYPTO_HEADER	8

/** Maximum cryptographic overhead after encrypted data
 *
 * This does not count the MIC in TKIP frames, since that is
 * considered to be part of the MSDU and thus contributes to the size
 * of the data field.
 *
 * It @e does count the MIC in CCMP frames, which is considered part
 * of the MPDU (outside the data field).
 */
#define IEEE80211_MAX_CRYPTO_TRAILER    8

/** Total maximum cryptographic overhead */
#define IEEE80211_MAX_CRYPTO_OVERHEAD	16

/** Bytes of network-layer data that can go into a regular data frame */
#define IEEE80211_MAX_FRAME_DATA	2296

/** Frame header length for frames we might work with
 *
 * QoS adds a two-byte field on top of this, and APs communicating
 * with each other in Wireless Distribution System (WDS) mode add an
 * extra 6-byte MAC address field, but we do not work with such
 * frames.
 */
#define IEEE80211_TYP_FRAME_HEADER_LEN	24

/** Theoretical maximum frame header length
 *
 * This includes the QoS and WDS Addr4 fields that we should never
 * see.
 */
#define IEEE80211_MAX_FRAME_HEADER_LEN	32

/** Maximum combined frame length
 *
 * The biggest frame will include 32 frame header bytes, 16 bytes of
 * crypto overhead, and 2304 data bytes.
 */
#define IEEE80211_MAX_FRAME_LEN         2352

/** Maximum length of an ESSID */
#define IEEE80211_MAX_SSID_LEN          32

/** @} */


/* ---------- Frame Control defines ---------- */

/**
 * @defgroup ieee80211_fc 802.11 Frame Control field bits
 * @{
 */

/** 802.11 Frame Control field, Version bitmask */
#define IEEE80211_FC_VERSION	0x0003

/** Expected value of Version bits in Frame Control */
#define  IEEE80211_THIS_VERSION  0x0000


/** 802.11 Frame Control field, Frame Type bitmask */
#define IEEE80211_FC_TYPE	0x000C

/** Type value for management (layer-2) frames */
#define  IEEE80211_TYPE_MGMT     0x0000

/** Type value for control (layer-1, hardware-managed) frames */
#define  IEEE80211_TYPE_CTRL     0x0004

/** Type value for data frames */
#define  IEEE80211_TYPE_DATA     0x0008


/** 802.11 Frame Control field, Frame Subtype bitmask */
#define IEEE80211_FC_SUBTYPE	0x00F0

/** Subtype value for association-request management frames
 *
 * Association request frames are sent after authentication from the
 * client to the Access Point to establish the client as part of the
 * Access Point's network.
 */
#define  IEEE80211_STYPE_ASSOC_REQ    0x0000

/** Subtype value for association-response management frames
 *
 * Association response frames are sent by the Access Point to confirm
 * or deny the association requested in an association request frame.
 */
#define  IEEE80211_STYPE_ASSOC_RESP   0x0010

/** Subtype value for reassociation-request management frames
 *
 * Reassociation request frames are sent by clients wishing to change
 * from one Access Point to another while roaming within the same
 * extended network (same ESSID).
 */
#define  IEEE80211_STYPE_REASSOC_REQ  0x0020

/** Subtype value for reassociation-response management frames
 *
 * Reassociation response frames are sent by the Access Point to
 * confirm or deny the swap requested in a reassociation request
 * frame.
 */
#define  IEEE80211_STYPE_REASSOC_RESP 0x0030

/** Subtype value for probe-request management frames
 *
 * Probe request frames are sent by clients to request that all Access
 * Points on the sending channel, or all belonging to a particular
 * ESSID, identify themselves by BSSID, supported transfer rates, RF
 * configuration, and other capabilities.
 */
#define  IEEE80211_STYPE_PROBE_REQ    0x0040

/** Subtype value for probe-response management frames
 *
 * Probe response frames are sent by Access Points in response to
 * probe request frames, providing the requested information.
 */
#define  IEEE80211_STYPE_PROBE_RESP   0x0050

/** Subtype value for beacon management frames
 *
 * Beacon frames are sent by Access Points at regular intervals,
 * usually ten per second, on the channel on which they communicate.
 * They can be used to probe passively for access points on a channel
 * where local regulatory restrictions prohibit active scanning, or
 * due to their regularity as a mechanism to determine the fraction of
 * packets that are being dropped.
 */
#define  IEEE80211_STYPE_BEACON       0x0080

/** Subtype value for disassociation management frames
 *
 * Disassociation frames are sent by either a client or an Access
 * Point to unequivocally terminate the association between the two.
 * They may be sent by clients upon leaving the network, or by an
 * Access Point upon reconfiguration, among other reasons; they are
 * usually more "polite" than deauthentication frames.
 */
#define  IEEE80211_STYPE_DISASSOC     0x00A0

/** Subtype value for authentication management frames
 *
 * Authentication frames are exchanged between a client and an Access
 * Point before association may be performed. Confusingly, in the most
 * common authentication method (Open System) no security tokens are
 * exchanged at all. Modern 802.11 security handshaking takes place
 * after association.
 */
#define  IEEE80211_STYPE_AUTH         0x00B0

/** Subtype value for deauthentication management frames
 *
 * Deauthentication frames are sent by either a client or an Access
 * Point to terminate the authentication (and therefore also the
 * association) between the two. They are generally more forceful than
 * disassociation frames, sent for such reasons as a failure to
 * set up security properly after associating.
 */
#define  IEEE80211_STYPE_DEAUTH       0x00C0

/** Subtype value for action management frames
 *
 * Action frames are used to implement spectrum management and QoS
 * features that iPXE currently does not support.
 */
#define  IEEE80211_STYPE_ACTION	      0x00D0


/** Subtype value for RTS (request to send) control frames */
#define  IEEE80211_STYPE_RTS          0x00B0

/** Subtype value for CTS (clear to send) control frames */
#define  IEEE80211_STYPE_CTS          0x00C0

/** Subtype value for ACK (acknowledgement) control frames */
#define  IEEE80211_STYPE_ACK          0x00D0


/** Subtype value for ordinary data frames, with no QoS or CF add-ons */
#define  IEEE80211_STYPE_DATA         0x0000

/** Subtype value for data frames containing no data */
#define  IEEE80211_STYPE_NODATA       0x0040


/** 802.11 Frame Control field: To Data System flag
 *
 * This is set on data frames sent to an Access Point.
 */
#define IEEE80211_FC_TODS       0x0100

/** 802.11 Frame Control field: From Data System flag
 *
 * This is set on data frames sent from an Access Point. If both TODS
 * and FROMDS are set, the frame header is a 4-address format used for
 * inter-Access Point communication.
 */
#define IEEE80211_FC_FROMDS     0x0200

/** 802.11 Frame Control field: More Fragments flag */
#define IEEE80211_FC_MORE_FRAG  0x0400

/** 802.11 Frame Control field: Retransmission flag */
#define IEEE80211_FC_RETRY      0x0800

/** 802.11 Frame Control field: Power Managed flag
 *
 * This is set on any frame sent by a low-power station that will go
 * into a power-saving mode immediately after this frame. Access
 * Points are not allowed to act as low-power stations.
 */
#define IEEE80211_FC_PWR_MGMT   0x1000

/** 802.11 Frame Control field: More Data flag
 *
 * This is set on any frame sent by a station that has more data
 * queued to be sent than is in the frame.
 */
#define IEEE80211_FC_MORE_DATA  0x2000

/** 802.11 Frame Control field: Protected flag
 *
 * This is set on frames in which data is encrypted (by any method).
 */
#define IEEE80211_FC_PROTECTED  0x4000

/** 802.11 Frame Control field: Ordered flag [?] */
#define IEEE80211_FC_ORDER      0x8000

/** @} */


/* ---------- Sequence Control defines ---------- */

/**
 * @defgroup ieee80211_seq 802.11 Sequence Control field handling
 * @{
 */

/** Extract sequence number from 802.11 Sequence Control field */
#define IEEE80211_SEQNR( seq )		( ( seq ) >> 4 )

/** Extract fragment number from 802.11 Sequence Control field */
#define IEEE80211_FRAG( seq )		( ( seq ) & 0x000F )

/** Make 802.11 Sequence Control field from sequence and fragment numbers */
#define IEEE80211_MAKESEQ( seqnr, frag )	\
	( ( ( ( seqnr ) & 0xFFF ) << 4 ) | ( ( frag ) & 0xF ) )

/** @} */


/* ---------- Frame header formats ---------- */

/**
 * @defgroup ieee80211_hdr 802.11 frame header formats
 * @{
 */

/** An 802.11 data or management frame without QoS or WDS header fields */
struct ieee80211_frame
{
	u16 fc;			/**< 802.11 Frame Control field */
	u16 duration;		/**< Microseconds to reserve link */
	u8 addr1[ETH_ALEN];	/**< Address 1 (immediate receiver) */
	u8 addr2[ETH_ALEN];	/**< Address 2 (immediate sender) */
	u8 addr3[ETH_ALEN];	/**< Address 3 (often "forward to") */
	u16 seq;		/**< 802.11 Sequence Control field */
	u8 data[0];		/**< Beginning of frame data */
} __attribute__((packed));

/** The 802.2 LLC/SNAP header sent before actual data in a data frame
 *
 * This header is not acknowledged in the 802.11 standard at all; it
 * is treated just like data for MAC-layer purposes, including
 * fragmentation and encryption. It is actually two headers
 * concatenated: a three-byte 802.2 LLC header indicating Subnetwork
 * Accesss Protocol (SNAP) in both source and destination Service
 * Access Point (SAP) fields, and a five-byte SNAP header indicating a
 * zero OUI and two-byte Ethernet protocol type field.
 *
 * Thus, an eight-byte header in which six of the bytes are redundant.
 * Lovely, isn't it?
 */
struct ieee80211_llc_snap_header
{
	/* LLC part: */
	u8 dsap;		/**< Destination SAP ID */
	u8 ssap;		/**< Source SAP ID */
	u8 ctrl;		/**< Control information */

	/* SNAP part: */
	u8 oui[3];		/**< Organization code, usually 0 */
	u16 ethertype;		/**< Ethernet Type field */
} __attribute__((packed));

/** Value for DSAP field in 802.2 LLC header for 802.11 frames: SNAP */
#define IEEE80211_LLC_DSAP	0xAA

/** Value for SSAP field in 802.2 LLC header for 802.11 frames: SNAP */
#define IEEE80211_LLC_SSAP	0xAA

/** Value for control field in 802.2 LLC header for 802.11 frames
 *
 * "Unnumbered Information".
 */
#define IEEE80211_LLC_CTRL	0x03


/** 16-byte RTS frame format, with abbreviated header */
struct ieee80211_rts
{
	u16 fc;			/**< 802.11 Frame Control field */
	u16 duration;		/**< Microseconds to reserve link */
	u8 addr1[ETH_ALEN];	/**< Address 1 (immediate receiver) */
	u8 addr2[ETH_ALEN];	/**< Address 2 (immediate sender) */
} __attribute__((packed));

/** Length of 802.11 RTS control frame */
#define IEEE80211_RTS_LEN	16

/** 10-byte CTS or ACK frame format, with abbreviated header */
struct ieee80211_cts_or_ack
{
	u16 fc;			/**< 802.11 Frame Control field */
	u16 duration;		/**< Microseconds to reserve link */
	u8 addr1[ETH_ALEN];	/**< Address 1 (immediate receiver) */
} __attribute__((packed));

#define ieee80211_cts ieee80211_cts_or_ack
#define ieee80211_ack ieee80211_cts_or_ack

/** Length of 802.11 CTS control frame */
#define IEEE80211_CTS_LEN	10

/** Length of 802.11 ACK control frame */
#define IEEE80211_ACK_LEN	10

/** @} */


/* ---------- Capability bits, status and reason codes ---------- */

/**
 * @defgroup ieee80211_capab 802.11 management frame capability field bits
 * @{
 */

/** Set if using an Access Point (managed mode) */
#define IEEE80211_CAPAB_MANAGED       0x0001

/** Set if operating in IBSS (no-AP, "Ad-Hoc") mode */
#define IEEE80211_CAPAB_ADHOC         0x0002

/** Set if we support Contention-Free Period operation */
#define IEEE80211_CAPAB_CFPOLL        0x0004

/** Set if we wish to be polled for Contention-Free operation */
#define IEEE80211_CAPAB_CFPR          0x0008

/** Set if the network is encrypted (by any method) */
#define IEEE80211_CAPAB_PRIVACY       0x0010

/** Set if PHY supports short preambles on 802.11b */
#define IEEE80211_CAPAB_SHORT_PMBL    0x0020

/** Set if PHY supports PBCC modulation */
#define IEEE80211_CAPAB_PBCC          0x0040

/** Set if we support Channel Agility */
#define IEEE80211_CAPAB_CHAN_AGILITY  0x0080

/** Set if we support spectrum management (DFS and TPC) on the 5GHz band */
#define IEEE80211_CAPAB_SPECTRUM_MGMT 0x0100

/** Set if we support Quality of Service enhancements */
#define IEEE80211_CAPAB_QOS           0x0200

/** Set if PHY supports short slot time on 802.11g */
#define IEEE80211_CAPAB_SHORT_SLOT    0x0400

/** Set if PHY supports APSD option */
#define IEEE80211_CAPAB_APSD          0x0800

/** Set if PHY supports DSSS/OFDM modulation (one way of 802.11 b/g mixing) */
#define IEEE80211_CAPAB_DSSS_OFDM     0x2000

/** Set if we support delayed block ACK */
#define IEEE80211_CAPAB_DELAYED_BACK  0x4000

/** Set if we support immediate block ACK */
#define IEEE80211_CAPAB_IMMED_BACK    0x8000

/** @} */


/**
 * @defgroup ieee80211_status 802.11 status codes
 *
 * These are returned to indicate an immediate denial of
 * authentication or association. In iPXE, the lower 5 bits of the
 * status code are encoded into the file-unique portion of an error
 * code, the ERRFILE portion is always @c ERRFILE_net80211, and the
 * POSIX error code is @c ECONNREFUSED for status 0-31 or @c
 * EHOSTUNREACH for status 32-63.
 *
 * For a complete table with non-abbreviated error messages, see IEEE
 * Std 802.11-2007, Table 7-23, p.94.
 *
 * @{
 */

#define IEEE80211_STATUS_SUCCESS		0
#define IEEE80211_STATUS_FAILURE		1
#define IEEE80211_STATUS_CAPAB_UNSUPP		10
#define IEEE80211_STATUS_REASSOC_INVALID	11
#define IEEE80211_STATUS_ASSOC_DENIED		12
#define IEEE80211_STATUS_AUTH_ALGO_UNSUPP	13
#define IEEE80211_STATUS_AUTH_SEQ_INVALID	14
#define IEEE80211_STATUS_AUTH_CHALL_INVALID	15
#define IEEE80211_STATUS_AUTH_TIMEOUT		16
#define IEEE80211_STATUS_ASSOC_NO_ROOM		17
#define IEEE80211_STATUS_ASSOC_NEED_RATE	18
#define IEEE80211_STATUS_ASSOC_NEED_SHORT_PMBL	19
#define IEEE80211_STATUS_ASSOC_NEED_PBCC	20
#define IEEE80211_STATUS_ASSOC_NEED_CHAN_AGILITY 21
#define IEEE80211_STATUS_ASSOC_NEED_SPECTRUM_MGMT 22
#define IEEE80211_STATUS_ASSOC_BAD_POWER	23
#define IEEE80211_STATUS_ASSOC_BAD_CHANNELS	24
#define IEEE80211_STATUS_ASSOC_NEED_SHORT_SLOT	25
#define IEEE80211_STATUS_ASSOC_NEED_DSSS_OFDM	26
#define IEEE80211_STATUS_QOS_FAILURE		32
#define IEEE80211_STATUS_QOS_NO_ROOM		33
#define IEEE80211_STATUS_LINK_IS_HORRIBLE	34
#define IEEE80211_STATUS_ASSOC_NEED_QOS		35
#define IEEE80211_STATUS_REQUEST_DECLINED	37
#define IEEE80211_STATUS_REQUEST_INVALID	38
#define IEEE80211_STATUS_TS_NOT_CREATED_AGAIN	39
#define IEEE80211_STATUS_INVALID_IE		40
#define IEEE80211_STATUS_GROUP_CIPHER_INVALID	41
#define IEEE80211_STATUS_PAIR_CIPHER_INVALID	42
#define IEEE80211_STATUS_AKMP_INVALID		43
#define IEEE80211_STATUS_RSN_VERSION_UNSUPP	44
#define IEEE80211_STATUS_RSN_CAPAB_INVALID	45
#define IEEE80211_STATUS_CIPHER_REJECTED	46
#define IEEE80211_STATUS_TS_NOT_CREATED_WAIT	47
#define IEEE80211_STATUS_DIRECT_LINK_FORBIDDEN	48
#define IEEE80211_STATUS_DEST_NOT_PRESENT	49
#define IEEE80211_STATUS_DEST_NOT_QOS		50
#define IEEE80211_STATUS_ASSOC_LISTEN_TOO_HIGH	51

/** @} */



/**
 * @defgroup ieee80211_reason 802.11 reason codes
 *
 * These are returned to indicate the reason for a deauthentication or
 * disassociation sent (usually) after authentication or association
 * had succeeded.  In iPXE, the lower 5 bits of the reason code are
 * encoded into the file-unique portion of an error code, the ERRFILE
 * portion is always @c ERRFILE_net80211, and the POSIX error code is
 * @c ECONNRESET for reason 0-31 or @c ENETRESET for reason 32-63.
 *
 * For a complete table with non-abbreviated error messages, see IEEE
 * Std 802.11-2007, Table 7-22, p.92.
 *
 * @{
 */

#define IEEE80211_REASON_NONE			0
#define IEEE80211_REASON_UNSPECIFIED		1
#define IEEE80211_REASON_AUTH_NO_LONGER_VALID	2
#define IEEE80211_REASON_LEAVING		3
#define IEEE80211_REASON_INACTIVITY		4
#define IEEE80211_REASON_OUT_OF_RESOURCES	5
#define IEEE80211_REASON_NEED_AUTH		6
#define IEEE80211_REASON_NEED_ASSOC		7
#define IEEE80211_REASON_LEAVING_TO_ROAM	8
#define IEEE80211_REASON_REASSOC_INVALID	9
#define IEEE80211_REASON_BAD_POWER		10
#define IEEE80211_REASON_BAD_CHANNELS		11
#define IEEE80211_REASON_INVALID_IE		13
#define IEEE80211_REASON_MIC_FAILURE		14
#define IEEE80211_REASON_4WAY_TIMEOUT		15
#define IEEE80211_REASON_GROUPKEY_TIMEOUT	16
#define IEEE80211_REASON_4WAY_INVALID		17
#define IEEE80211_REASON_GROUP_CIPHER_INVALID	18
#define IEEE80211_REASON_PAIR_CIPHER_INVALID	19
#define IEEE80211_REASON_AKMP_INVALID		20
#define IEEE80211_REASON_RSN_VERSION_INVALID	21
#define IEEE80211_REASON_RSN_CAPAB_INVALID	22
#define IEEE80211_REASON_8021X_FAILURE		23
#define IEEE80211_REASON_CIPHER_REJECTED	24
#define IEEE80211_REASON_QOS_UNSPECIFIED	32
#define IEEE80211_REASON_QOS_OUT_OF_RESOURCES	33
#define IEEE80211_REASON_LINK_IS_HORRIBLE	34
#define IEEE80211_REASON_INVALID_TXOP		35
#define IEEE80211_REASON_REQUESTED_LEAVING	36
#define IEEE80211_REASON_REQUESTED_NO_USE	37
#define IEEE80211_REASON_REQUESTED_NEED_SETUP	38
#define IEEE80211_REASON_REQUESTED_TIMEOUT	39
#define IEEE80211_REASON_CIPHER_UNSUPPORTED	45

/** @} */

/* ---------- Information element declarations ---------- */

/**
 * @defgroup ieee80211_ie 802.11 information elements
 *
 * Many management frames include a section that amounts to a
 * concatenation of these information elements, so that the sender can
 * choose which information to send and the receiver can ignore the
 * parts it doesn't understand. Each IE contains a two-byte header,
 * one byte ID and one byte length, followed by IE-specific data. The
 * length does not include the two-byte header. Information elements
 * are required to be sorted by ID, but iPXE does not require that in
 * those it receives.
 *
 * This group also includes a few inline functions to simplify common
 * tasks in IE processing.
 *
 * @{
 */

/** Generic 802.11 information element header */
struct ieee80211_ie_header {
	u8 id;			/**< Information element ID */
	u8 len;			/**< Information element length */
} __attribute__ ((packed));


/** 802.11 SSID information element */
struct ieee80211_ie_ssid {
	u8 id;			/**< SSID ID: 0 */
	u8 len;			/**< SSID length */
	char ssid[0];		/**< SSID data, not NUL-terminated */
} __attribute__ ((packed));

/** Information element ID for SSID information element */
#define IEEE80211_IE_SSID	0


/** 802.11 rates information element
 *
 * The first 8 rates go in an IE of type RATES (1), and any more rates
 * go in one of type EXT_RATES (50). Each rate is a byte with the low
 * 7 bits equal to the rate in units of 500 kbps, and the high bit set
 * if and only if the rate is "basic" (must be supported by all
 * connected stations).
 */
struct ieee80211_ie_rates {
	u8 id;			/**< Rates ID: 1 or 50 */
	u8 len;			/**< Number of rates */
	u8 rates[0];		/**< Rates data, one rate per byte */
} __attribute__ ((packed));

/** Information element ID for rates information element */
#define IEEE80211_IE_RATES	1

/** Information element ID for extended rates information element */
#define IEEE80211_IE_EXT_RATES	50


/** 802.11 Direct Spectrum parameter information element
 *
 * This just contains the channel number. It has the fancy name
 * because IEEE 802.11 also defines a frequency-hopping PHY that
 * changes channels at regular intervals following a predetermined
 * pattern; in practice nobody uses the FH PHY.
 */
struct ieee80211_ie_ds_param {
	u8 id;			/**< DS parameter ID: 3 */
	u8 len;			/**< DS parameter length: 1 */
	u8 current_channel;	/**< Current channel number, 1-14 */
} __attribute__ ((packed));

/** Information element ID for Direct Spectrum parameter information element */
#define IEEE80211_IE_DS_PARAM	3


/** 802.11 Country information element regulatory extension triplet */
struct ieee80211_ie_country_ext_triplet {
	u8 reg_ext_id;		/**< Regulatory extension ID */
	u8 reg_class_id;	/**< Regulatory class ID */
	u8 coverage_class;	/**< Coverage class */
} __attribute__ ((packed));

/** 802.11 Country information element regulatory band triplet */
struct ieee80211_ie_country_band_triplet {
	u8 first_channel;	/**< Channel number for first channel in band */
	u8 nr_channels;		/**< Number of contiguous channels in band */
	u8 max_txpower;		/**< Maximum TX power in dBm */
} __attribute__ ((packed));

/** 802.11 Country information element regulatory triplet
 *
 * It is a band triplet if the first byte is 200 or less, and a
 * regulatory extension triplet otherwise.
 */
union ieee80211_ie_country_triplet {
	/** Differentiator between band and ext triplets */
	u8 first;

	/** Information about a band of channels */
	struct ieee80211_ie_country_band_triplet band;

	/** Regulatory extension information */
	struct ieee80211_ie_country_ext_triplet ext;
};

/** 802.11 Country information element
 *
 * This contains some data about RF regulations.
 */
struct ieee80211_ie_country {
	u8 id;			/**< Country information ID: 7 */
	u8 len;			/**< Country information length: varies */
	char name[2];		/**< ISO Alpha2 country code */
	char in_out;		/**< 'I' for indoor, 'O' for outdoor */

	/** List of regulatory triplets */
	union ieee80211_ie_country_triplet triplet[0];
} __attribute__ ((packed));

/** Information element ID for Country information element */
#define IEEE80211_IE_COUNTRY	7


/** 802.11 Request information element
 *
 * This contains a list of information element types we would like to
 * be included in probe response frames.
 */
struct ieee80211_ie_request {
	u8 id;			/**< Request ID: 10 */
	u8 len;			/**< Number of IEs requested */
	u8 request[0];		/**< List of IEs requested */
} __attribute__ ((packed));

/** Information element ID for Request information element */
#define IEEE80211_IE_REQUEST	10


/** 802.11 Challenge Text information element
 *
 * This is used in authentication frames under Shared Key
 * authentication.
 */
struct ieee80211_ie_challenge_text {
	u8 id;			/**< Challenge Text ID: 16 */
	u8 len;			/**< Challenge Text length: usually 128 */
	u8 challenge_text[0];	/**< Challenge Text data */
} __attribute__ ((packed));

/** Information element ID for Challenge Text information element */
#define IEEE80211_IE_CHALLENGE_TEXT	16


/** 802.11 Power Constraint information element
 *
 * This is used to specify an additional power limitation on top of
 * the Country requirements.
 */
struct ieee80211_ie_power_constraint {
	u8 id;			/**< Power Constraint ID: 52 */
	u8 len;			/**< Power Constraint length: 1 */
	u8 power_constraint;	/**< Decrease in allowed TX power, dBm */
} __attribute__ ((packed));

/** Information element ID for Power Constraint information element */
#define IEEE80211_IE_POWER_CONSTRAINT	52


/** 802.11 Power Capability information element
 *
 * This is used in association request frames to indicate the extremes
 * of our TX power abilities. It is required only if we indicate
 * support for spectrum management.
 */
struct ieee80211_ie_power_capab {
	u8 id;			/**< Power Capability ID: 33 */
	u8 len;			/**< Power Capability length: 2 */
	u8 min_txpower;		/**< Minimum possible TX power, dBm */
	u8 max_txpower;		/**< Maximum possible TX power, dBm */
} __attribute__ ((packed));

/** Information element ID for Power Capability information element */
#define IEEE80211_IE_POWER_CAPAB	33


/** 802.11 Channels information element channel band tuple */
struct ieee80211_ie_channels_channel_band {
	u8 first_channel;	/**< Channel number of first channel in band */
	u8 nr_channels;		/**< Number of channels in band */
} __attribute__ ((packed));

/** 802.11 Channels information element
 *
 * This is used in association frames to indicate the channels we can
 * use. It is required only if we indicate support for spectrum
 * management.
 */
struct ieee80211_ie_channels {
	u8 id;			/**< Channels ID: 36 */
	u8 len;			/**< Channels length: 2 */

	/** List of (start, length) channel bands we can use */
	struct ieee80211_ie_channels_channel_band channels[0];
} __attribute__ ((packed));

/** Information element ID for Channels information element */
#define IEEE80211_IE_CHANNELS	36


/** 802.11 ERP Information information element
 *
 * This is used to communicate some PHY-level flags.
 */
struct ieee80211_ie_erp_info {
	u8 id;			/**< ERP Information ID: 42 */
	u8 len;			/**< ERP Information length: 1 */
	u8 erp_info;		/**< ERP flags */
} __attribute__ ((packed));

/** Information element ID for ERP Information information element */
#define IEEE80211_IE_ERP_INFO	42

/** ERP information element: Flag set if 802.11b stations are present */
#define  IEEE80211_ERP_NONERP_PRESENT	0x01

/** ERP information element: Flag set if CTS protection must be used */
#define  IEEE80211_ERP_USE_PROTECTION	0x02

/** ERP information element: Flag set if long preambles must be used */
#define  IEEE80211_ERP_BARKER_LONG	0x04


/** 802.11 Robust Security Network ("WPA") information element
 *
 * Showing once again a striking clarity of design, the IEEE folks put
 * dynamically-sized data in the middle of this structure. As such,
 * the below structure definition only works for IEs we create
 * ourselves, which always have one pairwise cipher and one AKM;
 * received IEs should be parsed piecemeal.
 *
 * Also inspired was IEEE's choice of 16-bit fields to count the
 * number of 4-byte elements in a structure with a maximum length of
 * 255 bytes.
 *
 * Many fields reference a cipher or authentication-type ID; this is a
 * three-byte OUI followed by one byte identifying the cipher with
 * respect to that OUI. For all standard ciphers the OUI is 00:0F:AC,
 * except in old-style WPA IEs encapsulated in vendor-specific IEs,
 * where it's 00:50:F2.
 */
struct ieee80211_ie_rsn {
	/** Information element ID */
	u8 id;

	/** Information element length */
	u8 len;

	/** RSN information element version */
	u16 version;

	/** Cipher ID for the cipher used in multicast/broadcast frames */
	u32 group_cipher;

	/** Number of unicast ciphers supported */
	u16 pairwise_count;

	/** List of cipher IDs for supported unicast frame ciphers */
	u32 pairwise_cipher[1];

	/** Number of authentication types supported */
	u16 akm_count;

	/** List of authentication type IDs for supported types */
	u32 akm_list[1];

	/** Security capabilities field (RSN only) */
	u16 rsn_capab;

	/** Number of PMKIDs included (present only in association frames) */
	u16 pmkid_count;

	/** List of PMKIDs included, each a 16-byte SHA1 hash */
	u8 pmkid_list[0];
} __attribute__((packed));

/** Information element ID for Robust Security Network information element */
#define IEEE80211_IE_RSN	48

/** Calculate necessary size of RSN information element
 *
 * @v npair	Number of pairwise ciphers supported
 * @v nauth	Number of authentication types supported
 * @v npmkid	Number of PMKIDs to include
 * @v is_rsn	If TRUE, calculate RSN IE size; if FALSE, calculate WPA IE size
 * @ret size	Necessary size of IE, including header bytes
 */
static inline size_t ieee80211_rsn_size ( int npair, int nauth, int npmkid,
					  int rsn_ie ) {
	return 16 + 4 * ( npair + nauth ) + 16 * npmkid - 4 * ! rsn_ie;
}

/** Make OUI plus type byte into 32-bit integer for easy comparison */
#if __BYTE_ORDER == __BIG_ENDIAN
#define _MKOUI( a, b, c, t )	\
		( ( ( a ) << 24 ) | ( ( b ) << 16 ) | ( ( c ) << 8 ) | ( d ) )
#define  OUI_ORG_MASK		0xFFFFFF00
#define  OUI_TYPE_MASK		0x000000FF
#else
#define _MKOUI( a, b, c, t )	\
		( ( ( t ) << 24 ) | ( ( c ) << 16 ) | ( ( b ) << 8 ) | ( a ) )
#define  OUI_ORG_MASK		0x00FFFFFF
#define  OUI_TYPE_MASK		0xFF000000
#endif

/** Organization part for OUIs in standard RSN IE */
#define  IEEE80211_RSN_OUI	_MKOUI ( 0x00, 0x0F, 0xAC, 0 )

/** Organization part for OUIs in old WPA IE */
#define  IEEE80211_WPA_OUI	_MKOUI ( 0x00, 0x50, 0xF2, 0 )

/** Old vendor-type WPA IE OUI type + subtype */
#define  IEEE80211_WPA_OUI_VEN	_MKOUI ( 0x00, 0x50, 0xF2, 0x01 )


/** 802.11 RSN IE: expected version number */
#define  IEEE80211_RSN_VERSION		1

/** 802.11 RSN IE: cipher type for 40-bit WEP */
#define  IEEE80211_RSN_CTYPE_WEP40	_MKOUI ( 0, 0, 0, 0x01 )

/** 802.11 RSN IE: cipher type for 104-bit WEP */
#define  IEEE80211_RSN_CTYPE_WEP104	_MKOUI ( 0, 0, 0, 0x05 )

/** 802.11 RSN IE: cipher type for TKIP ("WPA") */
#define  IEEE80211_RSN_CTYPE_TKIP	_MKOUI ( 0, 0, 0, 0x02 )

/** 802.11 RSN IE: cipher type for CCMP ("WPA2") */
#define  IEEE80211_RSN_CTYPE_CCMP	_MKOUI ( 0, 0, 0, 0x04 )

/** 802.11 RSN IE: cipher type for "use group"
 *
 * This can only appear as a pairwise cipher, and means unicast frames
 * should be encrypted in the same way as broadcast/multicast frames.
 */
#define  IEEE80211_RSN_CTYPE_USEGROUP	_MKOUI ( 0, 0, 0, 0x00 )

/** 802.11 RSN IE: auth method type for using an 802.1X server */
#define  IEEE80211_RSN_ATYPE_8021X	_MKOUI ( 0, 0, 0, 0x01 )

/** 802.11 RSN IE: auth method type for using a pre-shared key */
#define  IEEE80211_RSN_ATYPE_PSK	_MKOUI ( 0, 0, 0, 0x02 )

/** 802.11 RSN IE capabilities: AP supports pre-authentication */
#define  IEEE80211_RSN_CAPAB_PREAUTH	0x001

/** 802.11 RSN IE capabilities: Node has conflict between TKIP and WEP
 *
 * This is a legacy issue; APs always set it to 0, and iPXE sets it to
 * 0.
 */
#define  IEEE80211_RSN_CAPAB_NO_PAIRWISE 0x002

/** 802.11 RSN IE capabilities: Number of PTKSA replay counters
 *
 * A value of 0 means one replay counter, 1 means two, 2 means four,
 * and 3 means sixteen.
 */
#define  IEEE80211_RSN_CAPAB_PTKSA_REPLAY 0x00C

/** 802.11 RSN IE capabilities: Number of GTKSA replay counters
 *
 * A value of 0 means one replay counter, 1 means two, 2 means four,
 * and 3 means sixteen.
 */
#define  IEEE80211_RSN_CAPAB_GTKSA_REPLAY 0x030

/** 802.11 RSN IE capabilities: PeerKey Handshaking is suported */
#define  IEEE80211_RSN_CAPAB_PEERKEY	0x200


/** 802.11 RSN IE capabilities: One replay counter
 *
 * This should be AND'ed with @c IEEE80211_RSN_CAPAB_PTKSA_REPLAY or
 * @c IEEE80211_RSN_CAPAB_GTKSA_REPLAY (or both) to produce a value
 * which can be OR'ed into the capabilities field.
 */
#define IEEE80211_RSN_1_CTR		0x000

/** 802.11 RSN IE capabilities: Two replay counters */
#define IEEE80211_RSN_2_CTR		0x014

/** 802.11 RSN IE capabilities: Four replay counters */
#define IEEE80211_RSN_4_CTR		0x028

/** 802.11 RSN IE capabilities: 16 replay counters */
#define IEEE80211_RSN_16_CTR		0x03C


/** 802.11 Vendor Specific information element
 *
 * One often sees the RSN IE masquerading as vendor-specific on
 * devices that were produced prior to 802.11i (the WPA amendment)
 * being finalized.
 */
struct ieee80211_ie_vendor {
	u8 id;			/**< Vendor-specific ID: 221 */
	u8 len;			/**< Vendor-specific length: variable */
	u32 oui;		/**< OUI and vendor-specific type byte */
	u8 data[0];		/**< Vendor-specific data */
} __attribute__ ((packed));

/** Information element ID for Vendor Specific information element */
#define IEEE80211_IE_VENDOR	221




/** Any 802.11 information element
 *
 * This is formatted for ease of use, so IEs with complex structures
 * get referenced in full, while those with only one byte of data or a
 * simple array are pulled in to avoid a layer of indirection like
 * ie->channels.channels[0].
 */
union ieee80211_ie
{
	/** Generic and simple information element info */
	struct {
		u8 id;		/**< Information element ID */
		u8 len;		/**< Information element data length */
		union {
			char ssid[0];	/**< SSID text */
			u8 rates[0];	/**< Rates data */
			u8 request[0];	/**< Request list */
			u8 challenge_text[0]; /**< Challenge text data */
			u8 power_constraint; /**< Power constraint, dBm */
			u8 erp_info;	/**< ERP information flags */
			/** List of channels */
			struct ieee80211_ie_channels_channel_band channels[0];
		};
	};

	/** DS parameter set */
	struct ieee80211_ie_ds_param ds_param;

	/** Country information */
	struct ieee80211_ie_country country;

	/** Power capability */
	struct ieee80211_ie_power_capab power_capab;

	/** Security information */
	struct ieee80211_ie_rsn rsn;

	/** Vendor-specific */
	struct ieee80211_ie_vendor vendor;
};

/** Check that 802.11 information element is bounded by buffer
 *
 * @v ie	Information element
 * @v end	End of buffer in which information element is stored
 * @ret ok	TRUE if the IE is completely contained within the buffer
 */
static inline int ieee80211_ie_bound ( union ieee80211_ie *ie, void *end )
{
	void *iep = ie;
	return ( iep + 2 <= end && iep + 2 + ie->len <= end );
}

/** Advance to next 802.11 information element
 *
 * @v ie	Current information element pointer
 * @v end	Pointer to first byte not in information element space
 * @ret next	Pointer to next information element, or NULL if no more
 *
 * When processing received IEs, @a end should be set to the I/O
 * buffer tail pointer; when marshalling IEs for sending, @a end
 * should be NULL.
 */
static inline union ieee80211_ie * ieee80211_next_ie ( union ieee80211_ie *ie,
						       void *end )
{
	void *next_ie_byte = ( void * ) ie + ie->len + 2;
	union ieee80211_ie *next_ie = next_ie_byte;

	if ( ! end )
		return next_ie;

	if ( ieee80211_ie_bound ( next_ie, end ) )
		return next_ie;

	return NULL;
}

/** @} */


/* ---------- Management frame data formats ---------- */

/**
 * @defgroup ieee80211_mgmt_data Management frame data payloads
 * @{
 */

/** Beacon or probe response frame data */
struct ieee80211_beacon_or_probe_resp
{
	/** 802.11 TSFT value at frame send */
	u64 timestamp;

	/** Interval at which beacons are sent, in units of 1024 us */
	u16 beacon_interval;

	/** Capability flags */
	u16 capability;

	/** List of information elements */
	union ieee80211_ie info_element[0];
} __attribute__((packed));

#define ieee80211_beacon	ieee80211_beacon_or_probe_resp
#define ieee80211_probe_resp	ieee80211_beacon_or_probe_resp

/** Disassociation or deauthentication frame data */
struct ieee80211_disassoc_or_deauth
{
	/** Reason code */
	u16 reason;
} __attribute__((packed));

#define ieee80211_disassoc	ieee80211_disassoc_or_deauth
#define ieee80211_deauth	ieee80211_disassoc_or_deauth

/** Association request frame data */
struct ieee80211_assoc_req
{
	/** Capability flags */
	u16 capability;

	/** Interval at which we wake up, in units of the beacon interval */
	u16 listen_interval;

	/** List of information elements */
	union ieee80211_ie info_element[0];
} __attribute__((packed));

/** Association or reassociation response frame data */
struct ieee80211_assoc_or_reassoc_resp
{
	/** Capability flags */
	u16 capability;

	/** Status code */
	u16 status;

	/** Association ID */
	u16 aid;

	/** List of information elements */
	union ieee80211_ie info_element[0];
} __attribute__((packed));

#define ieee80211_assoc_resp	ieee80211_assoc_or_reassoc_resp
#define ieee80211_reassoc_resp	ieee80211_assoc_or_reassoc_resp

/** Reassociation request frame data */
struct ieee80211_reassoc_req
{
	/** Capability flags */
	u16 capability;

	/** Interval at which we wake up, in units of the beacon interval */
	u16 listen_interval;

	/** MAC address of current Access Point */
	u8 current_addr[ETH_ALEN];

	/** List of information elements */
	union ieee80211_ie info_element[0];
} __attribute__((packed));

/** Probe request frame data */
struct ieee80211_probe_req
{
	/** List of information elements */
	union ieee80211_ie info_element[0];
} __attribute__((packed));

/** Authentication frame data */
struct ieee80211_auth
{
	/** Authentication algorithm (Open System or Shared Key) */
	u16 algorithm;

	/** Sequence number of this frame; first from client to AP is 1 */
	u16 tx_seq;

	/** Status code */
	u16 status;

	/** List of information elements */
	union ieee80211_ie info_element[0];
} __attribute__((packed));

/** Open System authentication algorithm */
#define IEEE80211_AUTH_OPEN_SYSTEM  0

/** Shared Key authentication algorithm */
#define IEEE80211_AUTH_SHARED_KEY   1

/** @} */

#endif
