#ifndef _IPXE_NET80211_ERR_H
#define _IPXE_NET80211_ERR_H

#include <errno.h>
#include <ipxe/ieee80211.h>

/*
 * The iPXE 802.11 MAC layer.
 *
 * Copyright (c) 2009 Joshua Oreman <oremanj@rwcr.net>.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * The iPXE 802.11 MAC layer errors.
 */

/* Disambiguate the EINVAL's a bit */
#define EINVAL_PKT_TOO_SHORT __einfo_error ( EINFO_EINVAL_PKT_TOO_SHORT )
#define EINFO_EINVAL_PKT_TOO_SHORT __einfo_uniqify \
	( EINFO_EINVAL, 0x01, "Packet too short" )
#define EINVAL_PKT_VERSION __einfo_error ( EINFO_EINVAL_PKT_VERSION )
#define EINFO_EINVAL_PKT_VERSION __einfo_uniqify \
	( EINFO_EINVAL, 0x02, "Packet 802.11 version not supported" )
#define EINVAL_PKT_NOT_DATA __einfo_error ( EINFO_EINVAL_PKT_NOT_DATA )
#define EINFO_EINVAL_PKT_NOT_DATA __einfo_uniqify \
	( EINFO_EINVAL, 0x03, "Packet not a data packet" )
#define EINVAL_PKT_NOT_FROMDS __einfo_error ( EINFO_EINVAL_PKT_NOT_FROMDS )
#define EINFO_EINVAL_PKT_NOT_FROMDS __einfo_uniqify \
	( EINFO_EINVAL, 0x04, "Packet not from an Access Point" )
#define EINVAL_PKT_LLC_HEADER __einfo_error ( EINFO_EINVAL_PKT_LLC_HEADER )
#define EINFO_EINVAL_PKT_LLC_HEADER __einfo_uniqify \
	( EINFO_EINVAL, 0x05, "Packet has invalid LLC header" )
#define EINVAL_CRYPTO_REQUEST __einfo_error ( EINFO_EINVAL_CRYPTO_REQUEST )
#define EINFO_EINVAL_CRYPTO_REQUEST __einfo_uniqify \
	( EINFO_EINVAL, 0x06, "Packet decryption error" )
#define EINVAL_ACTIVE_SCAN __einfo_error ( EINFO_EINVAL_ACTIVE_SCAN )
#define EINFO_EINVAL_ACTIVE_SCAN __einfo_uniqify \
	( EINFO_EINVAL, 0x07, "Invalid active scan requested" )

/*
 * 802.11 error codes: The AP can give us a status code explaining why
 * authentication failed, or a reason code explaining why we were
 * deauthenticated/disassociated. These codes range from 0-63 (the
 * field is 16 bits wide, but only up to 45 or so are defined yet; we
 * allow up to 63 for extensibility). This is encoded into an error
 * code as such:
 *
 *                                      status & 0x1f goes here --vv--
 *   Status code 0-31:  ECONNREFUSED | EUNIQ_(status & 0x1f) (0e1a6038)
 *   Status code 32-63: EHOSTUNREACH | EUNIQ_(status & 0x1f) (171a6011)
 *   Reason code 0-31:  ECONNRESET | EUNIQ_(reason & 0x1f)   (0f1a6039)
 *   Reason code 32-63: ENETRESET | EUNIQ_(reason & 0x1f)    (271a6001)
 *
 * The POSIX error codes more or less convey the appropriate message
 * (status codes occur when we can't associate at all, reason codes
 * when we lose association unexpectedly) and let us extract the
 * complete 802.11 error code from the rc value.
 *
 * The error messages follow the 802.11 standard as much as is
 * feasible, but most have been abbreviated to fit the 50-character
 * limit imposed by strerror().
 */

/* 802.11 status codes (IEEE Std 802.11-2007, Table 7-23) */

#define ECONNREFUSED_FAILURE __einfo_error				\
	( EINFO_ECONNREFUSED_FAILURE )
#define EINFO_ECONNREFUSED_FAILURE __einfo_uniqify			\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_FAILURE & 0x1f ),				\
	  "Unspecified failure" )

#define ECONNREFUSED_CAPAB_UNSUPP __einfo_error				\
	( EINFO_ECONNREFUSED_CAPAB_UNSUPP )
#define EINFO_ECONNREFUSED_CAPAB_UNSUPP __einfo_uniqify			\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_CAPAB_UNSUPP & 0x1f ),			\
	  "Cannot support all requested capabilities" )

#define ECONNREFUSED_REASSOC_INVALID __einfo_error			\
	( EINFO_ECONNREFUSED_REASSOC_INVALID )
#define EINFO_ECONNREFUSED_REASSOC_INVALID __einfo_uniqify		\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_REASSOC_INVALID & 0x1f ),			\
	  "Reassociation denied due to lack of association" )

#define ECONNREFUSED_ASSOC_DENIED __einfo_error				\
	( EINFO_ECONNREFUSED_ASSOC_DENIED )
#define EINFO_ECONNREFUSED_ASSOC_DENIED __einfo_uniqify			\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_DENIED & 0x1f ),			\
	  "Association denied for another reason" )

#define ECONNREFUSED_AUTH_ALGO_UNSUPP __einfo_error			\
	( EINFO_ECONNREFUSED_AUTH_ALGO_UNSUPP )
#define EINFO_ECONNREFUSED_AUTH_ALGO_UNSUPP __einfo_uniqify		\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_AUTH_ALGO_UNSUPP & 0x1f ),			\
	  "Authentication algorithm unsupported" )

#define ECONNREFUSED_AUTH_SEQ_INVALID __einfo_error			\
	( EINFO_ECONNREFUSED_AUTH_SEQ_INVALID )
#define EINFO_ECONNREFUSED_AUTH_SEQ_INVALID __einfo_uniqify		\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_AUTH_SEQ_INVALID & 0x1f ),			\
	  "Authentication sequence number unexpected" )

#define ECONNREFUSED_AUTH_CHALL_INVALID __einfo_error			\
	( EINFO_ECONNREFUSED_AUTH_CHALL_INVALID )
#define EINFO_ECONNREFUSED_AUTH_CHALL_INVALID __einfo_uniqify		\
	( EINFO_ECONNREFUSED,					\
	  ( IEEE80211_STATUS_AUTH_CHALL_INVALID & 0x1f ),		\
	  "Authentication rejected due to challenge failure" )

#define ECONNREFUSED_AUTH_TIMEOUT __einfo_error				\
	( EINFO_ECONNREFUSED_AUTH_TIMEOUT )
#define EINFO_ECONNREFUSED_AUTH_TIMEOUT __einfo_uniqify			\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_AUTH_TIMEOUT & 0x1f ),			\
	  "Authentication rejected due to timeout" )

#define ECONNREFUSED_ASSOC_NO_ROOM __einfo_error			\
	( EINFO_ECONNREFUSED_ASSOC_NO_ROOM )
#define EINFO_ECONNREFUSED_ASSOC_NO_ROOM __einfo_uniqify		\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_NO_ROOM & 0x1f ),			\
	  "Association denied because AP is out of resources" )

#define ECONNREFUSED_ASSOC_NEED_RATE __einfo_error			\
	( EINFO_ECONNREFUSED_ASSOC_NEED_RATE )
#define EINFO_ECONNREFUSED_ASSOC_NEED_RATE __einfo_uniqify		\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_NEED_RATE & 0x1f ),			\
	  "Association denied; basic rate support required" )

#define ECONNREFUSED_ASSOC_NEED_SHORT_PMBL __einfo_error		\
	( EINFO_ECONNREFUSED_ASSOC_NEED_SHORT_PMBL )
#define EINFO_ECONNREFUSED_ASSOC_NEED_SHORT_PMBL __einfo_uniqify	\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_NEED_SHORT_PMBL & 0x1f ),		\
	  "Association denied; short preamble support req'd" )

#define ECONNREFUSED_ASSOC_NEED_PBCC __einfo_error			\
	( EINFO_ECONNREFUSED_ASSOC_NEED_PBCC )
#define EINFO_ECONNREFUSED_ASSOC_NEED_PBCC __einfo_uniqify		\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_NEED_PBCC & 0x1f ),			\
	  "Association denied; PBCC modulation support req'd" )

#define ECONNREFUSED_ASSOC_NEED_CHAN_AGILITY __einfo_error		\
	( EINFO_ECONNREFUSED_ASSOC_NEED_CHAN_AGILITY )
#define EINFO_ECONNREFUSED_ASSOC_NEED_CHAN_AGILITY __einfo_uniqify	\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_NEED_CHAN_AGILITY & 0x1f ),		\
	  "Association denied; Channel Agility support req'd" )

#define ECONNREFUSED_ASSOC_NEED_SPECTRUM_MGMT __einfo_error		\
	( EINFO_ECONNREFUSED_ASSOC_NEED_SPECTRUM_MGMT )
#define EINFO_ECONNREFUSED_ASSOC_NEED_SPECTRUM_MGMT __einfo_uniqify	\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_NEED_SPECTRUM_MGMT & 0x1f ),		\
	  "Association denied; Spectrum Management required" )

#define ECONNREFUSED_ASSOC_BAD_POWER __einfo_error			\
	( EINFO_ECONNREFUSED_ASSOC_BAD_POWER )
#define EINFO_ECONNREFUSED_ASSOC_BAD_POWER __einfo_uniqify		\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_BAD_POWER & 0x1f ),			\
	  "Association denied; Power Capability unacceptable" )

#define ECONNREFUSED_ASSOC_BAD_CHANNELS __einfo_error			\
	( EINFO_ECONNREFUSED_ASSOC_BAD_CHANNELS )
#define EINFO_ECONNREFUSED_ASSOC_BAD_CHANNELS __einfo_uniqify		\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_BAD_CHANNELS & 0x1f ),		\
	  "Association denied; Supported Channels unacceptable" )

#define ECONNREFUSED_ASSOC_NEED_SHORT_SLOT __einfo_error		\
	( EINFO_ECONNREFUSED_ASSOC_NEED_SHORT_SLOT )
#define EINFO_ECONNREFUSED_ASSOC_NEED_SHORT_SLOT __einfo_uniqify	\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_NEED_SHORT_SLOT & 0x1f ),		\
	  "Association denied; Short Slot Tume support req'd" )

#define ECONNREFUSED_ASSOC_NEED_DSSS_OFDM __einfo_error			\
	( EINFO_ECONNREFUSED_ASSOC_NEED_DSSS_OFDM )
#define EINFO_ECONNREFUSED_ASSOC_NEED_DSSS_OFDM __einfo_uniqify		\
	( EINFO_ECONNREFUSED,						\
	  ( IEEE80211_STATUS_ASSOC_NEED_DSSS_OFDM & 0x1f ),		\
	  "Association denied; DSSS-OFDM support required" )

#define EHOSTUNREACH_QOS_FAILURE __einfo_error				\
	( EINFO_EHOSTUNREACH_QOS_FAILURE )
#define EINFO_EHOSTUNREACH_QOS_FAILURE __einfo_uniqify			\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_QOS_FAILURE & 0x1f ),			\
	  "Unspecified, QoS-related failure" )

#define EHOSTUNREACH_QOS_NO_ROOM __einfo_error				\
	( EINFO_EHOSTUNREACH_QOS_NO_ROOM )
#define EINFO_EHOSTUNREACH_QOS_NO_ROOM __einfo_uniqify			\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_QOS_NO_ROOM & 0x1f ),			\
	  "Association denied; QoS AP out of QoS resources" )

#define EHOSTUNREACH_LINK_IS_HORRIBLE __einfo_error			\
	( EINFO_EHOSTUNREACH_LINK_IS_HORRIBLE )
#define EINFO_EHOSTUNREACH_LINK_IS_HORRIBLE __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_LINK_IS_HORRIBLE & 0x1f ),			\
	  "Association denied due to excessively poor link" )

#define EHOSTUNREACH_ASSOC_NEED_QOS __einfo_error			\
	( EINFO_EHOSTUNREACH_ASSOC_NEED_QOS )
#define EINFO_EHOSTUNREACH_ASSOC_NEED_QOS __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_ASSOC_NEED_QOS & 0x1f ),			\
	  "Association denied; QoS support required" )

#define EHOSTUNREACH_REQUEST_DECLINED __einfo_error			\
	( EINFO_EHOSTUNREACH_REQUEST_DECLINED )
#define EINFO_EHOSTUNREACH_REQUEST_DECLINED __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_REQUEST_DECLINED & 0x1f ),			\
	  "The request has been declined" )

#define EHOSTUNREACH_REQUEST_INVALID __einfo_error			\
	( EINFO_EHOSTUNREACH_REQUEST_INVALID )
#define EINFO_EHOSTUNREACH_REQUEST_INVALID __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_REQUEST_INVALID & 0x1f ),			\
	  "Request unsuccessful due to invalid parameters" )

#define EHOSTUNREACH_TS_NOT_CREATED_AGAIN __einfo_error			\
	( EINFO_EHOSTUNREACH_TS_NOT_CREATED_AGAIN )
#define EINFO_EHOSTUNREACH_TS_NOT_CREATED_AGAIN __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_TS_NOT_CREATED_AGAIN & 0x1f ),		\
	  "TS not created due to bad specification" )

#define EHOSTUNREACH_INVALID_IE __einfo_error				\
	( EINFO_EHOSTUNREACH_INVALID_IE )
#define EINFO_EHOSTUNREACH_INVALID_IE __einfo_uniqify			\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_INVALID_IE & 0x1f ),			\
	  "Invalid information element" )

#define EHOSTUNREACH_GROUP_CIPHER_INVALID __einfo_error			\
	( EINFO_EHOSTUNREACH_GROUP_CIPHER_INVALID )
#define EINFO_EHOSTUNREACH_GROUP_CIPHER_INVALID __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_GROUP_CIPHER_INVALID & 0x1f ),		\
	  "Invalid group cipher" )

#define EHOSTUNREACH_PAIR_CIPHER_INVALID __einfo_error			\
	( EINFO_EHOSTUNREACH_PAIR_CIPHER_INVALID )
#define EINFO_EHOSTUNREACH_PAIR_CIPHER_INVALID __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_PAIR_CIPHER_INVALID & 0x1f ),		\
	  "Invalid pairwise cipher" )

#define EHOSTUNREACH_AKMP_INVALID __einfo_error				\
	( EINFO_EHOSTUNREACH_AKMP_INVALID )
#define EINFO_EHOSTUNREACH_AKMP_INVALID __einfo_uniqify			\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_AKMP_INVALID & 0x1f ),			\
	  "Invalid AKMP" )

#define EHOSTUNREACH_RSN_VERSION_UNSUPP __einfo_error			\
	( EINFO_EHOSTUNREACH_RSN_VERSION_UNSUPP )
#define EINFO_EHOSTUNREACH_RSN_VERSION_UNSUPP __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_RSN_VERSION_UNSUPP & 0x1f ),		\
	  "Unsupported RSN information element version" )

#define EHOSTUNREACH_RSN_CAPAB_INVALID __einfo_error			\
	( EINFO_EHOSTUNREACH_RSN_CAPAB_INVALID )
#define EINFO_EHOSTUNREACH_RSN_CAPAB_INVALID __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_RSN_CAPAB_INVALID & 0x1f ),		\
	  "Invalid RSN information element capabilities" )

#define EHOSTUNREACH_CIPHER_REJECTED __einfo_error			\
	( EINFO_EHOSTUNREACH_CIPHER_REJECTED )
#define EINFO_EHOSTUNREACH_CIPHER_REJECTED __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_CIPHER_REJECTED & 0x1f ),			\
	  "Cipher suite rejected because of security policy" )

#define EHOSTUNREACH_TS_NOT_CREATED_WAIT __einfo_error			\
	( EINFO_EHOSTUNREACH_TS_NOT_CREATED_WAIT )
#define EINFO_EHOSTUNREACH_TS_NOT_CREATED_WAIT __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_TS_NOT_CREATED_WAIT & 0x1f ),		\
	  "TS not created due to insufficient delay" )

#define EHOSTUNREACH_DIRECT_LINK_FORBIDDEN __einfo_error		\
	( EINFO_EHOSTUNREACH_DIRECT_LINK_FORBIDDEN )
#define EINFO_EHOSTUNREACH_DIRECT_LINK_FORBIDDEN __einfo_uniqify	\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_DIRECT_LINK_FORBIDDEN & 0x1f ),		\
	  "Direct link is not allowed in the BSS by policy" )

#define EHOSTUNREACH_DEST_NOT_PRESENT __einfo_error			\
	( EINFO_EHOSTUNREACH_DEST_NOT_PRESENT )
#define EINFO_EHOSTUNREACH_DEST_NOT_PRESENT __einfo_uniqify		\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_DEST_NOT_PRESENT & 0x1f ),			\
	  "The Destination STA is not present within the BSS" )

#define EHOSTUNREACH_DEST_NOT_QOS __einfo_error				\
	( EINFO_EHOSTUNREACH_DEST_NOT_QOS )
#define EINFO_EHOSTUNREACH_DEST_NOT_QOS __einfo_uniqify			\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_DEST_NOT_QOS & 0x1f ),			\
	  "The Destination STA is not a QoS STA" )

#define EHOSTUNREACH_ASSOC_LISTEN_TOO_HIGH __einfo_error		\
	( EINFO_EHOSTUNREACH_ASSOC_LISTEN_TOO_HIGH )
#define EINFO_EHOSTUNREACH_ASSOC_LISTEN_TOO_HIGH __einfo_uniqify	\
	( EINFO_EHOSTUNREACH,						\
	  ( IEEE80211_STATUS_ASSOC_LISTEN_TOO_HIGH & 0x1f ),		\
	  "Association denied; Listen Interval is too large" )

/* 802.11 reason codes (IEEE Std 802.11-2007, Table 7-22) */

#define ECONNRESET_UNSPECIFIED __einfo_error				\
	( EINFO_ECONNRESET_UNSPECIFIED )
#define EINFO_ECONNRESET_UNSPECIFIED __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_UNSPECIFIED & 0x1f ),			\
	  "Unspecified reason" )

#define ECONNRESET_AUTH_NO_LONGER_VALID __einfo_error			\
	( EINFO_ECONNRESET_AUTH_NO_LONGER_VALID )
#define EINFO_ECONNRESET_AUTH_NO_LONGER_VALID __einfo_uniqify		\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_AUTH_NO_LONGER_VALID & 0x1f ),		\
	  "Previous authentication no longer valid" )

#define ECONNRESET_LEAVING __einfo_error				\
	( EINFO_ECONNRESET_LEAVING )
#define EINFO_ECONNRESET_LEAVING __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_LEAVING & 0x1f ),				\
	  "Deauthenticated due to leaving network" )

#define ECONNRESET_INACTIVITY __einfo_error				\
	( EINFO_ECONNRESET_INACTIVITY )
#define EINFO_ECONNRESET_INACTIVITY __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_INACTIVITY & 0x1f ),			\
	  "Disassociated due to inactivity" )

#define ECONNRESET_OUT_OF_RESOURCES __einfo_error			\
	( EINFO_ECONNRESET_OUT_OF_RESOURCES )
#define EINFO_ECONNRESET_OUT_OF_RESOURCES __einfo_uniqify		\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_OUT_OF_RESOURCES & 0x1f ),			\
	  "Disassociated because AP is out of resources" )

#define ECONNRESET_NEED_AUTH __einfo_error				\
	( EINFO_ECONNRESET_NEED_AUTH )
#define EINFO_ECONNRESET_NEED_AUTH __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_NEED_AUTH & 0x1f ),			\
	  "Class 2 frame received from nonauthenticated STA" )

#define ECONNRESET_NEED_ASSOC __einfo_error				\
	( EINFO_ECONNRESET_NEED_ASSOC )
#define EINFO_ECONNRESET_NEED_ASSOC __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_NEED_ASSOC & 0x1f ),			\
	  "Class 3 frame received from nonassociated STA" )

#define ECONNRESET_LEAVING_TO_ROAM __einfo_error			\
	( EINFO_ECONNRESET_LEAVING_TO_ROAM )
#define EINFO_ECONNRESET_LEAVING_TO_ROAM __einfo_uniqify		\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_LEAVING_TO_ROAM & 0x1f ),			\
	  "Disassociated due to roaming" )

#define ECONNRESET_REASSOC_INVALID __einfo_error			\
	( EINFO_ECONNRESET_REASSOC_INVALID )
#define EINFO_ECONNRESET_REASSOC_INVALID __einfo_uniqify		\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_REASSOC_INVALID & 0x1f ),			\
	  "STA requesting (re)association not authenticated" )

#define ECONNRESET_BAD_POWER __einfo_error				\
	( EINFO_ECONNRESET_BAD_POWER )
#define EINFO_ECONNRESET_BAD_POWER __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_BAD_POWER & 0x1f ),			\
	  "Disassociated; Power Capability unacceptable" )

#define ECONNRESET_BAD_CHANNELS __einfo_error				\
	( EINFO_ECONNRESET_BAD_CHANNELS )
#define EINFO_ECONNRESET_BAD_CHANNELS __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_BAD_CHANNELS & 0x1f ),			\
	  "Disassociated; Supported Channels unacceptable" )

#define ECONNRESET_INVALID_IE __einfo_error				\
	( EINFO_ECONNRESET_INVALID_IE )
#define EINFO_ECONNRESET_INVALID_IE __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_INVALID_IE & 0x1f ),			\
	  "Invalid information element" )

#define ECONNRESET_MIC_FAILURE __einfo_error				\
	( EINFO_ECONNRESET_MIC_FAILURE )
#define EINFO_ECONNRESET_MIC_FAILURE __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_MIC_FAILURE & 0x1f ),			\
	  "Message integrity code (MIC) failure" )

#define ECONNRESET_4WAY_TIMEOUT __einfo_error				\
	( EINFO_ECONNRESET_4WAY_TIMEOUT )
#define EINFO_ECONNRESET_4WAY_TIMEOUT __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_4WAY_TIMEOUT & 0x1f ),			\
	  "4-Way Handshake timeout" )

#define ECONNRESET_GROUPKEY_TIMEOUT __einfo_error			\
	( EINFO_ECONNRESET_GROUPKEY_TIMEOUT )
#define EINFO_ECONNRESET_GROUPKEY_TIMEOUT __einfo_uniqify		\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_GROUPKEY_TIMEOUT & 0x1f ),			\
	  "Group Key Handshake timeout" )

#define ECONNRESET_4WAY_INVALID __einfo_error				\
	( EINFO_ECONNRESET_4WAY_INVALID )
#define EINFO_ECONNRESET_4WAY_INVALID __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_4WAY_INVALID & 0x1f ),			\
	  "4-Way Handshake information element changed unduly" )

#define ECONNRESET_GROUP_CIPHER_INVALID __einfo_error			\
	( EINFO_ECONNRESET_GROUP_CIPHER_INVALID )
#define EINFO_ECONNRESET_GROUP_CIPHER_INVALID __einfo_uniqify		\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_GROUP_CIPHER_INVALID & 0x1f ),		\
	  "Invalid group cipher" )

#define ECONNRESET_PAIR_CIPHER_INVALID __einfo_error			\
	( EINFO_ECONNRESET_PAIR_CIPHER_INVALID )
#define EINFO_ECONNRESET_PAIR_CIPHER_INVALID __einfo_uniqify		\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_PAIR_CIPHER_INVALID & 0x1f ),		\
	  "Invalid pairwise cipher" )

#define ECONNRESET_AKMP_INVALID __einfo_error				\
	( EINFO_ECONNRESET_AKMP_INVALID )
#define EINFO_ECONNRESET_AKMP_INVALID __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_AKMP_INVALID & 0x1f ),			\
	  "Invalid AKMP" )

#define ECONNRESET_RSN_VERSION_INVALID __einfo_error			\
	( EINFO_ECONNRESET_RSN_VERSION_INVALID )
#define EINFO_ECONNRESET_RSN_VERSION_INVALID __einfo_uniqify		\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_RSN_VERSION_INVALID & 0x1f ),		\
	  "Unsupported RSN information element version" )

#define ECONNRESET_RSN_CAPAB_INVALID __einfo_error			\
	( EINFO_ECONNRESET_RSN_CAPAB_INVALID )
#define EINFO_ECONNRESET_RSN_CAPAB_INVALID __einfo_uniqify		\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_RSN_CAPAB_INVALID & 0x1f ),		\
	  "Invalid RSN information element capabilities" )

#define ECONNRESET_8021X_FAILURE __einfo_error				\
	( EINFO_ECONNRESET_8021X_FAILURE )
#define EINFO_ECONNRESET_8021X_FAILURE __einfo_uniqify			\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_8021X_FAILURE & 0x1f ),			\
	  "IEEE 802.1X authentication failed" )

#define ECONNRESET_CIPHER_REJECTED __einfo_error			\
	( EINFO_ECONNRESET_CIPHER_REJECTED )
#define EINFO_ECONNRESET_CIPHER_REJECTED __einfo_uniqify		\
	( EINFO_ECONNRESET,						\
	  ( IEEE80211_REASON_CIPHER_REJECTED & 0x1f ),			\
	  "Cipher suite rejected because of security policy" )

#define ENETRESET_QOS_UNSPECIFIED __einfo_error				\
	( EINFO_ENETRESET_QOS_UNSPECIFIED )
#define EINFO_ENETRESET_QOS_UNSPECIFIED __einfo_uniqify			\
	( EINFO_ENETRESET,						\
	  ( IEEE80211_REASON_QOS_UNSPECIFIED & 0x1f ),			\
	  "Disassociated for unspecified, QoS-related reason" )

#define ENETRESET_QOS_OUT_OF_RESOURCES __einfo_error			\
	( EINFO_ENETRESET_QOS_OUT_OF_RESOURCES )
#define EINFO_ENETRESET_QOS_OUT_OF_RESOURCES __einfo_uniqify		\
	( EINFO_ENETRESET,						\
	  ( IEEE80211_REASON_QOS_OUT_OF_RESOURCES & 0x1f ),		\
	  "Disassociated; QoS AP is out of QoS resources" )

#define ENETRESET_LINK_IS_HORRIBLE __einfo_error			\
	( EINFO_ENETRESET_LINK_IS_HORRIBLE )
#define EINFO_ENETRESET_LINK_IS_HORRIBLE __einfo_uniqify		\
	( EINFO_ENETRESET,						\
	  ( IEEE80211_REASON_LINK_IS_HORRIBLE & 0x1f ),			\
	  "Disassociated due to excessively poor link" )

#define ENETRESET_INVALID_TXOP __einfo_error				\
	( EINFO_ENETRESET_INVALID_TXOP )
#define EINFO_ENETRESET_INVALID_TXOP __einfo_uniqify			\
	( EINFO_ENETRESET,						\
	  ( IEEE80211_REASON_INVALID_TXOP & 0x1f ),			\
	  "Disassociated due to TXOP limit violation" )

#define ENETRESET_REQUESTED_LEAVING __einfo_error			\
	( EINFO_ENETRESET_REQUESTED_LEAVING )
#define EINFO_ENETRESET_REQUESTED_LEAVING __einfo_uniqify		\
	( EINFO_ENETRESET,						\
	  ( IEEE80211_REASON_REQUESTED_LEAVING & 0x1f ),		\
	  "Requested; STA is leaving the BSS (or resetting)" )

#define ENETRESET_REQUESTED_NO_USE __einfo_error			\
	( EINFO_ENETRESET_REQUESTED_NO_USE )
#define EINFO_ENETRESET_REQUESTED_NO_USE __einfo_uniqify		\
	( EINFO_ENETRESET,						\
	  ( IEEE80211_REASON_REQUESTED_NO_USE & 0x1f ),			\
	  "Requested; does not want to use the mechanism" )

#define ENETRESET_REQUESTED_NEED_SETUP __einfo_error			\
	( EINFO_ENETRESET_REQUESTED_NEED_SETUP )
#define EINFO_ENETRESET_REQUESTED_NEED_SETUP __einfo_uniqify		\
	( EINFO_ENETRESET,						\
	  ( IEEE80211_REASON_REQUESTED_NEED_SETUP & 0x1f ),		\
	  "Requested; setup is required" )

#define ENETRESET_REQUESTED_TIMEOUT __einfo_error			\
	( EINFO_ENETRESET_REQUESTED_TIMEOUT )
#define EINFO_ENETRESET_REQUESTED_TIMEOUT __einfo_uniqify		\
	( EINFO_ENETRESET,						\
	  ( IEEE80211_REASON_REQUESTED_TIMEOUT & 0x1f ),		\
	  "Requested from peer STA due to timeout" )

#define ENETRESET_CIPHER_UNSUPPORTED __einfo_error			\
	( EINFO_ENETRESET_CIPHER_UNSUPPORTED )
#define EINFO_ENETRESET_CIPHER_UNSUPPORTED __einfo_uniqify		\
	( EINFO_ENETRESET,						\
	  ( IEEE80211_REASON_CIPHER_UNSUPPORTED & 0x1f ),		\
	  "Peer STA does not support requested cipher suite" )

/** Make return status code from 802.11 status code */
#define E80211_STATUS( stat )						\
	( ( (stat) & 0x20 ) ?						\
	  EUNIQ ( EINFO_EHOSTUNREACH, ( (stat) & 0x1f ),		\
		  EHOSTUNREACH_QOS_FAILURE,				\
		  EHOSTUNREACH_QOS_NO_ROOM,				\
		  EHOSTUNREACH_LINK_IS_HORRIBLE,			\
		  EHOSTUNREACH_ASSOC_NEED_QOS,				\
		  EHOSTUNREACH_REQUEST_DECLINED,			\
		  EHOSTUNREACH_REQUEST_INVALID,				\
		  EHOSTUNREACH_TS_NOT_CREATED_AGAIN,			\
		  EHOSTUNREACH_INVALID_IE,				\
		  EHOSTUNREACH_GROUP_CIPHER_INVALID,			\
		  EHOSTUNREACH_PAIR_CIPHER_INVALID,			\
		  EHOSTUNREACH_AKMP_INVALID,				\
		  EHOSTUNREACH_RSN_VERSION_UNSUPP,			\
		  EHOSTUNREACH_RSN_CAPAB_INVALID,			\
		  EHOSTUNREACH_CIPHER_REJECTED,				\
		  EHOSTUNREACH_TS_NOT_CREATED_WAIT,			\
		  EHOSTUNREACH_DIRECT_LINK_FORBIDDEN,			\
		  EHOSTUNREACH_DEST_NOT_PRESENT,			\
		  EHOSTUNREACH_DEST_NOT_QOS,				\
		  EHOSTUNREACH_ASSOC_LISTEN_TOO_HIGH ) :		\
	  EUNIQ ( EINFO_ECONNREFUSED, ( (stat) & 0x1f ),		\
		  ECONNREFUSED_FAILURE,					\
		  ECONNREFUSED_CAPAB_UNSUPP,				\
		  ECONNREFUSED_REASSOC_INVALID,				\
		  ECONNREFUSED_ASSOC_DENIED,				\
		  ECONNREFUSED_AUTH_ALGO_UNSUPP,			\
		  ECONNREFUSED_AUTH_SEQ_INVALID,			\
		  ECONNREFUSED_AUTH_CHALL_INVALID,			\
		  ECONNREFUSED_AUTH_TIMEOUT,				\
		  ECONNREFUSED_ASSOC_NO_ROOM,				\
		  ECONNREFUSED_ASSOC_NEED_RATE,				\
		  ECONNREFUSED_ASSOC_NEED_SHORT_PMBL,			\
		  ECONNREFUSED_ASSOC_NEED_PBCC,				\
		  ECONNREFUSED_ASSOC_NEED_CHAN_AGILITY,			\
		  ECONNREFUSED_ASSOC_NEED_SPECTRUM_MGMT,		\
		  ECONNREFUSED_ASSOC_BAD_POWER,				\
		  ECONNREFUSED_ASSOC_BAD_CHANNELS,			\
		  ECONNREFUSED_ASSOC_NEED_SHORT_SLOT,			\
		  ECONNREFUSED_ASSOC_NEED_DSSS_OFDM ) )

/** Make return status code from 802.11 reason code */
#define E80211_REASON( reas )						\
	( ( (reas) & 0x20 ) ?						\
	  EUNIQ ( EINFO_ENETRESET, ( (reas) & 0x1f ),			\
		  ENETRESET_QOS_UNSPECIFIED,				\
		  ENETRESET_QOS_OUT_OF_RESOURCES,			\
		  ENETRESET_LINK_IS_HORRIBLE,				\
		  ENETRESET_INVALID_TXOP,				\
		  ENETRESET_REQUESTED_LEAVING,				\
		  ENETRESET_REQUESTED_NO_USE,				\
		  ENETRESET_REQUESTED_NEED_SETUP,			\
		  ENETRESET_REQUESTED_TIMEOUT,				\
		  ENETRESET_CIPHER_UNSUPPORTED ) :			\
	  EUNIQ ( EINFO_ECONNRESET, ( (reas) & 0x1f ),			\
		  ECONNRESET_UNSPECIFIED,				\
		  ECONNRESET_AUTH_NO_LONGER_VALID,			\
		  ECONNRESET_LEAVING,					\
		  ECONNRESET_INACTIVITY,				\
		  ECONNRESET_OUT_OF_RESOURCES,				\
		  ECONNRESET_NEED_AUTH,					\
		  ECONNRESET_NEED_ASSOC,				\
		  ECONNRESET_LEAVING_TO_ROAM,				\
		  ECONNRESET_REASSOC_INVALID,				\
		  ECONNRESET_BAD_POWER,					\
		  ECONNRESET_BAD_CHANNELS,				\
		  ECONNRESET_INVALID_IE,				\
		  ECONNRESET_MIC_FAILURE,				\
		  ECONNRESET_4WAY_TIMEOUT,				\
		  ECONNRESET_GROUPKEY_TIMEOUT,				\
		  ECONNRESET_4WAY_INVALID,				\
		  ECONNRESET_GROUP_CIPHER_INVALID,			\
		  ECONNRESET_PAIR_CIPHER_INVALID,			\
		  ECONNRESET_AKMP_INVALID,				\
		  ECONNRESET_RSN_VERSION_INVALID,			\
		  ECONNRESET_RSN_CAPAB_INVALID,				\
		  ECONNRESET_8021X_FAILURE,				\
		  ECONNRESET_CIPHER_REJECTED ) )

#endif /* _IPXE_NET80211_ERR_H */
