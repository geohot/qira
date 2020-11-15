#ifndef _IPXE_RC80211_H
#define _IPXE_RC80211_H

/** @file
 *
 * Rate-control algorithm prototype for 802.11.
 */

FILE_LICENCE ( GPL2_OR_LATER );

struct net80211_device;
struct rc80211_ctx;

struct rc80211_ctx * rc80211_init ( struct net80211_device *dev );
void rc80211_update_tx ( struct net80211_device *dev, int retries, int rc );
void rc80211_update_rx ( struct net80211_device *dev, int retry, u16 rate );
void rc80211_free ( struct rc80211_ctx *ctx );

#endif /* _IPXE_RC80211_H */
