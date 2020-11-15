/*
 * Simple 802.11 rate-control algorithm for iPXE.
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

#include <stdlib.h>
#include <ipxe/net80211.h>

/**
 * @file
 *
 * Simple 802.11 rate-control algorithm
 */

/** @page rc80211 Rate control philosophy
 *
 * We want to maximize our transmission speed, to the extent that we
 * can do that without dropping undue numbers of packets. We also
 * don't want to take up very much code space, so our algorithm has to
 * be pretty simple
 *
 * When we receive a packet, we know what rate it was transmitted at,
 * and whether it had to be retransmitted to get to us.
 *
 * When we send a packet, we hear back how many times it had to be
 * retried to get through, and whether it got through at all.
 *
 * Indications of TX success are more reliable than RX success, but RX
 * information helps us know where to start.
 *
 * To handle all of this, we keep for each rate and each direction (TX
 * and RX separately) some state information for the most recent
 * packets on that rate and the number of packets for which we have
 * information. The state is a 32-bit unsigned integer in which two
 * bits represent a packet: 11 if it went through well, 10 if it went
 * through with one retry, 01 if it went through with more than one
 * retry, or 00 if it didn't go through at all. We define the
 * "goodness" for a particular (rate, direction) combination as the
 * sum of all the 2-bit fields, times 33, divided by the number of
 * 2-bit fields containing valid information (16 except when we're
 * starting out). The number produced is between 0 and 99; we use -1
 * for rates with less than 4 RX packets or 1 TX, as an indicator that
 * we do not have enough information to rely on them.
 *
 * In deciding which rates are best, we find the weighted average of
 * TX and RX goodness, where the weighting is by number of packets
 * with data and TX packets are worth 4 times as much as RX packets.
 * The weighted average is called "net goodness" and is also a number
 * between 0 and 99.  If 3 consecutive packets fail transmission
 * outright, we automatically ratchet down the rate; otherwise, we
 * switch to the best rate whenever the current rate's goodness falls
 * below some threshold, and try increasing our rate when the goodness
 * is very high.
 *
 * This system is optimized for iPXE's style of usage. Because normal
 * operation always involves receiving something, we'll make our way
 * to the best rate pretty quickly. We tend to follow the lead of the
 * sending AP in choosing rates, but we won't use rates for long that
 * don't work well for us in transmission. We assume iPXE won't be
 * running for long enough that rate patterns will change much, so we
 * don't have to keep time counters or the like.  And if this doesn't
 * work well in practice there are many ways it could be tweaked.
 *
 * To avoid staying at 1Mbps for a long time, we don't track any
 * transmitted packets until we've set our rate based on received
 * packets.
 */

/** Two-bit packet status indicator for a packet with no retries */
#define RC_PKT_OK		0x3

/** Two-bit packet status indicator for a packet with one retry */
#define RC_PKT_RETRIED_ONCE	0x2

/** Two-bit packet status indicator for a TX packet with multiple retries
 *
 * It is not possible to tell whether an RX packet had one or multiple
 * retries; we rely instead on the fact that failed RX packets won't
 * get to us at all, so if we receive a lot of RX packets on a certain
 * rate it must be pretty good.
 */
#define RC_PKT_RETRIED_MULTI	0x1

/** Two-bit packet status indicator for a TX packet that was never ACKed
 *
 * It is not possible to tell whether an RX packet was setn if it
 * didn't get through to us, but if we don't see one we won't increase
 * the goodness for its rate. This asymmetry is part of why TX packets
 * are weighted much more heavily than RX.
 */
#define RC_PKT_FAILED		0x0

/** Number of times to weight TX packets more heavily than RX packets */
#define RC_TX_FACTOR		4

/** Number of consecutive failed TX packets that cause an automatic rate drop */
#define RC_TX_EMERG_FAIL	3

/** Minimum net goodness below which we will search for a better rate */
#define RC_GOODNESS_MIN		85

/** Maximum net goodness above which we will try to increase our rate */
#define RC_GOODNESS_MAX		95

/** Minimum (num RX + @c RC_TX_FACTOR * num TX) to use a certain rate */
#define RC_UNCERTAINTY_THRESH	4

/** TX direction */
#define TX	0

/** RX direction */
#define RX	1

/** A rate control context */
struct rc80211_ctx
{
	/** Goodness state for each rate, TX and RX */
	u32 goodness[2][NET80211_MAX_RATES];

	/** Number of packets recorded for each rate */
	u8 count[2][NET80211_MAX_RATES];

	/** Indication of whether we've set the device rate yet */
	int started;

	/** Counter of all packets sent and received */
	int packets;
};

/**
 * Initialize rate-control algorithm
 *
 * @v dev	802.11 device
 * @ret ctx	Rate-control context, to be stored in @c dev->rctl
 */
struct rc80211_ctx * rc80211_init ( struct net80211_device *dev __unused )
{
	struct rc80211_ctx *ret = zalloc ( sizeof ( *ret ) );
	return ret;
}

/**
 * Calculate net goodness for a certain rate
 *
 * @v ctx	Rate-control context
 * @v rate_idx	Index of rate to calculate net goodness for
 */
static int rc80211_calc_net_goodness ( struct rc80211_ctx *ctx,
				       int rate_idx )
{
	int sum[2], num[2], dir, pkt;

	for ( dir = 0; dir < 2; dir++ ) {
		u32 good = ctx->goodness[dir][rate_idx];

		num[dir] = ctx->count[dir][rate_idx];
		sum[dir] = 0;

		for ( pkt = 0; pkt < num[dir]; pkt++ )
			sum[dir] += ( good >> ( 2 * pkt ) ) & 0x3;
	}

	if ( ( num[TX] * RC_TX_FACTOR + num[RX] ) < RC_UNCERTAINTY_THRESH )
		return -1;

	return ( 33 * ( sum[TX] * RC_TX_FACTOR + sum[RX] ) /
		      ( num[TX] * RC_TX_FACTOR + num[RX] ) );
}

/**
 * Determine the best rate to switch to and return it
 *
 * @v dev		802.11 device
 * @ret rate_idx	Index of the best rate to switch to
 */
static int rc80211_pick_best ( struct net80211_device *dev )
{
	struct rc80211_ctx *ctx = dev->rctl;
	int best_net_good = 0, best_rate = -1, i;

	for ( i = 0; i < dev->nr_rates; i++ ) {
		int net_good = rc80211_calc_net_goodness ( ctx, i );

		if ( net_good > best_net_good ||
		     ( best_net_good > RC_GOODNESS_MIN &&
		       net_good > RC_GOODNESS_MIN ) ) {
			best_net_good = net_good;
			best_rate = i;
		}
	}

	if ( best_rate >= 0 ) {
		int old_good = rc80211_calc_net_goodness ( ctx, dev->rate );
		if ( old_good != best_net_good )
			DBGC ( ctx, "802.11 RC %p switching from goodness "
			       "%d to %d\n", ctx, old_good, best_net_good );

		ctx->started = 1;
		return best_rate;
	}

	return dev->rate;
}

/**
 * Set 802.11 device rate
 *
 * @v dev	802.11 device
 * @v rate_idx	Index of rate to switch to
 *
 * This is a thin wrapper around net80211_set_rate_idx to insert a
 * debugging message where appropriate.
 */
static inline void rc80211_set_rate ( struct net80211_device *dev,
				      int rate_idx )
{
	DBGC ( dev->rctl, "802.11 RC %p changing rate %d->%d Mbps\n", dev->rctl,
	       dev->rates[dev->rate] / 10, dev->rates[rate_idx] / 10 );

	net80211_set_rate_idx ( dev, rate_idx );
}

/**
 * Check rate-control state and change rate if necessary
 *
 * @v dev	802.11 device
 */
static void rc80211_maybe_set_new ( struct net80211_device *dev )
{
	struct rc80211_ctx *ctx = dev->rctl;
	int net_good;

	net_good = rc80211_calc_net_goodness ( ctx, dev->rate );

	if ( ! ctx->started ) {
		rc80211_set_rate ( dev, rc80211_pick_best ( dev ) );
		return;
	}

	if ( net_good < 0 )	/* insufficient data */
		return;

	if ( net_good > RC_GOODNESS_MAX && dev->rate + 1 < dev->nr_rates ) {
		int higher = rc80211_calc_net_goodness ( ctx, dev->rate + 1 );
		if ( higher > net_good || higher < 0 )
			rc80211_set_rate ( dev, dev->rate + 1 );
		else
			rc80211_set_rate ( dev, rc80211_pick_best ( dev ) );
	}

	if ( net_good < RC_GOODNESS_MIN ) {
		rc80211_set_rate ( dev, rc80211_pick_best ( dev ) );
	}
}

/**
 * Update rate-control state
 *
 * @v dev		802.11 device
 * @v direction		One of the direction constants TX or RX
 * @v rate_idx		Index of rate at which packet was sent or received
 * @v retries		Number of times packet was retried before success
 * @v failed		If nonzero, the packet failed to get through
 */
static void rc80211_update ( struct net80211_device *dev, int direction,
			     int rate_idx, int retries, int failed )
{
	struct rc80211_ctx *ctx = dev->rctl;
	u32 goodness = ctx->goodness[direction][rate_idx];

	if ( ctx->count[direction][rate_idx] < 16 )
		ctx->count[direction][rate_idx]++;

	goodness <<= 2;
	if ( failed )
		goodness |= RC_PKT_FAILED;
	else if ( retries > 1 )
		goodness |= RC_PKT_RETRIED_MULTI;
	else if ( retries )
		goodness |= RC_PKT_RETRIED_ONCE;
	else
		goodness |= RC_PKT_OK;

	ctx->goodness[direction][rate_idx] = goodness;

	ctx->packets++;

	rc80211_maybe_set_new ( dev );
}

/**
 * Update rate-control state for transmitted packet
 *
 * @v dev	802.11 device
 * @v retries	Number of times packet was transmitted before success
 * @v rc	Return status code for transmission
 */
void rc80211_update_tx ( struct net80211_device *dev, int retries, int rc )
{
	struct rc80211_ctx *ctx = dev->rctl;

	if ( ! ctx->started )
		return;

	rc80211_update ( dev, TX, dev->rate, retries, rc );

	/* Check if the last RC_TX_EMERG_FAIL packets have all failed */
	if ( ! ( ctx->goodness[TX][dev->rate] &
		 ( ( 1 << ( 2 * RC_TX_EMERG_FAIL ) ) - 1 ) ) ) {
		if ( dev->rate == 0 )
			DBGC ( dev->rctl, "802.11 RC %p saw %d consecutive "
			       "failed TX, but cannot lower rate any further\n",
			       dev->rctl, RC_TX_EMERG_FAIL );
		else {
			DBGC ( dev->rctl, "802.11 RC %p lowering rate (%d->%d "
			       "Mbps) due to %d consecutive TX failures\n",
			       dev->rctl, dev->rates[dev->rate] / 10,
			       dev->rates[dev->rate - 1] / 10,
			       RC_TX_EMERG_FAIL );

			rc80211_set_rate ( dev, dev->rate - 1 );
		}
	}
}

/**
 * Update rate-control state for received packet
 *
 * @v dev	802.11 device
 * @v retry	Whether the received packet had been retransmitted
 * @v rate	Rate at which packet was received, in 100 kbps units
 */
void rc80211_update_rx ( struct net80211_device *dev, int retry, u16 rate )
{
	int ridx;

	for ( ridx = 0; ridx < dev->nr_rates && dev->rates[ridx] != rate;
	      ridx++ )
		;
	if ( ridx >= dev->nr_rates )
		return;		/* couldn't find the rate */

	rc80211_update ( dev, RX, ridx, retry, 0 );
}

/**
 * Free rate-control context
 *
 * @v ctx	Rate-control context
 */
void rc80211_free ( struct rc80211_ctx *ctx )
{
	free ( ctx );
}
