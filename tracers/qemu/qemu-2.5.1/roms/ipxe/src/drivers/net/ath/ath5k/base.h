/*-
 * Copyright (c) 2002-2007 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Modified for iPXE, July 2009, by Joshua Oreman <oremanj@rwcr.net>
 * Original from Linux kernel 2.6.30.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 *
 */

/*
 * Defintions for the Atheros Wireless LAN controller driver.
 */
#ifndef _DEV_ATH_ATHVAR_H
#define _DEV_ATH_ATHVAR_H

FILE_LICENCE ( BSD3 );

#include "ath5k.h"
#include <ipxe/iobuf.h>

#define	ATH_RXBUF	16		/* number of RX buffers */
#define	ATH_TXBUF	16		/* number of TX buffers */

struct ath5k_buf {
	struct list_head	list;
	unsigned int		flags;	/* rx descriptor flags */
	struct ath5k_desc	*desc;	/* virtual addr of desc */
	u32			daddr;	/* physical addr of desc */
	struct io_buffer	*iob;	/* I/O buffer for buf */
	u32			iobaddr;/* physical addr of iob data */
};

/*
 * Data transmit queue state.  One of these exists for each
 * hardware transmit queue.  Packets sent to us from above
 * are assigned to queues based on their priority.  Not all
 * devices support a complete set of hardware transmit queues.
 * For those devices the array sc_ac2q will map multiple
 * priorities to fewer hardware queues (typically all to one
 * hardware queue).
 */
struct ath5k_txq {
	unsigned int		qnum;	/* hardware q number */
	u32			*link;	/* link ptr in last TX desc */
	struct list_head	q;	/* transmit queue */
	int			setup;
};

#if CHAN_DEBUG
#define ATH_CHAN_MAX	(26+26+26+200+200)
#else
#define ATH_CHAN_MAX	(14+14+14+252+20)
#endif

/* Software Carrier, keeps track of the driver state
 * associated with an instance of a device */
struct ath5k_softc {
	struct pci_device	*pdev;		/* for dma mapping */
	void			*iobase;	/* address of the device */
	struct net80211_device	*dev;		/* IEEE 802.11 common */
	struct ath5k_hw		*ah;		/* Atheros HW */
	struct net80211_hw_info	*hwinfo;
	int			curband;
	int			irq_ena; 	/* interrupts enabled */

	struct ath5k_buf	*bufptr;	/* allocated buffer ptr */
	struct ath5k_desc	*desc;		/* TX/RX descriptors */
	u32			desc_daddr;	/* DMA (physical) address */
	size_t			desc_len;	/* size of TX/RX descriptors */
	u16			cachelsz;	/* cache line size */

	int			status;
#define ATH_STAT_INVALID	0x01		/* disable hardware accesses */
#define ATH_STAT_MRRETRY	0x02		/* multi-rate retry support */
#define ATH_STAT_PROMISC	0x04
#define ATH_STAT_LEDSOFT	0x08		/* enable LED gpio status */
#define ATH_STAT_STARTED	0x10		/* opened & irqs enabled */

	unsigned int		filter_flags;	/* HW flags, AR5K_RX_FILTER_* */
	unsigned int		curmode;	/* current phy mode */
	struct net80211_channel	*curchan;	/* current h/w channel */

	enum ath5k_int		imask;		/* interrupt mask copy */

	u8			bssidmask[ETH_ALEN];

	unsigned int		rxbufsize;	/* rx size based on mtu */
	struct list_head	rxbuf;		/* receive buffer */
	u32			*rxlink;	/* link ptr in last RX desc */

	struct list_head	txbuf;		/* transmit buffer */
	unsigned int		txbuf_len;	/* buf count in txbuf list */
	struct ath5k_txq	txq;		/* tx queue */

	struct {
		u16 gpio;
		unsigned polarity;
	} rf_kill;

	int			last_calib_ticks;

	int 			power_level;	/* Requested tx power in dbm */
	int			assoc;		/* assocate state */

	int			hw_rate;	/* Hardware tx rate code */
	int			hw_rtscts_rate;	/* Hardware rts/cts rate code */
};

#define ath5k_hw_hasbssidmask(_ah) \
	(ath5k_hw_get_capability(_ah, AR5K_CAP_BSSIDMASK, 0, NULL) == 0)
#define ath5k_hw_hasveol(_ah) \
	(ath5k_hw_get_capability(_ah, AR5K_CAP_VEOL, 0, NULL) == 0)

#endif
