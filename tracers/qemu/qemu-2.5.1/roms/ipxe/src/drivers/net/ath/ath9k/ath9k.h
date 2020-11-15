/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Modified for iPXE by Scott K Logan <logans@cottsay.net> July 2011
 * Original from Linux kernel 3.0.1
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef ATH9K_H
#define ATH9K_H

FILE_LICENCE ( BSD2 );

#include "common.h"

/*
 * Header for the ath9k.ko driver core *only* -- hw code nor any other driver
 * should rely on this file or its contents.
 */

struct ath_node;
struct ath_softc;

/* Macro to expand scalars to 64-bit objects */

#define	ito64(x) (sizeof(x) == 1) ?			\
	(((unsigned long long int)(x)) & (0xff)) :	\
	(sizeof(x) == 2) ?				\
	(((unsigned long long int)(x)) & 0xffff) :	\
	((sizeof(x) == 4) ?				\
	 (((unsigned long long int)(x)) & 0xffffffff) : \
	 (unsigned long long int)(x))

/* increment with wrap-around */
#define INCR(_l, _sz)   do {			\
		(_l)++;				\
		(_l) &= ((_sz) - 1);		\
	} while (0)

/* decrement with wrap-around */
#define DECR(_l,  _sz)  do {			\
		(_l)--;				\
		(_l) &= ((_sz) - 1);		\
	} while (0)

#define A_MAX(a, b) ((a) > (b) ? (a) : (b))

#define TSF_TO_TU(_h,_l) \
	((((u32)(_h)) << 22) | (((u32)(_l)) >> 10))

#define	ATH_TXQ_SETUP(sc, i)        ((sc)->tx.txqsetup & (1<<i))

struct ath_config {
	u16 txpowlimit;
	u8 cabqReadytime;
};

/*************************/
/* Descriptor Management */
/*************************/

#define ATH_TXBUF_RESET(_bf) do {				\
		(_bf)->bf_stale = 0;			\
		(_bf)->bf_lastbf = NULL;			\
		(_bf)->bf_next = NULL;				\
		memset(&((_bf)->bf_state), 0,			\
		       sizeof(struct ath_buf_state));		\
	} while (0)

#define ATH_RXBUF_RESET(_bf) do {		\
		(_bf)->bf_stale = 0;	\
	} while (0)

/**
 * enum buffer_type - Buffer type flags
 *
 * @BUF_AMPDU: This buffer is an ampdu, as part of an aggregate (during TX)
 * @BUF_AGGR: Indicates whether the buffer can be aggregated
 *	(used in aggregation scheduling)
 * @BUF_XRETRY: To denote excessive retries of the buffer
 */
enum buffer_type {
	BUF_AMPDU		= BIT(0),
	BUF_AGGR		= BIT(1),
	BUF_XRETRY		= BIT(2),
};

#define bf_isampdu(bf)		(bf->bf_state.bf_type & BUF_AMPDU)
#define bf_isaggr(bf)		(bf->bf_state.bf_type & BUF_AGGR)
#define bf_isxretried(bf)	(bf->bf_state.bf_type & BUF_XRETRY)

#define ATH_TXSTATUS_RING_SIZE 64

struct ath_descdma {
	void *dd_desc;
	u32 dd_desc_paddr;
	u32 dd_desc_len;
	struct ath_buf *dd_bufptr;
};

int ath_descdma_setup(struct ath_softc *sc, struct ath_descdma *dd,
		      struct list_head *head, const char *name,
		      int nbuf, int ndesc, int is_tx);
void ath_descdma_cleanup(struct ath_softc *sc, struct ath_descdma *dd,
			 struct list_head *head);

/***********/
/* RX / TX */
/***********/

#define ATH_RXBUF               16
#define ATH_TXBUF               16
#define ATH_TXBUF_RESERVE       5
#define ATH_MAX_QDEPTH          (ATH_TXBUF / 4 - ATH_TXBUF_RESERVE)
#define ATH_TXMAXTRY            13

#define TID_TO_WME_AC(_tid)				\
	((((_tid) == 0) || ((_tid) == 3)) ? WME_AC_BE :	\
	 (((_tid) == 1) || ((_tid) == 2)) ? WME_AC_BK :	\
	 (((_tid) == 4) || ((_tid) == 5)) ? WME_AC_VI :	\
	 WME_AC_VO)

#define ATH_AGGR_DELIM_SZ          4
#define ATH_AGGR_MINPLEN           256 /* in bytes, minimum packet length */
/* number of delimiters for encryption padding */
#define ATH_AGGR_ENCRYPTDELIM      10
/* minimum h/w qdepth to be sustained to maximize aggregation */
#define ATH_AGGR_MIN_QDEPTH        2
#define ATH_AMPDU_SUBFRAME_DEFAULT 32

#define FCS_LEN                    4
#define IEEE80211_SEQ_SEQ_SHIFT    4
#define IEEE80211_SEQ_MAX          4096
#define IEEE80211_WEP_IVLEN        3
#define IEEE80211_WEP_KIDLEN       1
#define IEEE80211_WEP_CRCLEN       4
#define IEEE80211_MAX_MPDU_LEN     (3840 + FCS_LEN +		\
				    (IEEE80211_WEP_IVLEN +	\
				     IEEE80211_WEP_KIDLEN +	\
				     IEEE80211_WEP_CRCLEN))

/* return whether a bit at index _n in bitmap _bm is set
 * _sz is the size of the bitmap  */
#define ATH_BA_ISSET(_bm, _n)  (((_n) < (WME_BA_BMP_SIZE)) &&		\
				((_bm)[(_n) >> 5] & (1 << ((_n) & 31))))

/* return block-ack bitmap index given sequence and starting sequence */
#define ATH_BA_INDEX(_st, _seq) (((_seq) - (_st)) & (IEEE80211_SEQ_MAX - 1))

/* returns delimiter padding required given the packet length */
#define ATH_AGGR_GET_NDELIM(_len)					\
       (((_len) >= ATH_AGGR_MINPLEN) ? 0 :                             \
        DIV_ROUND_UP(ATH_AGGR_MINPLEN - (_len), ATH_AGGR_DELIM_SZ))

#define BAW_WITHIN(_start, _bawsz, _seqno) \
	((((_seqno) - (_start)) & 4095) < (_bawsz))

#define ATH_AN_2_TID(_an, _tidno)  (&(_an)->tid[(_tidno)])

#define ATH_TX_COMPLETE_POLL_INT	1000

enum ATH_AGGR_STATUS {
	ATH_AGGR_DONE,
	ATH_AGGR_BAW_CLOSED,
	ATH_AGGR_LIMITED,
};

#define ATH_TXFIFO_DEPTH 8
struct ath_txq {
	int mac80211_qnum; /* mac80211 queue number, -1 means not mac80211 Q */
	u32 axq_qnum; /* ath9k hardware queue number */
	u32 *axq_link;
	struct list_head axq_q;
	u32 axq_depth;
	u32 axq_ampdu_depth;
	int stopped;
	int axq_tx_inprogress;
	struct list_head axq_acq;
	struct list_head txq_fifo[ATH_TXFIFO_DEPTH];
	struct list_head txq_fifo_pending;
	u8 txq_headidx;
	u8 txq_tailidx;
	int pending_frames;
};

struct ath_atx_ac {
	struct ath_txq *txq;
	int sched;
	struct list_head list;
	struct list_head tid_q;
	int clear_ps_filter;
};

struct ath_frame_info {
	int framelen;
	u32 keyix;
	enum ath9k_key_type keytype;
	u8 retries;
	u16 seqno;
};

struct ath_buf_state {
	u8 bf_type;
	u8 bfs_paprd;
	unsigned long bfs_paprd_timestamp;
};

struct ath_buf {
	struct list_head list;
	struct ath_buf *bf_lastbf;	/* last buf of this unit (a frame or
					   an aggregate) */
	struct ath_buf *bf_next;	/* next subframe in the aggregate */
	struct io_buffer *bf_mpdu;	/* enclosing frame structure */
	void *bf_desc;			/* virtual addr of desc */
	u32 bf_daddr;			/* physical addr of desc */
	u32 bf_buf_addr;		/* physical addr of data buffer, for DMA */
	int bf_stale;
	u16 bf_flags;
	struct ath_buf_state bf_state;
};

struct ath_atx_tid {
	struct list_head list;
	struct list_head buf_q;
	struct ath_node *an;
	struct ath_atx_ac *ac;
	unsigned long tx_buf[BITS_TO_LONGS(ATH_TID_MAX_BUFS)];
	u16 seq_start;
	u16 seq_next;
	u16 baw_size;
	int tidno;
	int baw_head;   /* first un-acked tx buffer */
	int baw_tail;   /* next unused tx buffer slot */
	int sched;
	int paused;
	u8 state;
};

struct ath_node {
	struct ath_atx_tid tid[WME_NUM_TID];
	struct ath_atx_ac ac[WME_NUM_AC];
	int ps_key;

	u16 maxampdu;
	u8 mpdudensity;

	int sleeping;
};

#define AGGR_CLEANUP         BIT(1)
#define AGGR_ADDBA_COMPLETE  BIT(2)
#define AGGR_ADDBA_PROGRESS  BIT(3)

struct ath_tx_control {
	struct ath_txq *txq;
	struct ath_node *an;
	int if_id;
	u8 paprd;
};

#define ATH_TX_ERROR        0x01
#define ATH_TX_XRETRY       0x02
#define ATH_TX_BAR          0x04

/**
 * @txq_map:  Index is mac80211 queue number.  This is
 *  not necessarily the same as the hardware queue number
 *  (axq_qnum).
 */
struct ath_tx {
	u16 seq_no;
	u32 txqsetup;
	struct list_head txbuf;
	struct ath_txq txq[ATH9K_NUM_TX_QUEUES];
	struct ath_descdma txdma;
	struct ath_txq *txq_map[WME_NUM_AC];
};

struct ath_rx_edma {
	struct list_head rx_fifo;
	struct list_head rx_buffers;
	u32 rx_fifo_hwsize;
};

struct ath_rx {
	u8 defant;
	u8 rxotherant;
	u32 *rxlink;
	unsigned int rxfilter;
	struct list_head rxbuf;
	struct ath_descdma rxdma;
	struct ath_buf *rx_bufptr;
	struct ath_rx_edma rx_edma[ATH9K_RX_QUEUE_MAX];

	struct io_buffer *frag;
};

int ath_startrecv(struct ath_softc *sc);
int ath_stoprecv(struct ath_softc *sc);
void ath_flushrecv(struct ath_softc *sc);
u32 ath_calcrxfilter(struct ath_softc *sc);
int ath_rx_init(struct ath_softc *sc, int nbufs);
void ath_rx_cleanup(struct ath_softc *sc);
int ath_rx_tasklet(struct ath_softc *sc, int flush, int hp);
struct ath_txq *ath_txq_setup(struct ath_softc *sc, int qtype, int subtype);
void ath_tx_cleanupq(struct ath_softc *sc, struct ath_txq *txq);
int ath_drain_all_txq(struct ath_softc *sc, int retry_tx);
void ath_draintxq(struct ath_softc *sc,
		     struct ath_txq *txq, int retry_tx);
void ath_txq_schedule(struct ath_softc *sc, struct ath_txq *txq);
int ath_tx_init(struct ath_softc *sc, int nbufs);
void ath_tx_cleanup(struct ath_softc *sc);
int ath_txq_update(struct ath_softc *sc, int qnum,
		   struct ath9k_tx_queue_info *q);
int ath_tx_start(struct net80211_device *dev, struct io_buffer *iob,
		 struct ath_tx_control *txctl);
void ath_tx_tasklet(struct ath_softc *sc);

/*******/
/* ANI */
/*******/

#define ATH_STA_SHORT_CALINTERVAL 1000    /* 1 second */
#define ATH_AP_SHORT_CALINTERVAL  100     /* 100 ms */
#define ATH_ANI_POLLINTERVAL_OLD  100     /* 100 ms */
#define ATH_ANI_POLLINTERVAL_NEW  1000    /* 1000 ms */
#define ATH_LONG_CALINTERVAL_INT  1000    /* 1000 ms */
#define ATH_LONG_CALINTERVAL      30000   /* 30 seconds */
#define ATH_RESTART_CALINTERVAL   1200000 /* 20 minutes */

void ath_hw_pll_work(struct ath_softc *sc);
void ath_ani_calibrate(struct ath_softc *sc);

/********************/
/* Main driver core */
/********************/

/*
 * Default cache line size, in bytes.
 * Used when PCI device not fully initialized by bootrom/BIOS
*/
#define DEFAULT_CACHELINE       32
#define ATH_REGCLASSIDS_MAX     10
#define ATH_CABQ_READY_TIME     80      /* % of beacon interval */
#define ATH_MAX_SW_RETRIES      10
#define ATH_CHAN_MAX            255

#define ATH_TXPOWER_MAX         100     /* .5 dBm units */
#define ATH_RATE_DUMMY_MARKER   0

#define SC_OP_INVALID                BIT(0)
#define SC_OP_BEACONS                BIT(1)
#define SC_OP_RXAGGR                 BIT(2)
#define SC_OP_TXAGGR                 BIT(3)
#define SC_OP_OFFCHANNEL             BIT(4)
#define SC_OP_PREAMBLE_SHORT         BIT(5)
#define SC_OP_PROTECT_ENABLE         BIT(6)
#define SC_OP_RXFLUSH                BIT(7)
#define SC_OP_LED_ASSOCIATED         BIT(8)
#define SC_OP_LED_ON                 BIT(9)
#define SC_OP_TSF_RESET              BIT(11)
#define SC_OP_BT_PRIORITY_DETECTED   BIT(12)
#define SC_OP_BT_SCAN		     BIT(13)
#define SC_OP_ANI_RUN		     BIT(14)
#define SC_OP_ENABLE_APM	     BIT(15)
#define SC_OP_PRIM_STA_VIF	     BIT(16)

/* Powersave flags */
#define PS_WAIT_FOR_BEACON        BIT(0)
#define PS_WAIT_FOR_CAB           BIT(1)
#define PS_WAIT_FOR_PSPOLL_DATA   BIT(2)
#define PS_WAIT_FOR_TX_ACK        BIT(3)
#define PS_BEACON_SYNC            BIT(4)
#define PS_TSFOOR_SYNC            BIT(5)

struct ath_rate_table;

struct ath9k_legacy_rate {
        u16 bitrate;
        u32 flags;
        u16 hw_value;
        u16 hw_value_short;
};

enum ath9k_rate_control_flags {
	IEEE80211_TX_RC_USE_RTS_CTS		= BIT(0),
	IEEE80211_TX_RC_USE_CTS_PROTECT		= BIT(1),
	IEEE80211_TX_RC_USE_SHORT_PREAMBLE	= BIT(2),

	/* rate index is an MCS rate number instead of an index */
	IEEE80211_TX_RC_MCS			= BIT(3),
	IEEE80211_TX_RC_GREEN_FIELD		= BIT(4),
	IEEE80211_TX_RC_40_MHZ_WIDTH		= BIT(5),
	IEEE80211_TX_RC_DUP_DATA		= BIT(6),
	IEEE80211_TX_RC_SHORT_GI		= BIT(7),
};

struct survey_info {
	struct net80211_channel *channel;
	u64 channel_time;
	u64 channel_time_busy;
	u64 channel_time_ext_busy;
	u64 channel_time_rx;
	u64 channel_time_tx;
	u32 filled;
	s8 noise;
};

enum survey_info_flags {
	SURVEY_INFO_NOISE_DBM = 1<<0,
	SURVEY_INFO_IN_USE = 1<<1,
	SURVEY_INFO_CHANNEL_TIME = 1<<2,
	SURVEY_INFO_CHANNEL_TIME_BUSY = 1<<3,
	SURVEY_INFO_CHANNEL_TIME_EXT_BUSY = 1<<4,
	SURVEY_INFO_CHANNEL_TIME_RX = 1<<5,
	SURVEY_INFO_CHANNEL_TIME_TX = 1<<6,
};

struct ath9k_vif_iter_data {
	const u8 *hw_macaddr; /* phy's hardware address, set
			       * before starting iteration for
			       * valid bssid mask.
			       */
	u8 mask[ETH_ALEN]; /* bssid mask */
	int naps;      /* number of AP vifs */
	int nmeshes;   /* number of mesh vifs */
	int nstations; /* number of station vifs */
	int nwds;      /* number of nwd vifs */
	int nadhocs;   /* number of adhoc vifs */
	int nothers;   /* number of vifs not specified above. */
};

struct ath_softc {
	struct net80211_device *dev;
	struct pci_device *pdev;

	int chan_idx;
	int chan_is_ht;
	struct survey_info *cur_survey;
	struct survey_info survey[ATH9K_NUM_CHANNELS];

	void (*intr_tq)(struct ath_softc *sc);
	struct ath_hw *sc_ah;
	void *mem;
	int irq;

	void (*paprd_work)(struct ath_softc *sc);
	void (*hw_check_work)(struct ath_softc *sc);
	void (*paprd_complete)(struct ath_softc *sc);

	unsigned int hw_busy_count;

	u32 intrstatus;
	u32 sc_flags; /* SC_OP_* */
	u16 ps_flags; /* PS_* */
	u16 curtxpow;
	int ps_enabled;
	int ps_idle;
	short nbcnvifs;
	short nvifs;
	unsigned long ps_usecount;

	struct ath_config config;
	struct ath_rx rx;
	struct ath_tx tx;
	struct net80211_hw_info *hwinfo;
	struct ath9k_legacy_rate rates[NET80211_MAX_RATES];
	int hw_rix;

	struct ath9k_hw_cal_data caldata;
	int last_rssi;

	void (*tx_complete_work)(struct ath_softc *sc);
	unsigned long tx_complete_work_timer;
	void (*hw_pll_work)(struct ath_softc *sc);
	unsigned long hw_pll_work_timer;

	struct ath_descdma txsdma;
};

void ath9k_tasklet(struct ath_softc *sc);
int ath_reset(struct ath_softc *sc, int retry_tx);

static inline void ath_read_cachesize(struct ath_common *common, int *csz)
{
	common->bus_ops->read_cachesize(common, csz);
}

extern struct net80211_device_operations ath9k_ops;
extern int ath9k_modparam_nohwcrypt;
extern int is_ath9k_unloaded;

void ath_isr(struct net80211_device *dev);
void ath9k_init_crypto(struct ath_softc *sc);
int ath9k_init_device(u16 devid, struct ath_softc *sc, u16 subsysid,
		    const struct ath_bus_ops *bus_ops);
void ath9k_deinit_device(struct ath_softc *sc);
void ath9k_set_hw_capab(struct ath_softc *sc, struct net80211_device *dev);
int ath_set_channel(struct ath_softc *sc, struct net80211_device *dev,
		    struct ath9k_channel *hchan);

void ath_radio_enable(struct ath_softc *sc, struct net80211_device *dev);
void ath_radio_disable(struct ath_softc *sc, struct net80211_device *dev);
int ath9k_setpower(struct ath_softc *sc, enum ath9k_power_mode mode);
int ath9k_uses_beacons(int type);

u8 ath_txchainmask_reduction(struct ath_softc *sc, u8 chainmask, u32 rate);

void ath_start_rfkill_poll(struct ath_softc *sc);
extern void ath9k_rfkill_poll_state(struct net80211_device *dev);

#endif /* ATH9K_H */
