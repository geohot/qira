/*******************************************************************************

  Intel(R) 82576 Virtual Function Linux driver
  Copyright(c) 1999 - 2008 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

FILE_LICENCE ( GPL2_ONLY );

/* Linux PRO/1000 Ethernet Driver main header file */

#ifndef _IGBVF_H_
#define _IGBVF_H_

#include "igbvf_vf.h"

/* Forward declarations */
struct igbvf_info;
struct igbvf_adapter;

/* Interrupt defines */
#define IGBVF_START_ITR                    648 /* ~6000 ints/sec */

/* Tx/Rx descriptor defines */
#define IGBVF_DEFAULT_TXD		256
#define IGBVF_MAX_TXD			4096
#define IGBVF_MIN_TXD			80

#define IGBVF_DEFAULT_RXD		256
#define IGBVF_MAX_RXD			4096
#define IGBVF_MIN_RXD			80

#define IGBVF_MIN_ITR_USECS		10 /* 100000 irq/sec */
#define IGBVF_MAX_ITR_USECS		10000 /* 100    irq/sec */

/* RX descriptor control thresholds.
 * PTHRESH - MAC will consider prefetch if it has fewer than this number of
 *           descriptors available in its onboard memory.
 *           Setting this to 0 disables RX descriptor prefetch.
 * HTHRESH - MAC will only prefetch if there are at least this many descriptors
 *           available in host memory.
 *           If PTHRESH is 0, this should also be 0.
 * WTHRESH - RX descriptor writeback threshold - MAC will delay writing back
 *           descriptors until either it has this many to write back, or the
 *           ITR timer expires.
 */
#define IGBVF_RX_PTHRESH                    16
#define IGBVF_RX_HTHRESH                     8
#define IGBVF_RX_WTHRESH                     1

#define IGBVF_TX_PTHRESH                     8
#define IGBVF_TX_HTHRESH                     1
#define IGBVF_TX_WTHRESH                     1

/* this is the size past which hardware will drop packets when setting LPE=0 */
#define MAXIMUM_ETHERNET_VLAN_SIZE 1522

#define IGBVF_FC_PAUSE_TIME		0x0680 /* 858 usec */

/* How many Tx Descriptors do we need to call netif_wake_queue ? */
#define IGBVF_TX_QUEUE_WAKE	32
/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define IGBVF_RX_BUFFER_WRITE		16 /* Must be power of 2 */

#define AUTO_ALL_MODES			0
#define IGBVF_EEPROM_APME		0x0400

#define IGBVF_MNG_VLAN_NONE		(-1)

enum igbvf_boards {
	board_vf,
};

struct igbvf_queue_stats {
	u64 packets;
	u64 bytes;
};

/*
 * wrappers around a pointer to a socket buffer,
 * so a DMA handle can be stored along with the buffer
 */
struct igbvf_buffer {
#if 0
	dma_addr_t dma;
	dma_addr_t page_dma;
	struct sk_buff *skb;
	union {
		/* Tx */
		struct {
			unsigned long time_stamp;
			u16 length;
			u16 next_to_watch;
		};
		/* Rx */
		struct {
			struct page *page;
			unsigned int page_offset;
		};
	};
	struct page *page;
#endif
};

struct igbvf_ring {
#if 0
	struct igbvf_adapter *adapter;  /* backlink */
	void *desc;			/* pointer to ring memory  */
	dma_addr_t dma;			/* phys address of ring    */
	unsigned int size;		/* length of ring in bytes */
	unsigned int count;		/* number of desc. in ring */

	u16 next_to_use;
	u16 next_to_clean;

	u16 head;
	u16 tail;

	/* array of buffer information structs */
	struct igbvf_buffer *buffer_info;
	struct napi_struct napi;

	char name[IFNAMSIZ + 5];
	u32 eims_value;
	u32 itr_val;
	u16 itr_register;
	int set_itr;

	struct sk_buff *rx_skb_top;

	struct igbvf_queue_stats stats;
#endif
};

/* board specific private data structure */
struct igbvf_adapter {
#if 0
	struct timer_list watchdog_timer;
	struct timer_list blink_timer;

	struct work_struct reset_task;
	struct work_struct watchdog_task;

	const struct igbvf_info *ei;

	struct vlan_group *vlgrp;
	u32 bd_number;
	u32 rx_buffer_len;
	u32 polling_interval;
	u16 mng_vlan_id;
	u16 link_speed;
	u16 link_duplex;

	spinlock_t tx_queue_lock; /* prevent concurrent tail updates */

	/* track device up/down/testing state */
	unsigned long state;

	/* Interrupt Throttle Rate */
	u32 itr;
	u32 itr_setting;
	u16 tx_itr;
	u16 rx_itr;

	/*
	 * Tx
	 */
	struct igbvf_ring *tx_ring /* One per active queue */
						____cacheline_aligned_in_smp;

	unsigned long tx_queue_len;
	unsigned int restart_queue;
	u32 txd_cmd;

	bool detect_tx_hung;
	u8 tx_timeout_factor;

	unsigned int total_tx_bytes;
	unsigned int total_tx_packets;
	unsigned int total_rx_bytes;
	unsigned int total_rx_packets;

	/* Tx stats */
	u32 tx_timeout_count;
	u32 tx_fifo_head;
	u32 tx_head_addr;
	u32 tx_fifo_size;
	u32 tx_dma_failed;

	/*
	 * Rx
	 */
	struct igbvf_ring *rx_ring;

	/* Rx stats */
	u64 hw_csum_err;
	u64 hw_csum_good;
	u64 rx_hdr_split;
	u32 alloc_rx_buff_failed;
	u32 rx_dma_failed;

	unsigned int rx_ps_hdr_size;
	u32 max_frame_size;
	u32 min_frame_size;

	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;
	struct net_device_stats net_stats;
	spinlock_t stats_lock;      /* prevent concurrent stats updates */

	/* structs defined in e1000_hw.h */
	struct e1000_hw hw;

	/* The VF counters don't clear on read so we have to get a base
	 * count on driver start up and always subtract that base on
	 * on the first update, thus the flag..
	 */
	struct e1000_vf_stats stats;
	u64 zero_base;

	struct igbvf_ring test_tx_ring;
	struct igbvf_ring test_rx_ring;
	u32 test_icr;

	u32 msg_enable;
	struct msix_entry *msix_entries;
	int int_mode;
	u32 eims_enable_mask;
	u32 eims_other;
	u32 int_counter0;
	u32 int_counter1;

	u32 eeprom_wol;
	u32 wol;
	u32 pba;

	bool fc_autoneg;

	unsigned long led_status;

	unsigned int flags;
	unsigned long last_reset;
	u32 *config_space;
#endif
        /* OS defined structs */
        struct net_device *netdev;
        struct pci_device *pdev;
        struct net_device_stats net_stats;

        /* structs defined in e1000_hw.h */
        struct e1000_hw hw;

        u32 min_frame_size;
        u32 max_frame_size;

        u32 max_hw_frame_size;

#define NUM_TX_DESC     8
#define NUM_RX_DESC     8

        struct io_buffer *tx_iobuf[NUM_TX_DESC];
        struct io_buffer *rx_iobuf[NUM_RX_DESC];

        union e1000_adv_tx_desc *tx_base;
        union e1000_adv_rx_desc *rx_base;

        uint32_t tx_ring_size;
        uint32_t rx_ring_size;

        uint32_t tx_head;
        uint32_t tx_tail;
        uint32_t tx_fill_ctr;

        uint32_t rx_curr;

        uint32_t ioaddr;
        uint32_t irqno;

        uint32_t tx_int_delay;
        uint32_t tx_abs_int_delay;
        uint32_t txd_cmd;
};

struct igbvf_info {
	enum e1000_mac_type	mac;
	unsigned int		flags;
	u32			pba;
	void			(*init_ops)(struct e1000_hw *);
	s32			(*get_variants)(struct igbvf_adapter *);
};

/* hardware capability, feature, and workaround flags */
#define IGBVF_FLAG_RX_CSUM_DISABLED       (1 << 0)

#define IGBVF_DESC_UNUSED(R) \
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	(R)->next_to_clean - (R)->next_to_use - 1)

#define IGBVF_RX_DESC_ADV(R, i)	    \
	(&(((union e1000_adv_rx_desc *)((R).desc))[i]))
#define IGBVF_TX_DESC_ADV(R, i)	    \
	(&(((union e1000_adv_tx_desc *)((R).desc))[i]))
#define IGBVF_TX_CTXTDESC_ADV(R, i)	    \
	(&(((struct e1000_adv_tx_context_desc *)((R).desc))[i]))

enum igbvf_state_t {
	__IGBVF_TESTING,
	__IGBVF_RESETTING,
	__IGBVF_DOWN
};

enum latency_range {
	lowest_latency = 0,
	low_latency = 1,
	bulk_latency = 2,
	latency_invalid = 255
};

extern char igbvf_driver_name[];
extern const char igbvf_driver_version[];

extern void igbvf_check_options(struct igbvf_adapter *adapter);
extern void igbvf_set_ethtool_ops(struct net_device *netdev);
#ifdef ETHTOOL_OPS_COMPAT
extern int ethtool_ioctl(struct ifreq *ifr);
#endif

extern int igbvf_up(struct igbvf_adapter *adapter);
extern void igbvf_down(struct igbvf_adapter *adapter);
extern void igbvf_reinit_locked(struct igbvf_adapter *adapter);
extern void igbvf_reset(struct igbvf_adapter *adapter);
extern int igbvf_setup_rx_resources(struct igbvf_adapter *adapter);
extern int igbvf_setup_tx_resources(struct igbvf_adapter *adapter);
extern void igbvf_free_rx_resources(struct igbvf_adapter *adapter);
extern void igbvf_free_tx_resources(struct igbvf_adapter *adapter);
extern void igbvf_update_stats(struct igbvf_adapter *adapter);
extern void igbvf_set_interrupt_capability(struct igbvf_adapter *adapter);
extern void igbvf_reset_interrupt_capability(struct igbvf_adapter *adapter);

extern unsigned int copybreak;

static inline u32 __er32(struct e1000_hw *hw, unsigned long reg)
{
	return readl(hw->hw_addr + reg);
}

static inline void __ew32(struct e1000_hw *hw, unsigned long reg, u32 val)
{
	writel(val, hw->hw_addr + reg);
}
#define er32(reg)	E1000_READ_REG(hw, E1000_##reg)
#define ew32(reg,val)	E1000_WRITE_REG(hw, E1000_##reg, (val))
#define e1e_flush()	er32(STATUS)

#endif /* _IGBVF_H_ */
