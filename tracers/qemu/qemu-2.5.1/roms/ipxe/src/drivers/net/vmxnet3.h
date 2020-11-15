#ifndef _VMXNET3_H
#define _VMXNET3_H

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
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * @file
 *
 * VMware vmxnet3 virtual NIC driver
 *
 */

#include <ipxe/pci.h>

/** Maximum number of TX queues */
#define VMXNET3_MAX_TX_QUEUES 8

/** Maximum number of RX queues */
#define VMXNET3_MAX_RX_QUEUES 16

/** Maximum number of interrupts */
#define VMXNET3_MAX_INTRS 25

/** Maximum packet size */
#define VMXNET3_MAX_PACKET_LEN 0x4000

/** "PT" PCI BAR address */
#define VMXNET3_PT_BAR PCI_BASE_ADDRESS_0

/** "PT" PCI BAR size */
#define VMXNET3_PT_LEN 0x1000

/** Interrupt Mask Register */
#define VMXNET3_PT_IMR 0x0

/** Transmit producer index */
#define VMXNET3_PT_TXPROD 0x600

/** Rx producer index for ring 1 */
#define VMXNET3_PT_RXPROD 0x800

/** Rx producer index for ring 2 */
#define VMXNET3_PT_RXPROD2 0xa00

/** "VD" PCI BAR address */
#define VMXNET3_VD_BAR PCI_BASE_ADDRESS_1

/** "VD" PCI BAR size */
#define VMXNET3_VD_LEN 0x1000

/** vmxnet3 Revision Report Selection */
#define VMXNET3_VD_VRRS	0x0

/** UPT Version Report Selection */
#define VMXNET3_VD_UVRS 0x8

/** Driver Shared Address Low */
#define VMXNET3_VD_DSAL 0x10

/** Driver Shared Address High */
#define VMXNET3_VD_DSAH 0x18

/** Command */
#define VMXNET3_VD_CMD	0x20

/** MAC Address Low */
#define VMXNET3_VD_MACL 0x28

/** MAC Address High */
#define VMXNET3_VD_MACH 0x30

/** Interrupt Cause Register */
#define VMXNET3_VD_ICR	0x38

/** Event Cause Register */
#define VMXNET3_VD_ECR	0x40

/** Commands */
enum vmxnet3_command {
	VMXNET3_CMD_FIRST_SET = 0xcafe0000,
	VMXNET3_CMD_ACTIVATE_DEV = VMXNET3_CMD_FIRST_SET,
	VMXNET3_CMD_QUIESCE_DEV,
	VMXNET3_CMD_RESET_DEV,
	VMXNET3_CMD_UPDATE_RX_MODE,
	VMXNET3_CMD_UPDATE_MAC_FILTERS,
	VMXNET3_CMD_UPDATE_VLAN_FILTERS,
	VMXNET3_CMD_UPDATE_RSSIDT,
	VMXNET3_CMD_UPDATE_IML,
	VMXNET3_CMD_UPDATE_PMCFG,
	VMXNET3_CMD_UPDATE_FEATURE,
	VMXNET3_CMD_LOAD_PLUGIN,

	VMXNET3_CMD_FIRST_GET = 0xf00d0000,
	VMXNET3_CMD_GET_QUEUE_STATUS = VMXNET3_CMD_FIRST_GET,
	VMXNET3_CMD_GET_STATS,
	VMXNET3_CMD_GET_LINK,
	VMXNET3_CMD_GET_PERM_MAC_LO,
	VMXNET3_CMD_GET_PERM_MAC_HI,
	VMXNET3_CMD_GET_DID_LO,
	VMXNET3_CMD_GET_DID_HI,
	VMXNET3_CMD_GET_DEV_EXTRA_INFO,
	VMXNET3_CMD_GET_CONF_INTR
};

/** Events */
enum vmxnet3_event {
	VMXNET3_ECR_RQERR = 0x00000001,
	VMXNET3_ECR_TQERR = 0x00000002,
	VMXNET3_ECR_LINK = 0x00000004,
	VMXNET3_ECR_DIC = 0x00000008,
	VMXNET3_ECR_DEBUG = 0x00000010,
};

/** Miscellaneous configuration descriptor */
struct vmxnet3_misc_config {
	/** Driver version */
	uint32_t version;
	/** Guest information */
	uint32_t guest_info;
	/** Version supported */
	uint32_t version_support;
	/** UPT version supported */
	uint32_t upt_version_support;
	/** UPT features supported */
	uint64_t upt_features;
	/** Driver-private data address */
	uint64_t driver_data_address;
	/** Queue descriptors data address */
	uint64_t queue_desc_address;
	/** Driver-private data length */
	uint32_t driver_data_len;
	/** Queue descriptors data length */
	uint32_t queue_desc_len;
	/** Maximum transmission unit */
	uint32_t mtu;
	/** Maximum number of RX scatter-gather */
	uint16_t max_num_rx_sg;
	/** Number of TX queues */
	uint8_t num_tx_queues;
	/** Number of RX queues */
	uint8_t num_rx_queues;
	/** Reserved */
	uint32_t reserved0[4];
} __attribute__ (( packed ));

/** Driver version magic */
#define VMXNET3_VERSION_MAGIC 0x69505845

/** Interrupt configuration */
struct vmxnet3_interrupt_config {
	uint8_t mask_mode;
	uint8_t num_intrs;
	uint8_t event_intr_index;
	uint8_t moderation_level[VMXNET3_MAX_INTRS];
	uint32_t control;
	uint32_t reserved0[2];
} __attribute__ (( packed ));

/** Interrupt control - disable all interrupts */
#define VMXNET3_IC_DISABLE_ALL 0x1

/** Receive filter configuration */
struct vmxnet3_rx_filter_config {
	/** Receive filter mode */
	uint32_t mode;
	/** Multicast filter table length */
	uint16_t multicast_len;
	/** Reserved */
	uint16_t reserved0;
	/** Multicast filter table address */
	uint64_t multicast_address;
	/** VLAN filter table (one bit per possible VLAN) */
	uint8_t vlan_filter[512];
} __attribute__ (( packed ));

/** Receive filter mode */
enum vmxnet3_rx_filter_mode {
	VMXNET3_RXM_UCAST	= 0x01,  /**< Unicast only */
	VMXNET3_RXM_MCAST	= 0x02,  /**< Multicast passing the filters */
	VMXNET3_RXM_BCAST	= 0x04,  /**< Broadcast only */
	VMXNET3_RXM_ALL_MULTI	= 0x08,  /**< All multicast */
	VMXNET3_RXM_PROMISC	= 0x10,  /**< Promiscuous */
};

/** Variable-length configuration descriptor */
struct vmxnet3_variable_config {
	uint32_t version;
	uint32_t length;
	uint64_t address;
} __attribute__ (( packed ));

/** Driver shared area */
struct vmxnet3_shared {
	/** Magic signature */
	uint32_t magic;
	/** Reserved */
	uint32_t reserved0;
	/** Miscellaneous configuration */
	struct vmxnet3_misc_config misc;
	/** Interrupt configuration */
	struct vmxnet3_interrupt_config interrupt;
	/** Receive filter configuration */
	struct vmxnet3_rx_filter_config rx_filter;
	/** RSS configuration */
	struct vmxnet3_variable_config rss;
	/** Pattern-matching configuration */
	struct vmxnet3_variable_config pattern;
	/** Plugin configuration */
	struct vmxnet3_variable_config plugin;
	/** Event notifications */
	uint32_t ecr;
	/** Reserved */
	uint32_t reserved1[5];
} __attribute__ (( packed ));

/** Alignment of driver shared area */
#define VMXNET3_SHARED_ALIGN 8

/** Driver shared area magic */
#define VMXNET3_SHARED_MAGIC 0xbabefee1

/** Transmit descriptor */
struct vmxnet3_tx_desc {
	/** Address */
	uint64_t address;
	/** Flags */
	uint32_t flags[2];
} __attribute__ (( packed ));

/** Transmit generation flag */
#define VMXNET3_TXF_GEN 0x00004000UL

/** Transmit end-of-packet flag */
#define VMXNET3_TXF_EOP 0x000001000UL

/** Transmit completion request flag */
#define VMXNET3_TXF_CQ 0x000002000UL

/** Transmit completion descriptor */
struct vmxnet3_tx_comp {
	/** Index of the end-of-packet descriptor */
	uint32_t index;
	/** Reserved */
	uint32_t reserved0[2];
	/** Flags */
	uint32_t flags;
} __attribute__ (( packed ));

/** Transmit completion generation flag */
#define VMXNET3_TXCF_GEN 0x80000000UL

/** Transmit queue control */
struct vmxnet3_tx_queue_control {
	uint32_t num_deferred;
	uint32_t threshold;
	uint64_t reserved0;
} __attribute__ (( packed ));

/** Transmit queue configuration */
struct vmxnet3_tx_queue_config {
	/** Descriptor ring address */
	uint64_t desc_address;
	/** Data ring address */
	uint64_t immediate_address;
	/** Completion ring address */
	uint64_t comp_address;
	/** Driver-private data address */
	uint64_t driver_data_address;
	/** Reserved */
	uint64_t reserved0;
	/** Number of descriptors */
	uint32_t num_desc;
	/** Number of data descriptors */
	uint32_t num_immediate;
	/** Number of completion descriptors */
	uint32_t num_comp;
	/** Driver-private data length */
	uint32_t driver_data_len;
	/** Interrupt index */
	uint8_t intr_index;
	/** Reserved */
	uint8_t reserved[7];
} __attribute__ (( packed ));

/** Transmit queue statistics */
struct vmxnet3_tx_stats {
	/** Reserved */
	uint64_t reserved[10];
} __attribute__ (( packed ));

/** Receive descriptor */
struct vmxnet3_rx_desc {
	/** Address */
	uint64_t address;
	/** Flags */
	uint32_t flags;
	/** Reserved */
	uint32_t reserved0;
} __attribute__ (( packed ));

/** Receive generation flag */
#define VMXNET3_RXF_GEN 0x80000000UL

/** Receive completion descriptor */
struct vmxnet3_rx_comp {
	/** Descriptor index */
	uint32_t index;
	/** RSS hash value */
	uint32_t rss;
	/** Length */
	uint32_t len;
	/** Flags */
	uint32_t flags;
} __attribute__ (( packed ));

/** Receive completion generation flag */
#define VMXNET3_RXCF_GEN 0x80000000UL

/** Receive queue control */
struct vmxnet3_rx_queue_control {
	uint8_t update_prod;
	uint8_t reserved0[7];
	uint64_t reserved1;
} __attribute__ (( packed ));

/** Receive queue configuration */
struct vmxnet3_rx_queue_config {
	/** Descriptor ring addresses */
	uint64_t desc_address[2];
	/** Completion ring address */
	uint64_t comp_address;
	/** Driver-private data address */
	uint64_t driver_data_address;
	/** Reserved */
	uint64_t reserved0;
	/** Number of descriptors */
	uint32_t num_desc[2];
	/** Number of completion descriptors */
	uint32_t num_comp;
	/** Driver-private data length */
	uint32_t driver_data_len;
	/** Interrupt index */
	uint8_t intr_index;
	/** Reserved */
	uint8_t reserved[7];
} __attribute__ (( packed ));

/** Receive queue statistics */
struct vmxnet3_rx_stats {
	/** Reserved */
	uint64_t reserved[10];
} __attribute__ (( packed ));

/** Queue status */
struct vmxnet3_queue_status {
	uint8_t stopped;
	uint8_t reserved0[3];
	uint32_t error;
} __attribute__ (( packed ));

/** Transmit queue descriptor */
struct vmxnet3_tx_queue {
	struct vmxnet3_tx_queue_control ctrl;
	struct vmxnet3_tx_queue_config cfg;
	struct vmxnet3_queue_status status;
	struct vmxnet3_tx_stats state;
	uint8_t reserved[88];
} __attribute__ (( packed ));

/** Receive queue descriptor */
struct vmxnet3_rx_queue {
	struct vmxnet3_rx_queue_control ctrl;
	struct vmxnet3_rx_queue_config cfg;
	struct vmxnet3_queue_status status;
	struct vmxnet3_rx_stats stats;
	uint8_t reserved[88];
} __attribute__ (( packed ));

/**
 * Queue descriptor set
 *
 * We use only a single TX and RX queue
 */
struct vmxnet3_queues {
	/** Transmit queue descriptor(s) */
	struct vmxnet3_tx_queue tx;
	/** Receive queue descriptor(s) */
	struct vmxnet3_rx_queue rx;
} __attribute__ (( packed ));

/** Alignment of queue descriptor set */
#define VMXNET3_QUEUES_ALIGN 128

/** Alignment of rings */
#define VMXNET3_RING_ALIGN 512

/** Number of TX descriptors */
#define VMXNET3_NUM_TX_DESC 32

/** Number of TX completion descriptors */
#define VMXNET3_NUM_TX_COMP 32

/** Number of RX descriptors */
#define VMXNET3_NUM_RX_DESC 32

/** Number of RX completion descriptors */
#define VMXNET3_NUM_RX_COMP 32

/**
 * DMA areas
 *
 * These are arranged in order of decreasing alignment, to allow for a
 * single allocation
 */
struct vmxnet3_dma {
	/** TX descriptor ring */
	struct vmxnet3_tx_desc tx_desc[VMXNET3_NUM_TX_DESC];
	/** TX completion ring */
	struct vmxnet3_tx_comp tx_comp[VMXNET3_NUM_TX_COMP];
	/** RX descriptor ring */
	struct vmxnet3_rx_desc rx_desc[VMXNET3_NUM_RX_DESC];
	/** RX completion ring */
	struct vmxnet3_rx_comp rx_comp[VMXNET3_NUM_RX_COMP];
	/** Queue descriptors */
	struct vmxnet3_queues queues;
	/** Shared area */
	struct vmxnet3_shared shared;
} __attribute__ (( packed ));

/** DMA area alignment */
#define VMXNET3_DMA_ALIGN 512

/** Producer and consumer counters */
struct vmxnet3_counters {
	/** Transmit producer counter */
	unsigned int tx_prod;
	/** Transmit completion consumer counter */
	unsigned int tx_cons;
	/** Receive producer counter */
	unsigned int rx_prod;
	/** Receive fill level */
	unsigned int rx_fill;
	/** Receive consumer counter */
	unsigned int rx_cons;
};

/** A vmxnet3 NIC */
struct vmxnet3_nic {
	/** "PT" register base address */
	void *pt;
	/** "VD" register base address */
	void *vd;

	/** DMA area */
	struct vmxnet3_dma *dma;
	/** Producer and consumer counters */
	struct vmxnet3_counters count;
	/** Transmit I/O buffers */
	struct io_buffer *tx_iobuf[VMXNET3_NUM_TX_DESC];
	/** Receive I/O buffers */
	struct io_buffer *rx_iobuf[VMXNET3_NUM_RX_DESC];
};

/** vmxnet3 version that we support */
#define VMXNET3_VERSION_SELECT 1

/** UPT version that we support */
#define VMXNET3_UPT_VERSION_SELECT 1

/** MTU size */
#define VMXNET3_MTU ( ETH_FRAME_LEN + 4 /* VLAN */ + 4 /* FCS */ )

/** Receive ring maximum fill level */
#define VMXNET3_RX_FILL 8

/** Received packet alignment padding */
#define NET_IP_ALIGN 2

#endif /* _VMXNET3_H */
