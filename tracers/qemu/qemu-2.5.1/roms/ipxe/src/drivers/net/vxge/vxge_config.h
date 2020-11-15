/*
 * vxge-config.h: iPXE driver for Neterion Inc's X3100 Series 10GbE
 *              PCIe I/O Virtualized Server Adapter.
 *
 * Copyright(c) 2002-2010 Neterion Inc.
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License (GPL), incorporated herein by
 * reference.  Drivers based on or derived from this code fall under
 * the GPL and must retain the authorship, copyright and license
 * notice.
 *
 */

FILE_LICENCE(GPL2_ONLY);

#ifndef VXGE_CONFIG_H
#define VXGE_CONFIG_H

#include <stdint.h>
#include <ipxe/list.h>
#include <ipxe/pci.h>

#ifndef VXGE_CACHE_LINE_SIZE
#define VXGE_CACHE_LINE_SIZE 4096
#endif

#define WAIT_FACTOR          1

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)  (sizeof(a) / sizeof((a)[0]))
#endif

#define VXGE_HW_MAC_MAX_WIRE_PORTS      2
#define VXGE_HW_MAC_MAX_AGGR_PORTS      2
#define VXGE_HW_MAC_MAX_PORTS           3

#define VXGE_HW_MIN_MTU				68
#define VXGE_HW_MAX_MTU				9600
#define VXGE_HW_DEFAULT_MTU			1500

#ifndef __iomem
#define __iomem
#endif

#ifndef ____cacheline_aligned
#define ____cacheline_aligned
#endif

/**
 * debug filtering masks
 */
#define	VXGE_NONE	0x00
#define	VXGE_INFO	0x01
#define	VXGE_INTR	0x02
#define	VXGE_XMIT	0x04
#define VXGE_POLL	0x08
#define	VXGE_ERR	0x10
#define VXGE_TRACE	0x20
#define VXGE_ALL	(VXGE_INFO|VXGE_INTR|VXGE_XMIT\
			|VXGE_POLL|VXGE_ERR|VXGE_TRACE)

#define NULL_VPID					0xFFFFFFFF

#define VXGE_HW_EVENT_BASE                      0
#define VXGE_LL_EVENT_BASE                      100

#define VXGE_HW_BASE_INF	100
#define VXGE_HW_BASE_ERR	200
#define VXGE_HW_BASE_BADCFG	300
#define VXGE_HW_DEF_DEVICE_POLL_MILLIS            1000
#define VXGE_HW_MAX_PAYLOAD_SIZE_512            2

enum vxge_hw_status {
	VXGE_HW_OK				  = 0,
	VXGE_HW_FAIL				  = 1,
	VXGE_HW_PENDING				  = 2,
	VXGE_HW_COMPLETIONS_REMAIN		  = 3,

	VXGE_HW_INF_NO_MORE_COMPLETED_DESCRIPTORS = VXGE_HW_BASE_INF + 1,
	VXGE_HW_INF_OUT_OF_DESCRIPTORS		  = VXGE_HW_BASE_INF + 2,
	VXGE_HW_INF_SW_LRO_BEGIN		  = VXGE_HW_BASE_INF + 3,
	VXGE_HW_INF_SW_LRO_CONT			  = VXGE_HW_BASE_INF + 4,
	VXGE_HW_INF_SW_LRO_UNCAPABLE		  = VXGE_HW_BASE_INF + 5,
	VXGE_HW_INF_SW_LRO_FLUSH_SESSION	  = VXGE_HW_BASE_INF + 6,
	VXGE_HW_INF_SW_LRO_FLUSH_BOTH		  = VXGE_HW_BASE_INF + 7,

	VXGE_HW_ERR_INVALID_HANDLE		  = VXGE_HW_BASE_ERR + 1,
	VXGE_HW_ERR_OUT_OF_MEMORY		  = VXGE_HW_BASE_ERR + 2,
	VXGE_HW_ERR_VPATH_NOT_AVAILABLE	  	  = VXGE_HW_BASE_ERR + 3,
	VXGE_HW_ERR_VPATH_NOT_OPEN		  = VXGE_HW_BASE_ERR + 4,
	VXGE_HW_ERR_WRONG_IRQ			  = VXGE_HW_BASE_ERR + 5,
	VXGE_HW_ERR_SWAPPER_CTRL		  = VXGE_HW_BASE_ERR + 6,
	VXGE_HW_ERR_INVALID_MTU_SIZE		  = VXGE_HW_BASE_ERR + 7,
	VXGE_HW_ERR_INVALID_INDEX		  = VXGE_HW_BASE_ERR + 8,
	VXGE_HW_ERR_INVALID_TYPE		  = VXGE_HW_BASE_ERR + 9,
	VXGE_HW_ERR_INVALID_OFFSET		  = VXGE_HW_BASE_ERR + 10,
	VXGE_HW_ERR_INVALID_DEVICE		  = VXGE_HW_BASE_ERR + 11,
	VXGE_HW_ERR_VERSION_CONFLICT		  = VXGE_HW_BASE_ERR + 12,
	VXGE_HW_ERR_INVALID_PCI_INFO		  = VXGE_HW_BASE_ERR + 13,
	VXGE_HW_ERR_INVALID_TCODE 		  = VXGE_HW_BASE_ERR + 14,
	VXGE_HW_ERR_INVALID_BLOCK_SIZE		  = VXGE_HW_BASE_ERR + 15,
	VXGE_HW_ERR_INVALID_STATE		  = VXGE_HW_BASE_ERR + 16,
	VXGE_HW_ERR_PRIVILAGED_OPEARATION	  = VXGE_HW_BASE_ERR + 17,
	VXGE_HW_ERR_INVALID_PORT 		  = VXGE_HW_BASE_ERR + 18,
	VXGE_HW_ERR_FIFO		 	  = VXGE_HW_BASE_ERR + 19,
	VXGE_HW_ERR_VPATH			  = VXGE_HW_BASE_ERR + 20,
	VXGE_HW_ERR_CRITICAL			  = VXGE_HW_BASE_ERR + 21,
	VXGE_HW_ERR_SLOT_FREEZE 		  = VXGE_HW_BASE_ERR + 22,
	VXGE_HW_ERR_INVALID_MIN_BANDWIDTH	  = VXGE_HW_BASE_ERR + 25,
	VXGE_HW_ERR_INVALID_MAX_BANDWIDTH	  = VXGE_HW_BASE_ERR + 26,
	VXGE_HW_ERR_INVALID_TOTAL_BANDWIDTH	  = VXGE_HW_BASE_ERR + 27,
	VXGE_HW_ERR_INVALID_BANDWIDTH_LIMIT	  = VXGE_HW_BASE_ERR + 28,
	VXGE_HW_ERR_RESET_IN_PROGRESS		  = VXGE_HW_BASE_ERR + 29,
	VXGE_HW_ERR_OUT_OF_SPACE		  = VXGE_HW_BASE_ERR + 30,
	VXGE_HW_ERR_INVALID_FUNC_MODE		  = VXGE_HW_BASE_ERR + 31,
	VXGE_HW_ERR_INVALID_DP_MODE		  = VXGE_HW_BASE_ERR + 32,
	VXGE_HW_ERR_INVALID_FAILURE_BEHAVIOUR	  = VXGE_HW_BASE_ERR + 33,
	VXGE_HW_ERR_INVALID_L2_SWITCH_STATE	  = VXGE_HW_BASE_ERR + 34,
	VXGE_HW_ERR_INVALID_CATCH_BASIN_MODE	  = VXGE_HW_BASE_ERR + 35,

	VXGE_HW_BADCFG_RING_INDICATE_MAX_PKTS	  = VXGE_HW_BASE_BADCFG + 1,
	VXGE_HW_BADCFG_FIFO_BLOCKS		  = VXGE_HW_BASE_BADCFG + 2,
	VXGE_HW_BADCFG_VPATH_MTU		  = VXGE_HW_BASE_BADCFG + 3,
	VXGE_HW_BADCFG_VPATH_RPA_STRIP_VLAN_TAG	  = VXGE_HW_BASE_BADCFG + 4,
	VXGE_HW_BADCFG_VPATH_MIN_BANDWIDTH	  = VXGE_HW_BASE_BADCFG + 5,
	VXGE_HW_BADCFG_VPATH_BANDWIDTH_LIMIT	  = VXGE_HW_BASE_BADCFG + 6,
	VXGE_HW_BADCFG_INTR_MODE		  = VXGE_HW_BASE_BADCFG + 7,
	VXGE_HW_BADCFG_RTS_MAC_EN		  = VXGE_HW_BASE_BADCFG + 8,
	VXGE_HW_BADCFG_VPATH_AGGR_ACK		  = VXGE_HW_BASE_BADCFG + 9,
	VXGE_HW_BADCFG_VPATH_PRIORITY		  = VXGE_HW_BASE_BADCFG + 10,

	VXGE_HW_EOF_TRACE_BUF			  = -1
};

/**
 * enum enum vxge_hw_device_link_state - Link state enumeration.
 * @VXGE_HW_LINK_NONE: Invalid link state.
 * @VXGE_HW_LINK_DOWN: Link is down.
 * @VXGE_HW_LINK_UP: Link is up.
 *
 */
enum vxge_hw_device_link_state {
	VXGE_HW_LINK_NONE,
	VXGE_HW_LINK_DOWN,
	VXGE_HW_LINK_UP
};

/*forward declaration*/
struct vxge_vpath;
struct __vxge_hw_virtualpath;

/**
 * struct vxge_hw_ring_rxd_1 - One buffer mode RxD for ring
 *
 * One buffer mode RxD for ring structure
 */
struct vxge_hw_ring_rxd_1 {
	u64 host_control;
	u64 control_0;
#define VXGE_HW_RING_RXD_RTH_BUCKET_GET(ctrl0)		vxge_bVALn(ctrl0, 0, 7)

#define VXGE_HW_RING_RXD_LIST_OWN_ADAPTER		vxge_mBIT(7)

#define VXGE_HW_RING_RXD_FAST_PATH_ELIGIBLE_GET(ctrl0)	vxge_bVALn(ctrl0, 8, 1)

#define VXGE_HW_RING_RXD_L3_CKSUM_CORRECT_GET(ctrl0)	vxge_bVALn(ctrl0, 9, 1)

#define VXGE_HW_RING_RXD_L4_CKSUM_CORRECT_GET(ctrl0)	vxge_bVALn(ctrl0, 10, 1)

#define VXGE_HW_RING_RXD_T_CODE_GET(ctrl0)		vxge_bVALn(ctrl0, 12, 4)
#define VXGE_HW_RING_RXD_T_CODE(val) 			vxge_vBIT(val, 12, 4)

#define VXGE_HW_RING_RXD_T_CODE_UNUSED		VXGE_HW_RING_T_CODE_UNUSED

#define VXGE_HW_RING_RXD_SYN_GET(ctrl0)		vxge_bVALn(ctrl0, 16, 1)

#define VXGE_HW_RING_RXD_IS_ICMP_GET(ctrl0)		vxge_bVALn(ctrl0, 17, 1)

#define VXGE_HW_RING_RXD_RTH_SPDM_HIT_GET(ctrl0)	vxge_bVALn(ctrl0, 18, 1)

#define VXGE_HW_RING_RXD_RTH_IT_HIT_GET(ctrl0)		vxge_bVALn(ctrl0, 19, 1)

#define VXGE_HW_RING_RXD_RTH_HASH_TYPE_GET(ctrl0)	vxge_bVALn(ctrl0, 20, 4)

#define VXGE_HW_RING_RXD_IS_VLAN_GET(ctrl0)		vxge_bVALn(ctrl0, 24, 1)

#define VXGE_HW_RING_RXD_ETHER_ENCAP_GET(ctrl0)		vxge_bVALn(ctrl0, 25, 2)

#define VXGE_HW_RING_RXD_FRAME_PROTO_GET(ctrl0)		vxge_bVALn(ctrl0, 27, 5)

#define VXGE_HW_RING_RXD_L3_CKSUM_GET(ctrl0)	vxge_bVALn(ctrl0, 32, 16)

#define VXGE_HW_RING_RXD_L4_CKSUM_GET(ctrl0)	vxge_bVALn(ctrl0, 48, 16)

	u64 control_1;

#define VXGE_HW_RING_RXD_1_BUFFER0_SIZE_GET(ctrl1)	vxge_bVALn(ctrl1, 2, 14)
#define VXGE_HW_RING_RXD_1_BUFFER0_SIZE(val) vxge_vBIT(val, 2, 14)
#define VXGE_HW_RING_RXD_1_BUFFER0_SIZE_MASK		vxge_vBIT(0x3FFF, 2, 14)

#define VXGE_HW_RING_RXD_1_RTH_HASH_VAL_GET(ctrl1)    vxge_bVALn(ctrl1, 16, 32)

#define VXGE_HW_RING_RXD_VLAN_TAG_GET(ctrl1)	vxge_bVALn(ctrl1, 48, 16)

	u64 buffer0_ptr;
};

/**
 * struct vxge_hw_fifo_txd - Transmit Descriptor
 *
 * Transmit descriptor (TxD).Fifo descriptor contains configured number
 * (list) of TxDs. * For more details please refer to Titan User Guide,
 * Section 5.4.2 "Transmit Descriptor (TxD) Format".
 */
struct vxge_hw_fifo_txd {
	u64 control_0;
#define VXGE_HW_FIFO_TXD_LIST_OWN_ADAPTER		vxge_mBIT(7)

#define VXGE_HW_FIFO_TXD_T_CODE_GET(ctrl0)		vxge_bVALn(ctrl0, 12, 4)
#define VXGE_HW_FIFO_TXD_T_CODE(val) 			vxge_vBIT(val, 12, 4)
#define VXGE_HW_FIFO_TXD_T_CODE_UNUSED		VXGE_HW_FIFO_T_CODE_UNUSED

#define VXGE_HW_FIFO_TXD_GATHER_CODE(val) 		vxge_vBIT(val, 22, 2)
#define VXGE_HW_FIFO_TXD_GATHER_CODE_FIRST	VXGE_HW_FIFO_GATHER_CODE_FIRST
#define VXGE_HW_FIFO_TXD_GATHER_CODE_LAST	VXGE_HW_FIFO_GATHER_CODE_LAST

#define VXGE_HW_FIFO_TXD_LSO_EN				vxge_mBIT(30)
#define VXGE_HW_FIFO_TXD_LSO_MSS(val) 			vxge_vBIT(val, 34, 14)
#define VXGE_HW_FIFO_TXD_BUFFER_SIZE(val) 		vxge_vBIT(val, 48, 16)

	u64 control_1;
#define VXGE_HW_FIFO_TXD_TX_CKO_IPV4_EN			vxge_mBIT(5)
#define VXGE_HW_FIFO_TXD_TX_CKO_TCP_EN			vxge_mBIT(6)
#define VXGE_HW_FIFO_TXD_TX_CKO_UDP_EN			vxge_mBIT(7)
#define VXGE_HW_FIFO_TXD_VLAN_ENABLE			vxge_mBIT(15)

#define VXGE_HW_FIFO_TXD_VLAN_TAG(val) 			vxge_vBIT(val, 16, 16)
#define VXGE_HW_FIFO_TXD_NO_BW_LIMIT			vxge_mBIT(43)

#define VXGE_HW_FIFO_TXD_INT_NUMBER(val) 		vxge_vBIT(val, 34, 6)

#define VXGE_HW_FIFO_TXD_INT_TYPE_PER_LIST		vxge_mBIT(46)
#define VXGE_HW_FIFO_TXD_INT_TYPE_UTILZ			vxge_mBIT(47)

	u64 buffer_pointer;

	u64 host_control;
};

/**
 * struct vxge_hw_device_date - Date Format
 * @day: Day
 * @month: Month
 * @year: Year
 * @date: Date in string format
 *
 * Structure for returning date
 */

#define VXGE_HW_FW_STRLEN	32
struct vxge_hw_device_date {
	u32     day;
	u32     month;
	u32     year;
	char    date[VXGE_HW_FW_STRLEN];
};

struct vxge_hw_device_version {
	u32     major;
	u32     minor;
	u32     build;
	char    version[VXGE_HW_FW_STRLEN];
};

u64 __vxge_hw_vpath_pci_func_mode_get(
	u32 vp_id,
	struct vxge_hw_vpath_reg __iomem *vpath_reg);

/*
 * struct __vxge_hw_non_offload_db_wrapper - Non-offload Doorbell Wrapper
 * @control_0: Bits 0 to 7 - Doorbell type.
 *             Bits 8 to 31 - Reserved.
 *             Bits 32 to 39 - The highest TxD in this TxDL.
 *             Bits 40 to 47 - Reserved.
 *	       Bits 48 to 55 - Reserved.
 *             Bits 56 to 63 - No snoop flags.
 * @txdl_ptr:  The starting location of the TxDL in host memory.
 *
 * Created by the host and written to the adapter via PIO to a Kernel Doorbell
 * FIFO. All non-offload doorbell wrapper fields must be written by the host as
 * part of a doorbell write. Consumed by the adapter but is not written by the
 * adapter.
 */
struct __vxge_hw_non_offload_db_wrapper {
	u64		control_0;
#define	VXGE_HW_NODBW_GET_TYPE(ctrl0)			vxge_bVALn(ctrl0, 0, 8)
#define VXGE_HW_NODBW_TYPE(val) vxge_vBIT(val, 0, 8)
#define	VXGE_HW_NODBW_TYPE_NODBW				0

#define	VXGE_HW_NODBW_GET_LAST_TXD_NUMBER(ctrl0)	vxge_bVALn(ctrl0, 32, 8)
#define VXGE_HW_NODBW_LAST_TXD_NUMBER(val) vxge_vBIT(val, 32, 8)

#define	VXGE_HW_NODBW_GET_NO_SNOOP(ctrl0)		vxge_bVALn(ctrl0, 56, 8)
#define VXGE_HW_NODBW_LIST_NO_SNOOP(val) vxge_vBIT(val, 56, 8)
#define	VXGE_HW_NODBW_LIST_NO_SNOOP_TXD_READ_TXD0_WRITE		0x2
#define	VXGE_HW_NODBW_LIST_NO_SNOOP_TX_FRAME_DATA_READ		0x1

	u64		txdl_ptr;
};

/*
 * struct __vxge_hw_fifo - Fifo.
 * @vp_id: Virtual path id
 * @tx_intr_num: Interrupt Number associated with the TX
 * @txdl: Start pointer of the txdl list of this fifo.
 *        iPXE does not support tx fragmentation, so we need
 *        only one txd in a list
 * @depth: total number of lists in this fifo
 * @hw_offset: txd index from where adapter owns the txd list
 * @sw_offset: txd index from where driver owns the txd list
 *
 * @stats: Statistics of this fifo
 *
 */
struct __vxge_hw_fifo {
	struct vxge_hw_vpath_reg		*vp_reg;
	struct __vxge_hw_non_offload_db_wrapper	*nofl_db;
	u32					vp_id;
	u32					tx_intr_num;

	struct vxge_hw_fifo_txd		*txdl;
#define VXGE_HW_FIFO_TXD_DEPTH 128
	u16				depth;
	u16				hw_offset;
	u16				sw_offset;

	struct __vxge_hw_virtualpath    *vpathh;
};

/* Structure that represents the Rx descriptor block which contains
 * 128 Rx descriptors.
 */
struct __vxge_hw_ring_block {
#define VXGE_HW_MAX_RXDS_PER_BLOCK_1            127
	struct vxge_hw_ring_rxd_1 rxd[VXGE_HW_MAX_RXDS_PER_BLOCK_1];

	u64 reserved_0;
#define END_OF_BLOCK    0xFEFFFFFFFFFFFFFFULL
	/* 0xFEFFFFFFFFFFFFFF to mark last Rxd in this blk */
	u64 reserved_1;
	/* Logical ptr to next */
	u64 reserved_2_pNext_RxD_block;
	/* Buff0_ptr.In a 32 bit arch the upper 32 bits should be 0 */
	u64 pNext_RxD_Blk_physical;
};

/*
 * struct __vxge_hw_ring - Ring channel.
 *
 * Note: The structure is cache line aligned to better utilize
 *       CPU cache performance.
 */
struct __vxge_hw_ring {
	struct vxge_hw_vpath_reg		*vp_reg;
	struct vxge_hw_common_reg		*common_reg;
	u32					vp_id;
#define VXGE_HW_RING_RXD_QWORDS_MODE_1	4
	u32					doorbell_cnt;
	u32					total_db_cnt;
#define VXGE_HW_RING_RXD_QWORD_LIMIT	16
	u64					rxd_qword_limit;

	struct __vxge_hw_ring_block		*rxdl;
#define VXGE_HW_RING_BUF_PER_BLOCK 	9
	u16					buf_per_block;
	u16					rxd_offset;

#define VXGE_HW_RING_RX_POLL_WEIGHT	8
	u16					rx_poll_weight;

	struct io_buffer *iobuf[VXGE_HW_RING_BUF_PER_BLOCK + 1];
	struct __vxge_hw_virtualpath *vpathh;
};

/*
 * struct __vxge_hw_virtualpath - Virtual Path
 *
 * Virtual path structure to encapsulate the data related to a virtual path.
 * Virtual paths are allocated by the HW upon getting configuration from the
 * driver and inserted into the list of virtual paths.
 */
struct __vxge_hw_virtualpath {
	u32				vp_id;

	u32				vp_open;
#define VXGE_HW_VP_NOT_OPEN	0
#define	VXGE_HW_VP_OPEN		1

	struct __vxge_hw_device		*hldev;
	struct vxge_hw_vpath_reg	*vp_reg;
	struct vxge_hw_vpmgmt_reg	*vpmgmt_reg;
	struct __vxge_hw_non_offload_db_wrapper	*nofl_db;

	u32				max_mtu;
	u32				vsport_number;
	u32				max_kdfc_db;
	u32				max_nofl_db;

	struct __vxge_hw_ring ringh;
	struct __vxge_hw_fifo fifoh;
};
#define VXGE_HW_INFO_LEN	64
#define VXGE_HW_PMD_INFO_LEN	16
#define VXGE_MAX_PRINT_BUF_SIZE	128
/**
 * struct vxge_hw_device_hw_info - Device information
 * @host_type: Host Type
 * @func_id: Function Id
 * @vpath_mask: vpath bit mask
 * @fw_version: Firmware version
 * @fw_date: Firmware Date
 * @flash_version: Firmware version
 * @flash_date: Firmware Date
 * @mac_addrs: Mac addresses for each vpath
 * @mac_addr_masks: Mac address masks for each vpath
 *
 * Returns the vpath mask that has the bits set for each vpath allocated
 * for the driver and the first mac address for each vpath
 */
struct vxge_hw_device_hw_info {
	u32		host_type;
#define VXGE_HW_NO_MR_NO_SR_NORMAL_FUNCTION			0
#define VXGE_HW_MR_NO_SR_VH0_BASE_FUNCTION			1
#define VXGE_HW_NO_MR_SR_VH0_FUNCTION0				2
#define VXGE_HW_NO_MR_SR_VH0_VIRTUAL_FUNCTION			3
#define VXGE_HW_MR_SR_VH0_INVALID_CONFIG			4
#define VXGE_HW_SR_VH_FUNCTION0					5
#define VXGE_HW_SR_VH_VIRTUAL_FUNCTION				6
#define VXGE_HW_VH_NORMAL_FUNCTION				7
	u64		function_mode;
#define VXGE_HW_FUNCTION_MODE_MIN				0
#define VXGE_HW_FUNCTION_MODE_MAX				11

#define VXGE_HW_FUNCTION_MODE_SINGLE_FUNCTION			0
#define VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION			1
#define VXGE_HW_FUNCTION_MODE_SRIOV				2
#define VXGE_HW_FUNCTION_MODE_MRIOV				3
#define VXGE_HW_FUNCTION_MODE_MRIOV_8				4
#define VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_17			5
#define VXGE_HW_FUNCTION_MODE_SRIOV_8				6
#define VXGE_HW_FUNCTION_MODE_SRIOV_4				7
#define VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_2			8
#define VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_4			9
#define VXGE_HW_FUNCTION_MODE_MRIOV_4				10
#define VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_DIRECT_IO		11

	u32		func_id;
	u64		vpath_mask;
	struct vxge_hw_device_version fw_version;
	struct vxge_hw_device_date    fw_date;
	struct vxge_hw_device_version flash_version;
	struct vxge_hw_device_date    flash_date;
	u8		serial_number[VXGE_HW_INFO_LEN];
	u8		part_number[VXGE_HW_INFO_LEN];
	u8		product_desc[VXGE_HW_INFO_LEN];
	u8 (mac_addrs)[VXGE_HW_MAX_VIRTUAL_PATHS][ETH_ALEN];
	u8 (mac_addr_masks)[VXGE_HW_MAX_VIRTUAL_PATHS][ETH_ALEN];
};

/**
 * struct __vxge_hw_device  - Hal device object
 * @magic: Magic Number
 * @bar0: BAR0 virtual address.
 * @pdev: Physical device handle
 * @config: Confguration passed by the LL driver at initialization
 * @link_state: Link state
 *
 * HW device object. Represents Titan adapter
 */
struct __vxge_hw_device {
	u32				magic;
#define VXGE_HW_DEVICE_MAGIC		0x12345678
#define VXGE_HW_DEVICE_DEAD		0xDEADDEAD
	void __iomem			*bar0;
	struct pci_device		*pdev;
	struct net_device		*ndev;
	struct vxgedev 			*vdev;

	enum vxge_hw_device_link_state	link_state;

	u32				host_type;
	u32				func_id;
	u8				titan1;
	u32				access_rights;
#define VXGE_HW_DEVICE_ACCESS_RIGHT_VPATH      0x1
#define VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM     0x2
#define VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM     0x4
	struct vxge_hw_legacy_reg	*legacy_reg;
	struct vxge_hw_toc_reg		*toc_reg;
	struct vxge_hw_common_reg	*common_reg;
	struct vxge_hw_mrpcim_reg	*mrpcim_reg;
	struct vxge_hw_srpcim_reg	*srpcim_reg \
					[VXGE_HW_TITAN_SRPCIM_REG_SPACES];
	struct vxge_hw_vpmgmt_reg	*vpmgmt_reg \
					[VXGE_HW_TITAN_VPMGMT_REG_SPACES];
	struct vxge_hw_vpath_reg	*vpath_reg \
					[VXGE_HW_TITAN_VPATH_REG_SPACES];
	u8				*kdfc;
	u8				*usdc;
	struct __vxge_hw_virtualpath	virtual_path;
	u64				vpath_assignments;
	u64				vpaths_deployed;
	u32				first_vp_id;
	u64				tim_int_mask0[4];
	u32				tim_int_mask1[4];

	struct vxge_hw_device_hw_info   hw_info;
};

#define VXGE_HW_DEVICE_LINK_STATE_SET(hldev, ls) (hldev->link_state = ls)

#define VXGE_HW_DEVICE_TIM_INT_MASK_SET(m0, m1, i) {	\
	if (i < 16) {					\
		m0[0] |= vxge_vBIT(0x8, (i*4), 4);	\
		m0[1] |= vxge_vBIT(0x4, (i*4), 4);	\
	}			       		\
	else {					\
		m1[0] = 0x80000000;		\
		m1[1] = 0x40000000;		\
	}					\
}

#define VXGE_HW_DEVICE_TIM_INT_MASK_RESET(m0, m1, i) {	\
	if (i < 16) {					\
		m0[0] &= ~vxge_vBIT(0x8, (i*4), 4);	\
		m0[1] &= ~vxge_vBIT(0x4, (i*4), 4);	\
	}						\
	else {						\
		m1[0] = 0;				\
		m1[1] = 0;				\
	}						\
}

/**
 * enum enum vxge_hw_txdl_state - Descriptor (TXDL) state.
 * @VXGE_HW_TXDL_STATE_NONE: Invalid state.
 * @VXGE_HW_TXDL_STATE_AVAIL: Descriptor is available for reservation.
 * @VXGE_HW_TXDL_STATE_POSTED: Descriptor is posted for processing by the
 * device.
 * @VXGE_HW_TXDL_STATE_FREED: Descriptor is free and can be reused for
 * filling-in and posting later.
 *
 * Titan/HW descriptor states.
 *
 */
enum vxge_hw_txdl_state {
	VXGE_HW_TXDL_STATE_NONE	= 0,
	VXGE_HW_TXDL_STATE_AVAIL	= 1,
	VXGE_HW_TXDL_STATE_POSTED	= 2,
	VXGE_HW_TXDL_STATE_FREED	= 3
};


/* fifo and ring circular buffer offset tracking apis */
static inline void __vxge_hw_desc_offset_up(u16 upper_limit,
			u16 *offset)
{
	if (++(*offset) >= upper_limit)
		*offset = 0;
}

/* rxd offset handling apis */
static inline void vxge_hw_ring_rxd_offset_up(u16 *offset)
{
	__vxge_hw_desc_offset_up(VXGE_HW_MAX_RXDS_PER_BLOCK_1,
			offset);
}
/* txd offset handling apis */
static inline void vxge_hw_fifo_txd_offset_up(u16 *offset)
{
	__vxge_hw_desc_offset_up(VXGE_HW_FIFO_TXD_DEPTH, offset);
}

/**
 * vxge_hw_ring_rxd_1b_set - Prepare 1-buffer-mode descriptor.
 * @rxdh: Descriptor handle.
 * @dma_pointer: DMA address of	a single receive buffer	this descriptor
 * should carry. Note that by the time vxge_hw_ring_rxd_1b_set is called,
 * the receive buffer should be already mapped to the device
 * @size: Size of the receive @dma_pointer buffer.
 *
 * Prepare 1-buffer-mode Rx	descriptor for posting
 * (via	vxge_hw_ring_rxd_post()).
 *
 * This	inline helper-function does not	return any parameters and always
 * succeeds.
 *
 */
static inline
void vxge_hw_ring_rxd_1b_set(struct vxge_hw_ring_rxd_1 *rxdp,
	struct io_buffer *iob, u32 size)
{
	rxdp->host_control = (intptr_t)(iob);
	rxdp->buffer0_ptr = virt_to_bus(iob->data);
	rxdp->control_1	&= ~VXGE_HW_RING_RXD_1_BUFFER0_SIZE_MASK;
	rxdp->control_1	|= VXGE_HW_RING_RXD_1_BUFFER0_SIZE(size);
}

enum vxge_hw_status vxge_hw_device_hw_info_get(
	struct pci_device *pdev,
	void __iomem *bar0,
	struct vxge_hw_device_hw_info *hw_info);

enum vxge_hw_status
__vxge_hw_vpath_fw_ver_get(
	struct vxge_hw_vpath_reg __iomem *vpath_reg,
	struct vxge_hw_device_hw_info *hw_info);

enum vxge_hw_status
__vxge_hw_vpath_card_info_get(
	struct vxge_hw_vpath_reg __iomem *vpath_reg,
	struct vxge_hw_device_hw_info *hw_info);

/**
 * vxge_hw_device_link_state_get - Get link state.
 * @devh: HW device handle.
 *
 * Get link state.
 * Returns: link state.
 */
static inline
enum vxge_hw_device_link_state vxge_hw_device_link_state_get(
	struct __vxge_hw_device *devh)
{
	return devh->link_state;
}

void vxge_hw_device_terminate(struct __vxge_hw_device *devh);

enum vxge_hw_status vxge_hw_device_initialize(
	struct __vxge_hw_device **devh,
	void *bar0,
	struct pci_device *pdev,
	u8 titan1);

enum vxge_hw_status
vxge_hw_vpath_open(struct __vxge_hw_device *hldev, struct vxge_vpath *vpath);

enum vxge_hw_status
__vxge_hw_device_vpath_reset_in_prog_check(u64 __iomem *vpath_rst_in_prog);

enum vxge_hw_status vxge_hw_vpath_close(struct __vxge_hw_virtualpath *vpath);

enum vxge_hw_status vxge_hw_vpath_reset(struct __vxge_hw_virtualpath *vpath);

enum vxge_hw_status
vxge_hw_vpath_recover_from_reset(struct __vxge_hw_virtualpath *vpath);

void
vxge_hw_vpath_enable(struct __vxge_hw_virtualpath *vpath);

enum vxge_hw_status
vxge_hw_vpath_mtu_set(struct __vxge_hw_virtualpath *vpath, u32 new_mtu);

void
vxge_hw_vpath_rx_doorbell_init(struct __vxge_hw_virtualpath *vpath);

void
__vxge_hw_device_pci_e_init(struct __vxge_hw_device *hldev);

enum vxge_hw_status
__vxge_hw_legacy_swapper_set(struct vxge_hw_legacy_reg __iomem *legacy_reg);

enum vxge_hw_status
__vxge_hw_vpath_swapper_set(struct vxge_hw_vpath_reg __iomem *vpath_reg);

enum vxge_hw_status
__vxge_hw_kdfc_swapper_set(struct vxge_hw_legacy_reg __iomem *legacy_reg,
	struct vxge_hw_vpath_reg __iomem *vpath_reg);

enum vxge_hw_status
__vxge_hw_device_register_poll(
	void __iomem	*reg,
	u64 mask, u32 max_millis);

#ifndef readq
static inline u64 readq(void __iomem *addr)
{
	u64 ret = 0;
	ret = readl(addr + 4);
	ret <<= 32;
	ret |= readl(addr);

	return ret;
}
#endif

#ifndef writeq
static inline void writeq(u64 val, void __iomem *addr)
{
	writel((u32) (val), addr);
	writel((u32) (val >> 32), (addr + 4));
}
#endif

static inline void __vxge_hw_pio_mem_write32_upper(u32 val, void __iomem *addr)
{
	writel(val, addr + 4);
}

static inline void __vxge_hw_pio_mem_write32_lower(u32 val, void __iomem *addr)
{
	writel(val, addr);
}

static inline enum vxge_hw_status
__vxge_hw_pio_mem_write64(u64 val64, void __iomem *addr,
			  u64 mask, u32 max_millis)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	__vxge_hw_pio_mem_write32_lower((u32)vxge_bVALn(val64, 32, 32), addr);
	wmb();
	__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32), addr);
	wmb();

	status = __vxge_hw_device_register_poll(addr, mask, max_millis);
	return status;
}

void
__vxge_hw_device_host_info_get(struct __vxge_hw_device *hldev);

enum vxge_hw_status
__vxge_hw_device_initialize(struct __vxge_hw_device *hldev);

enum vxge_hw_status
__vxge_hw_vpath_pci_read(
	struct __vxge_hw_virtualpath	*vpath,
	u32			phy_func_0,
	u32			offset,
	u32			*val);

enum vxge_hw_status
__vxge_hw_vpath_addr_get(
	struct vxge_hw_vpath_reg __iomem *vpath_reg,
	u8 (macaddr)[ETH_ALEN],
	u8 (macaddr_mask)[ETH_ALEN]);

u32
__vxge_hw_vpath_func_id_get(struct vxge_hw_vpmgmt_reg __iomem *vpmgmt_reg);

enum vxge_hw_status
__vxge_hw_vpath_reset_check(struct __vxge_hw_virtualpath *vpath);

enum vxge_hw_status
vxge_hw_vpath_strip_fcs_check(struct __vxge_hw_device *hldev, u64 vpath_mask);

/**
 * vxge_debug
 * @mask: mask for the debug
 * @fmt: printf like format string
 */
static const u16 debug_filter = VXGE_ERR;
#define vxge_debug(mask, fmt...) 	do { 	\
		if (debug_filter & mask)	\
			DBG(fmt); 		\
	} while (0);

#define vxge_trace() 	vxge_debug(VXGE_TRACE, "%s:%d\n", __func__, __LINE__);

enum vxge_hw_status
vxge_hw_get_func_mode(struct __vxge_hw_device *hldev, u32 *func_mode);

enum vxge_hw_status
vxge_hw_set_fw_api(struct __vxge_hw_device *hldev,
		u64 vp_id, u32 action,
		u32 offset, u64 data0, u64 data1);
void
vxge_hw_vpath_set_zero_rx_frm_len(struct __vxge_hw_device *hldev);

#endif
