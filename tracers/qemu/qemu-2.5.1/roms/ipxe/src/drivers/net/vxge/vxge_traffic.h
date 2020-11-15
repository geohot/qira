/*
 * vxge-traffic.h: iPXE driver for Neterion Inc's X3100 Series 10GbE
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

#ifndef VXGE_TRAFFIC_H
#define VXGE_TRAFFIC_H

#include <stdint.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>

#include "vxge_reg.h"
#include "vxge_version.h"

#define VXGE_HW_DTR_MAX_T_CODE		16
#define VXGE_HW_ALL_FOXES		0xFFFFFFFFFFFFFFFFULL
#define VXGE_HW_INTR_MASK_ALL		0xFFFFFFFFFFFFFFFFULL
#define	VXGE_HW_MAX_VIRTUAL_PATHS	17

#define VXGE_HW_MAX_VIRTUAL_FUNCTIONS	8

#define VXGE_HW_MAC_MAX_MAC_PORT_ID	3

#define VXGE_HW_DEFAULT_32		0xffffffff
/* frames sizes */
#define VXGE_HW_HEADER_802_2_SIZE	3
#define VXGE_HW_HEADER_SNAP_SIZE	5
#define VXGE_HW_HEADER_VLAN_SIZE	4
#define VXGE_HW_MAC_HEADER_MAX_SIZE \
			(ETH_HLEN + \
			VXGE_HW_HEADER_802_2_SIZE + \
			VXGE_HW_HEADER_VLAN_SIZE + \
			VXGE_HW_HEADER_SNAP_SIZE)

/* 32bit alignments */

/* A receive data corruption can occur resulting in either a single-bit or
double-bit ECC error being flagged in the ASIC if the starting offset of a
buffer in single buffer mode is 0x2 to 0xa. The single bit ECC error will not
lock up the card but can hide the data corruption while the double-bit ECC
error will lock up the card. Limiting the starting offset of the buffers to
0x0, 0x1 or to a value greater than 0xF will workaround this issue.
VXGE_HW_HEADER_ETHERNET_II_802_3_ALIGN of 2 causes the starting offset of
buffer to be 0x2, 0x12 and so on, to have the start of the ip header dword
aligned. The start of buffer of 0x2 will cause this problem to occur. To
avoid this problem in all cases, add 0x10 to 0x2, to ensure that the start of
buffer is outside of the problem causing offsets.
*/
#define VXGE_HW_HEADER_ETHERNET_II_802_3_ALIGN		0x12
#define VXGE_HW_HEADER_802_2_SNAP_ALIGN			2
#define VXGE_HW_HEADER_802_2_ALIGN			3
#define VXGE_HW_HEADER_SNAP_ALIGN			1

#define VXGE_HW_L3_CKSUM_OK				0xFFFF
#define VXGE_HW_L4_CKSUM_OK				0xFFFF

/* Forward declarations */
struct __vxge_hw_device;
struct __vxge_hw_virtualpath;
struct __vxge_hw_fifo;
struct __vxge_hw_ring;
struct vxge_hw_ring_rxd_1;
struct vxge_hw_fifo_txd;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/*VXGE_HW_STATUS_H*/
#define VXGE_HW_EVENT_BASE                      0
#define VXGE_LL_EVENT_BASE                      100

/**
 * enum vxge_hw_event- Enumerates slow-path HW events.
 * @VXGE_HW_EVENT_UNKNOWN: Unknown (and invalid) event.
 * @VXGE_HW_EVENT_SERR: Serious vpath hardware error event.
 * @VXGE_HW_EVENT_ECCERR: vpath ECC error event.
 * @VXGE_HW_EVENT_VPATH_ERR: Error local to the respective vpath
 * @VXGE_HW_EVENT_FIFO_ERR: FIFO Doorbell fifo error.
 * @VXGE_HW_EVENT_SRPCIM_SERR: srpcim hardware error event.
 * @VXGE_HW_EVENT_MRPCIM_SERR: mrpcim hardware error event.
 * @VXGE_HW_EVENT_MRPCIM_ECCERR: mrpcim ecc error event.
 * @VXGE_HW_EVENT_RESET_START: Privileged entity is starting device reset
 * @VXGE_HW_EVENT_RESET_COMPLETE: Device reset has been completed
 * @VXGE_HW_EVENT_SLOT_FREEZE: Slot-freeze event. Driver tries to distinguish
 * slot-freeze from the rest critical events (e.g. ECC) when it is
 * impossible to PIO read "through" the bus, i.e. when getting all-foxes.
 *
 * enum vxge_hw_event enumerates slow-path HW eventis.
 *
 * See also: struct vxge_hw_uld_cbs{}, vxge_uld_link_up_f{},
 * vxge_uld_link_down_f{}.
 */
enum vxge_hw_event {
	VXGE_HW_EVENT_UNKNOWN           = 0,
	/* HW events */
	VXGE_HW_EVENT_RESET_START       = VXGE_HW_EVENT_BASE + 1,
	VXGE_HW_EVENT_RESET_COMPLETE    = VXGE_HW_EVENT_BASE + 2,
	VXGE_HW_EVENT_LINK_DOWN         = VXGE_HW_EVENT_BASE + 3,
	VXGE_HW_EVENT_LINK_UP           = VXGE_HW_EVENT_BASE + 4,
	VXGE_HW_EVENT_ALARM_CLEARED     = VXGE_HW_EVENT_BASE + 5,
	VXGE_HW_EVENT_ECCERR            = VXGE_HW_EVENT_BASE + 6,
	VXGE_HW_EVENT_MRPCIM_ECCERR     = VXGE_HW_EVENT_BASE + 7,
	VXGE_HW_EVENT_FIFO_ERR          = VXGE_HW_EVENT_BASE + 8,
	VXGE_HW_EVENT_VPATH_ERR         = VXGE_HW_EVENT_BASE + 9,
	VXGE_HW_EVENT_CRITICAL_ERR      = VXGE_HW_EVENT_BASE + 10,
	VXGE_HW_EVENT_SERR              = VXGE_HW_EVENT_BASE + 11,
	VXGE_HW_EVENT_SRPCIM_SERR       = VXGE_HW_EVENT_BASE + 12,
	VXGE_HW_EVENT_MRPCIM_SERR       = VXGE_HW_EVENT_BASE + 13,
	VXGE_HW_EVENT_SLOT_FREEZE       = VXGE_HW_EVENT_BASE + 14,
};

#define VXGE_HW_MAX_INTR_PER_VP        4
#define VXGE_HW_VPATH_INTR_TX          0
#define VXGE_HW_VPATH_INTR_RX          1
#define VXGE_HW_VPATH_INTR_EINTA       2
#define VXGE_HW_VPATH_INTR_BMAP        3

#define VXGE_HW_BLOCK_SIZE             4096

#define VXGE_HW_TIM_UTIL_SEL_LEGACY_TX_NET_UTIL         17
#define VXGE_HW_TIM_UTIL_SEL_LEGACY_RX_NET_UTIL         18
#define VXGE_HW_TIM_UTIL_SEL_LEGACY_TX_RX_AVE_NET_UTIL  19
#define VXGE_HW_TIM_UTIL_SEL_PER_VPATH                  63

/**
 * enum vxge_hw_ring_tcode - Transfer codes returned by adapter
 * @VXGE_HW_RING_T_CODE_OK: Transfer ok.
 * @VXGE_HW_RING_T_CODE_L3_CKSUM_MISMATCH: Layer 3 checksum presentation
 *		configuration mismatch.
 * @VXGE_HW_RING_T_CODE_L4_CKSUM_MISMATCH: Layer 4 checksum presentation
 *		configuration mismatch.
 * @VXGE_HW_RING_T_CODE_L3_L4_CKSUM_MISMATCH: Layer 3 and Layer 4 checksum
 *		presentation configuration mismatch.
 * @VXGE_HW_RING_T_CODE_L3_PKT_ERR: Layer 3 error unparseable packet,
 *		such as unknown IPv6 header.
 * @VXGE_HW_RING_T_CODE_L2_FRM_ERR: Layer 2 error frame integrity
 *		error, such as FCS or ECC).
 * @VXGE_HW_RING_T_CODE_BUF_SIZE_ERR: Buffer size error the RxD buffer(
 *		s) were not appropriately sized and data loss occurred.
 * @VXGE_HW_RING_T_CODE_INT_ECC_ERR: Internal ECC error RxD corrupted.
 * @VXGE_HW_RING_T_CODE_BENIGN_OVFLOW: Benign overflow the contents of
 *		Segment1 exceeded the capacity of Buffer1 and the remainder
 *		was placed in Buffer2. Segment2 now starts in Buffer3.
 *		No data loss or errors occurred.
 * @VXGE_HW_RING_T_CODE_ZERO_LEN_BUFF: Buffer size 0 one of the RxDs
 *		assigned buffers has a size of 0 bytes.
 * @VXGE_HW_RING_T_CODE_FRM_DROP: Frame dropped either due to
 *		VPath Reset or because of a VPIN mismatch.
 * @VXGE_HW_RING_T_CODE_UNUSED: Unused
 * @VXGE_HW_RING_T_CODE_MULTI_ERR: Multiple errors more than one
 *		transfer code condition occurred.
 *
 * Transfer codes returned by adapter.
 */
enum vxge_hw_ring_tcode {
	VXGE_HW_RING_T_CODE_OK				= 0x0,
	VXGE_HW_RING_T_CODE_L3_CKSUM_MISMATCH		= 0x1,
	VXGE_HW_RING_T_CODE_L4_CKSUM_MISMATCH		= 0x2,
	VXGE_HW_RING_T_CODE_L3_L4_CKSUM_MISMATCH	= 0x3,
	VXGE_HW_RING_T_CODE_L3_PKT_ERR			= 0x5,
	VXGE_HW_RING_T_CODE_L2_FRM_ERR			= 0x6,
	VXGE_HW_RING_T_CODE_BUF_SIZE_ERR		= 0x7,
	VXGE_HW_RING_T_CODE_INT_ECC_ERR			= 0x8,
	VXGE_HW_RING_T_CODE_BENIGN_OVFLOW		= 0x9,
	VXGE_HW_RING_T_CODE_ZERO_LEN_BUFF		= 0xA,
	VXGE_HW_RING_T_CODE_FRM_DROP			= 0xC,
	VXGE_HW_RING_T_CODE_UNUSED			= 0xE,
	VXGE_HW_RING_T_CODE_MULTI_ERR			= 0xF
};


/**
 * enum enum vxge_hw_fifo_gather_code - Gather codes used in fifo TxD
 * @VXGE_HW_FIFO_GATHER_CODE_FIRST: First TxDL
 * @VXGE_HW_FIFO_GATHER_CODE_MIDDLE: Middle TxDL
 * @VXGE_HW_FIFO_GATHER_CODE_LAST: Last TxDL
 * @VXGE_HW_FIFO_GATHER_CODE_FIRST_LAST: First and Last TxDL.
 *
 * These gather codes are used to indicate the position of a TxD in a TxD list
 */
enum vxge_hw_fifo_gather_code {
	VXGE_HW_FIFO_GATHER_CODE_FIRST		= 0x2,
	VXGE_HW_FIFO_GATHER_CODE_MIDDLE		= 0x0,
	VXGE_HW_FIFO_GATHER_CODE_LAST		= 0x1,
	VXGE_HW_FIFO_GATHER_CODE_FIRST_LAST	= 0x3
};

/**
 * enum enum vxge_hw_fifo_tcode - tcodes used in fifo
 * @VXGE_HW_FIFO_T_CODE_OK: Transfer OK
 * @VXGE_HW_FIFO_T_CODE_PCI_READ_CORRUPT: PCI read transaction (either TxD or
 *             frame data) returned with corrupt data.
 * @VXGE_HW_FIFO_T_CODE_PCI_READ_FAIL:PCI read transaction was returned
 *             with no data.
 * @VXGE_HW_FIFO_T_CODE_INVALID_MSS: The host attempted to send either a
 *             frame or LSO MSS that was too long (>9800B).
 * @VXGE_HW_FIFO_T_CODE_LSO_ERROR: Error detected during TCP/UDP Large Send
	*	       Offload operation, due to improper header template,
	*	       unsupported protocol, etc.
 * @VXGE_HW_FIFO_T_CODE_UNUSED: Unused
 * @VXGE_HW_FIFO_T_CODE_MULTI_ERROR: Set to 1 by the adapter if multiple
 *             data buffer transfer errors are encountered (see below).
 *             Otherwise it is set to 0.
 *
 * These tcodes are returned in various API for TxD status
 */
enum vxge_hw_fifo_tcode {
	VXGE_HW_FIFO_T_CODE_OK			= 0x0,
	VXGE_HW_FIFO_T_CODE_PCI_READ_CORRUPT	= 0x1,
	VXGE_HW_FIFO_T_CODE_PCI_READ_FAIL	= 0x2,
	VXGE_HW_FIFO_T_CODE_INVALID_MSS		= 0x3,
	VXGE_HW_FIFO_T_CODE_LSO_ERROR		= 0x4,
	VXGE_HW_FIFO_T_CODE_UNUSED		= 0x7,
	VXGE_HW_FIFO_T_CODE_MULTI_ERROR		= 0x8
};

enum vxge_hw_status
vxge_hw_ring_replenish(struct __vxge_hw_ring *ring);

void vxge_hw_ring_rxd_post(struct __vxge_hw_ring *ring_handle,
		struct vxge_hw_ring_rxd_1 *rxdp);

void vxge_hw_fifo_txdl_buffer_set(struct __vxge_hw_fifo *fifo,
		struct vxge_hw_fifo_txd *txdp,
		struct io_buffer *iob);

void vxge_hw_fifo_txdl_post(struct __vxge_hw_fifo *fifo,
		struct vxge_hw_fifo_txd *txdp);

enum vxge_hw_status __vxge_hw_ring_create(
	struct __vxge_hw_virtualpath *vpath,
	struct __vxge_hw_ring *ring);

enum vxge_hw_status __vxge_hw_ring_delete(
	struct __vxge_hw_ring *ringh);

enum vxge_hw_status __vxge_hw_fifo_create(
	struct __vxge_hw_virtualpath *vpath,
	struct __vxge_hw_fifo *fifo);

enum vxge_hw_status
__vxge_hw_fifo_delete(struct __vxge_hw_fifo *fifo);

enum vxge_hw_status __vxge_hw_vpath_reset(
	struct __vxge_hw_device *devh, u32 vp_id);

enum vxge_hw_status
__vxge_hw_vpath_enable(struct __vxge_hw_device *devh, u32 vp_id);

void
__vxge_hw_vpath_prc_configure(struct __vxge_hw_device *hldev);

enum vxge_hw_status
__vxge_hw_vpath_kdfc_configure(struct __vxge_hw_device *devh, u32 vp_id);

enum vxge_hw_status
__vxge_hw_vpath_mac_configure(struct __vxge_hw_device *devh);

enum vxge_hw_status
__vxge_hw_vpath_tim_configure(struct __vxge_hw_device *devh, u32 vp_id);

enum vxge_hw_status
__vxge_hw_vpath_initialize(struct __vxge_hw_device *devh, u32 vp_id);

enum vxge_hw_status __vxge_hw_vp_initialize(
	struct __vxge_hw_device *hldev, u32 vp_id,
	struct __vxge_hw_virtualpath *vpath);

void __vxge_hw_vp_terminate(struct __vxge_hw_device *hldev,
			struct __vxge_hw_virtualpath *vpath);

enum vxge_hw_status
vxge_hw_device_begin_irq(struct __vxge_hw_device *hldev);

void vxge_hw_device_intr_enable(struct __vxge_hw_device *hldev);

void vxge_hw_device_intr_disable(struct __vxge_hw_device *hldev);

void vxge_hw_device_mask_all(struct __vxge_hw_device *hldev);

void vxge_hw_device_unmask_all(struct __vxge_hw_device *hldev);

void vxge_hw_vpath_doorbell_rx(struct __vxge_hw_ring *ringh);

enum vxge_hw_status vxge_hw_vpath_poll_rx(struct __vxge_hw_ring *ringh);

enum vxge_hw_status vxge_hw_vpath_poll_tx(struct __vxge_hw_fifo *fifo);

struct vxge_hw_fifo_txd *
vxge_hw_fifo_free_txdl_get(struct __vxge_hw_fifo *fifo);

#endif
