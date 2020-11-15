/*
 * vxge-main.h: iPXE driver for Neterion Inc's X3100 Series 10GbE
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

#ifndef VXGE_MAIN_H
#define VXGE_MAIN_H

#include <unistd.h>
#include "vxge_traffic.h"
#include "vxge_config.h"

#define VXGE_DRIVER_NAME		"vxge"
#define VXGE_DRIVER_VENDOR		"Neterion, Inc"

#ifndef PCI_VENDOR_ID_S2IO
#define PCI_VENDOR_ID_S2IO		0x17D5
#endif

#ifndef PCI_DEVICE_ID_TITAN_WIN
#define PCI_DEVICE_ID_TITAN_WIN		0x5733
#endif

#ifndef PCI_DEVICE_ID_TITAN_UNI
#define PCI_DEVICE_ID_TITAN_UNI		0x5833
#endif

#define VXGE_HW_TITAN1_PCI_REVISION	1
#define	VXGE_HW_TITAN1A_PCI_REVISION	2

#define	VXGE_HP_ISS_SUBSYS_VENDORID	0x103C
#define	VXGE_HP_ISS_SUBSYS_DEVICEID_1	0x323B
#define	VXGE_HP_ISS_SUBSYS_DEVICEID_2	0x323C

#define	VXGE_USE_DEFAULT		0xffffffff
#define VXGE_HW_VPATH_MSIX_ACTIVE	4
#define VXGE_ALARM_MSIX_ID		2
#define VXGE_HW_RXSYNC_FREQ_CNT		4
#define VXGE_LL_RX_COPY_THRESHOLD	256
#define VXGE_DEF_FIFO_LENGTH		84

#define NO_STEERING		0
#define PORT_STEERING		0x1
#define RTH_TCP_UDP_STEERING	0x2
#define RTH_IPV4_STEERING	0x3
#define RTH_IPV6_EX_STEERING	0x4
#define RTH_BUCKET_SIZE		8

#define	TX_PRIORITY_STEERING		1
#define	TX_VLAN_STEERING		2
#define	TX_PORT_STEERING		3
#define	TX_MULTIQ_STEERING		4

#define VXGE_HW_PROM_MODE_ENABLE	1
#define VXGE_HW_PROM_MODE_DISABLE	0

#define VXGE_HW_FW_UPGRADE_DISABLE	0
#define VXGE_HW_FW_UPGRADE_ALL		1
#define VXGE_HW_FW_UPGRADE_FORCE	2
#define VXGE_HW_FUNC_MODE_DISABLE	0

#define VXGE_TTI_BTIMER_VAL 250000
#define VXGE_T1A_TTI_LTIMER_VAL 80
#define VXGE_T1A_TTI_RTIMER_VAL 400

#define VXGE_TTI_LTIMER_VAL 1000
#define VXGE_TTI_RTIMER_VAL 0
#define VXGE_RTI_BTIMER_VAL 250
#define VXGE_RTI_LTIMER_VAL 100
#define VXGE_RTI_RTIMER_VAL 0
#define VXGE_FIFO_INDICATE_MAX_PKTS VXGE_DEF_FIFO_LENGTH
#define VXGE_ISR_POLLING_CNT 	8
#define VXGE_MAX_CONFIG_DEV	0xFF
#define VXGE_EXEC_MODE_DISABLE	0
#define VXGE_EXEC_MODE_ENABLE	1
#define VXGE_MAX_CONFIG_PORT	1
#define VXGE_ALL_VID_DISABLE	0
#define VXGE_ALL_VID_ENABLE	1
#define VXGE_PAUSE_CTRL_DISABLE	0
#define VXGE_PAUSE_CTRL_ENABLE	1

#define TTI_TX_URANGE_A	5
#define TTI_TX_URANGE_B	15
#define TTI_TX_URANGE_C	40
#define TTI_TX_UFC_A	5
#define TTI_TX_UFC_B	40
#define TTI_TX_UFC_C	60
#define TTI_TX_UFC_D	100
#define TTI_T1A_TX_UFC_A	30
#define TTI_T1A_TX_UFC_B	80

/* Slope - (max_mtu - min_mtu)/(max_mtu_ufc - min_mtu_ufc) */
/* Slope - 93 */
/* 60 - 9k Mtu, 140 - 1.5k mtu */
#define TTI_T1A_TX_UFC_C(mtu)	(60 + ((VXGE_HW_MAX_MTU - mtu)/93))

/* Slope - 37 */
/* 100 - 9k Mtu, 300 - 1.5k mtu */
#define TTI_T1A_TX_UFC_D(mtu)	(100 + ((VXGE_HW_MAX_MTU - mtu)/37))

#define RTI_RX_URANGE_A		5
#define RTI_RX_URANGE_B		15
#define RTI_RX_URANGE_C		40
#define RTI_T1A_RX_URANGE_A	1
#define RTI_T1A_RX_URANGE_B	20
#define RTI_T1A_RX_URANGE_C	50
#define RTI_RX_UFC_A		1
#define RTI_RX_UFC_B		5
#define RTI_RX_UFC_C		10
#define RTI_RX_UFC_D		15
#define RTI_T1A_RX_UFC_B	20
#define RTI_T1A_RX_UFC_C	50
#define RTI_T1A_RX_UFC_D	60

/*
 * The interrupt rate is maintained at 3k per second with the moderation
 * parameters for most traffics but not all. This is the maximum interrupt
 * count per allowed per function with INTA or per vector in the case of in a
 * MSI-X 10 millisecond time period. Enabled only for Titan 1A.
 */
#define VXGE_T1A_MAX_INTERRUPT_COUNT 100

#define VXGE_ENABLE_NAPI	1
#define VXGE_DISABLE_NAPI	0
#define VXGE_LRO_MAX_BYTES 0x4000
#define VXGE_T1A_LRO_MAX_BYTES 0xC000

#define VXGE_HW_MIN_VPATH_TX_BW_SUPPORT 0
#define VXGE_HW_MAX_VPATH_TX_BW_SUPPORT 7

/* Milli secs timer period */
#define VXGE_TIMER_DELAY		10000

#define VXGE_TIMER_COUNT    	(2 * 60)

#define VXGE_LL_MAX_FRAME_SIZE(dev) ((dev)->mtu + VXGE_HW_MAC_HEADER_MAX_SIZE)

#define VXGE_REG_DUMP_BUFSIZE           65000

#define is_mf(function_mode) \
	((function_mode == VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION) ||   \
	(function_mode == VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_17) || \
	(function_mode == VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_2) ||  \
	(function_mode == VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_4))

#define is_titan1(dev_id, rev) (((dev_id == PCI_DEVICE_ID_TITAN_UNI) || \
				(dev_id == PCI_DEVICE_ID_TITAN_WIN)) && \
				(rev == VXGE_HW_TITAN1_PCI_REVISION))

/* These flags represent the devices temporary state */
#define __VXGE_STATE_RESET_CARD 	0x01
#define __VXGE_STATE_CARD_UP		0x02

#define test_bit(bit, loc) 	((bit) & (loc))
#define set_bit(bit, loc) 	do { (loc) |= (bit); } while (0);
#define clear_bit(bit, loc) 	do { (loc) &= ~(bit); } while (0);

#define msleep(n)       mdelay(n)

struct vxge_fifo {
	struct net_device	*ndev;
	struct pci_device	*pdev;
	struct __vxge_hw_fifo   *fifoh;
};

struct vxge_ring {
	struct net_device	*ndev;
	struct pci_device	*pdev;
	struct __vxge_hw_ring	*ringh;
};

struct vxge_vpath {

	struct vxge_fifo fifo;
	struct vxge_ring ring;

	/* Actual vpath id for this vpath in the device - 0 to 16 */
	int device_id;
	int is_open;
	int vp_open;
	u8 (macaddr)[ETH_ALEN];
	u8 (macmask)[ETH_ALEN];
	struct vxgedev *vdev;
	struct __vxge_hw_virtualpath *vpathh;
};

struct vxgedev {
	struct net_device	*ndev;
	struct pci_device	*pdev;
	struct __vxge_hw_device *devh;
	u8			titan1;

	unsigned long		state;

	struct vxge_vpath 	vpath;

	void __iomem 		*bar0;
	int			mtu;

	char			fw_version[VXGE_HW_FW_STRLEN];
};

void vxge_vpath_intr_enable(struct vxgedev *vdev, int vp_id);

void vxge_vpath_intr_disable(struct vxgedev *vdev, int vp_id);

int vxge_reset(struct vxgedev *vdev);

enum vxge_hw_status
vxge_xmit_compl(struct __vxge_hw_fifo *fifo_hw,
	struct vxge_hw_fifo_txd *txdp, enum vxge_hw_fifo_tcode tcode);

void vxge_close_vpaths(struct vxgedev *vdev);

int vxge_open_vpaths(struct vxgedev *vdev);

enum vxge_hw_status vxge_reset_all_vpaths(struct vxgedev *vdev);

#endif
