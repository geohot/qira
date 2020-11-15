/******************************************************************************
 * Copyright (c) 2007, 2012, 2013 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/
/*
 * Definitions for OHCI Controller
 *
 * USB on the PowerStation:
 *   ohci0 - port 0     -> not connected
 *   ohci0 - port 1 - 2 -> Internal connector (J60_USBINT)
 *   ohci1 - port 0     -> not connected
 *   ohci1 - port 1 - 2 -> External connector (J10_USBEXT)
 */

#ifndef USB_OHCI_H
#define USB_OHCI_H

#include <stdint.h>

struct ohci_regs {
	uint32_t rev;
	uint32_t control;
	uint32_t cmd_status;
	uint32_t intr_status;
	uint32_t intr_enable;
	uint32_t intr_disable;
	uint32_t hcca;
	uint32_t period_curr_ed;
	uint32_t cntl_head_ed;
	uint32_t cntl_curr_ed;
	uint32_t bulk_head_ed;
	uint32_t bulk_curr_ed;
	uint32_t done_head;
	uint32_t fm_interval;
	uint32_t fm_remaining;
	uint32_t fm_num;
	uint32_t period_start;
	uint32_t ls_threshold;
	uint32_t rh_desc_a;
	uint32_t rh_desc_b;
	uint32_t rh_status;
	uint32_t rh_ps[5];
} __attribute__((packed));

#define EDA_FADDR(x)     ((x & 0x7F))
#define EDA_EP(x)        ((x & 0x0F) << 7)
#define EDA_DIR_OUT      (1 << 11)
#define EDA_DIR_IN       (1 << 12)
#define EDA_LOW_SPEED    (1 << 13)
#define EDA_SKIP         (1 << 14)
#define EDA_SKIP_LE      (0x400000) /* avoiding conversions */
#define EDA_FORMAT_ISO   (1 << 15)
#define EDA_MPS(x)       ((x & 0x7FF) << 16)

#define EDA_HEADP_MASK    (0xFFFFFFFC)
#define EDA_HEADP_MASK_LE (cpu_to_le32(EDA_HEADP_MASK))
#define EDA_HEADP_HALTED  (0x1)
#define EDA_HEADP_CARRY   (0x2)

struct ohci_ed {
	uint32_t attr;
	uint32_t tailp;
	uint32_t headp;
	uint32_t next_ed;
} __attribute__((packed));

#define TDA_DONE         (1 << 17)
#define TDA_ROUNDING     (1 << 18)
#define TDA_DP_SETUP     (0 << 19)
#define TDA_DP_OUT       (1 << 19)
#define TDA_DP_IN        (1 << 20)
#define TDA_DI_NO        (0x7 << 21)
#define TDA_TOGGLE_DATA0 (0x02000000)
#define TDA_TOGGLE_DATA1 (0x03000000)
#define TDA_CC           (0xF << 28)

#define TDA_ERROR(x)         ((x) * -1)

/* Table 4-7: Completion Codes */
const char *tda_cc_error[] = {
#define USB_NOERROR TDA_ERROR(0)
	"NOERROR",
	"CRC",
	"BITSTUFFING",
	"DATATOGGLEMISMATCH",
#define USB_STALL TDA_ERROR(4)
	"STALL",
	"DEVICENOTRESPONDING",
	"PIDCHECKFAILURE",
	"UNEXPECTEDPID",
	"DATAOVERRUN",
	"DATAUNDERRUN",
	"reserved",
	"reserved",
	"BUFFEROVERRUN",
	"BUFFERUNDERRUN",
	"NOT ACCESSED",
	"NOT ACCESSED",
};

struct ohci_td {
	uint32_t attr;
	uint32_t cbp;
	uint32_t next_td;
	uint32_t be;
} __attribute__((packed));

#define	HCCA_SIZE	256
#define	HCCA_ALIGN	(HCCA_SIZE - 1)
#define HCCA_INTR_NUM   32
struct ohci_hcca {
	uint32_t  intr_table[HCCA_INTR_NUM];
	uint16_t  frame_num;
	uint16_t  pad1;
	uint32_t  done_head;
	uint32_t  reserved[120];
} __attribute__((packed));

struct ohci_pipe {
	struct ohci_ed  ed; /* has to be aligned at 16 byte address*/
	struct usb_pipe pipe;
	struct ohci_td  *td;
	void *buf;
	long ed_phys;
	long td_phys;
	long buf_phys;
	uint32_t buflen;
	uint32_t count;
	uint8_t pad[0];
}__attribute__((packed));

#define OHCI_PIPE_POOL_SIZE 4096
#define OHCI_MAX_TDS        256 /* supports 16k buffers, i.e. 64 * 256 */
#define OHCI_MAX_BULK_SIZE  4096

struct ohci_hcd {
	struct ohci_hcca *hcca;
	struct ohci_regs *regs;
	struct usb_hcd_dev *hcidev;
	struct usb_pipe *freelist;
	struct usb_pipe *end;
	struct usb_dev rhdev;
	long hcca_phys;
	void *pool;
	long pool_phys;
};

#define OHCI_CTRL_CBSR  (3 << 0)
#define OHCI_CTRL_PLE   (1 << 2)
#define OHCI_CTRL_CLE   (1 << 4)
#define OHCI_CTRL_BLE   (1 << 5)
#define OHCI_CTRL_HCFS  (3 << 6)
#define OHCI_USB_RESET   (0 << 6)
#define OHCI_USB_OPER    (2 << 6)
#define OHCI_USB_SUSPEND (3 << 6)
#define OHCI_CTRL_RWC   (1 << 9)

/* OHCI Command Status */
#define OHCI_CMD_STATUS_HCR   (1 << 0)
#define OHCI_CMD_STATUS_CLF   (1 << 1)
#define OHCI_CMD_STATUS_BLF   (1 << 2)

/* OHCI Interrupt status */
#define OHCI_INTR_STATUS_WD   (1 << 1)

/* Root Hub Descriptor A bits */
#define RHDA_NDP                 (0xFF)
#define RHDA_PSM_INDIVIDUAL      (1 << 8)
#define RHDA_NPS_ENABLE          (1 << 9)
#define RHDA_DT                  (1 << 10)
#define RHDA_OCPM_PERPORT        (1 << 11)
#define RHDA_NOCP_ENABLE         (1 << 12)

/* Root Hub Descriptor B bits */
#define RHDB_PPCM_PORT_POWER     (0xFFFE)
#define RHDB_PPCM_GLOBAL_POWER   (0x0000)

#define RH_STATUS_LPSC           (1 << 16)
#define RH_STATUS_OCIC           (1 << 17)
#define RH_STATUS_CREW           (1 << 31)

#define RH_PS_CCS                (1 <<  0)
#define RH_PS_PES                (1 <<  1)
#define RH_PS_PSS                (1 <<  2)
#define RH_PS_POCI               (1 <<  3)
#define RH_PS_PRS                (1 <<  4)
#define RH_PS_PPS                (1 <<  8)
#define RH_PS_LSDA               (1 <<  9)

#define RH_PS_CSC                (1 << 16)
#define RH_PS_PESC               (1 << 17)
#define RH_PS_PSSC               (1 << 18)
#define RH_PS_OCIC               (1 << 19)
#define RH_PS_PRSC               (1 << 20)

/*********************************************************************/
/* Values for USB Frame Timing                                       */
/* One USB frame (1ms) consists of 12000 bit-times as clock is 12MHz */
/* controller can be adjusted for performance optimization           */
/* We use standard values (OHCI spec 6.3.1, 5.1.1.4,  5.4, 7.3.4)    */
/*********************************************************************/
#define FRAME_INTERVAL		(((((11999 - 210) * 6) / 7) << 16) | 11999)
#define PERIODIC_START		((11999 * 9) / 10)


static inline struct ohci_ed *ohci_pipe_get_ed(struct usb_pipe *pipe);
static inline long ohci_pipe_get_ed_phys(struct usb_pipe *pipe);
static int ohci_alloc_pipe_pool(struct ohci_hcd *ohcd);

#endif	/* USB_OHCI_H */
