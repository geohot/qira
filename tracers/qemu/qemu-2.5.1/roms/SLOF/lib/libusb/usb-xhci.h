/******************************************************************************
 * Copyright (c) 2013 IBM Corporation
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
 * Definitions for XHCI Controller - Revision 1.0 (5/21/10)
 *
 */

#ifndef USB_XHCI_H
#define USB_XHCI_H

#include <stdint.h>
#include "usb-core.h"

#define BIT(x) (1 << x)

/* 5.3 Host Controller Capability Registers
 * Table 19
 */
struct xhci_cap_regs {
	uint8_t caplength;
	uint8_t reserved;
	uint16_t hciversion;
	uint32_t hcsparams1;
	uint32_t hcsparams2;
	uint32_t hcsparams3;
	uint32_t hccparams;
#define XHCI_HCCPARAMS_CSZ   BIT(2)
#define XHCI_HCCPARAMS_XECP(x)  ((x & 0xFFFF0000) >> 16)
	uint32_t dboff;
	uint32_t rtsoff;
} __attribute__ ((packed));

/* USB 3.0: Section 7 and 7.2 */
#define XHCI_XECP_CAP_ID(x)     ((x & 0xF))
#define XHCI_XECP_CAP_SP        2
#define XHCI_XECP_CAP_SP_MN(x)  ((x & 0xFF0000) >> 16)
#define XHCI_XECP_CAP_SP_MJ(x)  ((x & 0xFF000000) >> 24)
#define XHCI_XECP_CAP_SP_PC(x)  ((x & 0xFF00) >> 8)
#define XHCI_XECP_CAP_SP_PO(x)  (x & 0xFF)
#define XHCI_XECP_NEXT_PTR(x)   ((x & 0xFF00) >> 8)

/* Table 27: Host Controller USB Port Register Set */
struct xhci_port_regs {
	uint32_t portsc;
#define PORTSC_CCS        BIT(0)
#define PORTSC_PED        BIT(1)
#define PORTSC_OCA        BIT(3)
#define PORTSC_PR         BIT(4)
#define PORTSC_PLS_MASK   (0xF << 5)
#define PORTSC_PLS_U0         0
#define PORTSC_PLS_U1         1
#define PORTSC_PLS_U2         2
#define PORTSC_PLS_U3         3
#define PORTSC_PLS_DISABLED   4
#define PORTSC_PLS_RXDETECT   5
#define PORTSC_PLS_INACTIVE   6
#define PORTSC_PLS_POLLING    7
#define PORTSC_PLS_RECOVERY   8
#define PORTSC_PLS_HOTRESET   9
#define PORTSC_PLS_COMP_MODE  10
#define PORTSC_PLS_TEST_MODE  11
#define PORTSC_PLS_RESUME     15
#define PORTSC_PP         BIT(9)
#define PORTSC_PS_MASK    (0xF << 10)
#define PORTSC_PIC_MASK   (0x3 << 14)
#define PORTSC_LWS        BIT(16)
#define PORTSC_CSC        BIT(17)
#define PORTSC_PEC        BIT(18)
#define PORTSC_WRC        BIT(19)
#define PORTSC_OCC        BIT(20)
#define PORTSC_PRC        BIT(21)
#define PORTSC_PLC        BIT(22)
#define PORTSC_CEC        BIT(23)
#define PORTSC_CAS        BIT(24)
#define PORTSC_WCE        BIT(25)
#define PORTSC_WDE        BIT(26)
#define PORTSC_WOE        BIT(27)
#define PORTSC_DR         BIT(30)
#define PORTSC_WPR        BIT(31)

	uint32_t portpmsc;
	uint32_t portli;
	uint32_t reserved;
} __attribute__ ((packed));

struct port_state {
	bool    PP;
	bool    CCS;
	bool    PED;
	bool    PR;
	uint8_t PLS;
	char *state;
};


struct port_state ps_array_usb2[] = {
	{1, 0, 0, 0, PORTSC_PLS_U0, "ERROR"}
};

struct port_state ps_array_usb3[] = {
	{0, 0, 0, 0, PORTSC_PLS_DISABLED, "Powered-OFF"},
	{1, 0, 0, 0, PORTSC_PLS_POLLING,  "Polling"},
	{1, 0, 0, 0, PORTSC_PLS_U0,       "Polling"},
	{1, 0, 0, 0, PORTSC_PLS_RXDETECT, "***  Disconnected ***"},
	{1, 0, 0, 0, PORTSC_PLS_DISABLED, "Disabled"},
	{1, 0, 0, 0, PORTSC_PLS_INACTIVE, "Error"},
	{1, 0, 0, 0, PORTSC_PLS_TEST_MODE,"Loopback"},
	{1, 0, 0, 0, PORTSC_PLS_COMP_MODE,"Compliancek"},
	{1, 1, 0, 1, PORTSC_PLS_U0,       "******  Reset  ******"},
	{1, 1, 1, 0, PORTSC_PLS_U0,       "****** Enabled ******"},
};

/* 5.4 Host Controller Operational Registers
 * Table 26
 */
struct xhci_op_regs {
	uint32_t usbcmd;
#define XHCI_USBCMD_RS            BIT(0)
#define XHCI_USBCMD_HCRST         BIT(1)

	uint32_t usbsts;
#define XHCI_USBSTS_HCH           BIT(0)
#define XHCI_USBSTS_CNR           BIT(11)

	uint32_t pagesize;
	uint8_t reserved[8];    /* 0C - 13 */
	uint32_t dnctrl;        /* Device notification control */
	uint64_t crcr;          /* Command ring control */
#define XHCI_CRCR_CRP_MASK        0xFFFFFFFFFFFFFFC0
#define XHCI_CRCR_CRR             BIT(3)
#define XHCI_CRCR_CRP_SIZE        4096

	uint8_t reserved1[16];  /* 20 - 2F */
	uint64_t dcbaap;        /* Device Context Base Address Array Pointer */
#define XHCI_DCBAAP_MAX_SIZE      2048

	uint32_t config;         /* Configure */
#define XHCI_CONFIG_MAX_SLOT      4

	uint8_t reserved2[964]; /* 3C - 3FF */
	/* USB Port register set */
#define XHCI_PORT_MAX 256
	struct xhci_port_regs prs[XHCI_PORT_MAX];
} __attribute__ ((packed));

/*
 * 5.5.2  Interrupter Register Set
 * Table 42: Interrupter Registers
 */
struct xhci_int_regs {
	uint32_t iman;
	uint32_t imod;
	uint32_t erstsz;
#define XHCI_ERST_SIZE_MASK 0xFFFF
	uint32_t reserved;
	uint64_t erstba;
#define XHCI_ERST_ADDR_MASK (~(0x3FUL))
	uint64_t erdp;
#define XHCI_ERDP_MASK      (~(0xFUL))
} __attribute__ ((packed));

/* 5.5 Host Controller Runtime Registers */
struct xhci_run_regs {
	uint32_t mfindex;       /* microframe index */
	uint8_t reserved[28];
#define XHCI_IRS_MAX 1024
	struct xhci_int_regs irs[XHCI_IRS_MAX];
} __attribute__ ((packed));

/* 5.6 Doorbell Registers*/
struct xhci_db_regs {
	uint32_t db[256];
}  __attribute__ ((packed));

#define COMP_SUCCESS         1

#define TRB_SLOT_ID(x)       (((x) & (0xFF << 24)) >> 24)
#define TRB_CMD_SLOT_ID(x)   ((x & 0xFF) << 24)
#define TRB_TYPE(x)          (((x) & (0x3F << 10)) >> 10)
#define TRB_CMD_TYPE(x)      ((x & 0x3F)  << 10)
#define TRB_STATUS(x)        (((x) & (0xFF << 24)) >> 24)
#define TRB_ADDR_LOW(x)      ((uint32_t)((uint64_t)(x)))
#define TRB_ADDR_HIGH(x)     ((uint32_t)((uint64_t)(x) >> 32))
#define TRB_TRT(x)           (((x) & 0x3) << 16 )
#define TRB_DIR_IN           BIT(16)
#define TRB_IOC              BIT(5)
#define TRB_IDT              BIT(6)

#define TRB_CYCLE_STATE      BIT(0)

struct xhci_transfer_trb {
	uint64_t addr;
	uint32_t len;
	uint32_t flags;
} __attribute__ ((packed));

struct xhci_link_trb {
	uint64_t addr;
	uint32_t field2;
	uint32_t field3;
} __attribute__ ((packed));

/* Event TRB */
struct xhci_event_trb {
	uint64_t addr;
	uint32_t status;
	uint32_t flags;
} __attribute__ ((packed));

#define TRB_NORMAL           1
#define TRB_SETUP_STAGE      2
#define TRB_DATA_STAGE       3
#define TRB_STATUS_STAGE     4
#define TRB_ISOCH            5
#define TRB_LINK             6
#define TRB_EVENT_DATA       7
#define TRB_NOOP             8
#define TRB_ENABLE_SLOT      9
#define TRB_DISABLE_SLOT    10
#define TRB_ADDRESS_DEV     11
#define TRB_CONFIG_EP       12
#define TRB_EVAL_CNTX       13
#define TRB_TRANSFER_EVENT  32
#define TRB_CMD_COMPLETION  33
#define TRB_PORT_STATUS     34

struct xhci_command_trb {
	uint32_t field[4];
}__attribute__ ((packed));

union xhci_trb {
	struct xhci_event_trb event;
	struct xhci_transfer_trb xfer;
	struct xhci_command_trb cmd;
	struct xhci_link_trb link;
};

enum xhci_seg_type {
	TYPE_CTRL = 0,
	TYPE_BULK,
	TYPE_COMMAND,
	TYPE_EVENT,
};

struct xhci_seg {
	union xhci_trb *trbs;
	struct xhci_seg *next;
	uint64_t enq;
	uint64_t deq;
	uint64_t trbs_dma;
	uint32_t size;
	uint32_t cycle_state;
	enum xhci_seg_type type;
};

#define XHCI_TRB_SIZE          16
#define XHCI_EVENT_TRBS_SIZE   4096
#define XHCI_CONTROL_TRBS_SIZE 4096
#define XHCI_DATA_TRBS_SIZE    4096
#define XHCI_INTR_TRBS_SIZE    4096
#define XHCI_ERST_NUM_SEGS     1

#define XHCI_MAX_BULK_SIZE    0xF000

struct xhci_erst_entry {
	uint64_t addr;
	uint32_t size;
	uint32_t reserved;
} __attribute__ ((packed));

struct xhci_erst {
	struct xhci_erst_entry *entries;
	uint64_t dma;
	uint32_t num_segs; /* number of segments */
};

struct xhci_control_ctx {
	uint32_t d_flags;
	uint32_t a_flags;
	uint32_t reserved[6];
} __attribute__ ((packed));

struct xhci_slot_ctx {
	uint32_t field1;
#define	SLOT_SPEED_FS		BIT(20)
#define	SLOT_SPEED_LS		BIT(21)
#define	SLOT_SPEED_HS		BIT(22)
#define	SLOT_SPEED_SS		BIT(23)
#define LAST_CONTEXT(x)         (x << 27)

	uint32_t field2;
#define ROOT_HUB_PORT(x)        ((x & 0xff) << 16)

	uint32_t field3;
	uint32_t field4;
#define USB_DEV_ADDRESS(x)     (x & 0xFFU)
#define SLOT_STATE(x)          ((x >> 27) & 0x1FU)
#define SLOT_STATE_DIS_ENA     0
#define SLOT_STATE_DEFAULT     1
#define SLOT_STATE_ADDRESSED   2
#define SLOT_STATE_CONFIGURED  3


	uint32_t reserved[4];
} __attribute__ ((packed));

struct xhci_ep_ctx {
	uint32_t field1;
	uint32_t field2;
#define MAX_PACKET_SIZE(x)      (((x) & 0xFFFF) << 16)
#define MAX_BURST(x)            (((x) & 0xFF) << 8)
#define EP_TYPE(x)              (((x) & 0x07) << 3)
#define EP_ISOC_OUT	1
#define EP_BULK_OUT	2
#define EP_INT_OUT	3
#define EP_CTRL		4
#define EP_ISOC_IN	5
#define EP_BULK_IN	6
#define EP_INT_IN	7

#define ERROR_COUNT(x)          (((x) & 0x03) << 1)

	uint64_t deq_addr;
	uint32_t field4;
	uint32_t reserved[3];
} __attribute__ ((packed));

struct xhci_ctx {
	uint8_t type;
#define XHCI_CTX_TYPE_DEVICE  0x1
#define XHCI_CTX_TYPE_INPUT   0x2
	uint32_t size;
	uint8_t  *addr;
#define XHCI_CTX_BUF_SIZE 4096
	uint64_t dma_addr;
};

struct xhci_dev {
	struct usb_dev *dev;
	uint32_t slot_id;
	struct xhci_ctx in_ctx;
	struct xhci_ctx out_ctx;
	struct xhci_seg control;
	struct xhci_seg intr;
	struct xhci_seg bulk_in;
	struct xhci_seg bulk_out;
	uint32_t ctx_size;
};

struct xhci_hcd {
	struct xhci_cap_regs *cap_regs;
	struct xhci_op_regs  *op_regs;
	struct xhci_run_regs *run_regs;
	struct xhci_db_regs *db_regs;
	struct usb_hcd_dev *hcidev;
	struct xhci_dev xdevs[XHCI_CONFIG_MAX_SLOT + 1];
	struct usb_pipe *freelist;
	struct usb_pipe *end;
	uint64_t *dcbaap;
	uint64_t dcbaap_dma;
	struct xhci_seg ering;
	struct xhci_seg crseg;
	struct xhci_erst erst;
	uint64_t erds_dma;
	uint32_t erds_size;
	uint32_t slot_id;
	uint32_t hcc_csz_64;
	void *pool;
#define XHCI_PIPE_POOL_SIZE	4096

	long pool_phys;
};

struct xhci_pipe {
	struct usb_pipe pipe;
	struct xhci_seg *seg;
	void *buf;
	long buf_phys;
	uint32_t buflen;
};

#endif	/* USB_XHCI_H */
