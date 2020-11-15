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
 * Definitions for EHCI Controller
 *
 */

#ifndef USB_EHCI_H
#define USB_EHCI_H

#include <stdint.h>
#include "usb-core.h"

#define FL_SIZE	1024

struct ehci_cap_regs {
	uint8_t  caplength;
	uint8_t  reserved;
	uint16_t hciversion;
	uint32_t hcsparams;
	uint32_t hccparams;
	uint64_t portroute;
} __attribute__ ((packed));

struct ehci_op_regs {
	uint32_t usbcmd;
	uint32_t usbsts;
	uint32_t usbintr;
	uint32_t frindex;
	uint32_t ctrldssegment;
	uint32_t periodiclistbase;
	uint32_t asynclistaddr;
	uint32_t reserved[9];
	uint32_t configflag;
	uint32_t portsc[0];
} __attribute__ ((packed));

struct ehci_framelist {
	uint32_t fl_ptr[FL_SIZE];
} __attribute__ ((packed));

struct ehci_hcd {
	struct ehci_cap_regs *cap_regs;
	struct ehci_op_regs  *op_regs;
	struct usb_hcd_dev *hcidev;
	struct ehci_qh *qh_async;
	struct ehci_qh *qh_intr;
	struct usb_pipe *freelist;
	struct usb_pipe *end;
	struct ehci_framelist *fl;
	long qh_async_phys;
	long qh_intr_phys;
	long fl_phys;
	void *pool;
	long pool_phys;
};

struct ehci_qtd {
	uint32_t next_qtd;
	uint32_t alt_next_qtd;
	uint32_t token;
	uint32_t buffer[5];
} __attribute__ ((packed));

struct ehci_qh {
	uint32_t qh_ptr;
	uint32_t ep_cap1;
	uint32_t ep_cap2;
	uint32_t curr_qtd;
	uint32_t next_qtd;
	uint32_t alt_next_qtd;
	uint32_t token;
	uint32_t buffer[5];
} __attribute__ ((packed)) __attribute__((aligned(32)));

struct ehci_pipe {
	struct ehci_qh qh;
	struct usb_pipe pipe;
	long qh_phys;
};

#define EHCI_PIPE_POOL_SIZE	4096

#define EHCI_TYP_ITD	0x00
#define EHCI_TYP_QH	0x02
#define EHCI_TYP_SITD	0x04
#define EHCI_TYP_FSTN	0x06

#define PID_OUT		0x00
#define PID_IN		0x01
#define PID_SETUP	0x02

#define HCS_NPORTS_MASK        0x000f

#define CMD_IAAD	(1 << 6)
#define CMD_ASE		(1 << 5)
#define CMD_PSE		(1 << 4)
#define CMD_FLS_MASK	(3 << 2)
#define CMD_HCRESET	(1 << 1)
#define CMD_RUN		(1 << 0)

#define STS_IAA		(1 << 5)

#define PORT_RESET	(1 << 8)
#define PORT_PE		(1 << 2)
#define PORT_CSC	(1 << 1)
#define PORT_CONNECT	(1 << 0)

#define QH_LOW_SPEED	0
#define QH_FULL_SPEED	1
#define QH_HIGH_SPEED	2

#define QH_RL_SHIFT	28
#define QH_CAP_C	(1 << 27)
#define QH_MPS_SHIFT	16
#define QH_CAP_H	(1 << 15)
#define QH_CAP_DTC	(1 << 14)
#define QH_EPS_SHIFT	12
#define QH_EP_SHIFT	8
#define QH_CAP_I	(1 << 7)
#define QH_DEV_ADDR_SHIFT	0

#define QH_PTR_TERM	__builtin_bswap32(1)
#define QH_SMASK_SHIFT	0
#define QH_STS_ACTIVE	(1 << 7)
#define QH_STS_HALTED	(1 << 6)
#define QH_STS_DBE	(1 << 5)
#define QH_STS_BABBLE	(1 << 4)
#define QH_STS_XACTERR	(1 << 3)
#define QH_STS_MMF	(1 << 2)
#define QH_STS_SXS	(1 << 1)
#define QH_STS_PING	(1 << 0)

#define NUM_BULK_QTDS		4
#define MAX_XFER_PER_QTD	(20 * 1024)
#define QTD_MAX_TRANSFER_LEN	(NUM_BULK_QTDS * MAX_XFER_PER_QTD)

#define TOKEN_DT_SHIFT		31
#define TOKEN_TBTT_SHIFT	16
#define TOKEN_IOC_SHIFT		15
#define TOKEN_CPAGE_SHIFT	12
#define TOKEN_CERR_SHIFT	10
#define TOKEN_PID_SHIFT		8
#define TOKEN_STATUS_SHIFT	0

#endif	/* USB_EHCI_H */
