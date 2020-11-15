/*****************************************************************************
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

#include <string.h>
#include "usb.h"
#include "usb-core.h"
#include "usb-ehci.h"
#include "tools.h"
#include "paflof.h"

#undef EHCI_DEBUG
//#define EHCI_DEBUG
#ifdef EHCI_DEBUG
#define dprintf(_x ...) do { printf(_x); } while(0)
#else
#define dprintf(_x ...)
#endif

#ifdef EHCI_DEBUG
static void dump_ehci_regs(struct ehci_hcd *ehcd)
{
	struct ehci_cap_regs *cap_regs;
	struct ehci_op_regs *op_regs;

	cap_regs = ehcd->cap_regs;
	op_regs = ehcd->op_regs;

	dprintf("\n - CAPLENGTH           %02X", read_reg8(&cap_regs->caplength));
	dprintf("\n - HCIVERSION          %04X", read_reg16(&cap_regs->hciversion));
	dprintf("\n - HCSPARAMS           %08X", read_reg32(&cap_regs->hcsparams));
	dprintf("\n - HCCPARAMS           %08X", read_reg32(&cap_regs->hccparams));
	dprintf("\n - HCSP_PORTROUTE      %016llX", read_reg64(&cap_regs->portroute));
	dprintf("\n");

	dprintf("\n - USBCMD              %08X", read_reg32(&op_regs->usbcmd));
	dprintf("\n - USBSTS              %08X", read_reg32(&op_regs->usbsts));
	dprintf("\n - USBINTR             %08X", read_reg32(&op_regs->usbintr));
	dprintf("\n - FRINDEX             %08X", read_reg32(&op_regs->frindex));
	dprintf("\n - CTRLDSSEGMENT       %08X", read_reg32(&op_regs->ctrldssegment));
	dprintf("\n - PERIODICLISTBASE    %08X", read_reg32(&op_regs->periodiclistbase));
	dprintf("\n - ASYNCLISTADDR       %08X", read_reg32(&op_regs->asynclistaddr));
	dprintf("\n - CONFIGFLAG          %08X", read_reg32(&op_regs->configflag));
	dprintf("\n - PORTSC              %08X", read_reg32(&op_regs->portsc[0]));
	dprintf("\n");
}
#endif

static int ehci_hub_check_ports(struct ehci_hcd *ehcd)
{
	uint32_t num_ports, portsc, i;
	struct usb_dev *dev;

	dprintf("%s: enter\n", __func__);
	num_ports = read_reg32(&ehcd->cap_regs->hcsparams) & HCS_NPORTS_MASK;
	for (i = 0; i < num_ports; i++) {
		dprintf("%s: device %d\n", __func__, i);
		portsc = read_reg32(&ehcd->op_regs->portsc[i]);
		if (portsc & PORT_CONNECT) { /* Device present */
			dprintf("usb-ehci: Device present on port %d\n", i);
			/* Reset the port */
			portsc = read_reg32(&ehcd->op_regs->portsc[i]);
			portsc = (portsc & ~PORT_PE) | PORT_RESET;
			write_reg32(&ehcd->op_regs->portsc[i], portsc);
			SLOF_msleep(20);
			portsc = read_reg32(&ehcd->op_regs->portsc[i]);
			portsc &= ~PORT_RESET;
			write_reg32(&ehcd->op_regs->portsc[i], portsc);
			SLOF_msleep(20);
			dev = usb_devpool_get();
			dprintf("usb-ehci: allocated device %p\n", dev);
			dev->hcidev = ehcd->hcidev;
			dev->speed = USB_HIGH_SPEED; /* TODO: Check for Low/Full speed device */
			if (!setup_new_device(dev, i))
				printf("usb-ehci: unable to setup device on port %d\n", i);
		}
	}
	dprintf("%s: exit\n", __func__);
	return 0;
}

static int ehci_hcd_init(struct ehci_hcd *ehcd)
{
	uint32_t usbcmd;
	uint32_t time;
	struct ehci_framelist *fl;
	struct ehci_qh *qh_intr, *qh_async;
	int i;
	long fl_phys = 0, qh_intr_phys = 0, qh_async_phys;

	/* Reset the host controller */
	time = SLOF_GetTimer() + 250;
	usbcmd = read_reg32(&ehcd->op_regs->usbcmd);
	write_reg32(&ehcd->op_regs->usbcmd, (usbcmd & ~(CMD_PSE | CMD_ASE)) | CMD_HCRESET);
	while (time > SLOF_GetTimer())
		cpu_relax();
	usbcmd = read_reg32(&ehcd->op_regs->usbcmd);
	if (usbcmd & CMD_HCRESET) {
		printf("usb-ehci: reset failed\n");
		return -1;
	}

	/* Initialize periodic list */
	fl = SLOF_dma_alloc(sizeof(*fl));
	if (!fl) {
		printf("usb-ehci: Unable to allocate frame list\n");
		goto fail;
	}
	fl_phys = SLOF_dma_map_in(fl, sizeof(*fl), true);
	dprintf("fl %p, fl_phys %lx\n", fl, fl_phys);

	/* TODO: allocate qh pool */
	qh_intr = SLOF_dma_alloc(sizeof(*qh_intr));
	if (!qh_intr) {
		printf("usb-ehci: Unable to allocate interrupt queue head\n");
		goto fail_qh_intr;
	}
	qh_intr_phys = SLOF_dma_map_in(qh_intr, sizeof(*qh_intr), true);
	dprintf("qh_intr %p, qh_intr_phys %lx\n", qh_intr, qh_intr_phys);

	memset(qh_intr, 0, sizeof(*qh_intr));
	qh_intr->qh_ptr = QH_PTR_TERM;
	qh_intr->ep_cap2 = cpu_to_le32(0x01 << QH_SMASK_SHIFT);
	qh_intr->next_qtd = qh_intr->alt_next_qtd = QH_PTR_TERM;
	qh_intr->token = cpu_to_le32(QH_STS_HALTED);
	for (i = 0; i < FL_SIZE; i++)
		fl->fl_ptr[i] = cpu_to_le32(qh_intr_phys | EHCI_TYP_QH);
	write_reg32(&ehcd->op_regs->periodiclistbase, fl_phys);

	/* Initialize async list */
	qh_async = SLOF_dma_alloc(sizeof(*qh_async));
	if (!qh_async) {
		printf("usb-ehci: Unable to allocate async queue head\n");
		goto fail_qh_async;
	}
	qh_async_phys = SLOF_dma_map_in(qh_async, sizeof(*qh_async), true);
	dprintf("qh_async %p, qh_async_phys %lx\n", qh_async, qh_async_phys);

	memset(qh_async, 0, sizeof(*qh_async));
	qh_async->qh_ptr = cpu_to_le32(qh_async_phys | EHCI_TYP_QH);
	qh_async->ep_cap1 = cpu_to_le32(QH_CAP_H);
	qh_async->next_qtd = qh_async->alt_next_qtd = QH_PTR_TERM;
	qh_async->token = cpu_to_le32(QH_STS_HALTED);
	write_reg32(&ehcd->op_regs->asynclistaddr, qh_async_phys);
	ehcd->qh_async = qh_async;
	ehcd->qh_async_phys = qh_async_phys;
	ehcd->qh_intr = qh_intr;
	ehcd->qh_intr_phys = qh_intr_phys;
	ehcd->fl = fl;
	ehcd->fl_phys = fl_phys;

	write_reg32(&ehcd->op_regs->usbcmd, usbcmd | CMD_ASE | CMD_RUN);
	write_reg32(&ehcd->op_regs->configflag, 1);

	return 0;

fail_qh_async:
	SLOF_dma_map_out(qh_intr_phys, qh_intr, sizeof(*qh_intr));
	SLOF_dma_free(qh_intr, sizeof(*qh_intr));
fail_qh_intr:
	SLOF_dma_map_out(fl_phys, fl, sizeof(*fl));
	SLOF_dma_free(fl, sizeof(*fl));
fail:
	return -1;
}

static int ehci_hcd_exit(struct ehci_hcd *ehcd)
{
	uint32_t usbcmd;

	if (!ehcd) {
		dprintf("NULL pointer\n");
		return false;
	}

	usbcmd = read_reg32(&ehcd->op_regs->usbcmd);
	write_reg32(&ehcd->op_regs->usbcmd, usbcmd | ~CMD_RUN);
	write_reg32(&ehcd->op_regs->periodiclistbase, 0);

	if (ehcd->pool) {
		SLOF_dma_map_out(ehcd->pool_phys, ehcd->pool, EHCI_PIPE_POOL_SIZE);
		SLOF_dma_free(ehcd->pool, EHCI_PIPE_POOL_SIZE);
	}
	if (ehcd->qh_intr) {
		SLOF_dma_map_out(ehcd->qh_intr_phys, ehcd->qh_intr, sizeof(struct ehci_qh));
		SLOF_dma_free(ehcd->qh_intr, sizeof(struct ehci_qh));
	}
	if (ehcd->qh_async) {
		SLOF_dma_map_out(ehcd->qh_async_phys, ehcd->qh_async, sizeof(struct ehci_qh));
		SLOF_dma_free(ehcd->qh_async, sizeof(struct ehci_qh));
	}
	if (ehcd->fl) {
		SLOF_dma_map_out(ehcd->fl_phys, ehcd->fl, sizeof(struct ehci_framelist));
		SLOF_dma_free(ehcd->fl, sizeof(struct ehci_framelist));
	}
	return true;
}

static int ehci_alloc_pipe_pool(struct ehci_hcd *ehcd)
{
	struct ehci_pipe *epipe, *curr, *prev;
	unsigned int i, count;
	long epipe_phys = 0;

	count = EHCI_PIPE_POOL_SIZE/sizeof(*epipe);
	ehcd->pool = epipe = SLOF_dma_alloc(EHCI_PIPE_POOL_SIZE);
	if (!epipe)
		return -1;
	ehcd->pool_phys = epipe_phys = SLOF_dma_map_in(epipe, EHCI_PIPE_POOL_SIZE, true);
	dprintf("%s: epipe %p, epipe_phys %lx\n", __func__, epipe, epipe_phys);

	/* Although an array, link them */
	for (i = 0, curr = epipe, prev = NULL; i < count; i++, curr++) {
		if (prev)
			prev->pipe.next = &curr->pipe;
		curr->pipe.next = NULL;
		prev = curr;
		curr->qh_phys = epipe_phys + (curr - epipe) * sizeof(*curr) +
			offset_of(struct ehci_pipe, qh);
		dprintf("%s - %d: qh %p, qh_phys %lx\n", __func__,
			i, &curr->qh, curr->qh_phys);
	}

	if (!ehcd->freelist)
		ehcd->freelist = &epipe->pipe;
	else
		ehcd->end->next = &epipe->pipe;
	ehcd->end = &prev->pipe;

	return 0;
}

static void ehci_init(struct usb_hcd_dev *hcidev)
{
	struct ehci_hcd *ehcd;

	printf("  EHCI: Initializing\n");
	dprintf("%s: device base address %p\n", __func__, hcidev->base);

	ehcd = SLOF_alloc_mem(sizeof(*ehcd));
	if (!ehcd) {
		printf("usb-ehci: Unable to allocate memory\n");
		return;
	}
	memset(ehcd, 0, sizeof(*ehcd));

	hcidev->nextaddr = 1;
	hcidev->priv = ehcd;
	ehcd->hcidev = hcidev;
	ehcd->cap_regs = (struct ehci_cap_regs *)(hcidev->base);
	ehcd->op_regs = (struct ehci_op_regs *)(hcidev->base +
						read_reg8(&ehcd->cap_regs->caplength));
#ifdef EHCI_DEBUG
	dump_ehci_regs(ehcd);
#endif
	ehci_hcd_init(ehcd);
	ehci_hub_check_ports(ehcd);
}

static void ehci_exit(struct usb_hcd_dev *hcidev)
{
	struct ehci_hcd *ehcd;
	static int count = 0;

	dprintf("%s: enter \n", __func__);

	if (!hcidev && !hcidev->priv) {
		return;
	}
	count++;
	if (count > 1) {
		printf("%s: already called once \n", __func__);
		return;
	}
	ehcd = hcidev->priv;
	ehci_hcd_exit(ehcd);
	SLOF_free_mem(ehcd, sizeof(*ehcd));
	hcidev->priv = NULL;
}

static void ehci_detect(void)
{

}

static void ehci_disconnect(void)
{

}

static int ehci_handshake(struct ehci_hcd *ehcd, uint32_t timeout)
{
	uint32_t usbsts = 0, time;
	uint32_t usbcmd;
	mb();
	usbcmd = read_reg32(&ehcd->op_regs->usbcmd);
	/* Ring a doorbell */
	write_reg32(&ehcd->op_regs->usbcmd, usbcmd | CMD_IAAD);
	mb();
	time = SLOF_GetTimer() + timeout;
	while ((time > SLOF_GetTimer())) {
		/* Wait for controller to confirm */
		usbsts = read_reg32(&ehcd->op_regs->usbsts);
		if (usbsts & STS_IAA) {
			/* Acknowledge it, for next doorbell to work */
			write_reg32(&ehcd->op_regs->usbsts, STS_IAA);
			return true;
		}
		cpu_relax();
	}
	return false;
}

static int fill_qtd_buff(struct ehci_qtd *qtd, long data, uint32_t size)
{
	long i, rem;
	long pos = (data + 0x1000) & ~0xfff;

	qtd->buffer[0] = cpu_to_le32(PTR_U32(data));
	for (i = 1; i < 5; i++) {
		if ((data + size - 1) >= pos) {
			//dprintf("data spans page boundary: %d, %p\n", i, pos);
			qtd->buffer[i] = cpu_to_le32(pos);
			pos += 0x1000;
		} else
			break;
	}
	if ((data + size) > pos)
		rem = data + size - pos;
	else
		rem = 0;
	return rem;
}

static int ehci_send_ctrl(struct usb_pipe *pipe, struct usb_dev_req *req, void *data)
{
	struct ehci_hcd *ehcd;
	struct ehci_qtd *qtd, *qtds, *qtds_phys;
	struct ehci_pipe *epipe;
	uint32_t transfer_size = sizeof(*req);
	uint32_t datalen, pid;
	uint32_t time;
	long req_phys = 0, data_phys = 0;
	int ret = true;

	if (pipe->type != USB_EP_TYPE_CONTROL) {
		printf("usb-ehci: Not a control pipe.\n");
		return false;
	}

	ehcd = pipe->dev->hcidev->priv;
	qtds = qtd = SLOF_dma_alloc(sizeof(*qtds) * 3);
	if (!qtds) {
		printf("Error allocating qTDs.\n");
		return false;
	}
	qtds_phys = (struct ehci_qtd *)SLOF_dma_map_in(qtds, sizeof(*qtds) * 3, true);
	memset(qtds, 0, sizeof(*qtds) * 3);
	req_phys = SLOF_dma_map_in(req, sizeof(struct usb_dev_req), true);
	qtd->next_qtd = cpu_to_le32(PTR_U32(&qtds_phys[1]));
	qtd->alt_next_qtd = QH_PTR_TERM;
	qtd->token = cpu_to_le32((transfer_size << TOKEN_TBTT_SHIFT) |
			(3 << TOKEN_CERR_SHIFT) |
			(PID_SETUP << TOKEN_PID_SHIFT) |
			(QH_STS_ACTIVE << TOKEN_STATUS_SHIFT));
	fill_qtd_buff(qtd, req_phys, sizeof(*req));

	qtd++;
	datalen = cpu_to_le16(req->wLength);
	pid = (req->bmRequestType & REQT_DIR_IN) ? PID_IN : PID_OUT;
	if (datalen) {
		data_phys = SLOF_dma_map_in(data, datalen, true);
		qtd->next_qtd = cpu_to_le32(PTR_U32(&qtds_phys[2]));
		qtd->alt_next_qtd = QH_PTR_TERM;
		qtd->token = cpu_to_le32((1 << TOKEN_DT_SHIFT) |
				(datalen << TOKEN_TBTT_SHIFT) |
				(3 << TOKEN_CERR_SHIFT) |
				(pid << TOKEN_PID_SHIFT) |
				(QH_STS_ACTIVE << TOKEN_STATUS_SHIFT));
		fill_qtd_buff(qtd, data_phys, datalen);
		qtd++;
	}

	if (pid == PID_IN)
		pid = PID_OUT;
	else
		pid = PID_IN;
	qtd->next_qtd = QH_PTR_TERM;
	qtd->alt_next_qtd = QH_PTR_TERM;
	qtd->token = cpu_to_le32((1 << TOKEN_DT_SHIFT) |
			(3 << TOKEN_CERR_SHIFT) |
			(pid << TOKEN_PID_SHIFT) |
			(QH_STS_ACTIVE << TOKEN_STATUS_SHIFT));

	/* link qtd to qh and attach to ehcd */
	mb();
	epipe = container_of(pipe, struct ehci_pipe, pipe);
	epipe->qh.next_qtd = cpu_to_le32(PTR_U32(qtds_phys));
	epipe->qh.qh_ptr = cpu_to_le32(ehcd->qh_async_phys | EHCI_TYP_QH);
	epipe->qh.ep_cap1 = cpu_to_le32((pipe->mps << QH_MPS_SHIFT) |
				(pipe->speed << QH_EPS_SHIFT) |
				(pipe->epno << QH_EP_SHIFT) |
				(pipe->dev->addr << QH_DEV_ADDR_SHIFT));
	mb();

	ehcd->qh_async->qh_ptr = cpu_to_le32(epipe->qh_phys | EHCI_TYP_QH);

	/* transfer data */
	mb();
	qtd = &qtds[0];
	time = SLOF_GetTimer() + USB_TIMEOUT;
	do {
		if (le32_to_cpu(qtd->token) & (QH_STS_ACTIVE << TOKEN_STATUS_SHIFT))
			mb();
		else
			qtd++;

		if (time < SLOF_GetTimer()) { /* timed out */
			printf("usb-ehci: control transfer timed out_\n");
			ret = false;
			break;
		}
	} while (qtd->next_qtd != QH_PTR_TERM);

	ehcd->qh_async->qh_ptr = cpu_to_le32(ehcd->qh_async_phys | EHCI_TYP_QH);
	mb();
	if (!ehci_handshake(ehcd, USB_TIMEOUT)) {
		printf("%s: handshake failed\n", __func__);
		ret = false;
	}

	SLOF_dma_map_out(req_phys, req, sizeof(struct usb_dev_req));
	SLOF_dma_map_out(data_phys, data, datalen);
	SLOF_dma_map_out(PTR_U32(qtds_phys), qtds, sizeof(*qtds) * 3);
	SLOF_dma_free(qtds, sizeof(*qtds) * 3);

	return ret;
}

static int ehci_transfer_bulk(struct usb_pipe *pipe, void *td, void *td_phys,
			void *data_phys, int size)
{
	struct ehci_hcd *ehcd;
	struct ehci_qtd *qtd, *qtd_phys;
	struct ehci_pipe *epipe;
	uint32_t pid;
	int i, rem, ret = true;
	uint32_t time;
	long ptr;

	dprintf("usb-ehci: bulk transfer: data %p, size %d, td %p, td_phys %p\n",
		data_phys, size, td, td_phys);

	if (pipe->type != USB_EP_TYPE_BULK) {
		printf("usb-ehci: Not a bulk pipe.\n");
		return false;
	}

	if (size > QTD_MAX_TRANSFER_LEN) {
		printf("usb-ehci: bulk transfer size too big\n");
		return false;
	}

	ehcd = pipe->dev->hcidev->priv;
	pid = (pipe->dir == USB_PIPE_OUT) ? PID_OUT : PID_IN;
	qtd = (struct ehci_qtd *)td;
	qtd_phys = (struct ehci_qtd *)td_phys;
	ptr = (long)data_phys;
	for (i = 0; i < NUM_BULK_QTDS; i++) {
		memset(qtd, 0, sizeof(*qtd));
		rem = fill_qtd_buff(qtd, ptr, size);
		qtd->token = cpu_to_le32((1 << TOKEN_DT_SHIFT) |
				((size - rem) << TOKEN_TBTT_SHIFT) |
				(3 << TOKEN_CERR_SHIFT) |
				(pid << TOKEN_PID_SHIFT) |
				(QH_STS_ACTIVE << TOKEN_STATUS_SHIFT));
		if (rem) {
			qtd->next_qtd = cpu_to_le32(PTR_U32(&qtd_phys[i+1]));
			qtd->alt_next_qtd = QH_PTR_TERM;
			ptr += size - rem;
			size = rem;
			qtd++;
		} else {
			qtd->next_qtd = qtd->alt_next_qtd = QH_PTR_TERM;
			break; /* no more data */
		}
	}

	/* link qtd to qh and attach to ehcd */
	mb();
	epipe = container_of(pipe, struct ehci_pipe, pipe);
	epipe->qh.next_qtd = cpu_to_le32(PTR_U32(qtd_phys));
	epipe->qh.qh_ptr = cpu_to_le32(ehcd->qh_async_phys | EHCI_TYP_QH);
	epipe->qh.ep_cap1 = cpu_to_le32((pipe->mps << QH_MPS_SHIFT) |
				(pipe->speed << QH_EPS_SHIFT) |
				(pipe->epno << QH_EP_SHIFT) |
				(pipe->dev->addr << QH_DEV_ADDR_SHIFT));
	mb();

	ehcd->qh_async->qh_ptr = cpu_to_le32(epipe->qh_phys | EHCI_TYP_QH);

	/* transfer data */
	mb();
	qtd = (struct ehci_qtd *)td;
	for (i = 0; i < NUM_BULK_QTDS; i++) {
		time = SLOF_GetTimer() + USB_TIMEOUT;
		while ((time > SLOF_GetTimer()) &&
			(le32_to_cpu(qtd->token) & (QH_STS_ACTIVE << TOKEN_STATUS_SHIFT)))
			cpu_relax();
		mb();
		if (qtd->next_qtd == QH_PTR_TERM)
			break;

		if (le32_to_cpu(qtd->token) & (QH_STS_ACTIVE << TOKEN_STATUS_SHIFT)) {
			printf("usb-ehci: bulk transfer timed out_\n");
			ret = false;
			break;
		}
		qtd++;
	}

	ehcd->qh_async->qh_ptr = cpu_to_le32(ehcd->qh_async_phys | EHCI_TYP_QH);
	mb();
	if (!ehci_handshake(ehcd, USB_TIMEOUT)) {
		printf("%s: handshake failed\n", __func__);
		ret = false;
	}
	return ret;
}

static struct usb_pipe *ehci_get_pipe(struct usb_dev *dev, struct usb_ep_descr *ep,
				char *buf, size_t len)
{
	struct ehci_hcd *ehcd;
	struct usb_pipe *new = NULL;

	if (!dev)
		return NULL;

	ehcd = (struct ehci_hcd *)dev->hcidev->priv;
	if (!ehcd->freelist) {
		dprintf("usb-ehci: %s allocating pool\n", __func__);
		if (ehci_alloc_pipe_pool(ehcd))
			return NULL;
	}

	new = ehcd->freelist;
	ehcd->freelist = ehcd->freelist->next;
	if (!ehcd->freelist)
		ehcd->end = NULL;

	memset(new, 0, sizeof(*new));
	new->dev = dev;
	new->next = NULL;
	new->type = ep->bmAttributes & USB_EP_TYPE_MASK;
	new->speed = dev->speed;
	new->mps = ep->wMaxPacketSize;
	new->dir = (ep->bEndpointAddress & 0x80) >> 7;
	new->epno = ep->bEndpointAddress & 0x0f;

	return new;
}

static void ehci_put_pipe(struct usb_pipe *pipe)
{
	struct ehci_hcd *ehcd;

	dprintf("usb-ehci: %s enter - %p\n", __func__, pipe);
	if (!pipe || !pipe->dev)
		return;
	ehcd = pipe->dev->hcidev->priv;
	if (ehcd->end)
		ehcd->end->next = pipe;
	else
		ehcd->freelist = pipe;

	ehcd->end = pipe;
	pipe->next = NULL;
	pipe->dev = NULL;
	memset(pipe, 0, sizeof(*pipe));
	dprintf("usb-ehci: %s exit\n", __func__);
}

struct usb_hcd_ops ehci_ops = {
	.name          = "ehci-hcd",
	.init          = ehci_init,
	.exit          = ehci_exit,
	.detect        = ehci_detect,
	.disconnect    = ehci_disconnect,
	.get_pipe      = ehci_get_pipe,
	.put_pipe      = ehci_put_pipe,
	.send_ctrl     = ehci_send_ctrl,
	.transfer_bulk = ehci_transfer_bulk,
	.usb_type      = USB_EHCI,
	.next          = NULL,
};

void usb_ehci_register(void)
{
	usb_hcd_register(&ehci_ops);
}
