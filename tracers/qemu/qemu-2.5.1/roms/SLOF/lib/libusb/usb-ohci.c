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
#include <byteorder.h>
#include "usb.h"
#include "usb-core.h"
#include "usb-ohci.h"

#undef OHCI_DEBUG
//#define OHCI_DEBUG
#ifdef OHCI_DEBUG
#define dprintf(_x ...) do { printf(_x); } while(0)
#else
#define dprintf(_x ...)
#endif

#undef OHCI_DEBUG_PACKET
//#define OHCI_DEBUG_PACKET
#ifdef OHCI_DEBUG_PACKET
#define dpprintf(_x ...) do { printf(_x); } while(0)
#else
#define dpprintf(_x ...)
#endif


/*
 * Dump OHCI register
 *
 * @param   - ohci_hcd
 * @return  -
 */
static void ohci_dump_regs(struct ohci_regs *regs)
{
	dprintf("\n - HcRevision         %08X", read_reg32(&regs->rev));
	dprintf("   - HcControl          %08X", read_reg32(&regs->control));
	dprintf("\n - HcCommandStatus    %08X", read_reg32(&regs->cmd_status));
	dprintf("   - HcInterruptStatus  %08X", read_reg32(&regs->intr_status));
	dprintf("\n - HcInterruptEnable  %08X", read_reg32(&regs->intr_enable));
	dprintf("   - HcInterruptDisable %08X", read_reg32(&regs->intr_disable));
	dprintf("\n - HcHCCA             %08X", read_reg32(&regs->hcca));
	dprintf("   - HcPeriodCurrentED  %08X", read_reg32(&regs->period_curr_ed));
	dprintf("\n - HcControlHeadED    %08X", read_reg32(&regs->cntl_head_ed));
	dprintf("   - HcControlCurrentED %08X", read_reg32(&regs->cntl_curr_ed));
	dprintf("\n - HcBulkHeadED       %08X", read_reg32(&regs->bulk_head_ed));
	dprintf("   - HcBulkCurrentED    %08X", read_reg32(&regs->bulk_curr_ed));
	dprintf("\n - HcDoneHead         %08X", read_reg32(&regs->done_head));
	dprintf("   - HcFmInterval       %08X", read_reg32(&regs->fm_interval));
	dprintf("\n - HcFmRemaining      %08X", read_reg32(&regs->fm_remaining));
	dprintf("   - HcFmNumber         %08X", read_reg32(&regs->fm_num));
	dprintf("\n - HcPeriodicStart    %08X", read_reg32(&regs->period_start));
	dprintf("   - HcLSThreshold      %08X", read_reg32(&regs->ls_threshold));
	dprintf("\n - HcRhDescriptorA    %08X", read_reg32(&regs->rh_desc_a));
	dprintf("   - HcRhDescriptorB    %08X", read_reg32(&regs->rh_desc_b));
	dprintf("\n - HcRhStatus         %08X", read_reg32(&regs->rh_status));
	dprintf("\n");
}

/*
 * OHCI Spec 5.1.1
 * OHCI Spec 7.4 Root Hub Partition
 */
static int ohci_hcd_reset(struct ohci_regs *regs)
{
	uint32_t time;

	/* USBRESET - 1sec */
	write_reg32(&regs->control, 0);
	SLOF_msleep(100);

	write_reg32(&regs->intr_disable, ~0);
	write_reg32(&regs->cmd_status, OHCI_CMD_STATUS_HCR);
	mb();

	time = 30; /* wait for not more than 30usec */
	while ((read_reg32(&regs->cmd_status) & OHCI_CMD_STATUS_HCR) != 0) {
		time--;
		if (!time) {
			printf(" ** HCD Reset failed...");
			return -1;
		}
		SLOF_usleep(1);
	}
	return 0;
}

static int ohci_hcd_init(struct ohci_hcd *ohcd)
{
	struct ohci_regs *regs;
	struct ohci_ed *ed;
	long ed_phys = 0;
	unsigned int i;
	uint32_t oldrwc;
	struct usb_dev *rhdev = NULL;
	struct usb_ep_descr ep;
	uint32_t reg;

	if (!ohcd)
		return -1;

	regs = ohcd->regs;
	rhdev = &ohcd->rhdev;
	dprintf("%s: HCCA memory %p\n", __func__, ohcd->hcca);
	dprintf("%s: OHCI Regs   %p\n", __func__, regs);

	rhdev->hcidev = ohcd->hcidev;
	ep.bmAttributes = USB_EP_TYPE_INTR;
	ep.wMaxPacketSize = 8;
	rhdev->intr = usb_get_pipe(rhdev, &ep, NULL, 0);
	if (!rhdev->intr) {
		printf("usb-ohci: oops could not allocate intr_pipe\n");
		return -1;
	}

	/*
	 * OHCI Spec 4.4: Host Controller Communications Area
	 */
	ed = ohci_pipe_get_ed(rhdev->intr);
	ed_phys = ohci_pipe_get_ed_phys(rhdev->intr);
	memset(ohcd->hcca, 0, HCCA_SIZE);
	memset(ed, 0, sizeof(struct ohci_ed));
	ed->attr = cpu_to_le32(EDA_SKIP);
	for (i = 0; i < HCCA_INTR_NUM; i++)
		ohcd->hcca->intr_table[i] = cpu_to_le32(ed_phys);

	write_reg32(&regs->hcca, ohcd->hcca_phys);
	write_reg32(&regs->cntl_head_ed, 0);
	write_reg32(&regs->bulk_head_ed, 0);

	/* OHCI Spec 7.1.2 HcControl Register */
	oldrwc = read_reg32(&regs->control) & OHCI_CTRL_RWC;
	write_reg32(&regs->control, (OHCI_CTRL_CBSR | OHCI_CTRL_CLE |
					OHCI_CTRL_BLE | OHCI_CTRL_PLE |
					OHCI_USB_OPER | oldrwc));
	SLOF_msleep(100);
	/*
	 * For JS20/21 need to rewrite it after setting it to
	 * operational state
	 */
	write_reg32(&regs->fm_interval, FRAME_INTERVAL);
	write_reg32(&regs->period_start, PERIODIC_START);
	reg = read_reg32(&regs->rh_desc_a);
	reg &= ~( RHDA_PSM_INDIVIDUAL | RHDA_OCPM_PERPORT );
	reg |= RHDA_NPS_ENABLE;
	write_reg32(&regs->rh_desc_a, reg);
	write_reg32(&regs->rh_desc_b, 0);
	mb();
	SLOF_msleep(100);
	ohci_dump_regs(regs);
	return 0;
}

/*
 * OHCI Spec 7.4 Root Hub Partition
 */
static void ohci_hub_check_ports(struct ohci_hcd *ohcd)
{
	struct ohci_regs *regs;
	struct usb_dev *dev;
	unsigned int ports, i, port_status, port_clear = 0;

	regs = ohcd->regs;
	ports = read_reg32(&regs->rh_desc_a) & RHDA_NDP;
	write_reg32(&regs->rh_status, RH_STATUS_LPSC);
	SLOF_msleep(100);
	dprintf("usb-ohci: ports connected %d\n", ports);
	for (i = 0; i < ports; i++) {
		dprintf("usb-ohci: ports scanning %d\n", i);
		port_status = read_reg32(&regs->rh_ps[i]);
		if (port_status & RH_PS_CSC) {
			if (port_status & RH_PS_CCS) {
				write_reg32(&regs->rh_ps[i], RH_PS_PRS);
				mb();
				port_clear |= RH_PS_CSC;
				dprintf("Start enumerating device\n");
				SLOF_msleep(100);
			} else
				printf("Start removing device\n");
		}
		port_status = read_reg32(&regs->rh_ps[i]);
		if (port_status & RH_PS_PRSC) {
			port_clear |= RH_PS_PRSC;
			dev = usb_devpool_get();
			dprintf("usb-ohci: Device reset, setting up %p\n", dev);
			dev->hcidev = ohcd->hcidev;
			if (!setup_new_device(dev, i))
				printf("usb-ohci: unable to setup device on port %d\n", i);
		}
		if (port_status & RH_PS_PESC) {
			port_clear |= RH_PS_PESC;
			if (port_status & RH_PS_PES)
				dprintf("enabled\n");
			else
				dprintf("disabled\n");
		}
		if (port_status & RH_PS_PSSC) {
			port_clear |= RH_PS_PESC;
			dprintf("suspended\n");
		}
		port_clear &= 0xFFFF0000;
		if (port_clear)
			write_reg32(&regs->rh_ps[i], port_clear);
	}
}

static inline struct ohci_ed *ohci_pipe_get_ed(struct usb_pipe *pipe)
{
	struct ohci_pipe *opipe;
	opipe = container_of(pipe, struct ohci_pipe, pipe);
	dpprintf("%s: ed is %p\n", __func__, &opipe->ed);
	return &opipe->ed;
}

static inline long ohci_pipe_get_ed_phys(struct usb_pipe *pipe)
{
	struct ohci_pipe *opipe;
	opipe = container_of(pipe, struct ohci_pipe, pipe);
	dpprintf("%s: ed_phys is %x\n", __func__, opipe->ed_phys);
	return opipe->ed_phys;
}

static inline struct ohci_pipe *ohci_pipe_get_opipe(struct usb_pipe *pipe)
{
	struct ohci_pipe *opipe;
	opipe = container_of(pipe, struct ohci_pipe, pipe);
	dpprintf("%s: opipe is %p\n", __func__, opipe);
	return opipe;
}

static int ohci_alloc_pipe_pool(struct ohci_hcd *ohcd)
{
	struct ohci_pipe *opipe, *curr, *prev;
	long opipe_phys = 0;
	unsigned int i, count;
#ifdef OHCI_DEBUG_PACKET
	struct usb_pipe *pipe;
#endif

	dprintf("usb-ohci: %s enter\n", __func__);
	count = OHCI_PIPE_POOL_SIZE/sizeof(*opipe);
	ohcd->pool = opipe = SLOF_dma_alloc(OHCI_PIPE_POOL_SIZE);
	if (!opipe)
		return false;

	ohcd->pool_phys = opipe_phys = SLOF_dma_map_in(opipe, OHCI_PIPE_POOL_SIZE, true);
	dprintf("usb-ohci: %s opipe %x, opipe_phys %x size %d count %d\n",
		__func__, opipe, opipe_phys, sizeof(*opipe), count);
	/* Although an array, link them*/
	for (i = 0, curr = opipe, prev = NULL; i < count; i++, curr++) {
		if (prev)
			prev->pipe.next = &curr->pipe;
		curr->pipe.next = NULL;
		prev = curr;

		if (((uint64_t)&curr->ed) % 16)
			printf("usb-ohci: Warning ED not aligned to 16byte boundary");
		curr->ed_phys = opipe_phys + (curr - opipe) * sizeof(*curr) +
			offset_of(struct ohci_pipe, ed);
	}

	if (!ohcd->freelist)
		ohcd->freelist = &opipe->pipe;
	else
		ohcd->end->next = &opipe->pipe;
	ohcd->end = &prev->pipe;

#ifdef OHCI_DEBUG_PACKET
	for (i = 0, pipe = ohcd->freelist; pipe; pipe = pipe->next)
		dprintf("usb-ohci: %d: pipe cur %p ed %p ed_phys %x\n",
			i++, pipe, ohci_pipe_get_ed(pipe),
			ohci_pipe_get_ed_phys(pipe));
#endif

	dprintf("usb-ohci: %s exit\n", __func__);
	return true;
}

static void ohci_init(struct usb_hcd_dev *hcidev)
{
	struct ohci_hcd *ohcd;

	printf("  OHCI: initializing\n");
	dprintf("%s: device base address %p\n", __func__, hcidev->base);

	ohcd = SLOF_alloc_mem(sizeof(struct ohci_hcd));
	if (!ohcd) {
		printf("usb-ohci: Unable to allocate memory\n");
		goto out;
	}

	hcidev->nextaddr = 1;
	hcidev->priv = ohcd;
	memset(ohcd, 0, sizeof(*ohcd));
	ohcd->hcidev = hcidev;
	ohcd->freelist = NULL;
	ohcd->end = NULL;
	ohcd->regs = (struct ohci_regs *)(hcidev->base);
	ohcd->hcca = SLOF_dma_alloc(sizeof(struct ohci_hcca));
	if (!ohcd->hcca || PTR_U32(ohcd->hcca) & HCCA_ALIGN) {
		printf("usb-ohci: Unable to allocate/unaligned HCCA memory %p\n",
			ohcd->hcca);
		goto out_free_hcd;
	}
	ohcd->hcca_phys = SLOF_dma_map_in(ohcd->hcca,
					sizeof(struct ohci_hcca), true);
	dprintf("usb-ohci: HCCA memory %p HCCA-dev memory %08lx\n",
		ohcd->hcca, ohcd->hcca_phys);

	ohci_hcd_reset(ohcd->regs);
	ohci_hcd_init(ohcd);
	ohci_hub_check_ports(ohcd);
	return;

out_free_hcd:
	SLOF_dma_free(ohcd->hcca, sizeof(struct ohci_hcca));
	SLOF_free_mem(ohcd, sizeof(struct ohci_hcd));
out:
	return;
}

static void ohci_exit(struct usb_hcd_dev *hcidev)
{
	struct ohci_hcd *ohcd = NULL;

	dprintf("%s: enter \n", __func__);
	if (!hcidev && !hcidev->priv)
		return;

	ohcd = hcidev->priv;
	write_reg32(&ohcd->regs->control, (OHCI_CTRL_CBSR | OHCI_USB_SUSPEND));
	SLOF_msleep(20);
	write_reg32(&ohcd->regs->hcca, cpu_to_le32(0));

	if (ohcd->pool) {
		SLOF_dma_map_out(ohcd->pool_phys, ohcd->pool, OHCI_PIPE_POOL_SIZE);
		SLOF_dma_free(ohcd->pool, OHCI_PIPE_POOL_SIZE);
	}
	if (ohcd->hcca) {
		SLOF_dma_map_out(ohcd->hcca_phys, ohcd->hcca, sizeof(struct ohci_hcca));
		SLOF_dma_free(ohcd->hcca, sizeof(struct ohci_hcca));
	}
	SLOF_free_mem(ohcd, sizeof(struct ohci_hcd));
	return;
}

static void ohci_detect(void)
{

}

static void ohci_disconnect(void)
{

}

#define OHCI_CTRL_TDS 3

static void ohci_fill_td(struct ohci_td *td, long next,
			long req, size_t size, unsigned int attr)
{
	if (size && req) {
		td->cbp = cpu_to_le32(req);
		td->be = cpu_to_le32(req + size - 1);
	} else {
		td->cbp = 0;
		td->be = 0;
	}
	td->attr = cpu_to_le32(attr);
	td->next_td = cpu_to_le32(next);

	dpprintf("%s: cbp %08X attr %08X next_td %08X be %08X\n", __func__,
		le32_to_cpu(td->cbp), le32_to_cpu(td->attr),
		le32_to_cpu(td->next_td), le32_to_cpu(td->be));
}

static void ohci_fill_ed(struct ohci_ed *ed, long headp, long tailp,
			unsigned int attr, long next_ed)
{
	ed->attr = cpu_to_le32(attr);
	ed->headp = cpu_to_le32(headp) | (ed->headp & ~EDA_HEADP_MASK_LE);
	ed->tailp = cpu_to_le32(tailp);
	ed->next_ed = cpu_to_le32(next_ed);
	dpprintf("%s: headp %08X tailp %08X next_td %08X attr %08X\n", __func__,
		le32_to_cpu(ed->headp), le32_to_cpu(ed->tailp),
		le32_to_cpu(ed->next_ed), le32_to_cpu(ed->attr));

}

static long ohci_get_td_phys(struct ohci_td *curr, struct ohci_td *start, long td_phys)
{
	dpprintf("position %d\n", curr - start);
	return td_phys + (curr - start) * sizeof(*start);
}

static long ohci_get_td_virt(struct ohci_td *curr, struct ohci_td *start, long td_virt, long total_count)
{
	dpprintf("position %d\n", curr - start);
	if ( (curr - start) >= total_count) {
		/* busted position, should ignore this */
		return 0;
	}
	return td_virt + (curr - start) * sizeof(*start);
}

/* OHCI Spec: 4.4.2.3 HccaDoneHead*/
static int ohci_process_done_head(struct ohci_hcd *ohcd,
				struct ohci_td *td_start,
				long __td_start_phys, long total_count)
{
	struct ohci_hcca *hcca;
	struct ohci_td *td_phys = NULL, *td_start_phys;
	struct ohci_td *td, *prev_td = NULL;
	uint32_t reg = 0, time = 0;
	int ret = true;
	long count;

	count = total_count;
	td_start_phys = (struct ohci_td *) __td_start_phys;
	hcca = ohcd->hcca;
	time = SLOF_GetTimer() + USB_TIMEOUT;
	dpprintf("Claiming %ld\n", count);

again:
	mb();
	/* Check if there is an interrupt */
	reg = read_reg32(&ohcd->regs->intr_status);
	while(!(reg & OHCI_INTR_STATUS_WD))
	{
		if (time < SLOF_GetTimer()) {
			printf("Timed out waiting for interrupt %x\n", reg);
			return false;
		}
		mb();
		reg = read_reg32(&ohcd->regs->intr_status);
	}

	/* Interrupt is there, read from done_head pointer */
	td_phys = (struct ohci_td *)(uint64_t) le32_to_cpu(hcca->done_head);
	if (!td_phys) {
		dprintf("Again td_phys null %ld\n");
		goto again;
	}
	hcca->done_head = 0;
	mb();

	while (td_phys && (count > 0)) {
		td = (struct ohci_td *)(uint64_t) ohci_get_td_virt(td_phys,
								td_start_phys,
								PTR_U32(td_start),
								total_count);

		if (!td) {
			printf("USB: Error TD null %p\n", td_phys);
			break;
		}
		count--;
		dprintf("Claimed %p(%p) td_start %p count %ld\n",
			td, td_phys, td_start_phys, count);
		dpprintf("%s: cbp %08X attr %08X next_td %08X be %08X\n",
			__func__,
			le32_to_cpu(td->cbp), le32_to_cpu(td->attr),
			le32_to_cpu(td->next_td), le32_to_cpu(td->be));
		mb();
		reg = (le32_to_cpu(td->attr) & TDA_CC) >> 28;
		if (reg) {
			dprintf("%s: cbp %08X attr %08X next_td %08X be %08X\n",
				__func__,
				le32_to_cpu(td->cbp), le32_to_cpu(td->attr),
				le32_to_cpu(td->next_td), le32_to_cpu(td->be));
			printf("USB: Error %s %p\n", tda_cc_error[reg], td);
			if (reg > 3) /* Return negative error code */
				ret = reg * -1;
		}
		prev_td = td;
		td_phys = (struct ohci_td *)(uint64_t) le32_to_cpu(td->next_td);
		prev_td->attr |= cpu_to_le32(TDA_DONE);
		prev_td->next_td = 0;
		mb();
	}
	/* clear the WD interrupt status */
	write_reg32(&ohcd->regs->intr_status, OHCI_INTR_STATUS_WD);
	mb();
	read_reg32(&ohcd->regs->intr_status);

	if (count > 0) {
		dpprintf("Pending count %d\n", count);
		goto again;
	}
	dprintf("TD claims done\n");
	return ret;
}

/*
 * OHCI Spec:
 *           4.2 Endpoint Descriptor
 *           4.3.1 General Transfer Descriptor
 *           5.2.8 Transfer Descriptor Queues
 */
static int ohci_send_ctrl(struct usb_pipe *pipe, struct usb_dev_req *req, void *data)
{
	struct ohci_ed *ed;
	struct ohci_td *tds, *td, *td_phys;
	struct ohci_regs *regs;
	struct ohci_hcd *ohcd;
	uint32_t datalen;
	uint32_t dir, attr = 0;
	uint32_t time;
	int ret = true, i;
	long req_phys = 0, data_phys = 0, td_next = 0, td_count = 0;
	unsigned char *dbuf;

	datalen = le16_to_cpu(req->wLength);
	dir = (req->bmRequestType & REQT_DIR_IN) ? 1 : 0;

	dprintf("usb-ohci: %s len %d DIR_IN %d\n", __func__, datalen, dir);

	tds = td = (struct ohci_td *) SLOF_dma_alloc(sizeof(*td) * OHCI_CTRL_TDS);
	td_phys = (struct ohci_td *) SLOF_dma_map_in(td, sizeof(*td) * OHCI_CTRL_TDS, true);
	memset(td, 0, sizeof(*td) * OHCI_CTRL_TDS);

	req_phys = SLOF_dma_map_in(req, sizeof(struct usb_dev_req), true);
	attr = TDA_DP_SETUP | TDA_CC | TDA_TOGGLE_DATA0;
	td_next = ohci_get_td_phys(td + 1, tds, PTR_U32(td_phys));
	ohci_fill_td(td, td_next, req_phys, sizeof(*req), attr);
	td++; td_count++;

	if (datalen) {
		data_phys = SLOF_dma_map_in(data, datalen, true);
		attr = 0;
		attr = (dir ? TDA_DP_IN : TDA_DP_OUT) | TDA_TOGGLE_DATA1 | TDA_CC;
		td_next = ohci_get_td_phys(td + 1, tds, PTR_U32(td_phys));
		ohci_fill_td(td, td_next, data_phys, datalen, attr);
		td++; td_count++;
	}

	attr = 0;
	attr = (dir ? TDA_DP_OUT : TDA_DP_IN) | TDA_CC | TDA_TOGGLE_DATA1;
	td_next = ohci_get_td_phys(td + 1, tds, PTR_U32(td_phys));
	ohci_fill_td(td, 0, 0, 0, attr);
	td_count++;

	ed = ohci_pipe_get_ed(pipe);
	attr = 0;
	attr = EDA_FADDR(pipe->dev->addr) | EDA_MPS(pipe->mps) | EDA_SKIP;
	ohci_fill_ed(ed, PTR_U32(td_phys), td_next, attr, 0);
	ed->tailp = 0; /* HACK */
	dprintf("usb-ohci: %s - td_start %x td_end %x req %x\n", __func__,
		td_phys, td_next, req_phys);
	mb();
	ed->attr &= cpu_to_le32(~EDA_SKIP);

	ohcd = pipe->dev->hcidev->priv;
	regs = ohcd->regs;
	write_reg32(&regs->cntl_head_ed, ohci_pipe_get_ed_phys(pipe));
	mb();
	write_reg32(&regs->cmd_status, OHCI_CMD_STATUS_CLF);

	time = SLOF_GetTimer() + USB_TIMEOUT;
	while ((time > SLOF_GetTimer()) &&
		((ed->headp & EDA_HEADP_MASK_LE) != ed->tailp))
		cpu_relax();

	if ((ed->headp & EDA_HEADP_MASK_LE) == ed->tailp) {
		dprintf("%s: packet sent\n", __func__);
#ifdef OHCI_DEBUG_PACKET
		dpprintf("Request: ");
		dbuf = (unsigned char *)req;
		for(i = 0; i < 8; i++)
			printf("%02X ", dbuf[i]);
		dpprintf("\n");
		if (datalen) {
			dbuf = (unsigned char *)data;
			dpprintf("Reply:   ");
			for(i = 0; i < datalen; i++)
				printf("%02X ", dbuf[i]);
			dpprintf("\n");
		}
#endif
	}
	else {
		printf("%s: timed out - failed\n", __func__);
		dpprintf("%s: headp %08X tailp %08X next_td %08X attr %08X\n",
			__func__,
			le32_to_cpu(ed->headp), le32_to_cpu(ed->tailp),
			le32_to_cpu(ed->next_ed), le32_to_cpu(ed->attr));
		printf("Request: ");
		dbuf = (unsigned char *)req;
		for(i = 0; i < 8; i++)
			printf("%02X ", dbuf[i]);
		printf("\n");
	}
	ret = ohci_process_done_head(ohcd, tds, (long)td_phys, td_count);
	mb();
	ed->attr |= cpu_to_le32(EDA_SKIP);
	mb();
	write_reg32(&regs->cntl_head_ed, 0);
	write_reg32(&regs->cntl_curr_ed, 0);

	SLOF_dma_map_out(req_phys, req, sizeof(struct usb_dev_req));
	if (datalen)
		SLOF_dma_map_out(data_phys, data, datalen);
	SLOF_dma_map_out(PTR_U32(td_phys), tds, sizeof(*td) * OHCI_CTRL_TDS);
	SLOF_dma_free(tds, sizeof(*td) * OHCI_CTRL_TDS);
	return (ret > 0) ? true : false;
}

static int ohci_transfer_bulk(struct usb_pipe *pipe, void *td_ptr,
			void *td_phys_ptr, void *data_phys, int datalen)
{
	struct ohci_ed *ed;
	struct ohci_td *td, *tds;
	struct ohci_regs *regs;
	struct ohci_hcd *ohcd;
	long td_phys = 0, td_next, ed_phys, ptr, td_count = 0;
	uint32_t dir, attr = 0, count;
	size_t len, packet_len;
	uint32_t time;
	int ret = true;

	if (pipe->type != USB_EP_TYPE_BULK) {
		printf("usb-ohci: Not a bulk pipe.\n");
		ret = false;
		goto end;
	}

	dir = (pipe->dir == USB_PIPE_OUT) ? 0 : 1;
	count = datalen / OHCI_MAX_BULK_SIZE;
	if (count > OHCI_MAX_TDS) {
		printf("usb-ohci: buffer size not supported - %d\n", datalen);
		ret = false;
		goto end;
	}

	td = tds = (struct ohci_td *) td_ptr;
	td_phys = (long)td_phys_ptr;
	dprintf("usb-ohci: %s pipe %p data_phys %p len %d DIR_IN %d td %p td_phys %p\n",
		__func__, pipe, data_phys, datalen, dir, td, td_phys);

	if (!tds) {
		printf("%s: tds NULL recieved\n", __func__);
		ret = false;
		goto end;
	}
	memset(td, 0, sizeof(*td) * OHCI_MAX_TDS);

	len = datalen;
	ptr = (long)data_phys;
	attr = 0;
	attr = (dir ? TDA_DP_IN : TDA_DP_OUT) | TDA_CC | TDA_ROUNDING;
	while (len) {
		packet_len = (OHCI_MAX_BULK_SIZE < len)? OHCI_MAX_BULK_SIZE : len;
		td_next = ohci_get_td_phys((td + 1), tds, td_phys);
		ohci_fill_td(td, td_next, ptr, packet_len, attr);
		ptr = ptr + packet_len;
		len = len - packet_len;
		td++; td_count++;
	}

	ed = ohci_pipe_get_ed(pipe);
	attr = 0;
	dir = pipe->dir ? EDA_DIR_IN : EDA_DIR_OUT;
	attr = dir | EDA_FADDR(pipe->dev->addr) | EDA_MPS(pipe->mps)
		| EDA_SKIP | pipe->dev->speed | EDA_EP(pipe->epno);
	td_next = ohci_get_td_phys(td, tds, td_phys);
	ohci_fill_ed(ed, td_phys, td_next, attr, 0);
	dprintf("usb-ohci: %s - tds %p td %p\n", __func__, td_phys, td_next);
	mb();
	ed->attr &= cpu_to_le32(~EDA_SKIP);

	ohcd = pipe->dev->hcidev->priv;
	regs = ohcd->regs;
	ed_phys = ohci_pipe_get_ed_phys(pipe);
	write_reg32(&regs->bulk_head_ed, ed_phys);
	mb();
	write_reg32(&regs->cmd_status, 0x4);

	time = SLOF_GetTimer() + USB_TIMEOUT;
	while ((time > SLOF_GetTimer()) &&
		((ed->headp & EDA_HEADP_MASK_LE) != ed->tailp))
		cpu_relax();

	if ((ed->headp & EDA_HEADP_MASK_LE) == ed->tailp)
		dprintf("%s: packet sent\n", __func__);
	else {
		dpprintf("%s: headp %08X tailp %08X next_td %08X attr %08X\n", __func__,
			 le32_to_cpu(ed->headp), le32_to_cpu(ed->tailp),
			 le32_to_cpu(ed->next_ed), le32_to_cpu(ed->attr));
	}
	mb();
	ret = ohci_process_done_head(ohcd, tds, td_phys, td_count);
	mb();
	ed->attr |= cpu_to_le32(EDA_SKIP);
	mb();
	write_reg32(&regs->bulk_head_ed, 0);
	write_reg32(&regs->bulk_curr_ed, 0);

	if (le32_to_cpu(ed->headp) & EDA_HEADP_HALTED) {
		printf("ED Halted\n");
		printf("%s: headp %08X tailp %08X next_td %08X attr %08X\n", __func__,
			le32_to_cpu(ed->headp), le32_to_cpu(ed->tailp),
			le32_to_cpu(ed->next_ed), le32_to_cpu(ed->attr));
		ed->headp &= ~cpu_to_le32(EDA_HEADP_HALTED);
		mb();
		if (ret == USB_STALL) /* Call reset recovery */
			usb_msc_resetrecovery(pipe->dev);
	}

end:
	return (ret > 0) ? true : false;
}

/* Populate the hcca intr region with periodic intr */
static int ohci_get_pipe_intr(struct usb_pipe *pipe, struct ohci_hcd *ohcd,
			char *buf, size_t buflen)
{
	struct ohci_hcca *hcca;
	struct ohci_pipe *opipe;
	struct ohci_ed *ed;
	struct usb_dev *dev;
	struct ohci_td *tds, *td;
	int32_t count = 0, i;
	uint8_t *ptr;
	uint16_t mps;
	long ed_phys, td_phys, td_next, buf_phys;

	if (!pipe || !ohcd)
		return false;

	hcca = ohcd->hcca;
	dev = pipe->dev;
	if (dev->class != DEV_HID_KEYB && dev->class != DEV_HUB)
		return false;

	opipe = ohci_pipe_get_opipe(pipe);
	ed = &(opipe->ed);
	ed_phys = opipe->ed_phys;
	mps = pipe->mps;
	ed->attr = cpu_to_le32(EDA_DIR_IN |
			       EDA_FADDR(dev->addr) |
			       dev->speed |
			       EDA_MPS(pipe->mps) |
			       EDA_SKIP |
			       EDA_EP(pipe->epno));
	dprintf("%s: pipe %p ed %p dev %p opipe %p\n", __func__,
		pipe, ed, dev, opipe);
	count = (buflen/mps) + 1;
	tds = td = SLOF_dma_alloc(sizeof(*td) * count);
	if (!tds) {
		printf("%s: alloc failed\n", __func__);
		return false;
	}
	td_phys = SLOF_dma_map_in(td, sizeof(*td) * count, false);

	memset(tds, 0, sizeof(*tds) * count);
	memset(buf, 0, buflen);
	buf_phys = SLOF_dma_map_in(buf, buflen, false);
	opipe->td = td;
	opipe->td_phys = td_phys;
	opipe->count = count;
	opipe->buf = buf;
	opipe->buflen = buflen;
	opipe->buf_phys = buf_phys;

	ptr = (uint8_t *)buf_phys;
	for (i = 0; i < count - 1; i++, ptr += mps) {
		td = &tds[i];
		td_next = ohci_get_td_phys(td + 1, &tds[0], td_phys);
		td->cbp = cpu_to_le32(PTR_U32(ptr));
		td->attr = cpu_to_le32(TDA_DP_IN | TDA_ROUNDING | TDA_CC);
		td->next_td = cpu_to_le32(td_next);
		td->be = cpu_to_le32(PTR_U32(ptr) + mps - 1);
		dprintf("td %x td++ %x ptr %x be %x\n",
			td, le32_to_cpu(td->next_td),
			ptr, (PTR_U32(ptr) + mps - 1));
	}
	td->next_td = 0;
	td_next = ohci_get_td_phys(td, &tds[0], td_phys);
	ed->headp = cpu_to_le32(td_phys);
	ed->tailp = cpu_to_le32(td_next);

	dprintf("%s: head %08X tail %08X, count %d, mps %d\n", __func__,
		le32_to_cpu(ed->headp),
		le32_to_cpu(ed->tailp),
		count, mps);
	ed->next_ed = 0;


	switch (dev->class) {
	case DEV_HID_KEYB:
		dprintf("%s: Keyboard class %d\n", __func__, dev->class);
		hcca->intr_table[0] = cpu_to_le32(ed_phys);
		hcca->intr_table[8] = cpu_to_le32(ed_phys);
		hcca->intr_table[16] = cpu_to_le32(ed_phys);
		hcca->intr_table[24] = cpu_to_le32(ed_phys);
		ed->attr &= cpu_to_le32(~EDA_SKIP);
		break;

	case DEV_HUB:
		dprintf("%s: HUB class %x\n", __func__, dev->class);
		hcca->intr_table[1] = cpu_to_le32(ed_phys);
		ed->attr &= cpu_to_le32(~EDA_SKIP);
		break;

	default:
		dprintf("%s: unhandled class %d\n", __func__, dev->class);
	}
	return true;
}

static int ohci_put_pipe_intr(struct usb_pipe *pipe, struct ohci_hcd *ohcd)
{
	struct ohci_hcca *hcca;
	struct ohci_pipe *opipe;
	struct ohci_ed *ed;
	struct usb_dev *dev;
	struct ohci_td *td;
	long ed_phys;

	if (!pipe || !ohcd)
		return false;

	hcca = ohcd->hcca;
	dev = pipe->dev;

	if (dev->class != DEV_HID_KEYB && dev->class != DEV_HUB)
		return false;

	opipe = ohci_pipe_get_opipe(pipe);
	ed = &(opipe->ed);
	ed_phys = opipe->ed_phys;
	dprintf("%s: td %p td_phys %08lx buf %p buf_phys %08lx\n", __func__,
		opipe->td, opipe->td_phys, opipe->buf, opipe->buf_phys);

	ed->attr |= cpu_to_le32(EDA_SKIP);
	mb();
	ed->headp = 0;
	ed->tailp = 0;
	ed->next_ed = 0;
	SLOF_dma_map_out(opipe->buf_phys, opipe->buf, opipe->buflen);
	SLOF_dma_map_out(opipe->td_phys, opipe->td, sizeof(*td) * opipe->count);
	SLOF_dma_free(opipe->td, sizeof(*td) * opipe->count);

	switch (dev->class) {
	case DEV_HID_KEYB:
		dprintf("%s: Keyboard class %d\n", __func__, dev->class);
		hcca->intr_table[0] = cpu_to_le32(ed_phys);
		hcca->intr_table[8] = cpu_to_le32(ed_phys);
		hcca->intr_table[16] = cpu_to_le32(ed_phys);
		hcca->intr_table[24] = cpu_to_le32(ed_phys);
		break;

	case DEV_HUB:
		dprintf("%s: HUB class %d\n", __func__, dev->class);
		hcca->intr_table[1] = cpu_to_le32(ed_phys);
		break;

	default:
		dprintf("%s: unhandled class %d\n", __func__, dev->class);
	}
	return true;
}

static int ohci_init_bulk_ed(struct usb_dev *dev, struct usb_pipe *pipe)
{
	struct ohci_pipe *opipe;
	struct ohci_ed *ed;
	uint32_t dir;

	if (!pipe || !dev)
		return false;

	opipe = ohci_pipe_get_opipe(pipe);
	ed = &(opipe->ed);
	dir = pipe->dir ? EDA_DIR_IN : EDA_DIR_OUT;

	ed->attr = cpu_to_le32(dir |
			       EDA_FADDR(dev->addr) |
			       dev->speed |
			       EDA_MPS(pipe->mps) |
			       EDA_SKIP |
			       EDA_EP(pipe->epno));

	dprintf("%s: pipe %p attr %x\n", __func__, pipe,
		le32_to_cpu(ed->attr));
	return true;
}

static struct usb_pipe *ohci_get_pipe(struct usb_dev *dev, struct usb_ep_descr *ep,
				char *buf, size_t buflen)
{
	struct ohci_hcd *ohcd;
	struct usb_pipe *new = NULL;

	dprintf("usb-ohci: %s enter %p\n", __func__, dev);
	if (!dev)
		return NULL;

	ohcd = (struct ohci_hcd *)dev->hcidev->priv;
	if (!ohcd->freelist) {
		dprintf("usb-ohci: %s allocating pool\n", __func__);
		if (!ohci_alloc_pipe_pool(ohcd))
			return NULL;
	}

	new = ohcd->freelist;
	ohcd->freelist = ohcd->freelist->next;
	if (!ohcd->freelist)
		ohcd->end = NULL;

	memset(new, 0, sizeof(*new));
	new->dev = dev;
	new->next = NULL;
	new->type = ep->bmAttributes & USB_EP_TYPE_MASK;
	new->speed = dev->speed;
	new->mps = le16_to_cpu(ep->wMaxPacketSize);
	new->epno = ep->bEndpointAddress & 0xF;
	new->dir = ep->bEndpointAddress & 0x80;
	if (new->type == USB_EP_TYPE_INTR)
		if (!ohci_get_pipe_intr(new, ohcd, buf, buflen))
			dprintf("usb-ohci: %s alloc_intr failed  %p\n",
				__func__, new);
	if (new->type == USB_EP_TYPE_BULK)
		ohci_init_bulk_ed(dev, new);

	dprintf("usb-ohci: %s exit %p\n", __func__, new);
	return new;
}

static void ohci_put_pipe(struct usb_pipe *pipe)
{
	struct ohci_hcd *ohcd;

	dprintf("usb-ohci: %s enter - %p\n", __func__, pipe);
	if (!pipe || !pipe->dev)
		return;
	ohcd = pipe->dev->hcidev->priv;
	if (ohcd->end)
		ohcd->end->next = pipe;
	else
		ohcd->freelist = pipe;

	if (pipe->type == USB_EP_TYPE_INTR)
		if (!ohci_put_pipe_intr(pipe, ohcd))
			dprintf("usb-ohci: %s alloc_intr failed  %p\n",
				__func__, pipe);

	ohcd->end = pipe;
	pipe->next = NULL;
	pipe->dev = NULL;
	memset(pipe, 0, sizeof(*pipe));
	dprintf("usb-ohci: %s exit\n", __func__);
}

static uint16_t ohci_get_last_frame(struct usb_dev *dev)
{
	struct ohci_hcd *ohcd;
	struct ohci_regs *regs;

	ohcd = dev->hcidev->priv;
	regs = ohcd->regs;
	return read_reg32(&regs->fm_num);
}

static int ohci_poll_intr(struct usb_pipe *pipe, uint8_t *data)
{
	struct ohci_pipe *opipe;
	struct ohci_ed *ed;
	struct ohci_td *head, *tail, *curr, *next;
	struct ohci_td *head_phys, *tail_phys, *curr_phys;
	uint8_t *ptr = NULL;
	unsigned int i, pos;
	static uint16_t last_frame;
	long ptr_phys = 0;
	long td_next;

	if (!pipe || last_frame == ohci_get_last_frame(pipe->dev))
		return 0;

	dprintf("%s: enter\n", __func__);

	last_frame = ohci_get_last_frame(pipe->dev);
	opipe = ohci_pipe_get_opipe(pipe);
	ed = &opipe->ed;

	head_phys = (struct ohci_td *)(long)(le32_to_cpu(ed->headp) & EDA_HEADP_MASK);
	tail_phys = (struct ohci_td *)(long)le32_to_cpu(ed->tailp);
	curr_phys = (struct ohci_td *) opipe->td_phys;
	pos = (tail_phys - curr_phys + 1) % (opipe->count - 1);
	dprintf("pos %d %ld -- %d\n", pos, (tail_phys - curr_phys + 1),
		opipe->count);
	curr = opipe->td + pos;
	head = opipe->td + (head_phys - (struct ohci_td *) opipe->td_phys);
	tail = opipe->td + (tail_phys - (struct ohci_td *) opipe->td_phys);

	/* dprintf("%08X %08X %08X %08X\n",
	   opipe->td_phys, head_phys, tail_phys, curr_phys);
	   dprintf("%08X %08X %08X %08X\n", opipe->td, head, tail, curr); */

	if (curr != head) {
		ptr = (uint8_t *) ((long)opipe->buf + pipe->mps * pos);
		ptr_phys = opipe->buf_phys + pipe->mps * pos;
		if (le32_to_cpu(*(uint32_t *)ptr) != 0) {
			for (i = 0; i < 8; i++)
				data[i] = *(ptr + i);
		}

		next = curr + 1;
		if (next == (opipe->td + opipe->count - 1))
			next = opipe->td;

		curr->attr = cpu_to_le32(TDA_DP_IN | TDA_ROUNDING | TDA_CC);
		curr->next_td = cpu_to_le32(0);
		curr->cbp = cpu_to_le32(PTR_U32(ptr_phys));
		curr->be = cpu_to_le32(PTR_U32(ptr_phys + pipe->mps - 1));
		td_next = ohci_get_td_phys(curr, opipe->td, opipe->td_phys);
		dprintf("Connecting %p to %p(phys %08lx) ptr %p, "
			"ptr_phys %08lx\n", tail, curr, td_next, ptr, ptr_phys);
		tail->next_td = cpu_to_le32(td_next);
		mb();
		ed->tailp = cpu_to_le32(td_next);
	} else
		return 0;

	dprintf("%s: exit\n", __func__);
	return 1;
}

struct usb_hcd_ops ohci_ops = {
	.name        = "ohci-hcd",
	.init        = ohci_init,
	.exit        = ohci_exit,
	.detect      = ohci_detect,
	.disconnect  = ohci_disconnect,
	.get_pipe    = ohci_get_pipe,
	.put_pipe    = ohci_put_pipe,
	.send_ctrl   = ohci_send_ctrl,
	.transfer_bulk = ohci_transfer_bulk,
	.poll_intr   = ohci_poll_intr,
	.usb_type    = USB_OHCI,
	.next        = NULL,
};

void usb_ohci_register(void)
{
	usb_hcd_register(&ohci_ops);
}
