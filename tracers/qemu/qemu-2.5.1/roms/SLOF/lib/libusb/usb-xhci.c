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
#include "usb-xhci.h"
#include "tools.h"
#include "paflof.h"

#undef XHCI_DEBUG
//#define XHCI_DEBUG
#ifdef XHCI_DEBUG
#define dprintf(_x ...) do { printf("%s: ", __func__); printf(_x); } while (0)
#else
#define dprintf(_x ...)
#endif

static void dump_xhci_regs(struct xhci_hcd *xhcd)
{
#ifdef XHCI_DEBUG
	struct xhci_cap_regs *cap;
	struct xhci_op_regs *op;
	struct xhci_run_regs *run;

	cap = xhcd->cap_regs;
	op = xhcd->op_regs;
	run = xhcd->run_regs;

	dprintf("\n");
	dprintf(" - CAPLENGTH           %02X\n", read_reg8 (&cap->caplength));
	dprintf(" - HCIVERSION          %04X\n", read_reg16(&cap->hciversion));
	dprintf(" - HCSPARAMS1          %08X\n", read_reg32(&cap->hcsparams1));
	dprintf(" - HCSPARAMS2          %08X\n", read_reg32(&cap->hcsparams2));
	dprintf(" - HCSPARAMS3          %08X\n", read_reg32(&cap->hcsparams3));
	dprintf(" - HCCPARAMS           %08X\n", read_reg32(&cap->hccparams));
	dprintf(" - DBOFF               %08X\n", read_reg32(&cap->dboff));
	dprintf(" - RTSOFF              %08X\n", read_reg32(&cap->rtsoff));
	dprintf("\n");

	dprintf(" - USBCMD              %08X\n", read_reg32(&op->usbcmd));
	dprintf(" - USBSTS              %08X\n", read_reg32(&op->usbsts));
	dprintf(" - PAGESIZE            %08X\n", read_reg32(&op->pagesize));
	dprintf(" - DNCTRL              %08X\n", read_reg32(&op->dnctrl));
	dprintf(" - CRCR              %016llX\n", read_reg64(&op->crcr));
	dprintf(" - DCBAAP            %016llX\n", read_reg64(&op->dcbaap));
	dprintf(" - CONFIG              %08X\n", read_reg32(&op->config));
	dprintf("\n");

	dprintf(" - MFINDEX             %08X\n", read_reg32(&run->mfindex));
	dprintf("\n");
#endif
}

static void print_port_status(struct xhci_port_regs *prs)
{
#ifdef XHCI_DEBUG
	uint32_t portsc;
	uint32_t CCS, PED, PP, PLS, i, PR = 0;

	portsc = read_reg32(&prs->portsc);
	dprintf("portsc %08x portpmsc %08x portli %08x\n",
		portsc,
		read_reg32(&prs->portpmsc),
		read_reg32(&prs->portli));

	if (portsc & PORTSC_CCS) {
		printf("CCS ");
		CCS = 1;
	}
	if (portsc & PORTSC_PED) {
		printf("PED ");
		PED = 1;
	}
	if (portsc & PORTSC_OCA)
		printf("OCA ");
	if (portsc & PORTSC_PR)
		printf("OCA ");
	PLS = (portsc & PORTSC_PLS_MASK) >> 5;
	printf("PLS:%d ", PLS);
	if (portsc & PORTSC_PP) {
		printf("PP ");
		PP = 1;
	}
	printf("PS:%d ", (portsc & PORTSC_PS_MASK) >> 10);
	printf("PIC:%d ", (portsc & PORTSC_PIC_MASK) >> 14);
	if (portsc & PORTSC_LWS)
		printf("LWS ");
	if (portsc & PORTSC_CSC)
		printf("CSC ");
	if (portsc & PORTSC_PEC)
		printf("PEC ");
	if (portsc & PORTSC_WRC)
		printf("WRC ");
	if (portsc & PORTSC_OCC)
		printf("OCC ");
	if (portsc & PORTSC_PRC)
		printf("PRC ");
	if (portsc & PORTSC_PLC)
		printf("PLC ");
	if (portsc & PORTSC_CEC)
		printf("CEC ");
	if (portsc & PORTSC_CAS)
		printf("CAS ");
	if (portsc & PORTSC_WCE)
		printf("WCE ");
	if (portsc & PORTSC_WDE)
		printf("WDE ");
	if (portsc & PORTSC_WOE)
		printf("WOE ");
	if (portsc & PORTSC_DR)
		printf("DR ");
	if (portsc & PORTSC_WPR)
		printf("WPR ");
	printf("\n");

	for (i = 0 ; i < (sizeof(ps_array_usb3)/sizeof(struct port_state)); i++) {
		if (PP == ps_array_usb3[i].PP) {
			if (CCS == ps_array_usb3[i].CCS) {
				if (PED == ps_array_usb3[i].PED) {
					if (PR == ps_array_usb3[i].PR) {
						dprintf("%s - PLS %d\n", ps_array_usb3[i].state, PLS);
						break;
					}
				}
			}
		}
	}
#endif

}

static inline bool xhci_is_hc_ready(uint32_t *usbsts)
{
	return !(read_reg32(usbsts) & XHCI_USBSTS_CNR);
}

static inline bool xhci_wait_for_cnr(uint32_t *usbsts)
{
	/* Standard:
	 * Note: The xHC should halt within 16 ms. of software clearing the
	 * R/S bit to ‘0’.
	 * Give some more time... 32ms
	 */
	int count = 320;
	dprintf("Waiting for Controller ready ..");
	while (!xhci_is_hc_ready(usbsts)) {
		dprintf(".");
		count--;
		if (!count) {
			dprintf("  failed %08X\n", read_reg32(usbsts));
			return false;
		}
		SLOF_usleep(100);
	}
	dprintf("  done\n");
	return true;
}

static bool xhci_hcd_set_runstop(struct xhci_op_regs *op, bool run_req)
{
	uint32_t reg;

	dprintf("Request %s\n", run_req ? "RUN" : "STOP");
	if (!xhci_is_hc_ready(&op->usbsts)) {
		dprintf("Controller not ready\n");
		return false;
	}

	reg = read_reg32(&op->usbcmd);
	if (run_req)
		reg |= run_req;
	else
		reg &= (uint32_t)~1;
	dprintf("writing %08X\n", reg);
	write_reg32(&op->usbcmd, reg);
	mb();
	xhci_wait_for_cnr(&op->usbsts);
	return true;
}

static bool xhci_hcd_reset(struct xhci_op_regs *op)
{
	uint32_t reg;

	/* Check if the controller is halted, else halt it */
	if (!(read_reg32(&op->usbsts) & XHCI_USBSTS_HCH)) {
		dprintf("HCHalted not set\n");
		if (!xhci_hcd_set_runstop(op, false))
			return false;
	}

	if (read_reg32(&op->usbsts) & XHCI_USBSTS_CNR) {
		dprintf("Controller not ready\n");
		return false;
	}

	reg = read_reg32(&op->usbcmd) | XHCI_USBCMD_HCRST;
	/* Ready to Reset the controller now */
	write_reg32(&op->usbcmd, reg);
	xhci_wait_for_cnr(&op->usbsts);
	return true;
}

static void xhci_handle_cmd_completion(struct xhci_hcd *xhcd,
				struct xhci_event_trb *event)
{
	uint32_t flags, slot_id, status;

	status = le32_to_cpu(event->status);
	flags = le32_to_cpu(event->flags);
	slot_id = TRB_SLOT_ID(flags);
	if (TRB_STATUS(status) == COMP_SUCCESS)
		xhcd->slot_id = slot_id;
	else
		xhcd->slot_id = 0;
}

static uint64_t xhci_poll_event(struct xhci_hcd *xhcd,
				uint32_t event_type)
{
	struct xhci_event_trb *event;
	uint64_t val, retval = 0;
	uint32_t flags, time;
	int index;

	mb();
	event = (struct xhci_event_trb *)xhcd->ering.deq;
	flags = le32_to_cpu(event->flags);

	dprintf("Reading from event ptr %p %08x\n", event, flags);
	time = SLOF_GetTimer() + USB_TIMEOUT;

	while ((flags & TRB_CYCLE_STATE) != xhcd->ering.cycle_state) {
		mb();
		flags = le32_to_cpu(event->flags);
		if (time < SLOF_GetTimer())
			return 0;
	}

	mb();
	flags = le32_to_cpu(event->flags);
	switch(TRB_TYPE(flags))
	{
	case TRB_CMD_COMPLETION:
		dprintf("CMD Completion\n");
		xhci_handle_cmd_completion(xhcd, event);
		break;
	case TRB_PORT_STATUS:
		dprintf("Port status event\n");
		break;
	case TRB_TRANSFER_EVENT:
		dprintf("XFER event addr %16lx, status %08x, flags %08x\n",
			le64_to_cpu(event->addr),
			le32_to_cpu(event->status),
			le32_to_cpu(event->flags));
		break;
	default:
		printf("TRB_TYPE  %d\n", TRB_TYPE(flags));
		dprintf("Event addr %16lx, status %08x, flags %08x state %d\n",
			le64_to_cpu(event->addr),
			le32_to_cpu(event->status),
			flags, xhcd->ering.cycle_state);
		break;
	}
	xhcd->ering.deq = (uint64_t) (event + 1);
	retval = le64_to_cpu(event->addr);

	event->addr = 0;
	event->status = 0;
	event->flags = cpu_to_le32(xhcd->ering.cycle_state);

	index = xhcd->ering.deq - (uint64_t)xhcd->ering.trbs;
	val = xhcd->ering.trbs_dma;
	val += (index % XHCI_EVENT_TRBS_SIZE);
	if (!(index % XHCI_EVENT_TRBS_SIZE)) {
		xhcd->ering.deq = (uint64_t)xhcd->ering.trbs;
		xhcd->ering.cycle_state = xhcd->ering.cycle_state ? 0 : 1;
		dprintf("Rounding %d\n", xhcd->ering.cycle_state);
	}
	dprintf("Update start %x deq %x index %d\n",
		xhcd->ering.trbs_dma, val, index/sizeof(*event));
	write_reg64(&xhcd->run_regs->irs[0].erdp, val);

	if (retval == 0)
		return (uint64_t)event;
	else
		return retval;
}

static void xhci_send_cmd(struct xhci_hcd *xhcd, uint32_t field1,
			uint32_t field2, uint32_t field3, uint32_t field4)
{
	struct xhci_db_regs *dbr;
	struct xhci_command_trb *cmd;
	uint32_t val, cycle_state;

	dbr = xhcd->db_regs;
	cmd = (struct xhci_command_trb *)xhcd->crseg.enq;

	cmd->field[0] = cpu_to_le32(field1);
	cmd->field[1] = cpu_to_le32(field2);
	cmd->field[2] = cpu_to_le32(field3);

	val = le32_to_cpu(cmd->field[3]);
	cycle_state = (val & 0x1) ? 0 : 1;
	val = field4 | cycle_state;
	cmd->field[3] = cpu_to_le32(val);

	dprintf("CMD %016lx val %08x cycle_state %d field1 %08x, field2  %08x, field3 %08x field4 %08x\n",
		cmd, val, cycle_state,
		le32_to_cpu(cmd->field[0]),
		le32_to_cpu(cmd->field[1]),
		le32_to_cpu(cmd->field[2]),
		le32_to_cpu(cmd->field[3])
		);

	/* Ring the doorbell */
	write_reg32(&dbr->db[0], 0);
	xhci_poll_event(xhcd, 0);
	cmd++;
	xhcd->crseg.enq = (uint64_t)cmd;
	return;
}

static void xhci_send_enable_slot(struct xhci_hcd *xhcd, uint32_t port)
{
	uint32_t field1, field2, field3, field4;

	field1 = 0;
	field2 = 0;
	field3 = 0;
	field4 = TRB_CMD_TYPE(TRB_ENABLE_SLOT);
	xhci_send_cmd(xhcd, field1, field2, field3, field4);
}

static void xhci_send_addr_device(struct xhci_hcd *xhcd, uint32_t slot_id,
			uint64_t dma_in_ctx)
{
	uint32_t field1, field2, field3, field4;

	dprintf("Address device %lx, low %x, high %x\n", dma_in_ctx,
		TRB_ADDR_LOW(dma_in_ctx),
		TRB_ADDR_HIGH(dma_in_ctx));
	field1 = TRB_ADDR_LOW(dma_in_ctx) & ~0xF;
	field2 = TRB_ADDR_HIGH(dma_in_ctx);
	field3 = 0;
	field4 = TRB_CMD_TYPE(TRB_ADDRESS_DEV) | TRB_CMD_SLOT_ID(slot_id);
	xhci_send_cmd(xhcd, field1, field2, field3, field4);
}

static uint32_t xhci_get_epno(struct usb_pipe *pipe)
{
	uint32_t x_epno;
	x_epno = pipe->dir | 2 * pipe->epno;
	dprintf("EPno %d:%d DIR %d\n", pipe->epno, x_epno, pipe->dir);
	return x_epno;
}

static void xhci_configure_ep(struct xhci_hcd *xhcd, uint32_t slot_id,
			uint64_t dma_in_ctx)
{
	uint32_t field1, field2, field3, field4;

	dprintf("Configure EP %lx, low %x, high %x\n", dma_in_ctx,
		TRB_ADDR_LOW(dma_in_ctx),
		TRB_ADDR_HIGH(dma_in_ctx));
	field1 = TRB_ADDR_LOW(dma_in_ctx) & ~0xF;
	field2 = TRB_ADDR_HIGH(dma_in_ctx);
	field3 = 0;
	field4 = TRB_CMD_TYPE(TRB_CONFIG_EP) | TRB_CMD_SLOT_ID(slot_id);
	xhci_send_cmd(xhcd, field1, field2, field3, field4);
}

static void xhci_init_seg(struct xhci_seg *seg, uint32_t size, uint32_t type)
{
	struct xhci_link_trb *link;

	seg->size = size / XHCI_TRB_SIZE;
	seg->next = NULL;
	seg->type = type;
	seg->cycle_state = 1;
	seg->enq = (uint64_t)seg->trbs;
	seg->deq = (uint64_t)seg->trbs;
	memset((void *)seg->trbs, 0, size);

	if (type != TYPE_EVENT) {
		link =(struct xhci_link_trb *) (seg->trbs + seg->size - 1);
		link->addr = cpu_to_le64(seg->trbs_dma);
		link->field2 = 0;
		link->field3 = cpu_to_le32(0x1 | TRB_CMD_TYPE(TRB_LINK));
	}
	return;
}

static bool xhci_alloc_seg(struct xhci_seg *seg, uint32_t size, uint32_t type)
{
	seg->trbs = (union xhci_trb *)SLOF_dma_alloc(size);
	if (!seg->trbs) {
		dprintf("Alloc failed\n");
		return false;
	}
	xhci_init_seg(seg, size, type);
	seg->trbs_dma = SLOF_dma_map_in((void *)seg->trbs, size, false);

	dprintf(" TRBs %016lX TRBS-DMA %016lX\n", seg->trbs, seg->trbs_dma);
	return true;
}

static void xhci_free_seg(struct xhci_seg *seg, uint32_t size)
{
	if (seg->trbs) {
		dprintf(" TRBs %016lX TRBS-DMA %016lX size %x\n", seg->trbs, seg->trbs_dma, size);
		SLOF_dma_map_out(seg->trbs_dma, (void *)seg->trbs, size);
		SLOF_dma_free((void *)seg->trbs, size);
	}
	memset(seg, 0, sizeof(*seg));
}

#define CTX_SIZE(x)  ( (x) ? 64 : 32 )

static bool xhci_alloc_ctx(struct xhci_ctx *ctx, uint32_t size, uint32_t type)
{
	ctx->addr = (uint8_t *)SLOF_dma_alloc(size);
	if (!ctx->addr) {
		dprintf("Alloc failed\n");
		return false;
	}
	ctx->size = size;
	ctx->type = type;
	memset((void *)ctx->addr, 0, size);
	ctx->dma_addr = SLOF_dma_map_in((void *)ctx->addr, size, false);
	dprintf("ctx %llx, ctx_dma %llx\n", ctx->addr, ctx->dma_addr);
	return true;
}

static struct xhci_control_ctx *xhci_get_control_ctx(struct xhci_ctx *ctx)
{
	if (ctx->type == XHCI_CTX_TYPE_INPUT)
		return (struct xhci_control_ctx *) ctx->addr;
	return NULL;
}

static struct xhci_slot_ctx *xhci_get_slot_ctx(struct xhci_ctx *ctx, uint32_t ctx_size)
{
	uint32_t offset = 0;

	if (ctx->type == XHCI_CTX_TYPE_INPUT)
		offset += ctx_size;
	return (struct xhci_slot_ctx *)(ctx->addr + offset);
}

static struct xhci_ep_ctx *xhci_get_ep0_ctx(struct xhci_ctx *ctx, uint32_t ctx_size)
{
	uint32_t offset = 0;

	offset = ctx_size;
	if (ctx->type == XHCI_CTX_TYPE_INPUT)
		offset += ctx_size;
	return (struct xhci_ep_ctx *)(ctx->addr + offset);
}

static struct xhci_ep_ctx *xhci_get_ep_ctx(struct xhci_ctx *ctx, uint32_t ctx_size,
					uint32_t epno)
{
	uint32_t offset = 0;

	offset = ctx_size * epno;
	if (ctx->type == XHCI_CTX_TYPE_INPUT)
		offset += ctx_size;
	return (struct xhci_ep_ctx *)(ctx->addr + offset);
}

static void xhci_free_ctx(struct xhci_ctx *ctx, uint32_t size)
{
	SLOF_dma_map_out(ctx->dma_addr, (void *)ctx->addr, size);
	SLOF_dma_free((void *)ctx->addr, size);
}

static uint32_t usb_control_max_packet(uint32_t speed)
{
	uint32_t max_packet = 0;

	switch(speed)
	{
	case USB_LOW_SPEED:
		max_packet = 8;
		break;
	case USB_FULL_SPEED:
		max_packet = 8;
		break;
	case USB_HIGH_SPEED:
		max_packet = 64;
		break;
	case USB_SUPER_SPEED:
		max_packet = 512;
		break;
	default:
		/* should not reach here */
		dprintf("Unknown speed\n");
	}
	return max_packet;
}

static bool xhci_alloc_dev(struct xhci_hcd *xhcd, uint32_t slot_id, uint32_t port)
{
	struct usb_dev *dev;
	struct xhci_dev *xdev;
	struct xhci_slot_ctx *slot;
	struct xhci_control_ctx *ctrl;
	struct xhci_ep_ctx *ep0;
	uint32_t ctx_size, val;
	uint16_t max_packet;
	uint32_t newport;

	ctx_size = CTX_SIZE(xhcd->hcc_csz_64);
	xdev = &xhcd->xdevs[slot_id];
	xdev->slot_id = slot_id;
	xdev->ctx_size = ctx_size;

	/* 4.3.3 Device Slot initialization */
	/* Step 1 */
	if (!xhci_alloc_ctx(&xdev->in_ctx, XHCI_CTX_BUF_SIZE, XHCI_CTX_TYPE_INPUT)) {
		dprintf("Failed allocating in_ctx\n");
		return false;
	}

	/* Step 2 */
	ctrl = xhci_get_control_ctx(&xdev->in_ctx);
	ctrl->a_flags = cpu_to_le32(0x3);          /* A0, A1 */
	ctrl->d_flags = 0;

	/* Step 3 */
	slot = xhci_get_slot_ctx(&xdev->in_ctx, ctx_size);
	newport = port + 1;
	val = LAST_CONTEXT(1) | SLOT_SPEED_SS | (newport << 16); /* FIXME speed, read from PS */
	slot->field1 = cpu_to_le32(val);
	slot->field2 = cpu_to_le32(ROOT_HUB_PORT(newport)); /* FIXME how to get port no */

	/* Step 4 */
	if (!xhci_alloc_seg(&xdev->control, XHCI_CONTROL_TRBS_SIZE, TYPE_CTRL)) {
		dprintf("Failed allocating control\n");
		goto fail_in_ctx;
	}

	/* Step 5 */
	ep0 = xhci_get_ep0_ctx(&xdev->in_ctx, ctx_size);
	val = 0;
	max_packet = usb_control_max_packet(USB_SUPER_SPEED);
	max_packet = 64;
	val = EP_TYPE(EP_CTRL) | MAX_BURST(0) | ERROR_COUNT(3) |
		MAX_PACKET_SIZE(max_packet);
	ep0->field2 = cpu_to_le32(val);;
	ep0->deq_addr = cpu_to_le64(xdev->control.trbs_dma | xdev->control.cycle_state);
	ep0->field4 = cpu_to_le32(8);

	/* Step 6 */
	if (!xhci_alloc_ctx(&xdev->out_ctx, XHCI_CTX_BUF_SIZE, XHCI_CTX_TYPE_DEVICE)) {
		dprintf("Failed allocating out_ctx\n");
		goto fail_control_seg;
	}

	/* Step 7 */
	xhcd->dcbaap[slot_id] = cpu_to_le64(xdev->out_ctx.dma_addr);

	/* Step 8 */
	slot = xhci_get_slot_ctx(&xdev->out_ctx, ctx_size);
	ep0 = xhci_get_ep0_ctx(&xdev->out_ctx, ctx_size);

	dprintf("Slot State %x \n", SLOT_STATE(le32_to_cpu(slot->field4)));
	xhci_send_addr_device(xhcd, slot_id, xdev->in_ctx.dma_addr);
	mb();
	dprintf("Slot State %x \n", SLOT_STATE(le32_to_cpu(slot->field4)));

	dprintf("EP0 f0 %08X f1 %08X %016lX %08X\n",
		le32_to_cpu(ep0->field1),
		le32_to_cpu(ep0->field2),
		le64_to_cpu(ep0->deq_addr),
		le32_to_cpu(ep0->field4));

	/* Step 9 - configure ep */
	ctrl->a_flags = cpu_to_le32(0x1);          /* A0 */
	ctrl->d_flags = 0;
	xhci_configure_ep(xhcd, slot_id, xdev->in_ctx.dma_addr);
	mb();
	dprintf("Slot State %x \n", SLOT_STATE(le32_to_cpu(slot->field4)));
	dprintf("USB Device address %d \n", USB_DEV_ADDRESS(le32_to_cpu(slot->field4)));
	dprintf("EP0 f0 %08X f1 %08X %016lX %08X\n",
		le32_to_cpu(ep0->field1),
		le32_to_cpu(ep0->field2),
		le64_to_cpu(ep0->deq_addr),
		le32_to_cpu(ep0->field4));

	dev = usb_devpool_get();
	dprintf("allocated device %p\n", dev);
	dev->hcidev = xhcd->hcidev;
	dev->speed = USB_SUPER_SPEED;
	dev->addr = USB_DEV_ADDRESS(slot->field4);
	dev->port = newport;
	dev->priv = xdev;
	xdev->dev = dev;
	if (setup_new_device(dev, newport))
		return true;

	xhci_free_ctx(&xdev->out_ctx, XHCI_CTX_BUF_SIZE);
fail_control_seg:
	xhci_free_seg(&xdev->control, XHCI_CONTROL_TRBS_SIZE);
fail_in_ctx:
	xhci_free_ctx(&xdev->in_ctx, XHCI_CTX_BUF_SIZE);
	return false;
}

static void xhci_free_dev(struct xhci_dev *xdev)
{
	xhci_free_seg(&xdev->bulk_in, XHCI_DATA_TRBS_SIZE);
	xhci_free_seg(&xdev->bulk_out, XHCI_DATA_TRBS_SIZE);
	xhci_free_seg(&xdev->intr, XHCI_INTR_TRBS_SIZE);
	xhci_free_seg(&xdev->control, XHCI_CONTROL_TRBS_SIZE);
	xhci_free_ctx(&xdev->in_ctx, XHCI_CTX_BUF_SIZE);
	xhci_free_ctx(&xdev->out_ctx, XHCI_CTX_BUF_SIZE);
}

static bool usb3_dev_init(struct xhci_hcd *xhcd, uint32_t port)
{
	/* Device enable slot */
	xhci_send_enable_slot(xhcd, port);
	if (!xhcd->slot_id) {
		dprintf("Unable to get slot id\n");
		return false;
	}
	dprintf("SLOT ID: %d\n", xhcd->slot_id);
	if (!xhci_alloc_dev(xhcd, xhcd->slot_id, port)) {
		dprintf("Unable to allocate device\n");
		return false;
	}
	return true;
}

static int xhci_device_present(uint32_t portsc, uint32_t usb_ver)
{
	if (usb_ver == USB_XHCI) {
		/* Device present and enabled state */
		if ((portsc & PORTSC_CCS) &&
			(portsc & PORTSC_PP) &&
			(portsc & PORTSC_PED)) {
			return true;
		}
	} else if (usb_ver == USB_EHCI) {
		/* Device present and in disabled state */
		if ((portsc & PORTSC_CCS) && (portsc & PORTSC_CSC))
			return true;
	}
	return false;
}

static int xhci_port_scan(struct xhci_hcd *xhcd,
			uint32_t usb_ver)
{
	uint32_t num_ports, portsc, i;
	struct xhci_op_regs *op;
	struct xhci_port_regs *prs;
	struct xhci_cap_regs *cap;
	uint32_t xecp_off;
	uint32_t *xecp_addr, *base;
	uint32_t port_off = 0, port_cnt;

	dprintf("enter\n");

	op = xhcd->op_regs;
	cap = xhcd->cap_regs;
	port_cnt = num_ports = read_reg32(&cap->hcsparams1) >> 24;

	/* Read the xHCI extented capability to find usb3 ports and offset*/
	xecp_off = XHCI_HCCPARAMS_XECP(read_reg32(&cap->hccparams));
	base = (uint32_t *)cap;
	while (xecp_off > 0) {
		xecp_addr = base + xecp_off;
		dprintf("xecp_off %d %p %p \n", xecp_off, base, xecp_addr);

		if (XHCI_XECP_CAP_ID(read_reg32(xecp_addr)) == XHCI_XECP_CAP_SP &&
		    XHCI_XECP_CAP_SP_MJ(read_reg32(xecp_addr)) == usb_ver &&
		    XHCI_XECP_CAP_SP_MN(read_reg32(xecp_addr)) == 0) {
			port_cnt = XHCI_XECP_CAP_SP_PC(read_reg32(xecp_addr + 2));
			port_off = XHCI_XECP_CAP_SP_PO(read_reg32(xecp_addr + 2));
			dprintf("PortCount %d Portoffset %d\n", port_cnt, port_off);
		}
		base = xecp_addr;
		xecp_off = XHCI_XECP_NEXT_PTR(read_reg32(xecp_addr));
	}
	if (port_off == 0) /* port_off should always start from 1 */
		return false;
	for (i = (port_off - 1); i < (port_off + port_cnt - 1); i++) {
		prs = &op->prs[i];
		portsc = read_reg32(&prs->portsc);
		if (xhci_device_present(portsc, usb_ver)) {
			/* Device present */
			dprintf("Device present on port %d\n", i);
			/* Reset the port */
			portsc = read_reg32(&prs->portsc);
			portsc = portsc | PORTSC_PR;
			write_reg32(&prs->portsc, portsc);
			/* FIXME poll for port event */
			SLOF_msleep(20);
			xhci_poll_event(xhcd, 0);
			portsc = read_reg32(&prs->portsc);
			if (portsc & ~PORTSC_PRC) {
				dprintf("Port reset complete %d\n", i);
			}
			print_port_status(prs);
			if (!usb3_dev_init(xhcd, (i - (port_off - 1)))) {
				dprintf("USB device initialization failed\n");
			}
		}
	}
	dprintf("exit\n");
	return true;
}

static int xhci_hub_check_ports(struct xhci_hcd *xhcd)
{
	return xhci_port_scan(xhcd, USB_XHCI) | xhci_port_scan(xhcd, USB_EHCI);
}

static bool xhci_hcd_init(struct xhci_hcd *xhcd)
{
	struct xhci_op_regs *op;
	struct xhci_int_regs *irs;
	uint64_t val;
	uint32_t reg;

	if (!xhcd) {
		dprintf("NULL pointer\n");
		goto fail;
	}

	op = xhcd->op_regs;
	irs = &xhcd->run_regs->irs[0];
	if (!xhci_hcd_reset(op)) {
		dprintf("Reset failed\n");
		goto fail;
	}

	write_reg32(&op->config, XHCI_CONFIG_MAX_SLOT);
	reg = read_reg32(&xhcd->cap_regs->hccparams);
	/* 64byte context !! */
	xhcd->hcc_csz_64 = (reg & XHCI_HCCPARAMS_CSZ) ? 1 : 0;

	if (xhcd->hcc_csz_64) {
		printf("usb-xhci: 64 Byte context not supported\n");
		goto fail;
	}
	/*
	 * 6.1 Device Context Base Address Array
	 *
	 * Allocate memory and initialize
	 */
	xhcd->dcbaap = (uint64_t *)SLOF_dma_alloc(XHCI_DCBAAP_MAX_SIZE);
	if (!xhcd->dcbaap) {
		dprintf("Alloc failed\n");
		goto fail;
	}
	memset((void *)xhcd->dcbaap, 0, XHCI_DCBAAP_MAX_SIZE);
	xhcd->dcbaap_dma = SLOF_dma_map_in((void *)xhcd->dcbaap,
					XHCI_DCBAAP_MAX_SIZE, false);
	dprintf("dcbaap %llx, dcbaap_phys %llx\n", xhcd->dcbaap, xhcd->dcbaap_dma);
	write_reg64(&op->dcbaap, xhcd->dcbaap_dma);

	/*
	 * Command Ring Control - TRB
	 * FIXME - better way to allocate it...
	 */
	if (!xhci_alloc_seg(&xhcd->crseg, XHCI_CRCR_CRP_SIZE, TYPE_COMMAND))
		goto fail_dcbaap;

	val = read_reg64(&op->crcr) & ~XHCI_CRCR_CRP_MASK;
	val = val | (xhcd->crseg.trbs_dma & XHCI_CRCR_CRP_MASK);
	write_reg64(&op->crcr, val);

	/*
	 * Event Ring Control - TRB
	 * Allocate event TRBS
	 */
	if (!xhci_alloc_seg(&xhcd->ering, XHCI_EVENT_TRBS_SIZE, TYPE_EVENT))
		goto fail_crseg;

	/*
	 * Populate event ring segment table.
	 * Note: only using one segment.
	 */
	xhcd->erst.entries = SLOF_dma_alloc(XHCI_EVENT_TRBS_SIZE);
	if (!xhcd->erst.entries)
		goto fail_ering;
	xhcd->erst.dma = SLOF_dma_map_in((void *)xhcd->erst.entries,
					XHCI_EVENT_TRBS_SIZE, false);
	xhcd->erst.num_segs = XHCI_ERST_NUM_SEGS;

	/* populate entries[0] */
	write_reg64(&xhcd->erst.entries->addr, xhcd->ering.trbs_dma);
	write_reg32(&xhcd->erst.entries->size, xhcd->ering.size);
	write_reg32(&xhcd->erst.entries->reserved, 0);

	/* populate erdp */
	val = read_reg64(&irs->erdp) & ~XHCI_ERDP_MASK;
	val = val | (xhcd->ering.trbs_dma & XHCI_ERDP_MASK);
	write_reg64(&irs->erdp, val);

	/* populate erstsz */
	val = read_reg32(&irs->erstsz) & ~XHCI_ERST_SIZE_MASK;
	val = val | xhcd->erst.num_segs;
	write_reg32(&irs->erstsz, val);

	/* Now write the erstba */
	val = read_reg64(&irs->erstba) & ~XHCI_ERST_ADDR_MASK;
	val = val | (xhcd->erst.dma & XHCI_ERST_ADDR_MASK);
	write_reg64(&irs->erstba, val);

	dprintf("ERDP %llx TRB-DMA %llx\n", read_reg64(&irs->erdp),
		xhcd->ering.trbs_dma);
	dprintf("ERST %llx, ERST DMA %llx, size %d\n",
		(uint64_t)xhcd->erst.entries, xhcd->erst.dma,
		xhcd->erst.num_segs);

	mb();
	if (!xhci_hcd_set_runstop(op, true))
		goto fail_erst_entries;

	if (!xhci_hub_check_ports(xhcd))
		goto fail_erst_entries;

	return true;
fail_erst_entries:
	write_reg64(&irs->erstba, 0);
	mb();
	SLOF_dma_map_out(xhcd->erst.dma, (void *)xhcd->erst.entries, XHCI_EVENT_TRBS_SIZE);
	SLOF_dma_free((void *)xhcd->erst.entries, XHCI_EVENT_TRBS_SIZE);
fail_ering:
	xhci_free_seg(&xhcd->ering, XHCI_EVENT_TRBS_SIZE);
fail_crseg:
	val = read_reg64(&op->crcr) & ~XHCI_CRCR_CRP_MASK;
	write_reg64(&op->crcr, val);
	mb();
	xhci_free_seg(&xhcd->crseg, XHCI_CRCR_CRP_SIZE);
fail_dcbaap:
	write_reg64(&op->dcbaap, 0);
	mb();
	SLOF_dma_map_out(xhcd->dcbaap_dma, (void *)xhcd->dcbaap, XHCI_DCBAAP_MAX_SIZE);
	SLOF_dma_free((void *)xhcd->dcbaap, XHCI_DCBAAP_MAX_SIZE);
fail:
	return false;
}

static bool xhci_hcd_exit(struct xhci_hcd *xhcd)
{
	struct xhci_op_regs *op;
	struct xhci_int_regs *irs;
	uint64_t val;
	int i;

	if (!xhcd) {
		dprintf("NULL pointer\n");
		return false;
	}
	op = xhcd->op_regs;

	if (!xhci_hcd_set_runstop(op, false)) {
		dprintf("NULL pointer\n");
	}

	for (i = 1; i < XHCI_CONFIG_MAX_SLOT; i++) {
		if (xhcd->xdevs[i].dev)
			xhci_free_dev(&xhcd->xdevs[i]);
	}

	irs = &xhcd->run_regs->irs[0];
	write_reg64(&irs->erstba, 0);
	mb();
	if (xhcd->erst.entries) {
		SLOF_dma_map_out(xhcd->erst.dma, xhcd->erst.entries, XHCI_EVENT_TRBS_SIZE); 
		SLOF_dma_free(xhcd->erst.entries, XHCI_EVENT_TRBS_SIZE);
	}
	xhci_free_seg(&xhcd->ering, XHCI_EVENT_TRBS_SIZE);

	val = read_reg64(&op->crcr) & ~XHCI_CRCR_CRP_MASK;
	write_reg64(&op->crcr, val);
	xhci_free_seg(&xhcd->crseg, XHCI_CRCR_CRP_SIZE);
	write_reg64(&op->dcbaap, 0);
	if (xhcd->dcbaap) {
		SLOF_dma_map_out(xhcd->dcbaap_dma, (void *)xhcd->dcbaap, XHCI_DCBAAP_MAX_SIZE);
		SLOF_dma_free((void *)xhcd->dcbaap, XHCI_DCBAAP_MAX_SIZE);
	}

	/*
	 * QEMU implementation of XHCI doesn't implement halt
	 * properly. It basically says that it's halted immediately
	 * but doesn't actually terminate ongoing activities and
	 * DMAs. This needs to be fixed in QEMU.
	 *
	 * For now, wait for 50ms grace time till qemu stops using
	 * this device.
	 */
	SLOF_msleep(50);

	return true;
}

static void xhci_init(struct usb_hcd_dev *hcidev)
{
	struct xhci_hcd *xhcd;

	printf("  XHCI: Initializing\n");
	dprintf("device base address %p\n", hcidev->base);

	hcidev->base = (void *)((uint64_t)hcidev->base & ~7);
	xhcd = SLOF_alloc_mem(sizeof(*xhcd));
	if (!xhcd) {
		printf("usb-xhci: Unable to allocate memory\n");
		return;
	}
	memset(xhcd, 0, sizeof(*xhcd));

	hcidev->nextaddr = 1;
	hcidev->priv = xhcd;
	xhcd->hcidev = hcidev;
	xhcd->cap_regs = (struct xhci_cap_regs *)(hcidev->base);
	xhcd->op_regs = (struct xhci_op_regs *)(hcidev->base +
						read_reg8(&xhcd->cap_regs->caplength));
	xhcd->run_regs = (struct xhci_run_regs *)(hcidev->base +
						read_reg32(&xhcd->cap_regs->rtsoff));
	xhcd->db_regs = (struct xhci_db_regs *)(hcidev->base +
						read_reg32(&xhcd->cap_regs->dboff));
	dump_xhci_regs(xhcd);
	if (!xhci_hcd_init(xhcd))
		printf("usb-xhci: failed to initialize XHCI controller.\n");
	dump_xhci_regs(xhcd);
}

static void xhci_exit(struct usb_hcd_dev *hcidev)
{
	struct xhci_hcd *xhcd;

	dprintf("%s: enter \n", __func__);
	if (!hcidev && !hcidev->priv) {
		return;
	}

	xhcd = hcidev->priv;
	xhci_hcd_exit(xhcd);
	SLOF_free_mem(xhcd, sizeof(*xhcd));
	hcidev->priv = NULL;
}

static void fill_trb_buff(struct xhci_command_trb *cmd,  uint32_t field1,
			uint32_t field2, uint32_t field3, uint32_t field4)
{
	uint32_t val, cycle_state;

	cmd->field[0] = cpu_to_le32(field1);
	cmd->field[1] = cpu_to_le32(field2);
	cmd->field[2] = cpu_to_le32(field3);

	val = le32_to_cpu(cmd->field[3]);
	cycle_state = (val & 0x1) ? 0 : 1;
	val =  cycle_state | (field4 & ~0x1);
	cmd->field[3] = cpu_to_le32(val);

	dprintf("CMD %016lx val %08x cycle_state %d field1 %08x, field2  %08x, field3 %08x field4 %08x\n",
		cmd, val, cycle_state,
		le32_to_cpu(cmd->field[0]),
		le32_to_cpu(cmd->field[1]),
		le32_to_cpu(cmd->field[2]),
		le32_to_cpu(cmd->field[3])
		);

	return;
}

static void fill_setup_trb(struct xhci_command_trb *cmd, struct usb_dev_req *req,
			uint32_t size)
{
	uint32_t field1, field2, field3, field4 = 0;
	uint64_t req_raw;
	uint32_t datalen = 0, pid = 0;

	req_raw = *((uint64_t *)req);
	dprintf("%lx %lx \n", *((uint64_t *)req), req_raw);
	/* req_raw is already in right byte order... */
	field1 = cpu_to_le32(TRB_ADDR_HIGH(req_raw));
	field2 = cpu_to_le32(TRB_ADDR_LOW(req_raw));
	field3 = 8; /* ALWAYS 8 */

	datalen = cpu_to_le16(req->wLength);
	if (datalen) {
		pid = (req->bmRequestType & REQT_DIR_IN) ? 3 : 2;
		field4 = TRB_TRT(pid);
	}
	field4 |= TRB_CMD_TYPE(TRB_SETUP_STAGE) | TRB_IDT;
	fill_trb_buff(cmd, field1, field2, field3, field4);
}

static void fill_setup_data(struct xhci_command_trb *cmd, void *data,
			uint32_t size, uint32_t dir)
{
	uint32_t field1, field2, field3, field4;

	field1 = TRB_ADDR_LOW(data);
	field2 = TRB_ADDR_HIGH(data);
	field3 = size;
	if (dir)
		field4 = TRB_DIR_IN;
	field4 |= TRB_CMD_TYPE(TRB_DATA_STAGE);
	fill_trb_buff(cmd, field1, field2, field3, field4);
}

static void fill_status_trb(struct xhci_command_trb *cmd, uint32_t dir)
{
	uint32_t field1, field2, field3, field4;

	field1 = 0;
	field2 = 0;
	field3 = 0;
	if (dir)
		field4 = TRB_DIR_IN;

	field4 |= TRB_CMD_TYPE(TRB_STATUS_STAGE) | TRB_IOC;
	fill_trb_buff(cmd, field1, field2, field3, field4);
}

static void fill_normal_trb(struct xhci_transfer_trb *trb, void *data,
			uint32_t size)
{
	uint32_t field1, field2, field3, field4;

	field1 = TRB_ADDR_LOW(data);
	field2 = TRB_ADDR_HIGH(data);
	field3 = size;
	field4 = TRB_CMD_TYPE(TRB_NORMAL) | TRB_IOC;
	fill_trb_buff((struct xhci_command_trb *)trb, field1, field2, field3, field4);
}

static int xhci_send_ctrl(struct usb_pipe *pipe, struct usb_dev_req *req, void *data)
{
	struct xhci_dev *xdev;
	struct xhci_seg *ctrl;
	struct xhci_hcd *xhcd;
	struct xhci_command_trb *cmd;
	struct xhci_db_regs *dbr;
	long req_phys = 0, data_phys = 0;
	int ret = true;
	uint32_t slot_id, pid = 0, datalen = 0;

	if (!pipe->dev || !pipe->dev->hcidev) {
		dprintf(" NULL pointer\n");
		return false;
	}

	xdev = pipe->dev->priv;
	slot_id = xdev->slot_id;
	ctrl = &xdev->control;
	xhcd = (struct xhci_hcd *)pipe->dev->hcidev->priv;
	dbr = xhcd->db_regs;
	if (!ctrl || !xdev || !xhcd) {
		dprintf(" NULL pointer\n");
		return false;
	}

	cmd = (struct xhci_command_trb *)ctrl->enq;
	req_phys = SLOF_dma_map_in(req, sizeof(struct usb_dev_req), true);
	fill_setup_trb(cmd, req, sizeof(*req));

	cmd++;
	datalen = cpu_to_le16(req->wLength);
	if (datalen)
		pid = 1;
	if (datalen) {
		data_phys = SLOF_dma_map_in(data, datalen, true);
		fill_setup_data(cmd, (void *) data_phys, datalen, pid);
		cmd++;
	}

	fill_status_trb(cmd, pid);
	cmd++;

	/* Ring the doorbell - ep0 */
	write_reg32(&dbr->db[slot_id], 1);
	if (!xhci_poll_event(xhcd, 0)) {
		dprintf("Command failed\n");
		ret = false;
	}
	ctrl->enq = (uint64_t) cmd;
	SLOF_dma_map_out(req_phys, req, sizeof(struct usb_dev_req));
	if (datalen)
		SLOF_dma_map_out(data_phys, data, datalen);
	return ret;
}

static inline struct xhci_pipe *xhci_pipe_get_xpipe(struct usb_pipe *pipe)
{
	struct xhci_pipe *xpipe;
	xpipe = container_of(pipe, struct xhci_pipe, pipe);
	dprintf("%s: xpipe is %p\n", __func__, xpipe);
	return xpipe;
}

static inline struct xhci_seg *xhci_pipe_get_seg(struct usb_pipe *pipe)
{
	struct xhci_pipe *xpipe;
	xpipe = xhci_pipe_get_xpipe(pipe);
	return xpipe->seg;
}

static inline void *xhci_get_trb(struct xhci_seg *seg)
{
	uint64_t val, enq;
	int index;
	struct xhci_link_trb *link;

	enq = val = seg->enq;
	val = val + XHCI_TRB_SIZE;
	index = (enq - (uint64_t)seg->trbs) / XHCI_TRB_SIZE + 1;
	dprintf("%s: enq %llx, val %llx %x\n", __func__, enq, val, index);
	/* TRBs being a cyclic buffer, here we cycle back to beginning. */
	if (index == (seg->size - 1)) {
		dprintf("%s: rounding \n", __func__);
		seg->enq = (uint64_t)seg->trbs;
		seg->cycle_state ^= seg->cycle_state;
		link = (struct xhci_link_trb *) (seg->trbs + seg->size - 1);
		link->addr = cpu_to_le64(seg->trbs_dma);
		link->field2 = 0;
		link->field3 = cpu_to_le32(0x1 | TRB_CMD_TYPE(TRB_LINK));
		mb();
	}
	else {
		seg->enq = seg->enq + XHCI_TRB_SIZE;
	}

	return (void *)enq;
}

static uint64_t xhci_get_trb_phys(struct xhci_seg *seg, uint64_t trb)
{
	return seg->trbs_dma + (trb - (uint64_t)seg->trbs);
}

static int usb_kb = false;
static int xhci_transfer_bulk(struct usb_pipe *pipe, void *td, void *td_phys,
			void *data, int datalen)
{
	struct xhci_dev *xdev;
	struct xhci_seg *seg;
	struct xhci_hcd *xhcd;
	struct xhci_transfer_trb *trb;
	struct xhci_db_regs *dbr;
	int ret = true;
	uint32_t slot_id, epno, time;
	uint64_t trb_phys, event_phys;

	if (!pipe->dev || !pipe->dev->hcidev) {
		dprintf(" NULL pointer\n");
		dprintf(" pipe dev %p hcidev %p\n", pipe->dev, pipe->dev->hcidev);
		return false;
	}

	xdev = pipe->dev->priv;
	slot_id = xdev->slot_id;
	seg = xhci_pipe_get_seg(pipe);
	xhcd = (struct xhci_hcd *)pipe->dev->hcidev->priv;
	dbr = xhcd->db_regs;
	if (!seg || !xdev || !xhcd) {
		dprintf(" NULL pointer\n");
		dprintf(" seg %p xdev %p xhcd %p\n", seg, xdev, xhcd);
		return false;
	}

	if (datalen > XHCI_MAX_BULK_SIZE) {
		printf("usb-xhci: bulk transfer size too big\n");
		return false;
	}

	trb = xhci_get_trb(seg);
	trb_phys = xhci_get_trb_phys(seg, (uint64_t)trb);
	fill_normal_trb(trb, (void *)data, datalen);

	epno = xhci_get_epno(pipe);
	write_reg32(&dbr->db[slot_id], epno);

	time = SLOF_GetTimer() + USB_TIMEOUT;
	while (1) {
		event_phys = xhci_poll_event(xhcd, 0);
		if (event_phys == trb_phys) {
			break;
		} else if (event_phys == 0) { /* polling timed out */
			ret = false;
			break;
		} else
			usb_kb = true;

		/* transfer timed out */
		if (time < SLOF_GetTimer())
			return false;
	}
	trb->addr = 0;
	trb->len = 0;
	trb->flags = 0;
	mb();

	return ret;
}

static int xhci_alloc_pipe_pool(struct xhci_hcd *xhcd)
{
	struct xhci_pipe *xpipe, *curr, *prev;
	unsigned int i, count;
	long xpipe_phys = 0;

	count = XHCI_PIPE_POOL_SIZE/sizeof(*xpipe);
	xhcd->pool = xpipe = SLOF_dma_alloc(XHCI_PIPE_POOL_SIZE);
	if (!xpipe)
		return -1;
	xhcd->pool_phys = xpipe_phys = SLOF_dma_map_in(xpipe, XHCI_PIPE_POOL_SIZE, true);
	dprintf("%s: xpipe %p, xpipe_phys %lx\n", __func__, xpipe, xpipe_phys);

	/* Although an array, link them */
	for (i = 0, curr = xpipe, prev = NULL; i < count; i++, curr++) {
		if (prev)
			prev->pipe.next = &curr->pipe;
		curr->pipe.next = NULL;
		prev = curr;
	}

	if (!xhcd->freelist)
		xhcd->freelist = &xpipe->pipe;
	else
		xhcd->end->next = &xpipe->pipe;
	xhcd->end = &prev->pipe;

	return 0;
}

static void xhci_init_bulk_ep(struct usb_dev *dev, struct usb_pipe *pipe)
{
	struct xhci_hcd *xhcd;
	struct xhci_dev *xdev;
	struct xhci_seg *seg;
	struct xhci_pipe *xpipe;
	struct xhci_control_ctx *ctrl;
	struct xhci_ep_ctx *ep;
	uint32_t x_epno, val, type;

	if (!pipe || !dev || !dev->priv)
		return;

	xdev = dev->priv;
	xhcd = dev->hcidev->priv;
	dprintf("dir %d\n", pipe->dir);
	seg = xhci_pipe_get_seg(pipe);
	xpipe = xhci_pipe_get_xpipe(pipe);
	if (pipe->dir) {
		type = EP_BULK_IN;
		seg = &xdev->bulk_in;
	}
	else {
		type = EP_BULK_OUT;
		seg = &xdev->bulk_out;
	}

	if (!seg->trbs) {
		if (!xhci_alloc_seg(seg, XHCI_DATA_TRBS_SIZE, TYPE_BULK)) {
			printf("usb-xhci: allocation failed for bulk endpoint\n");
			return;
		}
	} else {
		xhci_init_seg(seg, XHCI_DATA_TRBS_SIZE, TYPE_BULK);
	}

	pipe->mps = XHCI_MAX_BULK_SIZE;
	ctrl = xhci_get_control_ctx(&xdev->in_ctx);
	x_epno = xhci_get_epno(pipe);
	ep = xhci_get_ep_ctx(&xdev->in_ctx, xdev->ctx_size, x_epno);
	val = EP_TYPE(type) | MAX_BURST(0) | ERROR_COUNT(3) |
		MAX_PACKET_SIZE(pipe->mps);
	ep->field2 = cpu_to_le32(val);;
	ep->deq_addr = cpu_to_le64(seg->trbs_dma | seg->cycle_state);
	ep->field4 = cpu_to_le32(8);
	ctrl->a_flags = cpu_to_le32(BIT(x_epno) | 0x1);
	ctrl->d_flags = 0;
	xhci_configure_ep(xhcd, xdev->slot_id, xdev->in_ctx.dma_addr);
	xpipe->seg = seg;
}

static int xhci_get_pipe_intr(struct usb_pipe *pipe,
			struct xhci_hcd *xhcd,
			char *buf, size_t len)
{
	struct xhci_dev *xdev;
	struct xhci_seg *seg;
	struct xhci_pipe *xpipe;
	struct xhci_control_ctx *ctrl;
	struct xhci_ep_ctx *ep;
	uint32_t x_epno, val, type;
	struct usb_dev *dev;
	struct xhci_transfer_trb *trb;

	dev = pipe->dev;
	if (dev->class != DEV_HID_KEYB)
		return false;

	xdev = dev->priv;
	pipe->mps = 8;
	seg = xhci_pipe_get_seg(pipe);
	xpipe = xhci_pipe_get_xpipe(pipe);
	type = EP_INT_IN;
	seg = &xdev->intr;

	if (!seg->trbs) {
		if (!xhci_alloc_seg(seg, XHCI_INTR_TRBS_SIZE, TYPE_BULK)) {
			printf("usb-xhci: allocation failed for interrupt endpoint\n");
			return false;
		}
	} else {
		xhci_init_seg(seg, XHCI_EVENT_TRBS_SIZE, TYPE_BULK);
	}

	xpipe->buf = buf;
	xpipe->buf_phys = SLOF_dma_map_in(buf, len, false);
	xpipe->buflen = len;

	ctrl = xhci_get_control_ctx(&xdev->in_ctx);
	x_epno = xhci_get_epno(pipe);
	ep = xhci_get_ep_ctx(&xdev->in_ctx, xdev->ctx_size, x_epno);
	val = EP_TYPE(type) | MAX_BURST(0) | ERROR_COUNT(3) |
		MAX_PACKET_SIZE(pipe->mps);
	ep->field2 = cpu_to_le32(val);
	ep->deq_addr = cpu_to_le64(seg->trbs_dma | seg->cycle_state);
	ep->field4 = cpu_to_le32(8);
	ctrl->a_flags = cpu_to_le32(BIT(x_epno) | 0x1);
	ctrl->d_flags = 0;
	xhci_configure_ep(xhcd, xdev->slot_id, xdev->in_ctx.dma_addr);
	xpipe->seg = seg;

	trb = xhci_get_trb(seg);
	fill_normal_trb(trb, (void *)xpipe->buf_phys, pipe->mps);
	return true;
}

static struct usb_pipe* xhci_get_pipe(struct usb_dev *dev, struct usb_ep_descr *ep, char *buf, size_t len)
{
	struct xhci_hcd *xhcd;
	struct usb_pipe *new = NULL;

	if (!dev)
		return NULL;

	xhcd = (struct xhci_hcd *)dev->hcidev->priv;
	if (!xhcd->freelist) {
		dprintf("usb-xhci: %s allocating pool\n", __func__);
		if (xhci_alloc_pipe_pool(xhcd))
			return NULL;
	}

	new = xhcd->freelist;
	xhcd->freelist = xhcd->freelist->next;
	if (!xhcd->freelist)
		xhcd->end = NULL;

	memset(new, 0, sizeof(*new));
	new->dev = dev;
	new->next = NULL;
	new->type = ep->bmAttributes & USB_EP_TYPE_MASK;
	new->speed = dev->speed;
	new->mps = ep->wMaxPacketSize;
	new->dir = (ep->bEndpointAddress & 0x80) >> 7;
	new->epno = ep->bEndpointAddress & 0x0f;

	if (new->type == USB_EP_TYPE_INTR) {
		if (!xhci_get_pipe_intr(new, xhcd, buf, len)) {
			printf("usb-xhci: %s alloc_intr failed  %p\n",
				__func__, new);
		}
	}
	if (new->type == USB_EP_TYPE_BULK)
		xhci_init_bulk_ep(dev, new);

	return new;
}

static void xhci_put_pipe(struct usb_pipe *pipe)
{
	struct xhci_hcd *xhcd;
	struct xhci_pipe *xpipe;

	dprintf("usb-xhci: %s enter - %p\n", __func__, pipe);
	if (!pipe || !pipe->dev)
		return;
	xhcd = pipe->dev->hcidev->priv;

	dprintf("dir %d\n", pipe->dir);
	if (pipe->type == USB_EP_TYPE_BULK) {
		xpipe = xhci_pipe_get_xpipe(pipe);
		xpipe->seg = NULL;
	} else if (pipe->type == USB_EP_TYPE_INTR) {
		xpipe = xhci_pipe_get_xpipe(pipe);
		SLOF_dma_map_out(xpipe->buf_phys, xpipe->buf, xpipe->buflen);
		xpipe->seg = NULL;
	}
	if (xhcd->end)
		xhcd->end->next = pipe;
	else
		xhcd->freelist = pipe;

	xhcd->end = pipe;
	pipe->next = NULL;
	pipe->dev = NULL;
	memset(pipe, 0, sizeof(*pipe));

	dprintf("usb-xhci: %s exit\n", __func__);
}

static int xhci_poll_intr(struct usb_pipe *pipe, uint8_t *data)
{
	struct xhci_transfer_trb *trb;
	struct xhci_seg *seg;
	struct xhci_pipe *xpipe;
	struct xhci_dev *xdev;
	struct xhci_hcd *xhcd;
	struct xhci_db_regs *dbr;
	uint32_t x_epno;
	uint8_t *buf, ret = 1;

	if (!pipe || !pipe->dev || !pipe->dev->hcidev)
		return 0;
	xdev = pipe->dev->priv;
	xhcd = (struct xhci_hcd *)pipe->dev->hcidev->priv;
	x_epno = xhci_get_epno(pipe);
	seg = xhci_pipe_get_seg(pipe);
	xpipe = xhci_pipe_get_xpipe(pipe);

	if (usb_kb == true) {
		/* This event was consumed by bulk transfer */
		usb_kb = false;
		goto skip_poll;
	}
	buf = xpipe->buf;
	memset(buf, 0, 8);

	mb();
	/* Ring the doorbell - x_epno */
	dbr = xhcd->db_regs;
	write_reg32(&dbr->db[xdev->slot_id], x_epno);
	if (!xhci_poll_event(xhcd, 0)) {
		printf("poll intr failed\n");
		return 0;
	}
	mb();
	memcpy(data, buf, 8);

skip_poll:
	trb = xhci_get_trb(seg);
	fill_normal_trb(trb, (void *)xpipe->buf_phys, pipe->mps);
	mb();
	return ret;
}

struct usb_hcd_ops xhci_ops = {
	.name          = "xhci-hcd",
	.init          = xhci_init,
	.exit          = xhci_exit,
	.usb_type      = USB_XHCI,
	.get_pipe      = xhci_get_pipe,
	.put_pipe      = xhci_put_pipe,
	.poll_intr     = xhci_poll_intr,
	.send_ctrl     = xhci_send_ctrl,
	.transfer_bulk = xhci_transfer_bulk,
	.next          = NULL,
};

void usb_xhci_register(void)
{
	usb_hcd_register(&xhci_ops);
}
