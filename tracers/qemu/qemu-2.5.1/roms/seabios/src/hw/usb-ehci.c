// Code for handling EHCI USB controllers.
//
// Copyright (C) 2010-2013  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_LOWFLAT
#include "config.h" // CONFIG_*
#include "output.h" // dprintf
#include "malloc.h" // free
#include "memmap.h" // PAGE_SIZE
#include "pci.h" // pci_bdf_to_bus
#include "pci_ids.h" // PCI_CLASS_SERIAL_USB_UHCI
#include "pci_regs.h" // PCI_BASE_ADDRESS_0
#include "string.h" // memset
#include "usb.h" // struct usb_s
#include "usb-ehci.h" // struct ehci_qh
#include "util.h" // msleep
#include "x86.h" // readl

struct usb_ehci_s {
    struct usb_s usb;
    struct ehci_caps *caps;
    struct ehci_regs *regs;
    struct ehci_qh *async_qh;
    int checkports;
};

struct ehci_pipe {
    struct ehci_qh qh;
    struct ehci_qtd *next_td, *tds;
    void *data;
    struct usb_pipe pipe;
};

static int PendingEHCI;


/****************************************************************
 * Root hub
 ****************************************************************/

#define EHCI_TIME_POSTPOWER 20
#define EHCI_TIME_POSTRESET 2

// Check if device attached to port
static int
ehci_hub_detect(struct usbhub_s *hub, u32 port)
{
    struct usb_ehci_s *cntl = container_of(hub->cntl, struct usb_ehci_s, usb);
    u32 *portreg = &cntl->regs->portsc[port];
    u32 portsc = readl(portreg);

    if (!(portsc & PORT_CONNECT))
        // No device present
        return 0;

    if ((portsc & PORT_LINESTATUS_MASK) == PORT_LINESTATUS_KSTATE) {
        // low speed device
        writel(portreg, portsc | PORT_OWNER);
        return -1;
    }

    // XXX - if just powered up, need to wait for USB_TIME_ATTDB?

    // Begin reset on port
    portsc = (portsc & ~PORT_PE) | PORT_RESET;
    writel(portreg, portsc);
    msleep(USB_TIME_DRSTR);
    return 1;
}

// Reset device on port
static int
ehci_hub_reset(struct usbhub_s *hub, u32 port)
{
    struct usb_ehci_s *cntl = container_of(hub->cntl, struct usb_ehci_s, usb);
    u32 *portreg = &cntl->regs->portsc[port];
    u32 portsc = readl(portreg);

    // Finish reset on port
    portsc &= ~PORT_RESET;
    writel(portreg, portsc);
    msleep(EHCI_TIME_POSTRESET);

    portsc = readl(portreg);
    if (!(portsc & PORT_CONNECT))
        // No longer connected
        return -1;
    if (!(portsc & PORT_PE)) {
        // full speed device
        writel(portreg, portsc | PORT_OWNER);
        return -1;
    }

    return USB_HIGHSPEED;
}

// Disable port
static void
ehci_hub_disconnect(struct usbhub_s *hub, u32 port)
{
    struct usb_ehci_s *cntl = container_of(hub->cntl, struct usb_ehci_s, usb);
    u32 *portreg = &cntl->regs->portsc[port];
    u32 portsc = readl(portreg);
    writel(portreg, portsc & ~PORT_PE);
}

static struct usbhub_op_s ehci_HubOp = {
    .detect = ehci_hub_detect,
    .reset = ehci_hub_reset,
    .disconnect = ehci_hub_disconnect,
};

// Find any devices connected to the root hub.
static int
check_ehci_ports(struct usb_ehci_s *cntl)
{
    // Power up ports.
    int i;
    for (i=0; i<cntl->checkports; i++) {
        u32 *portreg = &cntl->regs->portsc[i];
        u32 portsc = readl(portreg);
        if (!(portsc & PORT_POWER)) {
            portsc |= PORT_POWER;
            writel(portreg, portsc);
        }
    }
    msleep(EHCI_TIME_POSTPOWER);

    struct usbhub_s hub;
    memset(&hub, 0, sizeof(hub));
    hub.cntl = &cntl->usb;
    hub.portcount = cntl->checkports;
    hub.op = &ehci_HubOp;
    usb_enumerate(&hub);
    return hub.devcount;
}


/****************************************************************
 * Setup
 ****************************************************************/

// Wait for next USB async frame to start - for ensuring safe memory release.
static void
ehci_waittick(struct usb_ehci_s *cntl)
{
    if (MODE16) {
        msleep(10);
        return;
    }
    // Wait for access to "doorbell"
    barrier();
    u32 cmd, sts;
    u32 end = timer_calc(100);
    for (;;) {
        sts = readl(&cntl->regs->usbsts);
        if (!(sts & STS_IAA)) {
            cmd = readl(&cntl->regs->usbcmd);
            if (!(cmd & CMD_IAAD))
                break;
        }
        if (timer_check(end)) {
            warn_timeout();
            return;
        }
        yield();
    }
    // Ring "doorbell"
    writel(&cntl->regs->usbcmd, cmd | CMD_IAAD);
    // Wait for completion
    for (;;) {
        sts = readl(&cntl->regs->usbsts);
        if (sts & STS_IAA)
            break;
        if (timer_check(end)) {
            warn_timeout();
            return;
        }
        yield();
    }
    // Ack completion
    writel(&cntl->regs->usbsts, STS_IAA);
}

static void
ehci_free_pipes(struct usb_ehci_s *cntl)
{
    dprintf(7, "ehci_free_pipes %p\n", cntl);

    struct ehci_qh *start = cntl->async_qh;
    struct ehci_qh *pos = start;
    for (;;) {
        struct ehci_qh *next = (void*)(pos->next & ~EHCI_PTR_BITS);
        if (next == start)
            break;
        struct ehci_pipe *pipe = container_of(next, struct ehci_pipe, qh);
        if (usb_is_freelist(&cntl->usb, &pipe->pipe))
            pos->next = next->next;
        else
            pos = next;
    }
    ehci_waittick(cntl);
    for (;;) {
        struct usb_pipe *usbpipe = cntl->usb.freelist;
        if (!usbpipe)
            break;
        cntl->usb.freelist = usbpipe->freenext;
        struct ehci_pipe *pipe = container_of(usbpipe, struct ehci_pipe, pipe);
        free(pipe);
    }
}

static void
configure_ehci(void *data)
{
    struct usb_ehci_s *cntl = data;

    // Allocate ram for schedule storage
    struct ehci_framelist *fl = memalign_high(sizeof(*fl), sizeof(*fl));
    struct ehci_qh *intr_qh = memalign_high(EHCI_QH_ALIGN, sizeof(*intr_qh));
    struct ehci_qh *async_qh = memalign_high(EHCI_QH_ALIGN, sizeof(*async_qh));
    if (!fl || !intr_qh || !async_qh) {
        warn_noalloc();
        PendingEHCI--;
        goto fail;
    }

    // XXX - check for halted?

    // Reset the HC
    u32 cmd = readl(&cntl->regs->usbcmd);
    writel(&cntl->regs->usbcmd, (cmd & ~(CMD_ASE | CMD_PSE)) | CMD_HCRESET);
    u32 end = timer_calc(250);
    for (;;) {
        cmd = readl(&cntl->regs->usbcmd);
        if (!(cmd & CMD_HCRESET))
            break;
        if (timer_check(end)) {
            warn_timeout();
            PendingEHCI--;
            goto fail;
        }
        yield();
    }

    // Disable interrupts (just to be safe).
    writel(&cntl->regs->usbintr, 0);

    // Set schedule to point to primary intr queue head
    memset(intr_qh, 0, sizeof(*intr_qh));
    intr_qh->next = EHCI_PTR_TERM;
    intr_qh->info2 = (0x01 << QH_SMASK_SHIFT);
    intr_qh->token = QTD_STS_HALT;
    intr_qh->qtd_next = intr_qh->alt_next = EHCI_PTR_TERM;
    int i;
    for (i=0; i<ARRAY_SIZE(fl->links); i++)
        fl->links[i] = (u32)intr_qh | EHCI_PTR_QH;
    writel(&cntl->regs->periodiclistbase, (u32)fl);

    // Set async list to point to primary async queue head
    memset(async_qh, 0, sizeof(*async_qh));
    async_qh->next = (u32)async_qh | EHCI_PTR_QH;
    async_qh->info1 = QH_HEAD;
    async_qh->token = QTD_STS_HALT;
    async_qh->qtd_next = async_qh->alt_next = EHCI_PTR_TERM;
    cntl->async_qh = async_qh;
    writel(&cntl->regs->asynclistbase, (u32)async_qh);

    // Enable queues
    writel(&cntl->regs->usbcmd, cmd | CMD_ASE | CMD_PSE | CMD_RUN);

    // Set default of high speed for root hub.
    writel(&cntl->regs->configflag, 1);
    PendingEHCI--;

    // Find devices
    int count = check_ehci_ports(cntl);
    ehci_free_pipes(cntl);
    if (count)
        // Success
        return;

    // No devices found - shutdown and free controller.
    writel(&cntl->regs->usbcmd, cmd & ~CMD_RUN);
    msleep(4);  // 2ms to stop reading memory - XXX
fail:
    free(fl);
    free(intr_qh);
    free(async_qh);
    free(cntl);
}

static void
ehci_controller_setup(struct pci_device *pci)
{
    wait_preempt();  // Avoid pci_config_readl when preempting
    u16 bdf = pci->bdf;
    u32 baseaddr = pci_config_readl(bdf, PCI_BASE_ADDRESS_0);
    struct ehci_caps *caps = (void*)(baseaddr & PCI_BASE_ADDRESS_MEM_MASK);
    u32 hcc_params = readl(&caps->hccparams);

    struct usb_ehci_s *cntl = malloc_tmphigh(sizeof(*cntl));
    if (!cntl) {
        warn_noalloc();
        return;
    }
    memset(cntl, 0, sizeof(*cntl));
    cntl->usb.pci = pci;
    cntl->usb.type = USB_TYPE_EHCI;
    cntl->caps = caps;
    cntl->checkports = readl(&cntl->caps->hcsparams) & HCS_N_PORTS_MASK;
    cntl->regs = (void*)caps + readb(&caps->caplength);
    if (hcc_params & HCC_64BIT_ADDR)
        cntl->regs->ctrldssegment = 0;
    PendingEHCI++;

    dprintf(1, "EHCI init on dev %02x:%02x.%x (regs=%p)\n"
            , pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf)
            , pci_bdf_to_fn(bdf), cntl->regs);

    pci_config_maskw(bdf, PCI_COMMAND, 0, PCI_COMMAND_MASTER);

    // XXX - check for and disable SMM control?

    run_thread(configure_ehci, cntl);
}

void
ehci_setup(void)
{
    if (! CONFIG_USB_EHCI)
        return;
    struct pci_device *pci;
    foreachpci(pci) {
        if (pci_classprog(pci) == PCI_CLASS_SERIAL_USB_EHCI)
            ehci_controller_setup(pci);
    }

    // Wait for all EHCI controllers to initialize.  This forces OHCI/UHCI
    // setup to always be after any EHCI ports are routed to EHCI.
    while (PendingEHCI)
        yield();
}


/****************************************************************
 * End point communication
 ****************************************************************/

// Setup fields in qh
static void
ehci_desc2pipe(struct ehci_pipe *pipe, struct usbdevice_s *usbdev
               , struct usb_endpoint_descriptor *epdesc)
{
    usb_desc2pipe(&pipe->pipe, usbdev, epdesc);

    pipe->qh.info1 = ((pipe->pipe.maxpacket << QH_MAXPACKET_SHIFT)
                      | (pipe->pipe.speed << QH_SPEED_SHIFT)
                      | (pipe->pipe.ep << QH_EP_SHIFT)
                      | (pipe->pipe.devaddr << QH_DEVADDR_SHIFT));

    pipe->qh.info2 = (1 << QH_MULT_SHIFT);
    struct usbdevice_s *hubdev = usbdev->hub->usbdev;
    if (hubdev) {
        struct ehci_pipe *hpipe = container_of(
            hubdev->defpipe, struct ehci_pipe, pipe);
        if (hpipe->pipe.speed == USB_HIGHSPEED)
            pipe->qh.info2 |= (((usbdev->port+1) << QH_HUBPORT_SHIFT)
                               | (hpipe->pipe.devaddr << QH_HUBADDR_SHIFT));
        else
            pipe->qh.info2 = hpipe->qh.info2;
    }

    u8 eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    if (eptype == USB_ENDPOINT_XFER_CONTROL)
        pipe->qh.info1 |= ((pipe->pipe.speed != USB_HIGHSPEED ? QH_CONTROL : 0)
                           | QH_TOGGLECONTROL);
    else if (eptype == USB_ENDPOINT_XFER_INT)
        pipe->qh.info2 |= (0x01 << QH_SMASK_SHIFT) | (0x1c << QH_CMASK_SHIFT);
}

static struct usb_pipe *
ehci_alloc_intr_pipe(struct usbdevice_s *usbdev
                     , struct usb_endpoint_descriptor *epdesc)
{
    struct usb_ehci_s *cntl = container_of(
        usbdev->hub->cntl, struct usb_ehci_s, usb);
    int frameexp = usb_get_period(usbdev, epdesc);
    dprintf(7, "ehci_alloc_intr_pipe %p %d\n", &cntl->usb, frameexp);

    if (frameexp > 10)
        frameexp = 10;
    int maxpacket = epdesc->wMaxPacketSize;
    // Determine number of entries needed for 2 timer ticks.
    int ms = 1<<frameexp;
    int count = DIV_ROUND_UP(ticks_to_ms(2), ms);
    struct ehci_pipe *pipe = memalign_low(EHCI_QH_ALIGN, sizeof(*pipe));
    struct ehci_qtd *tds = memalign_low(EHCI_QTD_ALIGN, sizeof(*tds) * count);
    void *data = malloc_low(maxpacket * count);
    if (!pipe || !tds || !data) {
        warn_noalloc();
        goto fail;
    }
    memset(pipe, 0, sizeof(*pipe));
    memset(tds, 0, sizeof(*tds) * count);
    memset(data, 0, maxpacket * count);
    ehci_desc2pipe(pipe, usbdev, epdesc);
    pipe->next_td = pipe->tds = tds;
    pipe->data = data;
    pipe->qh.qtd_next = (u32)tds;

    int i;
    for (i=0; i<count; i++) {
        struct ehci_qtd *td = &tds[i];
        td->qtd_next = (i==count-1 ? (u32)tds : (u32)&td[1]);
        td->alt_next = EHCI_PTR_TERM;
        td->token = (ehci_explen(maxpacket) | QTD_STS_ACTIVE
                     | QTD_PID_IN | ehci_maxerr(3));
        td->buf[0] = (u32)data + maxpacket * i;
    }

    // Add to interrupt schedule.
    struct ehci_framelist *fl = (void*)readl(&cntl->regs->periodiclistbase);
    if (frameexp == 0) {
        // Add to existing interrupt entry.
        struct ehci_qh *intr_qh = (void*)(fl->links[0] & ~EHCI_PTR_BITS);
        pipe->qh.next = intr_qh->next;
        barrier();
        intr_qh->next = (u32)&pipe->qh | EHCI_PTR_QH;
    } else {
        int startpos = 1<<(frameexp-1);
        pipe->qh.next = fl->links[startpos];
        barrier();
        for (i=startpos; i<ARRAY_SIZE(fl->links); i+=ms)
            fl->links[i] = (u32)&pipe->qh | EHCI_PTR_QH;
    }

    return &pipe->pipe;
fail:
    free(pipe);
    free(tds);
    free(data);
    return NULL;
}

struct usb_pipe *
ehci_realloc_pipe(struct usbdevice_s *usbdev, struct usb_pipe *upipe
                  , struct usb_endpoint_descriptor *epdesc)
{
    if (! CONFIG_USB_EHCI)
        return NULL;
    usb_add_freelist(upipe);
    if (!epdesc)
        return NULL;
    u8 eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    if (eptype == USB_ENDPOINT_XFER_INT)
        return ehci_alloc_intr_pipe(usbdev, epdesc);
    struct usb_ehci_s *cntl = container_of(
        usbdev->hub->cntl, struct usb_ehci_s, usb);
    dprintf(7, "ehci_alloc_async_pipe %p %d\n", &cntl->usb, eptype);

    struct usb_pipe *usbpipe = usb_get_freelist(&cntl->usb, eptype);
    if (usbpipe) {
        // Use previously allocated pipe.
        struct ehci_pipe *pipe = container_of(usbpipe, struct ehci_pipe, pipe);
        ehci_desc2pipe(pipe, usbdev, epdesc);
        return usbpipe;
    }

    // Allocate a new queue head.
    struct ehci_pipe *pipe;
    if (eptype == USB_ENDPOINT_XFER_CONTROL)
        pipe = memalign_tmphigh(EHCI_QH_ALIGN, sizeof(*pipe));
    else
        pipe = memalign_low(EHCI_QH_ALIGN, sizeof(*pipe));
    if (!pipe) {
        warn_noalloc();
        return NULL;
    }
    memset(pipe, 0, sizeof(*pipe));
    ehci_desc2pipe(pipe, usbdev, epdesc);
    pipe->qh.qtd_next = pipe->qh.alt_next = EHCI_PTR_TERM;

    // Add queue head to controller list.
    struct ehci_qh *async_qh = cntl->async_qh;
    pipe->qh.next = async_qh->next;
    barrier();
    async_qh->next = (u32)&pipe->qh | EHCI_PTR_QH;
    return &pipe->pipe;
}

static void
ehci_reset_pipe(struct ehci_pipe *pipe)
{
    SET_LOWFLAT(pipe->qh.qtd_next, EHCI_PTR_TERM);
    SET_LOWFLAT(pipe->qh.alt_next, EHCI_PTR_TERM);
    barrier();
    SET_LOWFLAT(pipe->qh.token, GET_LOWFLAT(pipe->qh.token) & QTD_TOGGLE);
}

static int
ehci_wait_td(struct ehci_pipe *pipe, struct ehci_qtd *td, u32 end)
{
    u32 status;
    for (;;) {
        status = td->token;
        if (!(status & QTD_STS_ACTIVE))
            break;
        if (timer_check(end)) {
            u32 cur = GET_LOWFLAT(pipe->qh.current);
            u32 tok = GET_LOWFLAT(pipe->qh.token);
            u32 next = GET_LOWFLAT(pipe->qh.qtd_next);
            warn_timeout();
            dprintf(1, "ehci pipe=%p cur=%08x tok=%08x next=%x td=%p status=%x\n"
                    , pipe, cur, tok, next, td, status);
            ehci_reset_pipe(pipe);
            struct usb_ehci_s *cntl = container_of(
                GET_LOWFLAT(pipe->pipe.cntl), struct usb_ehci_s, usb);
            ehci_waittick(cntl);
            return -1;
        }
        yield();
    }
    if (status & QTD_STS_HALT) {
        dprintf(1, "ehci_wait_td error - status=%x\n", status);
        ehci_reset_pipe(pipe);
        return -2;
    }
    return 0;
}

static void
ehci_fill_tdbuf(struct ehci_qtd *td, u32 dest, int transfer)
{
    u32 *pos = td->buf, end = dest + transfer;
    for (; dest < end; dest = ALIGN_DOWN(dest + PAGE_SIZE, PAGE_SIZE))
        *pos++ = dest;
}

#define STACKQTDS 6

int
ehci_send_pipe(struct usb_pipe *p, int dir, const void *cmd
               , void *data, int datasize)
{
    if (! CONFIG_USB_EHCI)
        return -1;
    struct ehci_pipe *pipe = container_of(p, struct ehci_pipe, pipe);
    dprintf(7, "ehci_send_pipe qh=%p dir=%d data=%p size=%d\n"
            , &pipe->qh, dir, data, datasize);

    // Allocate tds on stack (with required alignment)
    u8 tdsbuf[sizeof(struct ehci_qtd) * STACKQTDS + EHCI_QTD_ALIGN - 1];
    struct ehci_qtd *tds = (void*)ALIGN((u32)tdsbuf, EHCI_QTD_ALIGN), *td = tds;
    memset(tds, 0, sizeof(*tds) * STACKQTDS);

    // Setup transfer descriptors
    u16 maxpacket = GET_LOWFLAT(pipe->pipe.maxpacket);
    u32 toggle = 0;
    if (cmd) {
        // Send setup pid on control transfers
        td->qtd_next = (u32)MAKE_FLATPTR(GET_SEG(SS), td+1);
        td->alt_next = EHCI_PTR_TERM;
        td->token = (ehci_explen(USB_CONTROL_SETUP_SIZE) | QTD_STS_ACTIVE
                     | QTD_PID_SETUP | ehci_maxerr(3));
        ehci_fill_tdbuf(td, (u32)cmd, USB_CONTROL_SETUP_SIZE);
        td++;
        toggle = QTD_TOGGLE;
    }
    u32 dest = (u32)data, dataend = dest + datasize;
    while (dest < dataend) {
        // Send data pids
        if (td >= &tds[STACKQTDS]) {
            warn_noalloc();
            return -1;
        }
        int maxtransfer = 5*PAGE_SIZE - (dest & (PAGE_SIZE-1));
        int transfer = dataend - dest;
        if (transfer > maxtransfer)
            transfer = ALIGN_DOWN(maxtransfer, maxpacket);
        td->qtd_next = (u32)MAKE_FLATPTR(GET_SEG(SS), td+1);
        td->alt_next = EHCI_PTR_TERM;
        td->token = (ehci_explen(transfer) | toggle | QTD_STS_ACTIVE
                     | (dir ? QTD_PID_IN : QTD_PID_OUT) | ehci_maxerr(3));
        ehci_fill_tdbuf(td, dest, transfer);
        td++;
        dest += transfer;
    }
    if (cmd) {
        // Send status pid on control transfers
        if (td >= &tds[STACKQTDS]) {
            warn_noalloc();
            return -1;
        }
        td->qtd_next = EHCI_PTR_TERM;
        td->alt_next = EHCI_PTR_TERM;
        td->token = (QTD_TOGGLE | QTD_STS_ACTIVE
                     | (dir ? QTD_PID_OUT : QTD_PID_IN) | ehci_maxerr(3));
        td++;
    }

    // Transfer data
    (td-1)->qtd_next = EHCI_PTR_TERM;
    barrier();
    SET_LOWFLAT(pipe->qh.qtd_next, (u32)MAKE_FLATPTR(GET_SEG(SS), tds));
    u32 end = timer_calc(usb_xfer_time(p, datasize));
    int i;
    for (i=0, td=tds; i<STACKQTDS; i++, td++) {
        int ret = ehci_wait_td(pipe, td, end);
        if (ret)
            return -1;
    }

    return 0;
}

int
ehci_poll_intr(struct usb_pipe *p, void *data)
{
    ASSERT16();
    if (! CONFIG_USB_EHCI)
        return -1;
    struct ehci_pipe *pipe = container_of(p, struct ehci_pipe, pipe);
    struct ehci_qtd *td = GET_LOWFLAT(pipe->next_td);
    u32 token = GET_LOWFLAT(td->token);
    if (token & QTD_STS_ACTIVE)
        // No intrs found.
        return -1;
    // XXX - check for errors.

    // Copy data.
    int maxpacket = GET_LOWFLAT(pipe->pipe.maxpacket);
    int pos = td - GET_LOWFLAT(pipe->tds);
    void *tddata = GET_LOWFLAT(pipe->data) + maxpacket * pos;
    memcpy_far(GET_SEG(SS), data, SEG_LOW, LOWFLAT2LOW(tddata), maxpacket);

    // Reenable this td.
    struct ehci_qtd *next = (void*)(GET_LOWFLAT(td->qtd_next) & ~EHCI_PTR_BITS);
    SET_LOWFLAT(pipe->next_td, next);
    SET_LOWFLAT(td->buf[0], (u32)tddata);
    barrier();
    SET_LOWFLAT(td->token, (ehci_explen(maxpacket) | QTD_STS_ACTIVE
                            | QTD_PID_IN | ehci_maxerr(3)));

    return 0;
}
