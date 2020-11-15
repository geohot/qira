// Code for handling UHCI USB controllers.
//
// Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_LOWFLAT
#include "config.h" // CONFIG_*
#include "malloc.h" // free
#include "output.h" // dprintf
#include "pci.h" // pci_bdf_to_bus
#include "pci_ids.h" // PCI_CLASS_SERIAL_USB_UHCI
#include "pci_regs.h" // PCI_BASE_ADDRESS_4
#include "string.h" // memset
#include "usb.h" // struct usb_s
#include "usb-uhci.h" // USBLEGSUP
#include "util.h" // msleep
#include "x86.h" // outw

struct usb_uhci_s {
    struct usb_s usb;
    u16 iobase;
    struct uhci_qh *control_qh;
    struct uhci_framelist *framelist;
};

struct uhci_pipe {
    struct uhci_qh qh;
    struct uhci_td *next_td;
    struct usb_pipe pipe;
    u16 iobase;
    u8 toggle;
};


/****************************************************************
 * Root hub
 ****************************************************************/

// Check if device attached to a given port
static int
uhci_hub_detect(struct usbhub_s *hub, u32 port)
{
    struct usb_uhci_s *cntl = container_of(hub->cntl, struct usb_uhci_s, usb);
    u16 ioport = cntl->iobase + USBPORTSC1 + port * 2;
    u16 status = inw(ioport);
    if (!(status & USBPORTSC_CCS))
        // No device found.
        return 0;

    // XXX - if just powered up, need to wait for USB_TIME_ATTDB?

    // Begin reset on port
    outw(USBPORTSC_PR, ioport);
    msleep(USB_TIME_DRSTR);
    return 1;
}

// Reset device on port
static int
uhci_hub_reset(struct usbhub_s *hub, u32 port)
{
    struct usb_uhci_s *cntl = container_of(hub->cntl, struct usb_uhci_s, usb);
    u16 ioport = cntl->iobase + USBPORTSC1 + port * 2;

    // Finish reset on port
    outw(0, ioport);
    udelay(6); // 64 high-speed bit times
    u16 status = inw(ioport);
    if (!(status & USBPORTSC_CCS))
        // No longer connected
        return -1;
    outw(USBPORTSC_PE, ioport);
    return !!(status & USBPORTSC_LSDA);
}

// Disable port
static void
uhci_hub_disconnect(struct usbhub_s *hub, u32 port)
{
    struct usb_uhci_s *cntl = container_of(hub->cntl, struct usb_uhci_s, usb);
    u16 ioport = cntl->iobase + USBPORTSC1 + port * 2;
    outw(0, ioport);
}

static struct usbhub_op_s uhci_HubOp = {
    .detect = uhci_hub_detect,
    .reset = uhci_hub_reset,
    .disconnect = uhci_hub_disconnect,
};

// Find any devices connected to the root hub.
static int
check_uhci_ports(struct usb_uhci_s *cntl)
{
    ASSERT32FLAT();
    struct usbhub_s hub;
    memset(&hub, 0, sizeof(hub));
    hub.cntl = &cntl->usb;
    hub.portcount = 2;
    hub.op = &uhci_HubOp;
    usb_enumerate(&hub);
    return hub.devcount;
}


/****************************************************************
 * Setup
 ****************************************************************/

// Wait for next USB frame to start - for ensuring safe memory release.
static void
uhci_waittick(u16 iobase)
{
    barrier();
    u16 startframe = inw(iobase + USBFRNUM);
    u32 end = timer_calc(1000 * 5);
    for (;;) {
        if (inw(iobase + USBFRNUM) != startframe)
            break;
        if (timer_check(end)) {
            warn_timeout();
            return;
        }
        yield();
    }
}

static void
uhci_free_pipes(struct usb_uhci_s *cntl)
{
    dprintf(7, "uhci_free_pipes %p\n", cntl);

    struct uhci_qh *pos = (void*)(cntl->framelist->links[0] & ~UHCI_PTR_BITS);
    for (;;) {
        u32 link = pos->link;
        if (link == UHCI_PTR_TERM)
            break;
        struct uhci_qh *next = (void*)(link & ~UHCI_PTR_BITS);
        struct uhci_pipe *pipe = container_of(next, struct uhci_pipe, qh);
        if (usb_is_freelist(&cntl->usb, &pipe->pipe))
            pos->link = next->link;
        else
            pos = next;
    }
    uhci_waittick(cntl->iobase);
    for (;;) {
        struct usb_pipe *usbpipe = cntl->usb.freelist;
        if (!usbpipe)
            break;
        cntl->usb.freelist = usbpipe->freenext;
        struct uhci_pipe *pipe = container_of(usbpipe, struct uhci_pipe, pipe);
        free(pipe);
    }
}

static void
reset_uhci(struct usb_uhci_s *cntl, u16 bdf)
{
    // XXX - don't reset if not needed.

    // Reset PIRQ and SMI
    pci_config_writew(bdf, USBLEGSUP, USBLEGSUP_RWC);

    // Reset the HC
    outw(USBCMD_HCRESET, cntl->iobase + USBCMD);
    udelay(5);

    // Disable interrupts and commands (just to be safe).
    outw(0, cntl->iobase + USBINTR);
    outw(0, cntl->iobase + USBCMD);
}

static void
configure_uhci(void *data)
{
    struct usb_uhci_s *cntl = data;

    // Allocate ram for schedule storage
    struct uhci_td *term_td = malloc_high(sizeof(*term_td));
    struct uhci_framelist *fl = memalign_high(sizeof(*fl), sizeof(*fl));
    struct uhci_pipe *intr_pipe = malloc_high(sizeof(*intr_pipe));
    struct uhci_pipe *term_pipe = malloc_high(sizeof(*term_pipe));
    if (!term_td || !fl || !intr_pipe || !term_pipe) {
        warn_noalloc();
        goto fail;
    }

    // Work around for PIIX errata
    memset(term_td, 0, sizeof(*term_td));
    term_td->link = UHCI_PTR_TERM;
    term_td->token = (uhci_explen(0) | (0x7f << TD_TOKEN_DEVADDR_SHIFT)
                      | USB_PID_IN);
    memset(term_pipe, 0, sizeof(*term_pipe));
    term_pipe->qh.element = (u32)term_td;
    term_pipe->qh.link = UHCI_PTR_TERM;
    term_pipe->pipe.cntl = &cntl->usb;

    // Set schedule to point to primary intr queue head
    memset(intr_pipe, 0, sizeof(*intr_pipe));
    intr_pipe->qh.element = UHCI_PTR_TERM;
    intr_pipe->qh.link = (u32)&term_pipe->qh | UHCI_PTR_QH;
    intr_pipe->pipe.cntl = &cntl->usb;
    int i;
    for (i=0; i<ARRAY_SIZE(fl->links); i++)
        fl->links[i] = (u32)&intr_pipe->qh | UHCI_PTR_QH;
    cntl->framelist = fl;
    cntl->control_qh = &intr_pipe->qh;
    barrier();

    // Set the frame length to the default: 1 ms exactly
    outb(USBSOF_DEFAULT, cntl->iobase + USBSOF);

    // Store the frame list base address
    outl((u32)fl->links, cntl->iobase + USBFLBASEADD);

    // Set the current frame number
    outw(0, cntl->iobase + USBFRNUM);

    // Mark as configured and running with a 64-byte max packet.
    outw(USBCMD_RS | USBCMD_CF | USBCMD_MAXP, cntl->iobase + USBCMD);

    // Find devices
    int count = check_uhci_ports(cntl);
    uhci_free_pipes(cntl);
    if (count)
        // Success
        return;

    // No devices found - shutdown and free controller.
    outw(0, cntl->iobase + USBCMD);
fail:
    free(term_td);
    free(fl);
    free(intr_pipe);
    free(term_pipe);
    free(cntl);
}

static void
uhci_controller_setup(struct pci_device *pci)
{
    u16 bdf = pci->bdf;
    struct usb_uhci_s *cntl = malloc_tmphigh(sizeof(*cntl));
    if (!cntl) {
        warn_noalloc();
        return;
    }
    wait_preempt();  // Avoid pci_config_readl when preempting
    memset(cntl, 0, sizeof(*cntl));
    cntl->usb.pci = pci;
    cntl->usb.type = USB_TYPE_UHCI;
    cntl->iobase = (pci_config_readl(bdf, PCI_BASE_ADDRESS_4)
                    & PCI_BASE_ADDRESS_IO_MASK);

    dprintf(1, "UHCI init on dev %02x:%02x.%x (io=%x)\n"
            , pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf)
            , pci_bdf_to_fn(bdf), cntl->iobase);

    pci_config_maskw(bdf, PCI_COMMAND, 0, PCI_COMMAND_MASTER);

    reset_uhci(cntl, bdf);

    run_thread(configure_uhci, cntl);
}

void
uhci_setup(void)
{
    if (! CONFIG_USB_UHCI)
        return;
    struct pci_device *pci;
    foreachpci(pci) {
        if (pci_classprog(pci) == PCI_CLASS_SERIAL_USB_UHCI)
            uhci_controller_setup(pci);
    }
}


/****************************************************************
 * End point communication
 ****************************************************************/

static struct usb_pipe *
uhci_alloc_intr_pipe(struct usbdevice_s *usbdev
                     , struct usb_endpoint_descriptor *epdesc)
{
    struct usb_uhci_s *cntl = container_of(
        usbdev->hub->cntl, struct usb_uhci_s, usb);
    int frameexp = usb_get_period(usbdev, epdesc);
    dprintf(7, "uhci_alloc_intr_pipe %p %d\n", &cntl->usb, frameexp);

    if (frameexp > 10)
        frameexp = 10;
    int maxpacket = epdesc->wMaxPacketSize;
    // Determine number of entries needed for 2 timer ticks.
    int ms = 1<<frameexp;
    int count = DIV_ROUND_UP(ticks_to_ms(2), ms);
    count = ALIGN(count, 2);
    struct uhci_pipe *pipe = malloc_low(sizeof(*pipe));
    struct uhci_td *tds = malloc_low(sizeof(*tds) * count);
    void *data = malloc_low(maxpacket * count);
    if (!pipe || !tds || !data) {
        warn_noalloc();
        goto fail;
    }
    memset(pipe, 0, sizeof(*pipe));
    usb_desc2pipe(&pipe->pipe, usbdev, epdesc);
    int lowspeed = pipe->pipe.speed;
    int devaddr = pipe->pipe.devaddr | (pipe->pipe.ep << 7);
    pipe->qh.element = (u32)tds;
    pipe->next_td = &tds[0];
    pipe->iobase = cntl->iobase;

    int toggle = 0;
    int i;
    for (i=0; i<count; i++) {
        tds[i].link = (i==count-1 ? (u32)&tds[0] : (u32)&tds[i+1]);
        tds[i].status = (uhci_maxerr(3) | (lowspeed ? TD_CTRL_LS : 0)
                         | TD_CTRL_ACTIVE);
        tds[i].token = (uhci_explen(maxpacket) | toggle
                        | (devaddr << TD_TOKEN_DEVADDR_SHIFT)
                        | USB_PID_IN);
        tds[i].buffer = data + maxpacket * i;
        toggle ^= TD_TOKEN_TOGGLE;
    }

    // Add to interrupt schedule.
    struct uhci_framelist *fl = cntl->framelist;
    if (frameexp == 0) {
        // Add to existing interrupt entry.
        struct uhci_qh *intr_qh = (void*)(fl->links[0] & ~UHCI_PTR_BITS);
        pipe->qh.link = intr_qh->link;
        barrier();
        intr_qh->link = (u32)&pipe->qh | UHCI_PTR_QH;
        if (cntl->control_qh == intr_qh)
            cntl->control_qh = &pipe->qh;
    } else {
        int startpos = 1<<(frameexp-1);
        pipe->qh.link = fl->links[startpos];
        barrier();
        for (i=startpos; i<ARRAY_SIZE(fl->links); i+=ms)
            fl->links[i] = (u32)&pipe->qh | UHCI_PTR_QH;
    }

    return &pipe->pipe;
fail:
    free(pipe);
    free(tds);
    free(data);
    return NULL;
}

struct usb_pipe *
uhci_realloc_pipe(struct usbdevice_s *usbdev, struct usb_pipe *upipe
                  , struct usb_endpoint_descriptor *epdesc)
{
    if (! CONFIG_USB_UHCI)
        return NULL;
    usb_add_freelist(upipe);
    if (!epdesc)
        return NULL;
    u8 eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    if (eptype == USB_ENDPOINT_XFER_INT)
        return uhci_alloc_intr_pipe(usbdev, epdesc);
    struct usb_uhci_s *cntl = container_of(
        usbdev->hub->cntl, struct usb_uhci_s, usb);
    dprintf(7, "uhci_alloc_async_pipe %p %d\n", &cntl->usb, eptype);

    struct usb_pipe *usbpipe = usb_get_freelist(&cntl->usb, eptype);
    if (usbpipe) {
        // Use previously allocated pipe.
        usb_desc2pipe(usbpipe, usbdev, epdesc);
        return usbpipe;
    }

    // Allocate a new queue head.
    struct uhci_pipe *pipe;
    if (eptype == USB_ENDPOINT_XFER_CONTROL)
        pipe = malloc_tmphigh(sizeof(*pipe));
    else
        pipe = malloc_low(sizeof(*pipe));
    if (!pipe) {
        warn_noalloc();
        return NULL;
    }
    memset(pipe, 0, sizeof(*pipe));
    usb_desc2pipe(&pipe->pipe, usbdev, epdesc);
    pipe->qh.element = UHCI_PTR_TERM;
    pipe->iobase = cntl->iobase;

    // Add queue head to controller list.
    struct uhci_qh *control_qh = cntl->control_qh;
    pipe->qh.link = control_qh->link;
    barrier();
    control_qh->link = (u32)&pipe->qh | UHCI_PTR_QH;
    if (eptype == USB_ENDPOINT_XFER_CONTROL)
        cntl->control_qh = &pipe->qh;
    return &pipe->pipe;
}

static int
wait_pipe(struct uhci_pipe *pipe, u32 end)
{
    for (;;) {
        u32 el_link = GET_LOWFLAT(pipe->qh.element);
        if (el_link & UHCI_PTR_TERM)
            return 0;
        if (timer_check(end)) {
            warn_timeout();
            u16 iobase = GET_LOWFLAT(pipe->iobase);
            struct uhci_td *td = (void*)(el_link & ~UHCI_PTR_BITS);
            dprintf(1, "Timeout on wait_pipe %p (td=%p s=%x c=%x/%x)\n"
                    , pipe, (void*)el_link, GET_LOWFLAT(td->status)
                    , inw(iobase + USBCMD)
                    , inw(iobase + USBSTS));
            SET_LOWFLAT(pipe->qh.element, UHCI_PTR_TERM);
            uhci_waittick(iobase);
            return -1;
        }
        yield();
    }
}

static int
wait_td(struct uhci_td *td, u32 end)
{
    u32 status;
    for (;;) {
        status = td->status;
        if (!(status & TD_CTRL_ACTIVE))
            break;
        if (timer_check(end)) {
            warn_timeout();
            return -1;
        }
        yield();
    }
    if (status & TD_CTRL_ANY_ERROR) {
        dprintf(1, "wait_td error - status=%x\n", status);
        return -2;
    }
    return 0;
}

#define STACKTDS 16
#define TDALIGN 16

int
uhci_send_pipe(struct usb_pipe *p, int dir, const void *cmd
               , void *data, int datasize)
{
    if (! CONFIG_USB_UHCI)
        return -1;
    struct uhci_pipe *pipe = container_of(p, struct uhci_pipe, pipe);
    dprintf(7, "uhci_send_pipe qh=%p dir=%d data=%p size=%d\n"
            , &pipe->qh, dir, data, datasize);
    int maxpacket = GET_LOWFLAT(pipe->pipe.maxpacket);
    int lowspeed = GET_LOWFLAT(pipe->pipe.speed);
    int devaddr = (GET_LOWFLAT(pipe->pipe.devaddr)
                   | (GET_LOWFLAT(pipe->pipe.ep) << 7));
    int toggle = GET_LOWFLAT(pipe->toggle) ? TD_TOKEN_TOGGLE : 0;

    // Allocate 16 tds on stack (16byte aligned)
    u8 tdsbuf[sizeof(struct uhci_td) * STACKTDS + TDALIGN - 1];
    struct uhci_td *tds = (void*)ALIGN((u32)tdsbuf, TDALIGN);
    memset(tds, 0, sizeof(*tds) * STACKTDS);
    int tdpos = 0;

    // Enable tds
    u32 end = timer_calc(usb_xfer_time(p, datasize));
    barrier();
    SET_LOWFLAT(pipe->qh.element, (u32)MAKE_FLATPTR(GET_SEG(SS), tds));

    // Setup transfer descriptors
    if (cmd) {
        // Send setup pid on control transfers
        struct uhci_td *td = &tds[tdpos++ % STACKTDS];
        u32 nexttd = (u32)MAKE_FLATPTR(GET_SEG(SS), &tds[tdpos % STACKTDS]);
        td->link = nexttd | UHCI_PTR_DEPTH;
        td->token = (uhci_explen(USB_CONTROL_SETUP_SIZE)
                     | (devaddr << TD_TOKEN_DEVADDR_SHIFT) | USB_PID_SETUP);
        td->buffer = (void*)cmd;
        barrier();
        td->status = (uhci_maxerr(3) | (lowspeed ? TD_CTRL_LS : 0)
                      | TD_CTRL_ACTIVE);
        toggle = TD_TOKEN_TOGGLE;
    }
    while (datasize) {
        // Send data pids
        struct uhci_td *td = &tds[tdpos++ % STACKTDS];
        int ret = wait_td(td, end);
        if (ret)
            goto fail;

        int transfer = datasize;
        if (transfer > maxpacket)
            transfer = maxpacket;
        u32 nexttd = (u32)MAKE_FLATPTR(GET_SEG(SS), &tds[tdpos % STACKTDS]);
        td->link = ((transfer==datasize && !cmd)
                    ? UHCI_PTR_TERM : (nexttd | UHCI_PTR_DEPTH));
        td->token = (uhci_explen(transfer) | toggle
                     | (devaddr << TD_TOKEN_DEVADDR_SHIFT)
                     | (dir ? USB_PID_IN : USB_PID_OUT));
        td->buffer = data;
        barrier();
        td->status = (uhci_maxerr(3) | (lowspeed ? TD_CTRL_LS : 0)
                      | TD_CTRL_ACTIVE);
        toggle ^= TD_TOKEN_TOGGLE;

        data += transfer;
        datasize -= transfer;
    }
    if (cmd) {
        // Send status pid on control transfers
        struct uhci_td *td = &tds[tdpos++ % STACKTDS];
        int ret = wait_td(td, end);
        if (ret)
            goto fail;
        td->link = UHCI_PTR_TERM;
        td->token = (uhci_explen(0) | TD_TOKEN_TOGGLE
                     | (devaddr << TD_TOKEN_DEVADDR_SHIFT)
                     | (dir ? USB_PID_OUT : USB_PID_IN));
        td->buffer = 0;
        barrier();
        td->status = (uhci_maxerr(0) | (lowspeed ? TD_CTRL_LS : 0)
                      | TD_CTRL_ACTIVE);
    }
    SET_LOWFLAT(pipe->toggle, !!toggle);
    return wait_pipe(pipe, end);
fail:
    dprintf(1, "uhci_send_bulk failed\n");
    SET_LOWFLAT(pipe->qh.element, UHCI_PTR_TERM);
    uhci_waittick(GET_LOWFLAT(pipe->iobase));
    return -1;
}

int
uhci_poll_intr(struct usb_pipe *p, void *data)
{
    ASSERT16();
    if (! CONFIG_USB_UHCI)
        return -1;

    struct uhci_pipe *pipe = container_of(p, struct uhci_pipe, pipe);
    struct uhci_td *td = GET_LOWFLAT(pipe->next_td);
    u32 status = GET_LOWFLAT(td->status);
    u32 token = GET_LOWFLAT(td->token);
    if (status & TD_CTRL_ACTIVE)
        // No intrs found.
        return -1;
    // XXX - check for errors.

    // Copy data.
    void *tddata = GET_LOWFLAT(td->buffer);
    memcpy_far(GET_SEG(SS), data, SEG_LOW, LOWFLAT2LOW(tddata)
               , uhci_expected_length(token));

    // Reenable this td.
    struct uhci_td *next = (void*)(GET_LOWFLAT(td->link) & ~UHCI_PTR_BITS);
    SET_LOWFLAT(pipe->next_td, next);
    barrier();
    SET_LOWFLAT(td->status, (uhci_maxerr(0) | (status & TD_CTRL_LS)
                             | TD_CTRL_ACTIVE));

    return 0;
}
