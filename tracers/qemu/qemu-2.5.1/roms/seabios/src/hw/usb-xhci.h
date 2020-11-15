#ifndef __USB_XHCI_H
#define __USB_XHCI_H

struct usbdevice_s;
struct usb_endpoint_descriptor;
struct usb_pipe;

// --------------------------------------------------------------

// usb-xhci.c
void xhci_setup(void);
struct usb_pipe *xhci_realloc_pipe(struct usbdevice_s *usbdev
                                   , struct usb_pipe *upipe
                                   , struct usb_endpoint_descriptor *epdesc);
int xhci_send_pipe(struct usb_pipe *p, int dir, const void *cmd
                   , void *data, int datasize);
int xhci_poll_intr(struct usb_pipe *p, void *data);

// --------------------------------------------------------------
// register interface

// capabilities
struct xhci_caps {
    u8  caplength;
    u8  reserved_01;
    u16 hciversion;
    u32 hcsparams1;
    u32 hcsparams2;
    u32 hcsparams3;
    u32 hccparams;
    u32 dboff;
    u32 rtsoff;
} PACKED;

// extended capabilities
struct xhci_xcap {
    u32 cap;
    u32 data[];
} PACKED;

// operational registers
struct xhci_op {
    u32 usbcmd;
    u32 usbsts;
    u32 pagesize;
    u32 reserved_01[2];
    u32 dnctl;
    u32 crcr_low;
    u32 crcr_high;
    u32 reserved_02[4];
    u32 dcbaap_low;
    u32 dcbaap_high;
    u32 config;
} PACKED;

// port registers
struct xhci_pr {
    u32 portsc;
    u32 portpmsc;
    u32 portli;
    u32 reserved_01;
} PACKED;

// doorbell registers
struct xhci_db {
    u32 doorbell;
} PACKED;

// runtime registers
struct xhci_rts {
    u32 mfindex;
} PACKED;

// interrupter registers
struct xhci_ir {
    u32 iman;
    u32 imod;
    u32 erstsz;
    u32 reserved_01;
    u32 erstba_low;
    u32 erstba_high;
    u32 erdp_low;
    u32 erdp_high;
} PACKED;

// --------------------------------------------------------------
// memory data structs

// slot context
struct xhci_slotctx {
    u32 ctx[4];
    u32 reserved_01[4];
} PACKED;

// endpoint context
struct xhci_epctx {
    u32 ctx[2];
    u32 deq_low;
    u32 deq_high;
    u32 length;
    u32 reserved_01[3];
} PACKED;

// device context array element
struct xhci_devlist {
    u32 ptr_low;
    u32 ptr_high;
} PACKED;

// input context
struct xhci_inctx {
    u32 del;
    u32 add;
    u32 reserved_01[6];
} PACKED;

// transfer block (ring element)
struct xhci_trb {
    u32 ptr_low;
    u32 ptr_high;
    u32 status;
    u32 control;
} PACKED;

// event ring segment
struct xhci_er_seg {
    u32 ptr_low;
    u32 ptr_high;
    u32 size;
    u32 reserved_01;
} PACKED;

#endif // usb-xhci.h
