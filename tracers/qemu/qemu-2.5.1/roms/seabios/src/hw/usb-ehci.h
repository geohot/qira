#ifndef __USB_EHCI_H
#define __USB_EHCI_H

// usb-ehci.c
void ehci_setup(void);
struct usbdevice_s;
struct usb_endpoint_descriptor;
struct usb_pipe;
struct usb_pipe *ehci_realloc_pipe(struct usbdevice_s *usbdev
                                   , struct usb_pipe *upipe
                                   , struct usb_endpoint_descriptor *epdesc);
int ehci_send_pipe(struct usb_pipe *p, int dir, const void *cmd
                   , void *data, int datasize);
int ehci_poll_intr(struct usb_pipe *p, void *data);


/****************************************************************
 * ehci structs and flags
 ****************************************************************/

struct ehci_caps {
    u8 caplength;
    u8 reserved_01;
    u16 hciversion;
    u32 hcsparams;
    u32 hccparams;
    u64 portroute;
} PACKED;

#define HCC_64BIT_ADDR 1

#define HCS_N_PORTS_MASK 0xf

struct ehci_regs {
    u32 usbcmd;
    u32 usbsts;
    u32 usbintr;
    u32 frindex;
    u32 ctrldssegment;
    u32 periodiclistbase;
    u32 asynclistbase;
    u32 reserved[9];
    u32 configflag;
    u32 portsc[0];
} PACKED;

#define CMD_PARK        (1<<11)
#define CMD_PARK_CNT(c) (((c)>>8)&3)
#define CMD_LRESET      (1<<7)
#define CMD_IAAD        (1<<6)
#define CMD_ASE         (1<<5)
#define CMD_PSE         (1<<4)
#define CMD_HCRESET     (1<<1)
#define CMD_RUN         (1<<0)

#define STS_ASS         (1<<15)
#define STS_PSS         (1<<14)
#define STS_RECL        (1<<13)
#define STS_HALT        (1<<12)
#define STS_IAA         (1<<5)
#define STS_FATAL       (1<<4)
#define STS_FLR         (1<<3)
#define STS_PCD         (1<<2)
#define STS_ERR         (1<<1)
#define STS_INT         (1<<0)

#define FLAG_CF         (1<<0)

#define PORT_WKOC_E     (1<<22)
#define PORT_WKDISC_E   (1<<21)
#define PORT_WKCONN_E   (1<<20)
#define PORT_TEST_PKT   (0x4<<16)
#define PORT_LED_OFF    (0<<14)
#define PORT_LED_AMBER  (1<<14)
#define PORT_LED_GREEN  (2<<14)
#define PORT_LED_MASK   (3<<14)
#define PORT_OWNER      (1<<13)
#define PORT_POWER      (1<<12)
#define PORT_LINESTATUS_MASK   (3<<10)
#define PORT_LINESTATUS_KSTATE (1<<10)
#define PORT_RESET      (1<<8)
#define PORT_SUSPEND    (1<<7)
#define PORT_RESUME     (1<<6)
#define PORT_OCC        (1<<5)
#define PORT_OC         (1<<4)
#define PORT_PEC        (1<<3)
#define PORT_PE         (1<<2)
#define PORT_CSC        (1<<1)
#define PORT_CONNECT    (1<<0)
#define PORT_RWC_BITS   (PORT_CSC | PORT_PEC | PORT_OCC)


#define EHCI_QH_ALIGN 128 // Can't span a 4K boundary, so increase from 32

struct ehci_qh {
    u32 next;
    u32 info1;
    u32 info2;
    u32 current;

    u32 qtd_next;
    u32 alt_next;
    u32 token;
    u32 buf[5];
    u32 buf_hi[5];
} PACKED;

#define QH_CONTROL       (1 << 27)
#define QH_MAXPACKET_SHIFT 16
#define QH_MAXPACKET_MASK  (0x7ff << QH_MAXPACKET_SHIFT)
#define QH_HEAD          (1 << 15)
#define QH_TOGGLECONTROL (1 << 14)
#define QH_SPEED_SHIFT   12
#define QH_SPEED_MASK    (0x3 << QH_SPEED_SHIFT)
#define QH_EP_SHIFT      8
#define QH_EP_MASK       (0xf << QH_EP_SHIFT)
#define QH_DEVADDR_SHIFT 0
#define QH_DEVADDR_MASK  (0x7f << QH_DEVADDR_SHIFT)

#define QH_SMASK_SHIFT   0
#define QH_SMASK_MASK    (0xff << QH_SMASK_SHIFT)
#define QH_CMASK_SHIFT   8
#define QH_CMASK_MASK    (0xff << QH_CMASK_SHIFT)
#define QH_HUBADDR_SHIFT 16
#define QH_HUBADDR_MASK  (0x7f << QH_HUBADDR_SHIFT)
#define QH_HUBPORT_SHIFT 23
#define QH_HUBPORT_MASK  (0x7f << QH_HUBPORT_SHIFT)
#define QH_MULT_SHIFT    30
#define QH_MULT_MASK     (0x3 << QH_MULT_SHIFT)

#define EHCI_PTR_BITS           0x001F
#define EHCI_PTR_TERM           0x0001
#define EHCI_PTR_QH             0x0002


#define EHCI_QTD_ALIGN 64 // Can't span a 4K boundary, so increase from 32

struct ehci_qtd {
    u32 qtd_next;
    u32 alt_next;
    u32 token;
    u32 buf[5];
    u32 buf_hi[5];
    /* keep struct size a multiple of 64 bytes, as we're allocating
       arrays. Without this padding, the second qtd could have the
       wrong alignment. */
} PACKED __aligned(EHCI_QTD_ALIGN);

#define QTD_TOGGLE      (1 << 31)
#define QTD_LENGTH_SHIFT 16
#define QTD_LENGTH_MASK (0x7fff << QTD_LENGTH_SHIFT)
#define QTD_CERR_SHIFT  10
#define QTD_CERR_MASK   (0x3 << QTD_CERR_SHIFT)
#define QTD_IOC         (1 << 15)
#define QTD_PID_OUT     (0x0 << 8)
#define QTD_PID_IN      (0x1 << 8)
#define QTD_PID_SETUP   (0x2 << 8)
#define QTD_STS_ACTIVE  (1 << 7)
#define QTD_STS_HALT    (1 << 6)
#define QTD_STS_DBE     (1 << 5)
#define QTD_STS_BABBLE  (1 << 4)
#define QTD_STS_XACT    (1 << 3)
#define QTD_STS_MMF     (1 << 2)
#define QTD_STS_STS     (1 << 1)
#define QTD_STS_PING    (1 << 0)

#define ehci_explen(len) (((len) << QTD_LENGTH_SHIFT) & QTD_LENGTH_MASK)

#define ehci_maxerr(err) (((err) << QTD_CERR_SHIFT) & QTD_CERR_MASK)


struct ehci_framelist {
    u32 links[1024];
} PACKED;

#endif // usb-ehci.h
