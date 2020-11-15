#ifndef __USB_UHCI_H
#define __USB_UHCI_H

// usb-uhci.c
void uhci_setup(void);
struct usbdevice_s;
struct usb_endpoint_descriptor;
struct usb_pipe;
struct usb_pipe *uhci_realloc_pipe(struct usbdevice_s *usbdev
                                   , struct usb_pipe *upipe
                                   , struct usb_endpoint_descriptor *epdesc);
int uhci_send_pipe(struct usb_pipe *p, int dir, const void *cmd
                   , void *data, int datasize);
int uhci_poll_intr(struct usb_pipe *p, void *data);


/****************************************************************
 * uhci structs and flags
 ****************************************************************/

/* USB port status and control registers */
#define USBPORTSC1      16
#define USBPORTSC2      18
#define   USBPORTSC_CCS         0x0001  /* Current Connect Status
                                         * ("device present") */
#define   USBPORTSC_CSC         0x0002  /* Connect Status Change */
#define   USBPORTSC_PE          0x0004  /* Port Enable */
#define   USBPORTSC_PEC         0x0008  /* Port Enable Change */
#define   USBPORTSC_DPLUS       0x0010  /* D+ high (line status) */
#define   USBPORTSC_DMINUS      0x0020  /* D- high (line status) */
#define   USBPORTSC_RD          0x0040  /* Resume Detect */
#define   USBPORTSC_RES1        0x0080  /* reserved, always 1 */
#define   USBPORTSC_LSDA        0x0100  /* Low Speed Device Attached */
#define   USBPORTSC_PR          0x0200  /* Port Reset */

/* Legacy support register */
#define USBLEGSUP               0xc0
#define   USBLEGSUP_RWC         0x8f00  /* the R/WC bits */

/* Command register */
#define USBCMD          0
#define   USBCMD_RS             0x0001  /* Run/Stop */
#define   USBCMD_HCRESET        0x0002  /* Host reset */
#define   USBCMD_GRESET         0x0004  /* Global reset */
#define   USBCMD_EGSM           0x0008  /* Global Suspend Mode */
#define   USBCMD_FGR            0x0010  /* Force Global Resume */
#define   USBCMD_SWDBG          0x0020  /* SW Debug mode */
#define   USBCMD_CF             0x0040  /* Config Flag (sw only) */
#define   USBCMD_MAXP           0x0080  /* Max Packet (0 = 32, 1 = 64) */

/* Status register */
#define USBSTS          2
#define   USBSTS_USBINT         0x0001  /* Interrupt due to IOC */
#define   USBSTS_ERROR          0x0002  /* Interrupt due to error */
#define   USBSTS_RD             0x0004  /* Resume Detect */
#define   USBSTS_HSE            0x0008  /* Host System Error: PCI problems */
#define   USBSTS_HCPE           0x0010  /* Host Controller Process Error:
                                         * the schedule is buggy */
#define   USBSTS_HCH            0x0020  /* HC Halted */

/* Interrupt enable register */
#define USBINTR         4
#define   USBINTR_TIMEOUT       0x0001  /* Timeout/CRC error enable */
#define   USBINTR_RESUME        0x0002  /* Resume interrupt enable */
#define   USBINTR_IOC           0x0004  /* Interrupt On Complete enable */
#define   USBINTR_SP            0x0008  /* Short packet interrupt enable */

#define USBFRNUM        6
#define USBFLBASEADD    8
#define USBSOF          12
#define   USBSOF_DEFAULT        64      /* Frame length is exactly 1 ms */

struct uhci_framelist {
    u32 links[1024];
} PACKED;

#define TD_CTRL_SPD             (1 << 29)       /* Short Packet Detect */
#define TD_CTRL_C_ERR_MASK      (3 << 27)       /* Error Counter bits */
#define TD_CTRL_C_ERR_SHIFT     27
#define TD_CTRL_LS              (1 << 26)       /* Low Speed Device */
#define TD_CTRL_IOS             (1 << 25)       /* Isochronous Select */
#define TD_CTRL_IOC             (1 << 24)       /* Interrupt on Complete */
#define TD_CTRL_ACTIVE          (1 << 23)       /* TD Active */
#define TD_CTRL_STALLED         (1 << 22)       /* TD Stalled */
#define TD_CTRL_DBUFERR         (1 << 21)       /* Data Buffer Error */
#define TD_CTRL_BABBLE          (1 << 20)       /* Babble Detected */
#define TD_CTRL_NAK             (1 << 19)       /* NAK Received */
#define TD_CTRL_CRCTIMEO        (1 << 18)       /* CRC/Time Out Error */
#define TD_CTRL_BITSTUFF        (1 << 17)       /* Bit Stuff Error */
#define TD_CTRL_ACTLEN_MASK     0x7FF   /* actual length, encoded as n - 1 */

#define TD_CTRL_ANY_ERROR       (TD_CTRL_STALLED | TD_CTRL_DBUFERR | \
                                 TD_CTRL_BABBLE | TD_CTRL_CRCTIMEO | \
                                 TD_CTRL_BITSTUFF)
#define uhci_maxerr(err)                ((err) << TD_CTRL_C_ERR_SHIFT)

#define TD_TOKEN_DEVADDR_SHIFT  8
#define TD_TOKEN_TOGGLE_SHIFT   19
#define TD_TOKEN_TOGGLE         (1 << 19)
#define TD_TOKEN_EXPLEN_SHIFT   21
#define TD_TOKEN_EXPLEN_MASK    0x7FF   /* expected length, encoded as n-1 */
#define TD_TOKEN_PID_MASK       0xFF

#define uhci_explen(len)        ((((len) - 1) & TD_TOKEN_EXPLEN_MASK) << \
                                        TD_TOKEN_EXPLEN_SHIFT)

#define uhci_expected_length(token) ((((token) >> TD_TOKEN_EXPLEN_SHIFT) + \
                                        1) & TD_TOKEN_EXPLEN_MASK)

struct uhci_td {
    u32 link;
    u32 status;
    u32 token;
    void *buffer;
} PACKED;

struct uhci_qh {
    u32 link;
    u32 element;
} PACKED;

#define UHCI_PTR_BITS           0x000F
#define UHCI_PTR_TERM           0x0001
#define UHCI_PTR_QH             0x0002
#define UHCI_PTR_DEPTH          0x0004
#define UHCI_PTR_BREADTH        0x0000

#endif // usb-uhci.h
