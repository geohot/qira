#ifndef _INTELXVF_H
#define _INTELXVF_H

/** @file
 *
 * Intel 10 Gigabit Ethernet virtual function network card driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include "intelvf.h"

/** Control Register */
#define INTELXVF_CTRL 0x0000UL
#define INTELXVF_CTRL_RST	0x04000000UL	/**< Function-level reset */

/** Link Status Register */
#define INTELXVF_LINKS 0x0010UL
#define INTELXVF_LINKS_UP	0x40000000UL	/**< Link up */

/** Extended Interrupt Cause Read Register */
#define INTELXVF_EICR 0x0100UL
#define INTELXVF_EIRQ_RX0	0x00000001UL	/**< RX queue 0 (via IVAR) */
#define INTELXVF_EIRQ_TX0	0x00000002UL	/**< TX queue 0 (via IVAR) */
#define INTELXVF_EIRQ_MBOX	0x00000004UL	/**< Mailbox (via IVARM) */

/** Extended Interrupt Mask Set/Read Register */
#define INTELXVF_EIMS 0x0108UL

/** Extended Interrupt Mask Clear Register */
#define INTELXVF_EIMC 0x010cUL

/** Interrupt Vector Allocation Register */
#define INTELXVF_IVAR 0x0120UL
#define INTELXVF_IVAR_RX0(bit)	( (bit) << 0 )	/**< RX queue 0 allocation */
#define INTELXVF_IVAR_RX0_DEFAULT INTELXVF_IVAR_RX0 ( 0x00 )
#define INTELXVF_IVAR_RX0_MASK	INTELXVF_IVAR_RX0 ( 0x01 )
#define INTELXVF_IVAR_RX0_VALID	0x00000080UL	/**< RX queue 0 valid */
#define INTELXVF_IVAR_TX0(bit)	( (bit) << 8 )	/**< TX queue 0 allocation */
#define INTELXVF_IVAR_TX0_DEFAULT INTELXVF_IVAR_TX0 ( 0x01 )
#define INTELXVF_IVAR_TX0_MASK	INTELXVF_IVAR_TX0 ( 0x01 )
#define INTELXVF_IVAR_TX0_VALID	0x00008000UL	/**< TX queue 0 valid */

/** Interrupt Vector Allocation Miscellaneous Register */
#define INTELXVF_IVARM 0x0140UL
#define INTELXVF_IVARM_MBOX(bit) ( (bit) << 0 )	/**< Mailbox allocation */
#define INTELXVF_IVARM_MBOX_DEFAULT INTELXVF_IVARM_MBOX ( 0x02 )
#define INTELXVF_IVARM_MBOX_MASK INTELXVF_IVARM_MBOX ( 0x03 )
#define INTELXVF_IVARM_MBOX_VALID 0x00000080UL	/**< Mailbox valid */

/** Mailbox Memory Register Base */
#define INTELXVF_MBMEM 0x0200UL

/** Mailbox Control Register */
#define INTELXVF_MBCTRL 0x02fcUL

/** Receive Descriptor register block */
#define INTELXVF_RD 0x1000UL

/** RX DCA Control Register */
#define INTELXVF_DCA_RXCTRL 0x100cUL
#define INTELXVF_DCA_RXCTRL_MUST_BE_ZERO 0x00001000UL /**< Must be zero */

/** Split Receive Control Register */
#define INTELXVF_SRRCTL 0x1014UL
#define INTELXVF_SRRCTL_BSIZE(kb) ( (kb) << 0 )	/**< Receive buffer size */
#define INTELXVF_SRRCTL_BSIZE_DEFAULT INTELXVF_SRRCTL_BSIZE ( 0x02 )
#define INTELXVF_SRRCTL_BSIZE_MASK INTELXVF_SRRCTL_BSIZE ( 0x1f )
#define INTELXVF_SRRCTL_DESCTYPE(typ) ( (typ) << 25 ) /**< Descriptor type */
#define INTELXVF_SRRCTL_DESCTYPE_DEFAULT INTELXVF_SRRCTL_DESCTYPE ( 0x00 )
#define INTELXVF_SRRCTL_DESCTYPE_MASK INTELXVF_SRRCTL_DESCTYPE ( 0x07 )

/** Good Packets Received Count */
#define INTELXVF_GPRC 0x101c

/** Good Packets Received Count Low */
#define INTELXVF_GORCL 0x1020

/** Good Packets Received Count High */
#define INTELXVF_GORCH 0x1024

/* Multicast Packets Received Count */
#define INTELXVF_MPRC 0x1034

/** Transmit Descriptor register block */
#define INTELXVF_TD 0x2000UL

/** Good Packets Transmitted Count */
#define INTELXVF_GPTC 0x201c

/** Good Packets Transmitted Count Low */
#define INTELXVF_GOTCL 0x2020

/** Good Packets Transmitted Count High */
#define INTELXVF_GOTCH 0x2024

/** Negotiate API version mailbox message */
#define INTELXVF_MSG_TYPE_VERSION 0x00000008UL

/** API version 1.1 */
#define INTELXVF_MSG_VERSION_1_1 0x00000002UL

#endif /* _INTELXVF_H */
