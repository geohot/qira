#ifndef _INTELX_H
#define _INTELX_H

/** @file
 *
 * Intel 10 Gigabit Ethernet network card driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/if_ether.h>
#include "intel.h"

/** Device Control Register */
#define INTELX_CTRL 0x00000UL
#define INTELX_CTRL_LRST	0x00000008UL	/**< Link reset */
#define INTELX_CTRL_RST		0x04000000UL	/**< Device reset */

/** Time to delay for device reset, in milliseconds */
#define INTELX_RESET_DELAY_MS 20

/** Extended Interrupt Cause Read Register */
#define INTELX_EICR 0x00800UL
#define INTELX_EIRQ_RX0		0x00000001UL	/**< RX0 (via IVAR) */
#define INTELX_EIRQ_TX0		0x00000002UL	/**< RX0 (via IVAR) */
#define INTELX_EIRQ_RXO		0x00020000UL	/**< Receive overrun */
#define INTELX_EIRQ_LSC		0x00100000UL	/**< Link status change */

/** Interrupt Mask Set/Read Register */
#define INTELX_EIMS 0x00880UL

/** Interrupt Mask Clear Register */
#define INTELX_EIMC 0x00888UL

/** Interrupt Vector Allocation Register */
#define INTELX_IVAR 0x00900UL
#define INTELX_IVAR_RX0(bit)	( (bit) << 0 )	/**< RX queue 0 allocation */
#define INTELX_IVAR_RX0_DEFAULT	INTELX_IVAR_RX0 ( 0x00 )
#define INTELX_IVAR_RX0_MASK	INTELX_IVAR_RX0 ( 0x3f )
#define INTELX_IVAR_RX0_VALID	0x00000080UL	/**< RX queue 0 valid */
#define INTELX_IVAR_TX0(bit)	( (bit) << 8 )	/**< TX queue 0 allocation */
#define INTELX_IVAR_TX0_DEFAULT	INTELX_IVAR_TX0 ( 0x01 )
#define INTELX_IVAR_TX0_MASK	INTELX_IVAR_TX0 ( 0x3f )
#define INTELX_IVAR_TX0_VALID	0x00008000UL	/**< TX queue 0 valid */

/** Receive Filter Control Register */
#define INTELX_FCTRL 0x05080UL
#define INTELX_FCTRL_MPE	0x00000100UL	/**< Multicast promiscuous */
#define INTELX_FCTRL_UPE	0x00000200UL	/**< Unicast promiscuous mode */
#define INTELX_FCTRL_BAM	0x00000400UL	/**< Broadcast accept mode */

/** Receive Address Low
 *
 * The MAC address registers RAL0/RAH0 exist at address 0x05400 for
 * the 82598 and 0x0a200 for the 82599, according to the datasheet.
 * In practice, the 82599 seems to also provide a copy of these
 * registers at 0x05400.  To aim for maximum compatibility, we try
 * both addresses when reading the initial MAC address, and set both
 * addresses when setting the MAC address.
 */
#define INTELX_RAL0 0x05400UL
#define INTELX_RAL0_ALT 0x0a200UL

/** Receive Address High */
#define INTELX_RAH0 0x05404UL
#define INTELX_RAH0_ALT 0x0a204UL
#define INTELX_RAH0_AV		0x80000000UL	/**< Address valid */

/** Receive Descriptor register block */
#define INTELX_RD 0x01000UL

/** Split Receive Control Register */
#define INTELX_SRRCTL 0x02100UL
#define INTELX_SRRCTL_BSIZE(kb)	( (kb) << 0 )	/**< Receive buffer size */
#define INTELX_SRRCTL_BSIZE_DEFAULT INTELX_SRRCTL_BSIZE ( 0x02 )
#define INTELX_SRRCTL_BSIZE_MASK INTELX_SRRCTL_BSIZE ( 0x1f )

/** Receive DMA Control Register */
#define INTELX_RDRXCTL 0x02f00UL
#define INTELX_RDRXCTL_SECRC	0x00000001UL	/**< Strip CRC */

/** Receive Control Register */
#define INTELX_RXCTRL 0x03000UL
#define INTELX_RXCTRL_RXEN	0x00000001UL	/**< Receive enable */

/** Transmit DMA Control Register */
#define INTELX_DMATXCTL 0x04a80UL
#define INTELX_DMATXCTL_TE	0x00000001UL	/**< Transmit enable */

/** Transmit Descriptor register block */
#define INTELX_TD 0x06000UL

/** RX DCA Control Register */
#define INTELX_DCA_RXCTRL 0x02200UL
#define INTELX_DCA_RXCTRL_MUST_BE_ZERO 0x00001000UL /**< Must be zero */

/** MAC Core Control 0 Register */
#define INTELX_HLREG0 0x04240UL
#define INTELX_HLREG0_JUMBOEN	0x00000004UL	/**< Jumbo frame enable */

/** Maximum Frame Size Register */
#define INTELX_MAXFRS 0x04268UL
#define INTELX_MAXFRS_MFS(len)	( (len) << 16 )	/**< Maximum frame size */
#define INTELX_MAXFRS_MFS_DEFAULT \
	INTELX_MAXFRS_MFS ( ETH_FRAME_LEN + 4 /* VLAN */ + 4 /* CRC */ )
#define INTELX_MAXFRS_MFS_MASK	INTELX_MAXFRS_MFS ( 0xffff )

/** Link Status Register */
#define INTELX_LINKS 0x042a4UL
#define INTELX_LINKS_UP		0x40000000UL	/**< Link up */

#endif /* _INTELX_H */
