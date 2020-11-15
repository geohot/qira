#ifndef _INTELVF_H
#define _INTELVF_H

/** @file
 *
 * Intel 10/100/1000 virtual function network card driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include "intel.h"

/** Intel VF BAR size */
#define INTELVF_BAR_SIZE ( 16 * 1024 )

/** Mailbox Control Register */
#define INTELVF_MBCTRL 0x0c40UL
#define INTELVF_MBCTRL_REQ	0x00000001UL	/**< Request for PF ready */
#define INTELVF_MBCTRL_ACK	0x00000002UL	/**< PF message received */
#define INTELVF_MBCTRL_VFU	0x00000004UL	/**< Buffer taken by VF */
#define INTELVF_MBCTRL_PFU	0x00000008UL	/**< Buffer taken to PF */
#define INTELVF_MBCTRL_PFSTS	0x00000010UL	/**< PF wrote a message */
#define INTELVF_MBCTRL_PFACK	0x00000020UL	/**< PF acknowledged message */
#define INTELVF_MBCTRL_RSTI	0x00000040UL	/**< PF reset in progress */
#define INTELVF_MBCTRL_RSTD	0x00000080UL	/**< PF reset complete */

/** Mailbox Memory Register Base */
#define INTELVF_MBMEM 0x0800UL

/** Reset mailbox message */
#define INTELVF_MSG_TYPE_RESET 0x00000001UL

/** Set MAC address mailbox message */
#define INTELVF_MSG_TYPE_SET_MAC 0x00000002UL

/** Set MTU mailbox message */
#define INTELVF_MSG_TYPE_SET_MTU 0x00000005UL

/** Control ("ping") mailbox message */
#define INTELVF_MSG_TYPE_CONTROL 0x00000100UL

/** Message type mask */
#define INTELVF_MSG_TYPE_MASK 0x0000ffffUL

/** Message NACK flag */
#define INTELVF_MSG_NACK 0x40000000UL

/** Message ACK flag */
#define INTELVF_MSG_ACK 0x80000000UL

/** Message is a response */
#define INTELVF_MSG_RESPONSE ( INTELVF_MSG_ACK | INTELVF_MSG_NACK )

/** MAC address mailbox message */
struct intelvf_msg_mac {
	/** Message header */
	uint32_t hdr;
	/** MAC address */
	uint8_t mac[ETH_ALEN];
	/** Alignment padding */
	uint8_t reserved[ (-ETH_ALEN) & 0x3 ];
} __attribute__ (( packed ));

/** Version number mailbox message */
struct intelvf_msg_version {
	/** Message header */
	uint32_t hdr;
	/** API version */
	uint32_t version;
} __attribute__ (( packed ));

/** MTU mailbox message */
struct intelvf_msg_mtu {
	/** Message header */
	uint32_t hdr;
	/** Maximum packet size */
	uint32_t mtu;
} __attribute__ (( packed ));

/** Mailbox message */
union intelvf_msg {
	/** Message header */
	uint32_t hdr;
	/** MAC address message */
	struct intelvf_msg_mac mac;
	/** Version number message */
	struct intelvf_msg_version version;
	/** MTU message */
	struct intelvf_msg_mtu mtu;
	/** Raw dwords */
	uint32_t dword[0];
};

/** Maximum time to wait for mailbox message
 *
 * This is a policy decision.
 */
#define INTELVF_MBOX_MAX_WAIT_MS 500

extern int intelvf_mbox_msg ( struct intel_nic *intel, union intelvf_msg *msg );
extern int intelvf_mbox_poll ( struct intel_nic *intel );
extern int intelvf_mbox_wait ( struct intel_nic *intel );
extern int intelvf_mbox_reset ( struct intel_nic *intel, uint8_t *hw_addr );
extern int intelvf_mbox_set_mac ( struct intel_nic *intel,
				  const uint8_t *ll_addr );
extern int intelvf_mbox_set_mtu ( struct intel_nic *intel, size_t mtu );

#endif /* _INTELVF_H */
