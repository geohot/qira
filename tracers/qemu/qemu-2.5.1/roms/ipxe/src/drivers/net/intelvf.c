/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ipxe/io.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include "intelvf.h"

/** @file
 *
 * Intel 10/100/1000 virtual function network card driver
 *
 */

/******************************************************************************
 *
 * Mailbox messages
 *
 ******************************************************************************
 */

/**
 * Write message to mailbox
 *
 * @v intel		Intel device
 * @v msg		Message
 */
static void intelvf_mbox_write ( struct intel_nic *intel,
				 const union intelvf_msg *msg ) {
	unsigned int i;

	/* Write message */
	DBGC2 ( intel, "INTEL %p sending message", intel );
	for ( i = 0 ; i < ( sizeof ( *msg ) / sizeof ( msg->dword[0] ) ) ; i++){
		DBGC2 ( intel, "%c%08x", ( i ? ':' : ' ' ), msg->dword[i] );
		writel ( msg->dword[i], ( intel->regs + intel->mbox.mem +
					  ( i * sizeof ( msg->dword[0] ) ) ) );
	}
	DBGC2 ( intel, "\n" );
}

/**
 * Read message from mailbox
 *
 * @v intel		Intel device
 * @v msg		Message
 */
static void intelvf_mbox_read ( struct intel_nic *intel,
				union intelvf_msg *msg ) {
	unsigned int i;

	/* Read message */
	DBGC2 ( intel, "INTEL %p received message", intel );
	for ( i = 0 ; i < ( sizeof ( *msg ) / sizeof ( msg->dword[0] ) ) ; i++){
		msg->dword[i] = readl ( intel->regs + intel->mbox.mem +
					( i * sizeof ( msg->dword[0] ) ) );
		DBGC2 ( intel, "%c%08x", ( i ? ':' : ' ' ), msg->dword[i] );
	}
	DBGC2 ( intel, "\n" );
}

/**
 * Poll mailbox
 *
 * @v intel		Intel device
 * @ret rc		Return status code
 *
 * Note that polling the mailbox may fail if the underlying PF is
 * reset.
 */
int intelvf_mbox_poll ( struct intel_nic *intel ) {
	struct intel_mailbox *mbox = &intel->mbox;
	union intelvf_msg msg;
	uint32_t ctrl;

	/* Get mailbox status */
	ctrl = readl ( intel->regs + mbox->ctrl );

	/* Fail if a reset is in progress */
	if ( ctrl & INTELVF_MBCTRL_RSTI )
		return -EPIPE;

	/* Acknowledge (and ignore) any received messages */
	if ( ctrl & INTELVF_MBCTRL_PFSTS ) {
		intelvf_mbox_read ( intel, &msg );
		writel ( INTELVF_MBCTRL_ACK, intel->regs + mbox->ctrl );
	}

	return 0;
}

/**
 * Wait for PF reset to complete
 *
 * @v intel		Intel device
 * @ret rc		Return status code
 */
int intelvf_mbox_wait ( struct intel_nic *intel ) {
	unsigned int i;
	int rc;

	/* Wait until a poll completes successfully */
	for ( i = 0 ; i < INTELVF_MBOX_MAX_WAIT_MS ; i++ ) {

		/* Check for successful poll */
		if ( ( rc = intelvf_mbox_poll ( intel ) ) == 0 )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( intel, "INTEL %p timed out waiting for reset\n", intel );
	return -ETIMEDOUT;
}

/**
 * Send/receive mailbox message
 *
 * @v intel		Intel device
 * @v msg		Message buffer
 * @ret rc		Return status code
 */
int intelvf_mbox_msg ( struct intel_nic *intel, union intelvf_msg *msg ) {
	struct intel_mailbox *mbox = &intel->mbox;
	uint32_t ctrl;
	uint32_t seen = 0;
	unsigned int i;

	/* Sanity check */
	assert ( ! ( msg->hdr & INTELVF_MSG_RESPONSE ) );

	/* Handle mailbox */
	for ( i = 0 ; i < INTELVF_MBOX_MAX_WAIT_MS ; i++ ) {

		/* Attempt to claim mailbox, if we have not yet sent
		 * our message.
		 */
		if ( ! ( seen & INTELVF_MBCTRL_VFU ) )
			writel ( INTELVF_MBCTRL_VFU, intel->regs + mbox->ctrl );

		/* Get mailbox status and record observed flags */
		ctrl = readl ( intel->regs + mbox->ctrl );
		seen |= ctrl;

		/* If a reset is in progress, clear VFU and abort */
		if ( ctrl & INTELVF_MBCTRL_RSTI ) {
			writel ( 0, intel->regs + mbox->ctrl );
			return -EPIPE;
		}

		/* Write message to mailbox, if applicable.  This
		 * potentially overwrites a message sent by the PF (if
		 * the PF has simultaneously released PFU (thus
		 * allowing our VFU) and asserted PFSTS), but that
		 * doesn't really matter since there are no
		 * unsolicited PF->VF messages that require the actual
		 * message content to be observed.
		 */
		if ( ctrl & INTELVF_MBCTRL_VFU )
			intelvf_mbox_write ( intel, msg );

		/* Read message from mailbox, if applicable. */
		if ( ( seen & INTELVF_MBCTRL_VFU ) &&
		     ( seen & INTELVF_MBCTRL_PFACK ) &&
		     ( ctrl & INTELVF_MBCTRL_PFSTS ) )
			intelvf_mbox_read ( intel, msg );

		/* Acknowledge received message (if applicable),
		 * release VFU lock, and send message (if applicable).
		 */
		ctrl = ( ( ( ctrl & INTELVF_MBCTRL_PFSTS ) ?
			   INTELVF_MBCTRL_ACK : 0 ) |
			 ( ( ctrl & INTELVF_MBCTRL_VFU ) ?
			   INTELVF_MBCTRL_REQ : 0 ) );
		writel ( ctrl, intel->regs + mbox->ctrl );

		/* Exit successfully if we have received a response */
		if ( msg->hdr & INTELVF_MSG_RESPONSE ) {

			/* Sanity check */
			assert ( seen & INTELVF_MBCTRL_VFU );
			assert ( seen & INTELVF_MBCTRL_PFACK );
			assert ( seen & INTELVF_MBCTRL_PFSTS );

			return 0;
		}

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( intel, "INTEL %p timed out waiting for mailbox (seen %08x)\n",
	       intel, seen );
	return -ETIMEDOUT;
}

/**
 * Send reset message and get initial MAC address
 *
 * @v intel		Intel device
 * @v hw_addr		Hardware address to fill in, or NULL
 * @ret rc		Return status code
 */
int intelvf_mbox_reset ( struct intel_nic *intel, uint8_t *hw_addr ) {
	union intelvf_msg msg;
	int rc;

	/* Send reset message */
	memset ( &msg, 0, sizeof ( msg ) );
	msg.hdr = INTELVF_MSG_TYPE_RESET;
	if ( ( rc = intelvf_mbox_msg ( intel, &msg ) ) != 0 ) {
		DBGC ( intel, "INTEL %p reset failed: %s\n",
		       intel, strerror ( rc ) );
		return rc;
	}

	/* Check response */
	if ( ( msg.hdr & INTELVF_MSG_TYPE_MASK ) != INTELVF_MSG_TYPE_RESET ) {
		DBGC ( intel, "INTEL %p reset unexpected response:\n", intel );
		DBGC_HDA ( intel, 0, &msg, sizeof ( msg ) );
		return -EPROTO;
	}

	/* Fill in MAC address, if applicable */
	if ( hw_addr ) {
		if ( msg.hdr & INTELVF_MSG_ACK ) {
			memcpy ( hw_addr, msg.mac.mac, sizeof ( msg.mac.mac ) );
			DBGC ( intel, "INTEL %p reset assigned MAC address "
			       "%s\n", intel, eth_ntoa ( hw_addr ) );
		} else {
			eth_random_addr ( hw_addr );
			DBGC ( intel, "INTEL %p reset generated MAC address "
			       "%s\n", intel, eth_ntoa ( hw_addr ) );
		}
	}

	return 0;
}

/**
 * Send set MAC address message
 *
 * @v intel		Intel device
 * @v ll_addr		Link-layer address
 * @ret rc		Return status code
 */
int intelvf_mbox_set_mac ( struct intel_nic *intel, const uint8_t *ll_addr ) {
	union intelvf_msg msg;
	int rc;

	/* Send set MAC address message */
	memset ( &msg, 0, sizeof ( msg ) );
	msg.hdr = INTELVF_MSG_TYPE_SET_MAC;
	memcpy ( msg.mac.mac, ll_addr, sizeof ( msg.mac.mac ) );
	if ( ( rc = intelvf_mbox_msg ( intel, &msg ) ) != 0 ) {
		DBGC ( intel, "INTEL %p set MAC address failed: %s\n",
		       intel, strerror ( rc ) );
		return rc;
	}

	/* Check response */
	if ( ( msg.hdr & INTELVF_MSG_TYPE_MASK ) != INTELVF_MSG_TYPE_SET_MAC ) {
		DBGC ( intel, "INTEL %p set MAC address unexpected response:\n",
		       intel );
		DBGC_HDA ( intel, 0, &msg, sizeof ( msg ) );
		return -EPROTO;
	}

	/* Check that we were allowed to set the MAC address */
	if ( ! ( msg.hdr & INTELVF_MSG_ACK ) ) {
		DBGC ( intel, "INTEL %p set MAC address refused\n", intel );
		return -EPERM;
	}

	return 0;
}

/**
 * Send set MTU message
 *
 * @v intel		Intel device
 * @v mtu		Maximum packet size
 * @ret rc		Return status code
 */
int intelvf_mbox_set_mtu ( struct intel_nic *intel, size_t mtu ) {
	union intelvf_msg msg;
	int rc;

	/* Send set MTU message */
	memset ( &msg, 0, sizeof ( msg ) );
	msg.hdr = INTELVF_MSG_TYPE_SET_MTU;
	msg.mtu.mtu = mtu;
	if ( ( rc = intelvf_mbox_msg ( intel, &msg ) ) != 0 ) {
		DBGC ( intel, "INTEL %p set MTU failed: %s\n",
		       intel, strerror ( rc ) );
		return rc;
	}

	/* Check response */
	if ( ( msg.hdr & INTELVF_MSG_TYPE_MASK ) != INTELVF_MSG_TYPE_SET_MTU ) {
		DBGC ( intel, "INTEL %p set MTU unexpected response:\n",
		       intel );
		DBGC_HDA ( intel, 0, &msg, sizeof ( msg ) );
		return -EPROTO;
	}

	/* Check that we were allowed to set the MTU */
	if ( ! ( msg.hdr & INTELVF_MSG_ACK ) ) {
		DBGC ( intel, "INTEL %p set MTU refused\n", intel );
		return -EPERM;
	}

	return 0;
}
