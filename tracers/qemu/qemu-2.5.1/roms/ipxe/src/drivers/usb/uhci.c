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

#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/malloc.h>
#include <ipxe/pci.h>
#include <ipxe/usb.h>
#include "ehci.h"
#include "uhci.h"

/** @file
 *
 * USB Universal Host Controller Interface (UHCI) driver
 *
 */

/******************************************************************************
 *
 * Register access
 *
 ******************************************************************************
 */

/**
 * Check that address is reachable
 *
 * @v addr		Address
 * @v len		Length
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline)) int
uhci_reachable ( void *addr, size_t len ) {
	physaddr_t phys = virt_to_phys ( addr );

	/* Always reachable in a 32-bit build */
	if ( sizeof ( physaddr_t ) <= sizeof ( uint32_t ) )
		return 0;

	/* Reachable if below 4GB */
	if ( ( ( phys + len - 1 ) & ~0xffffffffULL ) == 0 )
		return 0;

	return -ENOTSUP;
}

/******************************************************************************
 *
 * Run / stop / reset
 *
 ******************************************************************************
 */

/**
 * Start UHCI device
 *
 * @v uhci		UHCI device
 */
static void uhci_run ( struct uhci_device *uhci ) {
	uint16_t usbcmd;

	/* Set run/stop bit */
	usbcmd = inw ( uhci->regs + UHCI_USBCMD );
	usbcmd |= ( UHCI_USBCMD_RUN | UHCI_USBCMD_MAX64 );
	outw ( usbcmd, uhci->regs + UHCI_USBCMD );
}

/**
 * Stop UHCI device
 *
 * @v uhci		UHCI device
 * @ret rc		Return status code
 */
static int uhci_stop ( struct uhci_device *uhci ) {
	uint16_t usbcmd;
	uint16_t usbsts;
	unsigned int i;

	/* Clear run/stop bit */
	usbcmd = inw ( uhci->regs + UHCI_USBCMD );
	usbcmd &= ~UHCI_USBCMD_RUN;
	outw ( usbcmd, uhci->regs + UHCI_USBCMD );

	/* Wait for device to stop */
	for ( i = 0 ; i < UHCI_STOP_MAX_WAIT_MS ; i++ ) {

		/* Check if device is stopped */
		usbsts = inw ( uhci->regs + UHCI_USBSTS );
		if ( usbsts & UHCI_USBSTS_HCHALTED )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( uhci, "UHCI %s timed out waiting for stop\n", uhci->name );
	return -ETIMEDOUT;
}

/**
 * Reset UHCI device
 *
 * @v uhci		UHCI device
 * @ret rc		Return status code
 */
static int uhci_reset ( struct uhci_device *uhci ) {
	uint16_t usbcmd;
	unsigned int i;
	int rc;

	/* The UHCI specification states that resetting a running
	 * device may result in undefined behaviour, so try stopping
	 * it first.
	 */
	if ( ( rc = uhci_stop ( uhci ) ) != 0 ) {
		/* Ignore errors and attempt to reset the device anyway */
	}

	/* Reset device */
	outw ( UHCI_USBCMD_HCRESET, uhci->regs + UHCI_USBCMD );

	/* Wait for reset to complete */
	for ( i = 0 ; i < UHCI_RESET_MAX_WAIT_MS ; i++ ) {

		/* Check if reset is complete */
		usbcmd = inw ( uhci->regs + UHCI_USBCMD );
		if ( ! ( usbcmd & UHCI_USBCMD_HCRESET ) )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( uhci, "UHCI %s timed out waiting for reset\n", uhci->name );
	return -ETIMEDOUT;
}

/******************************************************************************
 *
 * Transfer descriptor rings
 *
 ******************************************************************************
 */

/**
 * Allocate transfer ring
 *
 * @v ring		Transfer ring
 * @ret rc		Return status code
 */
static int uhci_ring_alloc ( struct uhci_ring *ring ) {
	int rc;

	/* Initialise structure */
	memset ( ring, 0, sizeof ( *ring ) );

	/* Allocate queue head */
	ring->head = malloc_dma ( sizeof ( *ring->head ), UHCI_ALIGN );
	if ( ! ring->head ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	if ( ( rc = uhci_reachable ( ring->head,
				     sizeof ( *ring->head ) ) ) != 0 )
		goto err_unreachable;

	/* Initialise queue head */
	ring->head->current = cpu_to_le32 ( UHCI_LINK_TERMINATE );

	return 0;

 err_unreachable:
	free_dma ( ring->head, sizeof ( *ring->head ) );
 err_alloc:
	return rc;
}

/**
 * Free transfer ring
 *
 * @v ring		Transfer ring
 */
static void uhci_ring_free ( struct uhci_ring *ring ) {
	unsigned int i;

	/* Sanity checks */
	assert ( uhci_ring_fill ( ring ) == 0 );
	for ( i = 0 ; i < UHCI_RING_COUNT ; i++ )
		assert ( ring->xfer[i] == NULL );

	/* Free queue head */
	free_dma ( ring->head, sizeof ( *ring->head ) );
}

/**
 * Enqueue new transfer
 *
 * @v ring		Transfer ring
 * @v iobuf		I/O buffer
 * @v count		Number of descriptors
 * @ret rc		Return status code
 */
static int uhci_enqueue ( struct uhci_ring *ring, struct io_buffer *iobuf,
			  unsigned int count ) {
	struct uhci_transfer *xfer;
	struct uhci_transfer *end;
	struct uhci_transfer_descriptor *desc;
	unsigned int index = ( ring->prod % UHCI_RING_COUNT );
	uint32_t link;
	size_t len;
	int rc;

	/* Sanity check */
	assert ( count > 0 );
	assert ( iobuf != NULL );

	/* Check for space in ring */
	if ( ! uhci_ring_remaining ( ring ) ) {
		rc = -ENOBUFS;
		goto err_ring_full;
	}

	/* Check for reachability of I/O buffer */
	if ( ( rc = uhci_reachable ( iobuf->data, iob_len ( iobuf ) ) ) != 0 )
		goto err_unreachable_iobuf;

	/* Allocate transfer */
	xfer = malloc ( sizeof ( *xfer ) );
	if ( ! xfer ) {
		rc = -ENOMEM;
		goto err_alloc_xfer;
	}

	/* Initialise transfer */
	xfer->prod = 0;
	xfer->cons = 0;
	xfer->len = 0;
	xfer->iobuf = iobuf;

	/* Allocate transfer descriptors */
	len = ( count * sizeof ( xfer->desc[0] ) );
	xfer->desc = malloc_dma ( len, UHCI_ALIGN );
	if ( ! xfer->desc ) {
		rc = -ENOMEM;
		goto err_alloc_desc;
	}
	if ( ( rc = uhci_reachable ( xfer->desc, len ) ) != 0 )
		goto err_unreachable_desc;

	/* Initialise transfer descriptors */
	memset ( xfer->desc, 0, len );
	desc = xfer->desc;
	for ( ; --count ; desc++ ) {
		link = ( virt_to_phys ( desc + 1 ) | UHCI_LINK_DEPTH_FIRST );
		desc->link = cpu_to_le32 ( link );
		desc->flags = ring->flags;
	}
	desc->link = cpu_to_le32 ( UHCI_LINK_TERMINATE );
	desc->flags = ( ring->flags | UHCI_FL_IOC );

	/* Add to ring */
	wmb();
	link = virt_to_phys ( xfer->desc );
	if ( uhci_ring_fill ( ring ) > 0 ) {
		end = ring->end;
		end->desc[ end->prod - 1 ].link = cpu_to_le32 ( link );
	} else {
		ring->head->current = cpu_to_le32 ( link );
	}
	assert ( ring->xfer[index] == NULL );
	ring->xfer[index] = xfer;
	ring->end = xfer;
	ring->prod++;

	return 0;

 err_unreachable_desc:
	free_dma ( xfer->desc, len );
 err_alloc_desc:
	free ( xfer );
 err_alloc_xfer:
 err_unreachable_iobuf:
 err_ring_full:
	return rc;
}

/**
 * Describe transfer
 *
 * @v ring		Transfer ring
 * @v data		Data
 * @v len		Length of data
 * @v pid		Packet ID
 */
static void uhci_describe ( struct uhci_ring *ring, void *data,
			    size_t len, uint8_t pid ) {
	struct uhci_transfer *xfer = ring->end;
	struct uhci_transfer_descriptor *desc;
	size_t frag_len;
	uint32_t control;

	do {
		/* Calculate fragment length */
		frag_len = len;
		if ( frag_len > ring->mtu )
			frag_len = ring->mtu;

		/* Populate descriptor */
		desc = &xfer->desc[xfer->prod++];
		if ( pid == USB_PID_IN )
			desc->flags |= UHCI_FL_SPD;
		control = ( ring->control | UHCI_CONTROL_PID ( pid ) |
			    UHCI_CONTROL_LEN ( frag_len ) );
		desc->control = cpu_to_le32 ( control );
		if ( data )
			desc->data = virt_to_phys ( data );
		wmb();
		desc->status = UHCI_STATUS_ACTIVE;

		/* Update data toggle */
		ring->control ^= UHCI_CONTROL_TOGGLE;

		/* Move to next descriptor */
		data += frag_len;
		len -= frag_len;

	} while ( len );
}

/**
 * Dequeue transfer
 *
 * @v ring		Transfer ring
 * @ret iobuf		I/O buffer
 */
static struct io_buffer * uhci_dequeue ( struct uhci_ring *ring ) {
	unsigned int index = ( ring->cons % UHCI_RING_COUNT );
	struct io_buffer *iobuf;
	struct uhci_transfer *xfer;
	size_t len;

	/* Sanity checks */
	assert ( uhci_ring_fill ( ring ) > 0 );

	/* Consume transfer */
	xfer = ring->xfer[index];
	assert ( xfer != NULL );
	assert ( xfer->desc != NULL );
	iobuf = xfer->iobuf;
	assert ( iobuf != NULL );
	ring->xfer[index] = NULL;
	ring->cons++;

	/* Free transfer descriptors */
	len = ( xfer->prod * sizeof ( xfer->desc[0] ) );
	free_dma ( xfer->desc, len );

	/* Free transfer */
	free ( xfer );

	return iobuf;
}

/**
 * Restart ring
 *
 * @v ring		Transfer ring
 * @v toggle		Expected data toggle for next descriptor
 */
static void uhci_restart ( struct uhci_ring *ring, uint32_t toggle ) {
	struct uhci_transfer *xfer;
	struct uhci_transfer_descriptor *desc;
	struct uhci_transfer_descriptor *first;
	uint32_t link;
	unsigned int i;
	unsigned int j;

	/* Sanity check */
	assert ( ring->head->current == cpu_to_le32 ( UHCI_LINK_TERMINATE ) );

	/* If ring is empty, then just update the data toggle for the
	 * next descriptor.
	 */
	if ( uhci_ring_fill ( ring ) == 0 ) {
		ring->control &= ~UHCI_CONTROL_TOGGLE;
		ring->control |= toggle;
		return;
	}

	/* If expected toggle does not match the toggle in the first
	 * unconsumed descriptor, then invert all toggles.
	 */
	xfer = ring->xfer[ ring->cons % UHCI_RING_COUNT ];
	assert ( xfer != NULL );
	assert ( xfer->cons == 0 );
	first = &xfer->desc[0];
	if ( ( le32_to_cpu ( first->control ) ^ toggle ) & UHCI_CONTROL_TOGGLE){

		/* Invert toggle on all unconsumed transfer descriptors */
		for ( i = ring->cons ; i != ring->prod ; i++ ) {
			xfer = ring->xfer[ i % UHCI_RING_COUNT ];
			assert ( xfer != NULL );
			assert ( xfer->cons == 0 );
			for ( j = 0 ; j < xfer->prod ; j++ ) {
				desc = &xfer->desc[j];
				desc->control ^=
					cpu_to_le32 ( UHCI_CONTROL_TOGGLE );
			}
		}

		/* Invert toggle for next descriptor to be enqueued */
		ring->control ^= UHCI_CONTROL_TOGGLE;
	}

	/* Restart ring at first unconsumed transfer */
	link = virt_to_phys ( first );
	wmb();
	ring->head->current = cpu_to_le32 ( link );
}

/******************************************************************************
 *
 * Schedule management
 *
 ******************************************************************************
 */

/**
 * Get link value for a queue head
 *
 * @v queue		Queue head
 * @ret link		Link value
 */
static inline uint32_t uhci_link_qh ( struct uhci_queue_head *queue ) {

	return ( virt_to_phys ( queue ) | UHCI_LINK_TYPE_QH );
}

/**
 * (Re)build asynchronous schedule
 *
 * @v uhci		UHCI device
 */
static void uhci_async_schedule ( struct uhci_device *uhci ) {
	struct uhci_endpoint *endpoint;
	struct uhci_queue_head *queue;
	uint32_t end;
	uint32_t link;

	/* Build schedule in reverse order of execution.  Provided
	 * that we only ever add or remove single endpoints, this can
	 * safely run concurrently with hardware execution of the
	 * schedule.
	 */
	link = end = uhci_link_qh ( uhci->head );
	list_for_each_entry_reverse ( endpoint, &uhci->async, schedule ) {
		queue = endpoint->ring.head;
		queue->link = cpu_to_le32 ( link );
		wmb();
		link = uhci_link_qh ( queue );
	}
	if ( link == end )
		link = UHCI_LINK_TERMINATE;
	uhci->head->link = cpu_to_le32 ( link );
	wmb();
}

/**
 * Add endpoint to asynchronous schedule
 *
 * @v endpoint		Endpoint
 */
static void uhci_async_add ( struct uhci_endpoint *endpoint ) {
	struct uhci_device *uhci = endpoint->uhci;

	/* Add to end of schedule */
	list_add_tail ( &endpoint->schedule, &uhci->async );

	/* Rebuild schedule */
	uhci_async_schedule ( uhci );
}

/**
 * Remove endpoint from asynchronous schedule
 *
 * @v endpoint		Endpoint
 */
static void uhci_async_del ( struct uhci_endpoint *endpoint ) {
	struct uhci_device *uhci = endpoint->uhci;

	/* Remove from schedule */
	list_check_contains_entry ( endpoint, &uhci->async, schedule );
	list_del ( &endpoint->schedule );

	/* Rebuild schedule */
	uhci_async_schedule ( uhci );

	/* Delay for a whole USB frame (with a 100% safety margin) */
	mdelay ( 2 );
}

/**
 * (Re)build periodic schedule
 *
 * @v uhci		UHCI device
 */
static void uhci_periodic_schedule ( struct uhci_device *uhci ) {
	struct uhci_endpoint *endpoint;
	struct uhci_queue_head *queue;
	uint32_t link;
	uint32_t end;
	unsigned int max_interval;
	unsigned int i;

	/* Build schedule in reverse order of execution.  Provided
	 * that we only ever add or remove single endpoints, this can
	 * safely run concurrently with hardware execution of the
	 * schedule.
	 */
	DBGCP ( uhci, "UHCI %s periodic schedule: ", uhci->name );
	link = end = uhci_link_qh ( uhci->head );
	list_for_each_entry_reverse ( endpoint, &uhci->periodic, schedule ) {
		queue = endpoint->ring.head;
		queue->link = cpu_to_le32 ( link );
		wmb();
		DBGCP ( uhci, "%s%d", ( ( link == end ) ? "" : "<-" ),
			endpoint->ep->interval );
		link = uhci_link_qh ( queue );
	}
	DBGCP ( uhci, "\n" );

	/* Populate periodic frame list */
	DBGCP ( uhci, "UHCI %s periodic frame list:", uhci->name );
	for ( i = 0 ; i < UHCI_FRAMES ; i++ ) {

		/* Calculate maximum interval (in microframes) which
		 * may appear as part of this frame list.
		 */
		if ( i == 0 ) {
			/* Start of list: include all endpoints */
			max_interval = -1U;
		} else {
			/* Calculate highest power-of-two frame interval */
			max_interval = ( 1 << ( ffs ( i ) - 1 ) );
			/* Convert to microframes */
			max_interval <<= 3;
			/* Round up to nearest 2^n-1 */
			max_interval = ( ( max_interval << 1 ) - 1 );
		}

		/* Find first endpoint in schedule satisfying this
		 * maximum interval constraint.
		 */
		link = uhci_link_qh ( uhci->head );
		list_for_each_entry ( endpoint, &uhci->periodic, schedule ) {
			if ( endpoint->ep->interval <= max_interval ) {
				queue = endpoint->ring.head;
				link = uhci_link_qh ( queue );
				DBGCP ( uhci, " %d:%d",
					i, endpoint->ep->interval );
				break;
			}
		}
		uhci->frame->link[i] = cpu_to_le32 ( link );
	}
	wmb();
	DBGCP ( uhci, "\n" );
}

/**
 * Add endpoint to periodic schedule
 *
 * @v endpoint		Endpoint
 */
static void uhci_periodic_add ( struct uhci_endpoint *endpoint ) {
	struct uhci_device *uhci = endpoint->uhci;
	struct uhci_endpoint *before;
	unsigned int interval = endpoint->ep->interval;

	/* Find first endpoint with a smaller interval */
	list_for_each_entry ( before, &uhci->periodic, schedule ) {
		if ( before->ep->interval < interval )
			break;
	}
	list_add_tail ( &endpoint->schedule, &before->schedule );

	/* Rebuild schedule */
	uhci_periodic_schedule ( uhci );
}

/**
 * Remove endpoint from periodic schedule
 *
 * @v endpoint		Endpoint
 */
static void uhci_periodic_del ( struct uhci_endpoint *endpoint ) {
	struct uhci_device *uhci = endpoint->uhci;

	/* Remove from schedule */
	list_check_contains_entry ( endpoint, &uhci->periodic, schedule );
	list_del ( &endpoint->schedule );

	/* Rebuild schedule */
	uhci_periodic_schedule ( uhci );

	/* Delay for a whole USB frame (with a 100% safety margin) */
	mdelay ( 2 );
}

/**
 * Add endpoint to appropriate schedule
 *
 * @v endpoint		Endpoint
 */
static void uhci_schedule_add ( struct uhci_endpoint *endpoint ) {
	struct usb_endpoint *ep = endpoint->ep;
	unsigned int attr = ( ep->attributes & USB_ENDPOINT_ATTR_TYPE_MASK );

	if ( attr == USB_ENDPOINT_ATTR_INTERRUPT ) {
		uhci_periodic_add ( endpoint );
	} else {
		uhci_async_add ( endpoint );
	}
}

/**
 * Remove endpoint from appropriate schedule
 *
 * @v endpoint		Endpoint
 */
static void uhci_schedule_del ( struct uhci_endpoint *endpoint ) {
	struct usb_endpoint *ep = endpoint->ep;
	unsigned int attr = ( ep->attributes & USB_ENDPOINT_ATTR_TYPE_MASK );

	if ( attr == USB_ENDPOINT_ATTR_INTERRUPT ) {
		uhci_periodic_del ( endpoint );
	} else {
		uhci_async_del ( endpoint );
	}
}

/******************************************************************************
 *
 * Endpoint operations
 *
 ******************************************************************************
 */

/**
 * Open endpoint
 *
 * @v ep		USB endpoint
 * @ret rc		Return status code
 */
static int uhci_endpoint_open ( struct usb_endpoint *ep ) {
	struct usb_device *usb = ep->usb;
	struct uhci_device *uhci = usb_get_hostdata ( usb );
	struct uhci_endpoint *endpoint;
	int rc;

	/* Allocate and initialise structure */
	endpoint = zalloc ( sizeof ( *endpoint ) );
	if ( ! endpoint ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	endpoint->uhci = uhci;
	endpoint->ep = ep;
	usb_endpoint_set_hostdata ( ep, endpoint );

	/* Initialise descriptor ring */
	if ( ( rc = uhci_ring_alloc ( &endpoint->ring ) ) != 0 )
		goto err_ring_alloc;
	endpoint->ring.mtu = ep->mtu;
	endpoint->ring.flags = UHCI_FL_CERR_MAX;
	if ( usb->port->speed < USB_SPEED_FULL )
		endpoint->ring.flags |= UHCI_FL_LS;
	endpoint->ring.control = ( UHCI_CONTROL_DEVICE ( usb->address ) |
				   UHCI_CONTROL_ENDPOINT ( ep->address ) );

	/* Add to list of endpoints */
	list_add_tail ( &endpoint->list, &uhci->endpoints );

	/* Add to schedule */
	uhci_schedule_add ( endpoint );

	return 0;

	uhci_ring_free ( &endpoint->ring );
 err_ring_alloc:
	free ( endpoint );
 err_alloc:
	return rc;
}

/**
 * Close endpoint
 *
 * @v ep		USB endpoint
 */
static void uhci_endpoint_close ( struct usb_endpoint *ep ) {
	struct uhci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct io_buffer *iobuf;

	/* Remove from schedule */
	uhci_schedule_del ( endpoint );

	/* Cancel any incomplete transfers */
	while ( uhci_ring_fill ( &endpoint->ring ) ) {
		iobuf = uhci_dequeue ( &endpoint->ring );
		if ( iobuf )
			usb_complete_err ( ep, iobuf, -ECANCELED );
	}

	/* Remove from list of endpoints */
	list_del ( &endpoint->list );

	/* Free descriptor ring */
	uhci_ring_free ( &endpoint->ring );

	/* Free endpoint */
	free ( endpoint );
}

/**
 * Reset endpoint
 *
 * @v ep		USB endpoint
 * @ret rc		Return status code
 */
static int uhci_endpoint_reset ( struct usb_endpoint *ep ) {
	struct uhci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct uhci_ring *ring = &endpoint->ring;

	/* Restart ring */
	uhci_restart ( ring, 0 );

	return 0;
}

/**
 * Update MTU
 *
 * @v ep		USB endpoint
 * @ret rc		Return status code
 */
static int uhci_endpoint_mtu ( struct usb_endpoint *ep ) {
	struct uhci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );

	/* Update endpoint MTU */
	endpoint->ring.mtu = ep->mtu;

	return 0;
}

/**
 * Enqueue message transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int uhci_endpoint_message ( struct usb_endpoint *ep,
				   struct io_buffer *iobuf ) {
	struct uhci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct uhci_ring *ring = &endpoint->ring;
	struct usb_setup_packet *packet;
	unsigned int count;
	size_t len;
	int input;
	int rc;

	/* Calculate number of descriptors */
	assert ( iob_len ( iobuf ) >= sizeof ( *packet ) );
	len = ( iob_len ( iobuf ) - sizeof ( *packet ) );
	count = ( 1 /* setup stage */ +
		  ( ( len + ring->mtu - 1 ) / ring->mtu ) /* data stage */ +
		  1 /* status stage */ );

	/* Enqueue transfer */
	if ( ( rc = uhci_enqueue ( ring, iobuf, count ) ) != 0 )
		return rc;

	/* Describe setup stage */
	packet = iobuf->data;
	ring->control &= ~UHCI_CONTROL_TOGGLE;
	uhci_describe ( ring, packet, sizeof ( *packet ), USB_PID_SETUP );
	iob_pull ( iobuf, sizeof ( *packet ) );

	/* Describe data stage, if applicable */
	assert ( ring->control & UHCI_CONTROL_TOGGLE );
	input = ( packet->request & cpu_to_le16 ( USB_DIR_IN ) );
	if ( len ) {
		uhci_describe ( ring, iobuf->data, len,
				( input ? USB_PID_IN : USB_PID_OUT ) );
	}

	/* Describe status stage */
	ring->control |= UHCI_CONTROL_TOGGLE;
	uhci_describe ( ring, NULL, 0,
			( ( len && input ) ? USB_PID_OUT : USB_PID_IN ) );

	/* Sanity check */
	assert ( ring->end->prod == count );

	return 0;
}

/**
 * Enqueue stream transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v terminate		Terminate using a short packet
 * @ret rc		Return status code
 */
static int uhci_endpoint_stream ( struct usb_endpoint *ep,
				  struct io_buffer *iobuf, int terminate ) {
	struct uhci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct uhci_ring *ring = &endpoint->ring;
	unsigned int count;
	size_t len;
	int input;
	int zlp;
	int rc;

	/* Calculate number of descriptors */
	len = iob_len ( iobuf );
	zlp = ( terminate && ( ( len & ( ring->mtu - 1 ) ) == 0 ) );
	count = ( ( ( len + ring->mtu - 1 ) / ring->mtu ) + ( zlp ? 1 : 0 ) );

	/* Enqueue transfer */
	if ( ( rc = uhci_enqueue ( ring, iobuf, count ) ) != 0 )
		return rc;

	/* Describe data packet */
	input = ( ep->address & USB_DIR_IN );
	uhci_describe ( ring, iobuf->data, len,
			( input ? USB_PID_IN : USB_PID_OUT ) );

	/* Describe zero-length packet, if applicable */
	if ( zlp )
		uhci_describe ( ring, NULL, 0, USB_PID_OUT );

	/* Sanity check */
	assert ( ring->end->prod == count );

	return 0;
}

/**
 * Check if transfer is a message transfer
 *
 * @v xfer		UHCI transfer
 * @ret is_message	Transfer is a message transfer
 */
static inline int uhci_is_message ( struct uhci_transfer *xfer ) {
	struct uhci_transfer_descriptor *desc = &xfer->desc[0];

	return ( ( desc->control & cpu_to_le32 ( UHCI_CONTROL_PID_MASK ) ) ==
		 cpu_to_le32 ( UHCI_CONTROL_PID ( USB_PID_SETUP ) ) );
}

/**
 * Poll for completions
 *
 * @v endpoint		Endpoint
 */
static void uhci_endpoint_poll ( struct uhci_endpoint *endpoint ) {
	struct uhci_ring *ring = &endpoint->ring;
	struct uhci_device *uhci = endpoint->uhci;
	struct usb_endpoint *ep = endpoint->ep;
	struct usb_device *usb = ep->usb;
	struct uhci_transfer *xfer;
	struct uhci_transfer_descriptor *desc;
	struct io_buffer *iobuf;
	unsigned int index;
	uint32_t link;
	uint32_t toggle;
	uint32_t control;
	uint16_t actual;
	size_t len;

	/* Consume all completed descriptors */
	while ( uhci_ring_fill ( ring ) ) {

		/* Stop if we reach an uncompleted descriptor */
		index = ( ring->cons % UHCI_RING_COUNT );
		xfer = ring->xfer[index];
		assert ( xfer != NULL );
		assert ( xfer->cons < xfer->prod );
		desc = &xfer->desc[xfer->cons];
		rmb();
		if ( desc->status & UHCI_STATUS_ACTIVE )
			break;
		control = le32_to_cpu ( desc->control );
		actual = le16_to_cpu ( desc->actual );

		/* Update data length, if applicable */
		if ( UHCI_DATA_PACKET ( control ) )
			xfer->len += UHCI_ACTUAL_LEN ( actual );

		/* If we have encountered an error, then deactivate
		 * the queue head (to prevent further hardware
		 * accesses to this transfer), consume the transfer,
		 * and report the error to the USB core.
		 */
		if ( desc->status & UHCI_STATUS_STALLED ) {
			DBGC ( uhci, "UHCI %s %s completion %d.%d failed "
			       "(status %02x)\n", usb->name,
			       usb_endpoint_name ( ep ), index,
			       xfer->cons, desc->status );
			link = UHCI_LINK_TERMINATE;
			ring->head->current = cpu_to_le32 ( link );
			wmb();
			iobuf = uhci_dequeue ( ring );
			usb_complete_err ( ep, iobuf, -EIO );
			break;
		}

		/* Consume this descriptor */
		xfer->cons++;

		/* Check for short packets */
		if ( UHCI_SHORT_PACKET ( control, actual ) ) {

			/* Sanity checks */
			assert ( desc->flags & UHCI_FL_SPD );
			link = virt_to_phys ( desc );
			assert ( ( le32_to_cpu ( ring->head->current ) &
				   ~( UHCI_ALIGN - 1 ) ) == link );

			/* If this is a message transfer, then restart
			 * at the status stage.
			 */
			if ( uhci_is_message ( xfer ) ) {
				xfer->cons = ( xfer->prod - 1 );
				link = virt_to_phys ( &xfer->desc[xfer->cons] );
				ring->head->current = cpu_to_le32 ( link );
				break;
			}

			/* Otherwise, this is a stream transfer.
			 * First, prevent further hardware access to
			 * this transfer.
			 */
			link = UHCI_LINK_TERMINATE;
			ring->head->current = cpu_to_le32 ( link );
			wmb();

			/* Determine expected data toggle for next descriptor */
			toggle = ( ( control ^ UHCI_CONTROL_TOGGLE ) &
				   UHCI_CONTROL_TOGGLE );

			/* Consume this transfer */
			len = xfer->len;
			iobuf = uhci_dequeue ( ring );

			/* Update packet length */
			assert ( len <= iob_len ( iobuf ) );
			iob_unput ( iobuf, ( iob_len ( iobuf ) - len ) );

			/* Restart ring */
			uhci_restart ( ring, toggle );

		} else if ( xfer->cons == xfer->prod ) {

			/* Completed a transfer: consume it */
			len = xfer->len;
			iobuf = uhci_dequeue ( ring );
			assert ( len == iob_len ( iobuf ) );

		} else {

			/* Not a short packet and not yet complete:
			 * continue processing.
			 */
			continue;
		}

		/* Report completion to USB core */
		usb_complete ( ep, iobuf );
	}
}

/******************************************************************************
 *
 * Device operations
 *
 ******************************************************************************
 */

/**
 * Open device
 *
 * @v usb		USB device
 * @ret rc		Return status code
 */
static int uhci_device_open ( struct usb_device *usb ) {
	struct uhci_device *uhci = usb_bus_get_hostdata ( usb->port->hub->bus );

	usb_set_hostdata ( usb, uhci );
	return 0;
}

/**
 * Close device
 *
 * @v usb		USB device
 */
static void uhci_device_close ( struct usb_device *usb ) {
	struct uhci_device *uhci = usb_get_hostdata ( usb );
	struct usb_bus *bus = uhci->bus;

	/* Free device address, if assigned */
	if ( usb->address )
		usb_free_address ( bus, usb->address );
}

/**
 * Assign device address
 *
 * @v usb		USB device
 * @ret rc		Return status code
 */
static int uhci_device_address ( struct usb_device *usb ) {
	struct uhci_device *uhci = usb_get_hostdata ( usb );
	struct usb_bus *bus = uhci->bus;
	struct usb_endpoint *ep0 = usb_endpoint ( usb, USB_EP0_ADDRESS );
	struct uhci_endpoint *endpoint0 = usb_endpoint_get_hostdata ( ep0 );
	int address;
	int rc;

	/* Sanity checks */
	assert ( usb->address == 0 );
	assert ( ep0 != NULL );

	/* Allocate device address */
	address = usb_alloc_address ( bus );
	if ( address < 0 ) {
		rc = address;
		DBGC ( uhci, "UHCI %s could not allocate address: %s\n",
		       usb->name, strerror ( rc ) );
		goto err_alloc_address;
	}

	/* Set address */
	if ( ( rc = usb_set_address ( usb, address ) ) != 0 )
		goto err_set_address;

	/* Update device address */
	usb->address = address;
	endpoint0->ring.control |= UHCI_CONTROL_DEVICE ( address );

	return 0;

 err_set_address:
	usb_free_address ( bus, address );
 err_alloc_address:
	return rc;
}

/******************************************************************************
 *
 * Hub operations
 *
 ******************************************************************************
 */

/**
 * Open hub
 *
 * @v hub		USB hub
 * @ret rc		Return status code
 */
static int uhci_hub_open ( struct usb_hub *hub __unused ) {

	/* Nothing to do */
	return 0;
}

/**
 * Close hub
 *
 * @v hub		USB hub
 */
static void uhci_hub_close ( struct usb_hub *hub __unused ) {

	/* Nothing to do */
}

/******************************************************************************
 *
 * Root hub operations
 *
 ******************************************************************************
 */

/**
 * Open root hub
 *
 * @v hub		USB hub
 * @ret rc		Return status code
 */
static int uhci_root_open ( struct usb_hub *hub ) {
	struct usb_bus *bus = hub->bus;
	struct uhci_device *uhci = usb_bus_get_hostdata ( bus );

	/* Record hub driver private data */
	usb_hub_set_drvdata ( hub, uhci );

	return 0;
}

/**
 * Close root hub
 *
 * @v hub		USB hub
 */
static void uhci_root_close ( struct usb_hub *hub ) {

	/* Clear hub driver private data */
	usb_hub_set_drvdata ( hub, NULL );
}

/**
 * Enable port
 *
 * @v hub		USB hub
 * @v port		USB port
 * @ret rc		Return status code
 */
static int uhci_root_enable ( struct usb_hub *hub, struct usb_port *port ) {
	struct uhci_device *uhci = usb_hub_get_drvdata ( hub );
	uint16_t portsc;
	unsigned int i;

	/* Reset port */
	portsc = inw ( uhci->regs + UHCI_PORTSC ( port->address ) );
	portsc |= UHCI_PORTSC_PR;
	outw ( portsc, uhci->regs + UHCI_PORTSC ( port->address ) );
	mdelay ( USB_RESET_DELAY_MS );
	portsc &= ~UHCI_PORTSC_PR;
	outw ( portsc, uhci->regs + UHCI_PORTSC ( port->address ) );
	mdelay ( USB_RESET_RECOVER_DELAY_MS );

	/* Enable port */
	portsc |= UHCI_PORTSC_PED;
	outw ( portsc, uhci->regs + UHCI_PORTSC ( port->address ) );
	mdelay ( USB_RESET_RECOVER_DELAY_MS );

	/* Wait for port to become enabled */
	for ( i = 0 ; i < UHCI_PORT_ENABLE_MAX_WAIT_MS ; i++ ) {

		/* Check port status */
		portsc = inw ( uhci->regs + UHCI_PORTSC ( port->address ) );
		if ( portsc & UHCI_PORTSC_PED )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( uhci, "UHCI %s-%d timed out waiting for port to enable "
	       "(status %04x)\n",  uhci->name, port->address, portsc );
	return -ETIMEDOUT;
}

/**
 * Disable port
 *
 * @v hub		USB hub
 * @v port		USB port
 * @ret rc		Return status code
 */
static int uhci_root_disable ( struct usb_hub *hub, struct usb_port *port ) {
	struct uhci_device *uhci = usb_hub_get_drvdata ( hub );
	uint16_t portsc;

	/* Disable port */
	portsc = inw ( uhci->regs + UHCI_PORTSC ( port->address ) );
	portsc &= ~UHCI_PORTSC_PED;
	outw ( portsc, uhci->regs + UHCI_PORTSC ( port->address ) );

	return 0;
}

/**
 * Update root hub port speed
 *
 * @v hub		USB hub
 * @v port		USB port
 * @ret rc		Return status code
 */
static int uhci_root_speed ( struct usb_hub *hub, struct usb_port *port ) {
	struct uhci_device *uhci = usb_hub_get_drvdata ( hub );
	struct pci_device pci;
	uint16_t portsc;
	unsigned int speed;

	/* Read port status */
	portsc = inw ( uhci->regs + UHCI_PORTSC ( port->address ) );
	if ( ! ( portsc & UHCI_PORTSC_CCS ) ) {
		/* Port not connected */
		speed = USB_SPEED_NONE;
	} else if ( uhci->companion &&
		    ! find_usb_bus_by_location ( BUS_TYPE_PCI,
						 uhci->companion ) ) {
		/* Defer connection detection until companion
		 * controller has been enumerated.
		 */
		pci_init ( &pci, uhci->companion );
		DBGC ( uhci, "UHCI %s-%d deferring for companion " PCI_FMT "\n",
		       uhci->name, port->address, PCI_ARGS ( &pci ) );
		speed = USB_SPEED_NONE;
	} else if ( portsc & UHCI_PORTSC_LS ) {
		/* Low-speed device */
		speed = USB_SPEED_LOW;
	} else {
		/* Full-speed device */
		speed = USB_SPEED_FULL;
	}
	port->speed = speed;

	/* Record disconnections and clear changes */
	port->disconnected |= ( portsc & UHCI_PORTSC_CSC );
	outw ( portsc, uhci->regs + UHCI_PORTSC ( port->address ) );

	return 0;
}

/**
 * Clear transaction translator buffer
 *
 * @v hub		USB hub
 * @v port		USB port
 * @v ep		USB endpoint
 * @ret rc		Return status code
 */
static int uhci_root_clear_tt ( struct usb_hub *hub, struct usb_port *port,
				struct usb_endpoint *ep ) {
	struct uhci_device *uhci = usb_hub_get_drvdata ( hub );

	/* Should never be called; this is a root hub */
	DBGC ( uhci, "UHCI %s-%d nonsensical CLEAR_TT for %s %s\n", uhci->name,
	       port->address, ep->usb->name, usb_endpoint_name ( ep ) );

	return -ENOTSUP;
}

/**
 * Poll for port status changes
 *
 * @v hub		USB hub
 * @v port		USB port
 */
static void uhci_root_poll ( struct usb_hub *hub, struct usb_port *port ) {
	struct uhci_device *uhci = usb_hub_get_drvdata ( hub );
	uint16_t portsc;
	uint16_t change;

	/* Do nothing unless something has changed */
	portsc = inw ( uhci->regs + UHCI_PORTSC ( port->address ) );
	change = ( portsc & UHCI_PORTSC_CHANGE );
	if ( ! change )
		return;

	/* Record disconnections and clear changes */
	port->disconnected |= ( portsc & UHCI_PORTSC_CSC );
	outw ( portsc, uhci->regs + UHCI_PORTSC ( port->address ) );

	/* Report port status change */
	usb_port_changed ( port );
}

/******************************************************************************
 *
 * Bus operations
 *
 ******************************************************************************
 */

/**
 * Open USB bus
 *
 * @v bus		USB bus
 * @ret rc		Return status code
 */
static int uhci_bus_open ( struct usb_bus *bus ) {
	struct uhci_device *uhci = usb_bus_get_hostdata ( bus );
	int rc;

	/* Sanity checks */
	assert ( list_empty ( &uhci->async ) );
	assert ( list_empty ( &uhci->periodic ) );

	/* Allocate and initialise asynchronous queue head */
	uhci->head = malloc_dma ( sizeof ( *uhci->head ), UHCI_ALIGN );
	if ( ! uhci->head ) {
		rc = -ENOMEM;
		goto err_alloc_head;
	}
	if ( ( rc = uhci_reachable ( uhci->head, sizeof ( *uhci->head ) ) ) !=0)
		goto err_unreachable_head;
	memset ( uhci->head, 0, sizeof ( *uhci->head ) );
	uhci->head->current = cpu_to_le32 ( UHCI_LINK_TERMINATE );
	uhci_async_schedule ( uhci );

	/* Allocate periodic frame list */
	uhci->frame = malloc_dma ( sizeof ( *uhci->frame ),
				   sizeof ( *uhci->frame ) );
	if ( ! uhci->frame ) {
		rc = -ENOMEM;
		goto err_alloc_frame;
	}
	if ( ( rc = uhci_reachable ( uhci->frame,
				     sizeof ( *uhci->frame ) ) ) != 0 )
		goto err_unreachable_frame;
	uhci_periodic_schedule ( uhci );
	outl ( virt_to_phys ( uhci->frame ), uhci->regs + UHCI_FLBASEADD );

	/* Start controller */
	uhci_run ( uhci );

	return 0;

	uhci_stop ( uhci );
 err_unreachable_frame:
	free_dma ( uhci->frame, sizeof ( *uhci->frame ) );
 err_alloc_frame:
 err_unreachable_head:
	free_dma ( uhci->head, sizeof ( *uhci->head ) );
 err_alloc_head:
	return rc;
}

/**
 * Close USB bus
 *
 * @v bus		USB bus
 */
static void uhci_bus_close ( struct usb_bus *bus ) {
	struct uhci_device *uhci = usb_bus_get_hostdata ( bus );

	/* Sanity checks */
	assert ( list_empty ( &uhci->async ) );
	assert ( list_empty ( &uhci->periodic ) );

	/* Stop controller */
	uhci_stop ( uhci );

	/* Free periodic frame list */
	free_dma ( uhci->frame, sizeof ( *uhci->frame ) );

	/* Free asynchronous schedule */
	free_dma ( uhci->head, sizeof ( *uhci->head ) );
}

/**
 * Poll USB bus
 *
 * @v bus		USB bus
 */
static void uhci_bus_poll ( struct usb_bus *bus ) {
	struct uhci_device *uhci = usb_bus_get_hostdata ( bus );
	struct usb_hub *hub = bus->hub;
	struct uhci_endpoint *endpoint;
	unsigned int i;

	/* UHCI defers interrupts (including short packet detection)
	 * until the end of the frame.  This can result in bulk IN
	 * endpoints remaining halted for much of the time, waiting
	 * for software action to reset the data toggles.  We
	 * therefore ignore USBSTS and unconditionally poll all
	 * endpoints for completed transfer descriptors.
	 *
	 * As with EHCI, we trust that completion handlers are minimal
	 * and will not do anything that could plausibly affect the
	 * endpoint list itself.
	 */
	list_for_each_entry ( endpoint, &uhci->endpoints, list )
		uhci_endpoint_poll ( endpoint );

	/* UHCI provides no single bit to indicate that a port status
	 * change has occurred.  We therefore unconditionally iterate
	 * over all ports looking for status changes.
	 */
	for ( i = 1 ; i <= UHCI_PORTS ; i++ )
		uhci_root_poll ( hub, usb_port ( hub, i ) );
}

/******************************************************************************
 *
 * PCI interface
 *
 ******************************************************************************
 */

/** USB host controller operations */
static struct usb_host_operations uhci_operations = {
	.endpoint = {
		.open = uhci_endpoint_open,
		.close = uhci_endpoint_close,
		.reset = uhci_endpoint_reset,
		.mtu = uhci_endpoint_mtu,
		.message = uhci_endpoint_message,
		.stream = uhci_endpoint_stream,
	},
	.device = {
		.open = uhci_device_open,
		.close = uhci_device_close,
		.address = uhci_device_address,
	},
	.bus = {
		.open = uhci_bus_open,
		.close = uhci_bus_close,
		.poll = uhci_bus_poll,
	},
	.hub = {
		.open = uhci_hub_open,
		.close = uhci_hub_close,
	},
	.root = {
		.open = uhci_root_open,
		.close = uhci_root_close,
		.enable = uhci_root_enable,
		.disable = uhci_root_disable,
		.speed = uhci_root_speed,
		.clear_tt = uhci_root_clear_tt,
	},
};

/**
 * Locate EHCI companion controller (when no EHCI support is present)
 *
 * @v pci		PCI device
 * @ret busdevfn	EHCI companion controller bus:dev.fn (if any)
 */
__weak unsigned int ehci_companion ( struct pci_device *pci __unused ) {
	return 0;
}

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 */
static int uhci_probe ( struct pci_device *pci ) {
	struct uhci_device *uhci;
	struct usb_port *port;
	unsigned int i;
	int rc;

	/* Allocate and initialise structure */
	uhci = zalloc ( sizeof ( *uhci ) );
	if ( ! uhci ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	uhci->name = pci->dev.name;
	INIT_LIST_HEAD ( &uhci->endpoints );
	INIT_LIST_HEAD ( &uhci->async );
	INIT_LIST_HEAD ( &uhci->periodic );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Identify EHCI companion controller, if any */
	uhci->companion = ehci_companion ( pci );

	/* Claim ownership from BIOS.  (There is no release mechanism
	 * for UHCI.)
	 */
	pci_write_config_word ( pci, UHCI_USBLEGSUP, UHCI_USBLEGSUP_DEFAULT );

	/* Map registers */
	uhci->regs = pci->ioaddr;
	if ( ! uhci->regs ) {
		rc = -ENODEV;
		goto err_ioremap;
	}

	/* Reset device */
	if ( ( rc = uhci_reset ( uhci ) ) != 0 )
		goto err_reset;

	/* Allocate USB bus */
	uhci->bus = alloc_usb_bus ( &pci->dev, UHCI_PORTS, UHCI_MTU,
				    &uhci_operations );
	if ( ! uhci->bus ) {
		rc = -ENOMEM;
		goto err_alloc_bus;
	}
	usb_bus_set_hostdata ( uhci->bus, uhci );
	usb_hub_set_drvdata ( uhci->bus->hub, uhci );

	/* Set port protocols */
	for ( i = 1 ; i <= UHCI_PORTS ; i++ ) {
		port = usb_port ( uhci->bus->hub, i );
		port->protocol = USB_PROTO_2_0;
	}

	/* Register USB bus */
	if ( ( rc = register_usb_bus ( uhci->bus ) ) != 0 )
		goto err_register;

	pci_set_drvdata ( pci, uhci );
	return 0;

	unregister_usb_bus ( uhci->bus );
 err_register:
	free_usb_bus ( uhci->bus );
 err_alloc_bus:
	uhci_reset ( uhci );
 err_reset:
 err_ioremap:
	free ( uhci );
 err_alloc:
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci		PCI device
 */
static void uhci_remove ( struct pci_device *pci ) {
	struct uhci_device *uhci = pci_get_drvdata ( pci );
	struct usb_bus *bus = uhci->bus;

	unregister_usb_bus ( bus );
	assert ( list_empty ( &uhci->async ) );
	assert ( list_empty ( &uhci->periodic ) );
	free_usb_bus ( bus );
	uhci_reset ( uhci );
	free ( uhci );
}

/** UHCI PCI device IDs */
static struct pci_device_id uhci_ids[] = {
	PCI_ROM ( 0xffff, 0xffff, "uhci", "UHCI", 0 ),
};

/** UHCI PCI driver */
struct pci_driver uhci_driver __pci_driver = {
	.ids = uhci_ids,
	.id_count = ( sizeof ( uhci_ids ) / sizeof ( uhci_ids[0] ) ),
	.class = PCI_CLASS_ID ( PCI_CLASS_SERIAL, PCI_CLASS_SERIAL_USB,
				PCI_CLASS_SERIAL_USB_UHCI ),
	.probe = uhci_probe,
	.remove = uhci_remove,
};
