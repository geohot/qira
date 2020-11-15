/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/malloc.h>
#include <ipxe/pci.h>
#include <ipxe/usb.h>
#include <ipxe/init.h>
#include "ehci.h"

/** @file
 *
 * USB Enhanced Host Controller Interface (EHCI) driver
 *
 */

/**
 * Construct error code from transfer descriptor status
 *
 * @v status		Transfer descriptor status
 * @ret rc		Error code
 *
 * Bits 2-5 of the status code provide some indication as to the root
 * cause of the error.  We incorporate these into the error code as
 * reported to usb_complete_err().
 */
#define EIO_STATUS( status ) EUNIQ ( EINFO_EIO, ( ( (status) >> 2 ) & 0xf ) )

/******************************************************************************
 *
 * Register access
 *
 ******************************************************************************
 */

/**
 * Initialise device
 *
 * @v ehci		EHCI device
 * @v regs		MMIO registers
 */
static void ehci_init ( struct ehci_device *ehci, void *regs ) {
	uint32_t hcsparams;
	uint32_t hccparams;
	size_t caplength;

	/* Locate capability and operational registers */
	ehci->cap = regs;
	caplength = readb ( ehci->cap + EHCI_CAP_CAPLENGTH );
	ehci->op = ( ehci->cap + caplength );
	DBGC2 ( ehci, "EHCI %s cap %08lx op %08lx\n", ehci->name,
		virt_to_phys ( ehci->cap ), virt_to_phys ( ehci->op ) );

	/* Read structural parameters */
	hcsparams = readl ( ehci->cap + EHCI_CAP_HCSPARAMS );
	ehci->ports = EHCI_HCSPARAMS_PORTS ( hcsparams );
	DBGC ( ehci, "EHCI %s has %d ports\n", ehci->name, ehci->ports );

	/* Read capability parameters 1 */
	hccparams = readl ( ehci->cap + EHCI_CAP_HCCPARAMS );
	ehci->addr64 = EHCI_HCCPARAMS_ADDR64 ( hccparams );
	ehci->flsize = ( EHCI_HCCPARAMS_FLSIZE ( hccparams ) ?
			 EHCI_FLSIZE_SMALL : EHCI_FLSIZE_DEFAULT );
	ehci->eecp = EHCI_HCCPARAMS_EECP ( hccparams );
	DBGC2 ( ehci, "EHCI %s %d-bit flsize %d\n", ehci->name,
		( ehci->addr64 ? 64 : 32 ), ehci->flsize );
}

/**
 * Find extended capability
 *
 * @v ehci		EHCI device
 * @v pci		PCI device
 * @v id		Capability ID
 * @v offset		Offset to previous extended capability instance, or zero
 * @ret offset		Offset to extended capability, or zero if not found
 */
static unsigned int ehci_extended_capability ( struct ehci_device *ehci,
					       struct pci_device *pci,
					       unsigned int id,
					       unsigned int offset ) {
	uint32_t eecp;

	/* Locate the extended capability */
	while ( 1 ) {

		/* Locate first or next capability as applicable */
		if ( offset ) {
			pci_read_config_dword ( pci, offset, &eecp );
			offset = EHCI_EECP_NEXT ( eecp );
		} else {
			offset = ehci->eecp;
		}
		if ( ! offset )
			return 0;

		/* Check if this is the requested capability */
		pci_read_config_dword ( pci, offset, &eecp );
		if ( EHCI_EECP_ID ( eecp ) == id )
			return offset;
	}
}

/**
 * Calculate buffer alignment
 *
 * @v len		Length
 * @ret align		Buffer alignment
 *
 * Determine alignment required for a buffer which must be aligned to
 * at least EHCI_MIN_ALIGN and which must not cross a page boundary.
 */
static inline size_t ehci_align ( size_t len ) {
	size_t align;

	/* Align to own length (rounded up to a power of two) */
	align = ( 1 << fls ( len - 1 ) );

	/* Round up to EHCI_MIN_ALIGN if needed */
	if ( align < EHCI_MIN_ALIGN )
		align = EHCI_MIN_ALIGN;

	return align;
}

/**
 * Check control data structure reachability
 *
 * @v ehci		EHCI device
 * @v ptr		Data structure pointer
 * @ret rc		Return status code
 */
static int ehci_ctrl_reachable ( struct ehci_device *ehci, void *ptr ) {
	physaddr_t phys = virt_to_phys ( ptr );
	uint32_t segment;

	/* Always reachable in a 32-bit build */
	if ( sizeof ( physaddr_t ) <= sizeof ( uint32_t ) )
		return 0;

	/* Reachable only if control segment matches in a 64-bit build */
	segment = ( ( ( uint64_t ) phys ) >> 32 );
	if ( segment == ehci->ctrldssegment )
		return 0;

	return -ENOTSUP;
}

/******************************************************************************
 *
 * USB legacy support
 *
 ******************************************************************************
 */

/** Prevent the release of ownership back to BIOS */
static int ehci_legacy_prevent_release;

/**
 * Initialise USB legacy support
 *
 * @v ehci		EHCI device
 * @v pci		PCI device
 */
static void ehci_legacy_init ( struct ehci_device *ehci,
			       struct pci_device *pci ) {
	unsigned int legacy;
	uint8_t bios;

	/* Locate USB legacy support capability (if present) */
	legacy = ehci_extended_capability ( ehci, pci, EHCI_EECP_ID_LEGACY, 0 );
	if ( ! legacy ) {
		/* Not an error; capability may not be present */
		DBGC ( ehci, "EHCI %s has no USB legacy support capability\n",
		       ehci->name );
		return;
	}

	/* Check if legacy USB support is enabled */
	pci_read_config_byte ( pci, ( legacy + EHCI_USBLEGSUP_BIOS ), &bios );
	if ( ! ( bios & EHCI_USBLEGSUP_BIOS_OWNED ) ) {
		/* Not an error; already owned by OS */
		DBGC ( ehci, "EHCI %s USB legacy support already disabled\n",
		       ehci->name );
		return;
	}

	/* Record presence of USB legacy support capability */
	ehci->legacy = legacy;
}

/**
 * Claim ownership from BIOS
 *
 * @v ehci		EHCI device
 * @v pci		PCI device
 */
static void ehci_legacy_claim ( struct ehci_device *ehci,
				struct pci_device *pci ) {
	unsigned int legacy = ehci->legacy;
	uint32_t ctlsts;
	uint8_t bios;
	unsigned int i;

	/* Do nothing unless legacy support capability is present */
	if ( ! legacy )
		return;

	/* Claim ownership */
	pci_write_config_byte ( pci, ( legacy + EHCI_USBLEGSUP_OS ),
				EHCI_USBLEGSUP_OS_OWNED );

	/* Wait for BIOS to release ownership */
	for ( i = 0 ; i < EHCI_USBLEGSUP_MAX_WAIT_MS ; i++ ) {

		/* Check if BIOS has released ownership */
		pci_read_config_byte ( pci, ( legacy + EHCI_USBLEGSUP_BIOS ),
				       &bios );
		if ( ! ( bios & EHCI_USBLEGSUP_BIOS_OWNED ) ) {
			DBGC ( ehci, "EHCI %s claimed ownership from BIOS\n",
			       ehci->name );
			pci_read_config_dword ( pci, ( legacy +
						       EHCI_USBLEGSUP_CTLSTS ),
						&ctlsts );
			if ( ctlsts ) {
				DBGC ( ehci, "EHCI %s warning: BIOS retained "
				       "SMIs: %08x\n", ehci->name, ctlsts );
			}
			return;
		}

		/* Delay */
		mdelay ( 1 );
	}

	/* BIOS did not release ownership.  Claim it forcibly by
	 * disabling all SMIs.
	 */
	DBGC ( ehci, "EHCI %s could not claim ownership from BIOS: forcibly "
	       "disabling SMIs\n", ehci->name );
	pci_write_config_dword ( pci, ( legacy + EHCI_USBLEGSUP_CTLSTS ), 0 );
}

/**
 * Release ownership back to BIOS
 *
 * @v ehci		EHCI device
 * @v pci		PCI device
 */
static void ehci_legacy_release ( struct ehci_device *ehci,
				  struct pci_device *pci ) {

	/* Do nothing unless legacy support capability is present */
	if ( ! ehci->legacy )
		return;

	/* Do nothing if releasing ownership is prevented */
	if ( ehci_legacy_prevent_release ) {
		DBGC ( ehci, "EHCI %s not releasing ownership to BIOS\n",
		       ehci->name );
		return;
	}

	/* Release ownership */
	pci_write_config_byte ( pci, ( ehci->legacy + EHCI_USBLEGSUP_OS ), 0 );
	DBGC ( ehci, "EHCI %s released ownership to BIOS\n", ehci->name );
}

/******************************************************************************
 *
 * Companion controllers
 *
 ******************************************************************************
 */

/**
 * Poll child companion controllers
 *
 * @v ehci		EHCI device
 */
static void ehci_poll_companions ( struct ehci_device *ehci ) {
	struct usb_bus *bus;
	struct device_description *desc;

	/* Poll any USB buses belonging to child companion controllers */
	for_each_usb_bus ( bus ) {

		/* Get underlying devices description */
		desc = &bus->dev->desc;

		/* Skip buses that are not PCI devices */
		if ( desc->bus_type != BUS_TYPE_PCI )
			continue;

		/* Skip buses that are not part of the same PCI device */
		if ( PCI_FIRST_FUNC ( desc->location ) !=
		     PCI_FIRST_FUNC ( ehci->bus->dev->desc.location ) )
			continue;

		/* Skip buses that are not UHCI or OHCI PCI devices */
		if ( ( desc->class != PCI_CLASS ( PCI_CLASS_SERIAL,
						  PCI_CLASS_SERIAL_USB,
						  PCI_CLASS_SERIAL_USB_UHCI ))&&
		     ( desc->class != PCI_CLASS ( PCI_CLASS_SERIAL,
						  PCI_CLASS_SERIAL_USB,
						  PCI_CLASS_SERIAL_USB_OHCI ) ))
			continue;

		/* Poll child companion controller bus */
		DBGC2 ( ehci, "EHCI %s polling companion %s\n",
			ehci->name, bus->name );
		usb_poll ( bus );
	}
}

/**
 * Locate EHCI companion controller
 *
 * @v pci		PCI device
 * @ret busdevfn	EHCI companion controller bus:dev.fn (if any)
 */
unsigned int ehci_companion ( struct pci_device *pci ) {
	struct pci_device tmp;
	unsigned int busdevfn;
	int rc;

	/* Look for an EHCI function on the same PCI device */
	busdevfn = pci->busdevfn;
	while ( ++busdevfn <= PCI_LAST_FUNC ( pci->busdevfn ) ) {
		pci_init ( &tmp, busdevfn );
		if ( ( rc = pci_read_config ( &tmp ) ) != 0 )
			continue;
		if ( tmp.class == PCI_CLASS ( PCI_CLASS_SERIAL,
					      PCI_CLASS_SERIAL_USB,
					      PCI_CLASS_SERIAL_USB_EHCI ) )
			return busdevfn;
	}

	return 0;
}

/******************************************************************************
 *
 * Run / stop / reset
 *
 ******************************************************************************
 */

/**
 * Start EHCI device
 *
 * @v ehci		EHCI device
 */
static void ehci_run ( struct ehci_device *ehci ) {
	uint32_t usbcmd;

	/* Set run/stop bit */
	usbcmd = readl ( ehci->op + EHCI_OP_USBCMD );
	usbcmd &= ~EHCI_USBCMD_FLSIZE_MASK;
	usbcmd |= ( EHCI_USBCMD_RUN | EHCI_USBCMD_FLSIZE ( ehci->flsize ) |
		    EHCI_USBCMD_PERIODIC | EHCI_USBCMD_ASYNC );
	writel ( usbcmd, ehci->op + EHCI_OP_USBCMD );
}

/**
 * Stop EHCI device
 *
 * @v ehci		EHCI device
 * @ret rc		Return status code
 */
static int ehci_stop ( struct ehci_device *ehci ) {
	uint32_t usbcmd;
	uint32_t usbsts;
	unsigned int i;

	/* Clear run/stop bit */
	usbcmd = readl ( ehci->op + EHCI_OP_USBCMD );
	usbcmd &= ~( EHCI_USBCMD_RUN | EHCI_USBCMD_PERIODIC |
		     EHCI_USBCMD_ASYNC );
	writel ( usbcmd, ehci->op + EHCI_OP_USBCMD );

	/* Wait for device to stop */
	for ( i = 0 ; i < EHCI_STOP_MAX_WAIT_MS ; i++ ) {

		/* Check if device is stopped */
		usbsts = readl ( ehci->op + EHCI_OP_USBSTS );
		if ( usbsts & EHCI_USBSTS_HCH )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( ehci, "EHCI %s timed out waiting for stop\n", ehci->name );
	return -ETIMEDOUT;
}

/**
 * Reset EHCI device
 *
 * @v ehci		EHCI device
 * @ret rc		Return status code
 */
static int ehci_reset ( struct ehci_device *ehci ) {
	uint32_t usbcmd;
	unsigned int i;
	int rc;

	/* The EHCI specification states that resetting a running
	 * device may result in undefined behaviour, so try stopping
	 * it first.
	 */
	if ( ( rc = ehci_stop ( ehci ) ) != 0 ) {
		/* Ignore errors and attempt to reset the device anyway */
	}

	/* Reset device */
	writel ( EHCI_USBCMD_HCRST, ehci->op + EHCI_OP_USBCMD );

	/* Wait for reset to complete */
	for ( i = 0 ; i < EHCI_RESET_MAX_WAIT_MS ; i++ ) {

		/* Check if reset is complete */
		usbcmd = readl ( ehci->op + EHCI_OP_USBCMD );
		if ( ! ( usbcmd & EHCI_USBCMD_HCRST ) )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( ehci, "EHCI %s timed out waiting for reset\n", ehci->name );
	return -ETIMEDOUT;
}

/******************************************************************************
 *
 * Transfer descriptor rings
 *
 ******************************************************************************
 */

/**
 * Allocate transfer descriptor ring
 *
 * @v ehci		EHCI device
 * @v ring		Transfer descriptor ring
 * @ret rc		Return status code
 */
static int ehci_ring_alloc ( struct ehci_device *ehci,
			     struct ehci_ring *ring ) {
	struct ehci_transfer_descriptor *desc;
	struct ehci_transfer_descriptor *next;
	unsigned int i;
	size_t len;
	uint32_t link;
	int rc;

	/* Initialise structure */
	memset ( ring, 0, sizeof ( *ring ) );

	/* Allocate I/O buffers */
	ring->iobuf = zalloc ( EHCI_RING_COUNT * sizeof ( ring->iobuf[0] ) );
	if ( ! ring->iobuf ) {
		rc = -ENOMEM;
		goto err_alloc_iobuf;
	}

	/* Allocate queue head */
	ring->head = malloc_dma ( sizeof ( *ring->head ),
				  ehci_align ( sizeof ( *ring->head ) ) );
	if ( ! ring->head ) {
		rc = -ENOMEM;
		goto err_alloc_queue;
	}
	if ( ( rc = ehci_ctrl_reachable ( ehci, ring->head ) ) != 0 ) {
		DBGC ( ehci, "EHCI %s queue head unreachable\n", ehci->name );
		goto err_unreachable_queue;
	}
	memset ( ring->head, 0, sizeof ( *ring->head ) );

	/* Allocate transfer descriptors */
	len = ( EHCI_RING_COUNT * sizeof ( ring->desc[0] ) );
	ring->desc = malloc_dma ( len, sizeof ( ring->desc[0] ) );
	if ( ! ring->desc ) {
		rc = -ENOMEM;
		goto err_alloc_desc;
	}
	memset ( ring->desc, 0, len );

	/* Initialise transfer descriptors */
	for ( i = 0 ; i < EHCI_RING_COUNT ; i++ ) {
		desc = &ring->desc[i];
		if ( ( rc = ehci_ctrl_reachable ( ehci, desc ) ) != 0 ) {
			DBGC ( ehci, "EHCI %s descriptor unreachable\n",
			       ehci->name );
			goto err_unreachable_desc;
		}
		next = &ring->desc[ ( i + 1 ) % EHCI_RING_COUNT ];
		link = virt_to_phys ( next );
		desc->next = cpu_to_le32 ( link );
		desc->alt = cpu_to_le32 ( link );
	}

	/* Initialise queue head */
	link = virt_to_phys ( &ring->desc[0] );
	ring->head->cache.next = cpu_to_le32 ( link );

	return 0;

 err_unreachable_desc:
	free_dma ( ring->desc, len );
 err_alloc_desc:
 err_unreachable_queue:
	free_dma ( ring->head, sizeof ( *ring->head ) );
 err_alloc_queue:
	free ( ring->iobuf );
 err_alloc_iobuf:
	return rc;
}

/**
 * Free transfer descriptor ring
 *
 * @v ring		Transfer descriptor ring
 */
static void ehci_ring_free ( struct ehci_ring *ring ) {
	unsigned int i;

	/* Sanity checks */
	assert ( ehci_ring_fill ( ring ) == 0 );
	for ( i = 0 ; i < EHCI_RING_COUNT ; i++ )
		assert ( ring->iobuf[i] == NULL );

	/* Free transfer descriptors */
	free_dma ( ring->desc, ( EHCI_RING_COUNT * sizeof ( ring->desc[0] ) ) );

	/* Free queue head */
	free_dma ( ring->head, sizeof ( *ring->head ) );

	/* Free I/O buffers */
	free ( ring->iobuf );
}

/**
 * Enqueue transfer descriptors
 *
 * @v ehci		EHCI device
 * @v ring		Transfer descriptor ring
 * @v iobuf		I/O buffer
 * @v xfers		Transfers
 * @v count		Number of transfers
 * @ret rc		Return status code
 */
static int ehci_enqueue ( struct ehci_device *ehci, struct ehci_ring *ring,
			  struct io_buffer *iobuf,
			  const struct ehci_transfer *xfer,
			  unsigned int count ) {
	struct ehci_transfer_descriptor *desc;
	physaddr_t phys;
	void *data;
	size_t len;
	size_t offset;
	size_t frag_len;
	unsigned int toggle;
	unsigned int index;
	unsigned int i;

	/* Sanity check */
	assert ( iobuf != NULL );
	assert ( count > 0 );

	/* Fail if ring does not have sufficient space */
	if ( ehci_ring_remaining ( ring ) < count )
		return -ENOBUFS;

	/* Fail if any portion is unreachable */
	for ( i = 0 ; i < count ; i++ ) {
		phys = ( virt_to_phys ( xfer[i].data ) + xfer[i].len - 1 );
		if ( ( phys > 0xffffffffUL ) && ( ! ehci->addr64 ) )
			return -ENOTSUP;
	}

	/* Enqueue each transfer, recording the I/O buffer with the last */
	for ( ; count ; ring->prod++, xfer++ ) {

		/* Populate descriptor header */
		index = ( ring->prod % EHCI_RING_COUNT );
		desc = &ring->desc[index];
		toggle = ( xfer->flags & EHCI_FL_TOGGLE );
		assert ( xfer->len <= EHCI_LEN_MASK );
		assert ( EHCI_FL_TOGGLE == EHCI_LEN_TOGGLE );
		desc->len = cpu_to_le16 ( xfer->len | toggle );
		desc->flags = ( xfer->flags | EHCI_FL_CERR_MAX );

		/* Populate buffer pointers */
		data = xfer->data;
		len = xfer->len;
		for ( i = 0 ; len ; i++ ) {

			/* Calculate length of this fragment */
			phys = virt_to_phys ( data );
			offset = ( phys & ( EHCI_PAGE_ALIGN - 1 ) );
			frag_len = ( EHCI_PAGE_ALIGN - offset );
			if ( frag_len > len )
				frag_len = len;

			/* Sanity checks */
			assert ( ( i == 0 ) || ( offset == 0 ) );
			assert ( i < ( sizeof ( desc->low ) /
				       sizeof ( desc->low[0] ) ) );

			/* Populate buffer pointer */
			desc->low[i] = cpu_to_le32 ( phys );
			if ( sizeof ( physaddr_t ) > sizeof ( uint32_t ) ) {
				desc->high[i] =
					cpu_to_le32 ( ((uint64_t) phys) >> 32 );
			}

			/* Move to next fragment */
			data += frag_len;
			len -= frag_len;
		}

		/* Ensure everything is valid before activating descriptor */
		wmb();
		desc->status = EHCI_STATUS_ACTIVE;

		/* Record I/O buffer against last ring index */
		if ( --count == 0 )
			ring->iobuf[index] = iobuf;
	}

	return 0;
}

/**
 * Dequeue a transfer descriptor
 *
 * @v ring		Transfer descriptor ring
 * @ret iobuf		I/O buffer (or NULL)
 */
static struct io_buffer * ehci_dequeue ( struct ehci_ring *ring ) {
	struct ehci_transfer_descriptor *desc;
	struct io_buffer *iobuf;
	unsigned int index = ( ring->cons % EHCI_RING_COUNT );

	/* Sanity check */
	assert ( ehci_ring_fill ( ring ) > 0 );

	/* Mark descriptor as inactive (and not halted) */
	desc = &ring->desc[index];
	desc->status = 0;

	/* Retrieve I/O buffer */
	iobuf = ring->iobuf[index];
	ring->iobuf[index] = NULL;

	/* Update consumer counter */
	ring->cons++;

	return iobuf;
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
static inline uint32_t ehci_link_qh ( struct ehci_queue_head *queue ) {

	return ( virt_to_phys ( queue ) | EHCI_LINK_TYPE_QH );
}

/**
 * (Re)build asynchronous schedule
 *
 * @v ehci		EHCI device
 */
static void ehci_async_schedule ( struct ehci_device *ehci ) {
	struct ehci_endpoint *endpoint;
	struct ehci_queue_head *queue;
	uint32_t link;

	/* Build schedule in reverse order of execution.  Provided
	 * that we only ever add or remove single endpoints, this can
	 * safely run concurrently with hardware execution of the
	 * schedule.
	 */
	link = ehci_link_qh ( ehci->head );
	list_for_each_entry_reverse ( endpoint, &ehci->async, schedule ) {
		queue = endpoint->ring.head;
		queue->link = cpu_to_le32 ( link );
		wmb();
		link = ehci_link_qh ( queue );
	}
	ehci->head->link = cpu_to_le32 ( link );
	wmb();
}

/**
 * Add endpoint to asynchronous schedule
 *
 * @v endpoint		Endpoint
 */
static void ehci_async_add ( struct ehci_endpoint *endpoint ) {
	struct ehci_device *ehci = endpoint->ehci;

	/* Add to end of schedule */
	list_add_tail ( &endpoint->schedule, &ehci->async );

	/* Rebuild schedule */
	ehci_async_schedule ( ehci );
}

/**
 * Remove endpoint from asynchronous schedule
 *
 * @v endpoint		Endpoint
 * @ret rc		Return status code
 */
static int ehci_async_del ( struct ehci_endpoint *endpoint ) {
	struct ehci_device *ehci = endpoint->ehci;
	uint32_t usbcmd;
	uint32_t usbsts;
	unsigned int i;

	/* Remove from schedule */
	list_check_contains_entry ( endpoint, &ehci->async, schedule );
	list_del ( &endpoint->schedule );

	/* Rebuild schedule */
	ehci_async_schedule ( ehci );

	/* Request notification when asynchronous schedule advances */
	usbcmd = readl ( ehci->op + EHCI_OP_USBCMD );
	usbcmd |= EHCI_USBCMD_ASYNC_ADVANCE;
	writel ( usbcmd, ehci->op + EHCI_OP_USBCMD );

	/* Wait for asynchronous schedule to advance */
	for ( i = 0 ; i < EHCI_ASYNC_ADVANCE_MAX_WAIT_MS ; i++ ) {

		/* Check for asynchronous schedule advancing */
		usbsts = readl ( ehci->op + EHCI_OP_USBSTS );
		if ( usbsts & EHCI_USBSTS_ASYNC_ADVANCE ) {
			usbsts &= ~EHCI_USBSTS_CHANGE;
			usbsts |= EHCI_USBSTS_ASYNC_ADVANCE;
			writel ( usbsts, ehci->op + EHCI_OP_USBSTS );
			return 0;
		}

		/* Delay */
		mdelay ( 1 );
	}

	/* Bad things will probably happen now */
	DBGC ( ehci, "EHCI %s timed out waiting for asynchronous schedule "
	       "to advance\n", ehci->name );
	return -ETIMEDOUT;
}

/**
 * (Re)build periodic schedule
 *
 * @v ehci		EHCI device
 */
static void ehci_periodic_schedule ( struct ehci_device *ehci ) {
	struct ehci_endpoint *endpoint;
	struct ehci_queue_head *queue;
	uint32_t link;
	unsigned int frames;
	unsigned int max_interval;
	unsigned int i;

	/* Build schedule in reverse order of execution.  Provided
	 * that we only ever add or remove single endpoints, this can
	 * safely run concurrently with hardware execution of the
	 * schedule.
	 */
	DBGCP ( ehci, "EHCI %s periodic schedule: ", ehci->name );
	link = EHCI_LINK_TERMINATE;
	list_for_each_entry_reverse ( endpoint, &ehci->periodic, schedule ) {
		queue = endpoint->ring.head;
		queue->link = cpu_to_le32 ( link );
		wmb();
		DBGCP ( ehci, "%s%d",
			( ( link == EHCI_LINK_TERMINATE ) ? "" : "<-" ),
			endpoint->ep->interval );
		link = ehci_link_qh ( queue );
	}
	DBGCP ( ehci, "\n" );

	/* Populate periodic frame list */
	DBGCP ( ehci, "EHCI %s periodic frame list:", ehci->name );
	frames = EHCI_PERIODIC_FRAMES ( ehci->flsize );
	for ( i = 0 ; i < frames ; i++ ) {

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
		link = EHCI_LINK_TERMINATE;
		list_for_each_entry ( endpoint, &ehci->periodic, schedule ) {
			if ( endpoint->ep->interval <= max_interval ) {
				queue = endpoint->ring.head;
				link = ehci_link_qh ( queue );
				DBGCP ( ehci, " %d:%d",
					i, endpoint->ep->interval );
				break;
			}
		}
		ehci->frame[i].link = cpu_to_le32 ( link );
	}
	wmb();
	DBGCP ( ehci, "\n" );
}

/**
 * Add endpoint to periodic schedule
 *
 * @v endpoint		Endpoint
 */
static void ehci_periodic_add ( struct ehci_endpoint *endpoint ) {
	struct ehci_device *ehci = endpoint->ehci;
	struct ehci_endpoint *before;
	unsigned int interval = endpoint->ep->interval;

	/* Find first endpoint with a smaller interval */
	list_for_each_entry ( before, &ehci->periodic, schedule ) {
		if ( before->ep->interval < interval )
			break;
	}
	list_add_tail ( &endpoint->schedule, &before->schedule );

	/* Rebuild schedule */
	ehci_periodic_schedule ( ehci );
}

/**
 * Remove endpoint from periodic schedule
 *
 * @v endpoint		Endpoint
 * @ret rc		Return status code
 */
static int ehci_periodic_del ( struct ehci_endpoint *endpoint ) {
	struct ehci_device *ehci = endpoint->ehci;

	/* Remove from schedule */
	list_check_contains_entry ( endpoint, &ehci->periodic, schedule );
	list_del ( &endpoint->schedule );

	/* Rebuild schedule */
	ehci_periodic_schedule ( ehci );

	/* Delay for a whole USB frame (with a 100% safety margin) */
	mdelay ( 2 );

	return 0;
}

/**
 * Add endpoint to appropriate schedule
 *
 * @v endpoint		Endpoint
 */
static void ehci_schedule_add ( struct ehci_endpoint *endpoint ) {
	struct usb_endpoint *ep = endpoint->ep;
	unsigned int attr = ( ep->attributes & USB_ENDPOINT_ATTR_TYPE_MASK );

	if ( attr == USB_ENDPOINT_ATTR_INTERRUPT ) {
		ehci_periodic_add ( endpoint );
	} else {
		ehci_async_add ( endpoint );
	}
}

/**
 * Remove endpoint from appropriate schedule
 *
 * @v endpoint		Endpoint
 * @ret rc		Return status code
 */
static int ehci_schedule_del ( struct ehci_endpoint *endpoint ) {
	struct usb_endpoint *ep = endpoint->ep;
	unsigned int attr = ( ep->attributes & USB_ENDPOINT_ATTR_TYPE_MASK );

	if ( attr == USB_ENDPOINT_ATTR_INTERRUPT ) {
		return ehci_periodic_del ( endpoint );
	} else {
		return ehci_async_del ( endpoint );
	}
}

/******************************************************************************
 *
 * Endpoint operations
 *
 ******************************************************************************
 */

/**
 * Determine endpoint characteristics
 *
 * @v ep		USB endpoint
 * @ret chr		Endpoint characteristics
 */
static uint32_t ehci_endpoint_characteristics ( struct usb_endpoint *ep ) {
	struct usb_device *usb = ep->usb;
	unsigned int attr = ( ep->attributes & USB_ENDPOINT_ATTR_TYPE_MASK );
	uint32_t chr;

	/* Determine basic characteristics */
	chr = ( EHCI_CHR_ADDRESS ( usb->address ) |
		EHCI_CHR_ENDPOINT ( ep->address ) |
		EHCI_CHR_MAX_LEN ( ep->mtu ) );

	/* Control endpoints require manual control of the data toggle */
	if ( attr == USB_ENDPOINT_ATTR_CONTROL )
		chr |= EHCI_CHR_TOGGLE;

	/* Determine endpoint speed */
	if ( usb->port->speed == USB_SPEED_HIGH ) {
		chr |= EHCI_CHR_EPS_HIGH;
	} else {
		if ( usb->port->speed == USB_SPEED_FULL ) {
			chr |= EHCI_CHR_EPS_FULL;
		} else {
			chr |= EHCI_CHR_EPS_LOW;
		}
		if ( attr == USB_ENDPOINT_ATTR_CONTROL )
			chr |= EHCI_CHR_CONTROL;
	}

	return chr;
}

/**
 * Determine endpoint capabilities
 *
 * @v ep		USB endpoint
 * @ret cap		Endpoint capabilities
 */
static uint32_t ehci_endpoint_capabilities ( struct usb_endpoint *ep ) {
	struct usb_device *usb = ep->usb;
	struct usb_port *tt = usb_transaction_translator ( usb );
	unsigned int attr = ( ep->attributes & USB_ENDPOINT_ATTR_TYPE_MASK );
	uint32_t cap;
	unsigned int i;

	/* Determine basic capabilities */
	cap = EHCI_CAP_MULT ( ep->burst + 1 );

	/* Determine interrupt schedule mask, if applicable */
	if ( ( attr == USB_ENDPOINT_ATTR_INTERRUPT ) &&
	     ( ( ep->interval != 0 ) /* avoid infinite loop */ ) ) {
		for ( i = 0 ; i < 8 /* microframes per frame */ ;
		      i += ep->interval ) {
			cap |= EHCI_CAP_INTR_SCHED ( i );
		}
	}

	/* Set transaction translator hub address and port, if applicable */
	if ( tt ) {
		assert ( tt->hub->usb );
		cap |= ( EHCI_CAP_TT_HUB ( tt->hub->usb->address ) |
			 EHCI_CAP_TT_PORT ( tt->address ) );
		if ( attr == USB_ENDPOINT_ATTR_INTERRUPT )
			cap |= EHCI_CAP_SPLIT_SCHED_DEFAULT;
	}

	return cap;
}

/**
 * Update endpoint characteristics and capabilities
 *
 * @v ep		USB endpoint
 */
static void ehci_endpoint_update ( struct usb_endpoint *ep ) {
	struct ehci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct ehci_queue_head *head;

	/* Update queue characteristics and capabilities */
	head = endpoint->ring.head;
	head->chr = cpu_to_le32 ( ehci_endpoint_characteristics ( ep ) );
	head->cap = cpu_to_le32 ( ehci_endpoint_capabilities ( ep ) );
}

/**
 * Open endpoint
 *
 * @v ep		USB endpoint
 * @ret rc		Return status code
 */
static int ehci_endpoint_open ( struct usb_endpoint *ep ) {
	struct usb_device *usb = ep->usb;
	struct ehci_device *ehci = usb_get_hostdata ( usb );
	struct ehci_endpoint *endpoint;
	int rc;

	/* Allocate and initialise structure */
	endpoint = zalloc ( sizeof ( *endpoint ) );
	if ( ! endpoint ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	endpoint->ehci = ehci;
	endpoint->ep = ep;
	usb_endpoint_set_hostdata ( ep, endpoint );

	/* Initialise descriptor ring */
	if ( ( rc = ehci_ring_alloc ( ehci, &endpoint->ring ) ) != 0 )
		goto err_ring_alloc;

	/* Update queue characteristics and capabilities */
	ehci_endpoint_update ( ep );

	/* Add to list of endpoints */
	list_add_tail ( &endpoint->list, &ehci->endpoints );

	/* Add to schedule */
	ehci_schedule_add ( endpoint );

	return 0;

	ehci_ring_free ( &endpoint->ring );
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
static void ehci_endpoint_close ( struct usb_endpoint *ep ) {
	struct ehci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct ehci_device *ehci = endpoint->ehci;
	struct usb_device *usb = ep->usb;
	struct io_buffer *iobuf;
	int rc;

	/* Remove from schedule */
	if ( ( rc = ehci_schedule_del ( endpoint ) ) != 0 ) {
		/* No way to prevent hardware from continuing to
		 * access the memory, so leak it.
		 */
		DBGC ( ehci, "EHCI %s %s could not unschedule: %s\n",
		       usb->name, usb_endpoint_name ( ep ), strerror ( rc ) );
		return;
	}

	/* Cancel any incomplete transfers */
	while ( ehci_ring_fill ( &endpoint->ring ) ) {
		iobuf = ehci_dequeue ( &endpoint->ring );
		if ( iobuf )
			usb_complete_err ( ep, iobuf, -ECANCELED );
	}

	/* Remove from list of endpoints */
	list_del ( &endpoint->list );

	/* Free descriptor ring */
	ehci_ring_free ( &endpoint->ring );

	/* Free endpoint */
	free ( endpoint );
}

/**
 * Reset endpoint
 *
 * @v ep		USB endpoint
 * @ret rc		Return status code
 */
static int ehci_endpoint_reset ( struct usb_endpoint *ep ) {
	struct ehci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct ehci_ring *ring = &endpoint->ring;
	struct ehci_transfer_descriptor *cache = &ring->head->cache;
	uint32_t link;

	/* Sanity checks */
	assert ( ! ( cache->status & EHCI_STATUS_ACTIVE ) );
	assert ( cache->status & EHCI_STATUS_HALTED );

	/* Reset residual count */
	ring->residual = 0;

	/* Reset data toggle */
	cache->len = 0;

	/* Prepare to restart at next unconsumed descriptor */
	link = virt_to_phys ( &ring->desc[ ring->cons % EHCI_RING_COUNT ] );
	cache->next = cpu_to_le32 ( link );

	/* Restart ring */
	wmb();
	cache->status = 0;

	return 0;
}

/**
 * Update MTU
 *
 * @v ep		USB endpoint
 * @ret rc		Return status code
 */
static int ehci_endpoint_mtu ( struct usb_endpoint *ep ) {

	/* Update endpoint characteristics and capabilities */
	ehci_endpoint_update ( ep );

	return 0;
}

/**
 * Enqueue message transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int ehci_endpoint_message ( struct usb_endpoint *ep,
				   struct io_buffer *iobuf ) {
	struct ehci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct ehci_device *ehci = endpoint->ehci;
	struct usb_setup_packet *packet;
	unsigned int input;
	struct ehci_transfer xfers[3];
	struct ehci_transfer *xfer = xfers;
	size_t len;
	int rc;

	/* Construct setup stage */
	assert ( iob_len ( iobuf ) >= sizeof ( *packet ) );
	packet = iobuf->data;
	iob_pull ( iobuf, sizeof ( *packet ) );
	xfer->data = packet;
	xfer->len = sizeof ( *packet );
	xfer->flags = EHCI_FL_PID_SETUP;
	xfer++;

	/* Construct data stage, if applicable */
	len = iob_len ( iobuf );
	input = ( packet->request & cpu_to_le16 ( USB_DIR_IN ) );
	if ( len ) {
		xfer->data = iobuf->data;
		xfer->len = len;
		xfer->flags = ( EHCI_FL_TOGGLE |
				( input ? EHCI_FL_PID_IN : EHCI_FL_PID_OUT ) );
		xfer++;
	}

	/* Construct status stage */
	xfer->data = NULL;
	xfer->len = 0;
	xfer->flags = ( EHCI_FL_TOGGLE | EHCI_FL_IOC |
			( ( len && input ) ? EHCI_FL_PID_OUT : EHCI_FL_PID_IN));
	xfer++;

	/* Enqueue transfer */
	if ( ( rc = ehci_enqueue ( ehci, &endpoint->ring, iobuf, xfers,
				   ( xfer - xfers ) ) ) != 0 )
		return rc;

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
static int ehci_endpoint_stream ( struct usb_endpoint *ep,
				  struct io_buffer *iobuf, int terminate ) {
	struct ehci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct ehci_device *ehci = endpoint->ehci;
	unsigned int input = ( ep->address & USB_DIR_IN );
	struct ehci_transfer xfers[2];
	struct ehci_transfer *xfer = xfers;
	size_t len = iob_len ( iobuf );
	int rc;

	/* Create transfer */
	xfer->data = iobuf->data;
	xfer->len = len;
	xfer->flags = ( EHCI_FL_IOC |
			( input ? EHCI_FL_PID_IN : EHCI_FL_PID_OUT ) );
	xfer++;
	if ( terminate && ( ( len & ( ep->mtu - 1 ) ) == 0 ) ) {
		xfer->data = NULL;
		xfer->len = 0;
		assert ( ! input );
		xfer->flags = ( EHCI_FL_IOC | EHCI_FL_PID_OUT );
		xfer++;
	}

	/* Enqueue transfer */
	if ( ( rc = ehci_enqueue ( ehci, &endpoint->ring, iobuf, xfers,
				   ( xfer - xfers ) ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Poll for completions
 *
 * @v endpoint		Endpoint
 */
static void ehci_endpoint_poll ( struct ehci_endpoint *endpoint ) {
	struct ehci_device *ehci = endpoint->ehci;
	struct ehci_ring *ring = &endpoint->ring;
	struct ehci_transfer_descriptor *desc;
	struct usb_endpoint *ep = endpoint->ep;
	struct usb_device *usb = ep->usb;
	struct io_buffer *iobuf;
	unsigned int index;
	unsigned int status;
	int rc;

	/* Consume all completed descriptors */
	while ( ehci_ring_fill ( &endpoint->ring ) ) {

		/* Stop if we reach an uncompleted descriptor */
		rmb();
		index = ( ring->cons % EHCI_RING_COUNT );
		desc = &ring->desc[index];
		status = desc->status;
		if ( status & EHCI_STATUS_ACTIVE )
			break;

		/* Consume this descriptor */
		iobuf = ehci_dequeue ( ring );

		/* If we have encountered an error, then consume all
		 * remaining descriptors in this transaction, report
		 * the error to the USB core, and stop further
		 * processing.
		 */
		if ( status & EHCI_STATUS_HALTED ) {
			rc = -EIO_STATUS ( status );
			DBGC ( ehci, "EHCI %s %s completion %d failed (status "
			       "%02x): %s\n", usb->name,
			       usb_endpoint_name ( ep ), index, status,
			       strerror ( rc ) );
			while ( ! iobuf )
				iobuf = ehci_dequeue ( ring );
			usb_complete_err ( endpoint->ep, iobuf, rc );
			return;
		}

		/* Accumulate residual data count */
		ring->residual += ( le16_to_cpu ( desc->len ) & EHCI_LEN_MASK );

		/* If this is not the end of a transaction (i.e. has
		 * no I/O buffer), then continue to next descriptor.
		 */
		if ( ! iobuf )
			continue;

		/* Update I/O buffer length */
		iob_unput ( iobuf, ring->residual );
		ring->residual = 0;

		/* Report completion to USB core */
		usb_complete ( endpoint->ep, iobuf );
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
static int ehci_device_open ( struct usb_device *usb ) {
	struct ehci_device *ehci = usb_bus_get_hostdata ( usb->port->hub->bus );

	usb_set_hostdata ( usb, ehci );
	return 0;
}

/**
 * Close device
 *
 * @v usb		USB device
 */
static void ehci_device_close ( struct usb_device *usb ) {
	struct ehci_device *ehci = usb_get_hostdata ( usb );
	struct usb_bus *bus = ehci->bus;

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
static int ehci_device_address ( struct usb_device *usb ) {
	struct ehci_device *ehci = usb_get_hostdata ( usb );
	struct usb_bus *bus = ehci->bus;
	struct usb_endpoint *ep0 = usb_endpoint ( usb, USB_EP0_ADDRESS );
	int address;
	int rc;

	/* Sanity checks */
	assert ( usb->address == 0 );
	assert ( ep0 != NULL );

	/* Allocate device address */
	address = usb_alloc_address ( bus );
	if ( address < 0 ) {
		rc = address;
		DBGC ( ehci, "EHCI %s could not allocate address: %s\n",
		       usb->name, strerror ( rc ) );
		goto err_alloc_address;
	}

	/* Set address */
	if ( ( rc = usb_set_address ( usb, address ) ) != 0 )
		goto err_set_address;

	/* Update device address */
	usb->address = address;

	/* Update control endpoint characteristics and capabilities */
	ehci_endpoint_update ( ep0 );

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
static int ehci_hub_open ( struct usb_hub *hub __unused ) {

	/* Nothing to do */
	return 0;
}

/**
 * Close hub
 *
 * @v hub		USB hub
 */
static void ehci_hub_close ( struct usb_hub *hub __unused ) {

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
static int ehci_root_open ( struct usb_hub *hub ) {
	struct usb_bus *bus = hub->bus;
	struct ehci_device *ehci = usb_bus_get_hostdata ( bus );
	uint32_t portsc;
	unsigned int i;

	/* Route all ports to EHCI controller */
	writel ( EHCI_CONFIGFLAG_CF, ehci->op + EHCI_OP_CONFIGFLAG );

	/* Enable power to all ports */
	for ( i = 1 ; i <= ehci->ports ; i++ ) {
		portsc = readl ( ehci->op + EHCI_OP_PORTSC ( i ) );
		portsc &= ~EHCI_PORTSC_CHANGE;
		portsc |= EHCI_PORTSC_PP;
		writel ( portsc, ehci->op + EHCI_OP_PORTSC ( i ) );
	}

	/* Wait 20ms after potentially enabling power to a port */
	mdelay ( EHCI_PORT_POWER_DELAY_MS );

	/* Record hub driver private data */
	usb_hub_set_drvdata ( hub, ehci );

	return 0;
}

/**
 * Close root hub
 *
 * @v hub		USB hub
 */
static void ehci_root_close ( struct usb_hub *hub ) {
	struct ehci_device *ehci = usb_hub_get_drvdata ( hub );

	/* Route all ports back to companion controllers */
	writel ( 0, ehci->op + EHCI_OP_CONFIGFLAG );

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
static int ehci_root_enable ( struct usb_hub *hub, struct usb_port *port ) {
	struct ehci_device *ehci = usb_hub_get_drvdata ( hub );
	uint32_t portsc;
	unsigned int line;
	unsigned int i;

	/* Check for a low-speed device */
	portsc = readl ( ehci->op + EHCI_OP_PORTSC ( port->address ) );
	line = EHCI_PORTSC_LINE_STATUS ( portsc );
	if ( line == EHCI_PORTSC_LINE_STATUS_LOW ) {
		DBGC ( ehci, "EHCI %s-%d detected low-speed device: "
		       "disowning\n", ehci->name, port->address );
		goto disown;
	}

	/* Reset port */
	portsc &= ~( EHCI_PORTSC_PED | EHCI_PORTSC_CHANGE );
	portsc |= EHCI_PORTSC_PR;
	writel ( portsc, ehci->op + EHCI_OP_PORTSC ( port->address ) );
	mdelay ( USB_RESET_DELAY_MS );
	portsc &= ~EHCI_PORTSC_PR;
	writel ( portsc, ehci->op + EHCI_OP_PORTSC ( port->address ) );

	/* Wait for reset to complete */
	for ( i = 0 ; i < EHCI_PORT_RESET_MAX_WAIT_MS ; i++ ) {

		/* Check port status */
		portsc = readl ( ehci->op + EHCI_OP_PORTSC ( port->address ) );
		if ( ! ( portsc & EHCI_PORTSC_PR ) ) {
			if ( portsc & EHCI_PORTSC_PED )
				return 0;
			DBGC ( ehci, "EHCI %s-%d not enabled after reset: "
			       "disowning\n", ehci->name, port->address );
			goto disown;
		}

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( ehci, "EHCI %s-%d timed out waiting for port to reset\n",
	       ehci->name, port->address );
	return -ETIMEDOUT;

 disown:
	/* Disown port */
	portsc &= ~EHCI_PORTSC_CHANGE;
	portsc |= EHCI_PORTSC_OWNER;
	writel ( portsc, ehci->op + EHCI_OP_PORTSC ( port->address ) );

	/* Delay to allow child companion controllers to settle */
	mdelay ( EHCI_DISOWN_DELAY_MS );

	/* Poll child companion controllers */
	ehci_poll_companions ( ehci );

	return -ENODEV;
}

/**
 * Disable port
 *
 * @v hub		USB hub
 * @v port		USB port
 * @ret rc		Return status code
 */
static int ehci_root_disable ( struct usb_hub *hub, struct usb_port *port ) {
	struct ehci_device *ehci = usb_hub_get_drvdata ( hub );
	uint32_t portsc;

	/* Disable port */
	portsc = readl ( ehci->op + EHCI_OP_PORTSC ( port->address ) );
	portsc &= ~( EHCI_PORTSC_PED | EHCI_PORTSC_CHANGE );
	writel ( portsc, ehci->op + EHCI_OP_PORTSC ( port->address ) );

	return 0;
}

/**
 * Update root hub port speed
 *
 * @v hub		USB hub
 * @v port		USB port
 * @ret rc		Return status code
 */
static int ehci_root_speed ( struct usb_hub *hub, struct usb_port *port ) {
	struct ehci_device *ehci = usb_hub_get_drvdata ( hub );
	uint32_t portsc;
	unsigned int speed;
	unsigned int line;
	int ccs;
	int csc;
	int ped;

	/* Read port status */
	portsc = readl ( ehci->op + EHCI_OP_PORTSC ( port->address ) );
	DBGC2 ( ehci, "EHCI %s-%d status is %08x\n",
		ehci->name, port->address, portsc );
	ccs = ( portsc & EHCI_PORTSC_CCS );
	csc = ( portsc & EHCI_PORTSC_CSC );
	ped = ( portsc & EHCI_PORTSC_PED );
	line = EHCI_PORTSC_LINE_STATUS ( portsc );

	/* Record disconnections and clear changes */
	port->disconnected |= csc;
	writel ( portsc, ehci->op + EHCI_OP_PORTSC ( port->address ) );

	/* Determine port speed */
	if ( ! ccs ) {
		/* Port not connected */
		speed = USB_SPEED_NONE;
	} else if ( line == EHCI_PORTSC_LINE_STATUS_LOW ) {
		/* Detected as low-speed */
		speed = USB_SPEED_LOW;
	} else if ( ped ) {
		/* Port already enabled: must be high-speed */
		speed = USB_SPEED_HIGH;
	} else {
		/* Not low-speed and not yet enabled.  Could be either
		 * full-speed or high-speed; we can't yet tell.
		 */
		speed = USB_SPEED_FULL;
	}
	port->speed = speed;
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
static int ehci_root_clear_tt ( struct usb_hub *hub, struct usb_port *port,
				struct usb_endpoint *ep ) {
	struct ehci_device *ehci = usb_hub_get_drvdata ( hub );

	/* Should never be called; this is a root hub */
	DBGC ( ehci, "EHCI %s-%d nonsensical CLEAR_TT for %s %s\n", ehci->name,
	       port->address, ep->usb->name, usb_endpoint_name ( ep ) );

	return -ENOTSUP;
}

/**
 * Poll for port status changes
 *
 * @v hub		USB hub
 * @v port		USB port
 */
static void ehci_root_poll ( struct usb_hub *hub, struct usb_port *port ) {
	struct ehci_device *ehci = usb_hub_get_drvdata ( hub );
	uint32_t portsc;
	uint32_t change;

	/* Do nothing unless something has changed */
	portsc = readl ( ehci->op + EHCI_OP_PORTSC ( port->address ) );
	change = ( portsc & EHCI_PORTSC_CHANGE );
	if ( ! change )
		return;

	/* Record disconnections and clear changes */
	port->disconnected |= ( portsc & EHCI_PORTSC_CSC );
	writel ( portsc, ehci->op + EHCI_OP_PORTSC ( port->address ) );

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
static int ehci_bus_open ( struct usb_bus *bus ) {
	struct ehci_device *ehci = usb_bus_get_hostdata ( bus );
	unsigned int frames;
	size_t len;
	int rc;

	/* Sanity checks */
	assert ( list_empty ( &ehci->async ) );
	assert ( list_empty ( &ehci->periodic ) );

	/* Allocate and initialise asynchronous queue head */
	ehci->head = malloc_dma ( sizeof ( *ehci->head ),
				  ehci_align ( sizeof ( *ehci->head ) ) );
	if ( ! ehci->head ) {
		rc = -ENOMEM;
		goto err_alloc_head;
	}
	memset ( ehci->head, 0, sizeof ( *ehci->head ) );
	ehci->head->chr = cpu_to_le32 ( EHCI_CHR_HEAD );
	ehci->head->cache.next = cpu_to_le32 ( EHCI_LINK_TERMINATE );
	ehci->head->cache.status = EHCI_STATUS_HALTED;
	ehci_async_schedule ( ehci );
	writel ( virt_to_phys ( ehci->head ),
		 ehci->op + EHCI_OP_ASYNCLISTADDR );

	/* Use async queue head to determine control data structure segment */
	ehci->ctrldssegment =
		( ( ( uint64_t ) virt_to_phys ( ehci->head ) ) >> 32 );
	if ( ehci->addr64 ) {
		writel ( ehci->ctrldssegment, ehci->op + EHCI_OP_CTRLDSSEGMENT);
	} else if ( ehci->ctrldssegment ) {
		DBGC ( ehci, "EHCI %s CTRLDSSEGMENT not supported\n",
		       ehci->name );
		rc = -ENOTSUP;
		goto err_ctrldssegment;
	}

	/* Allocate periodic frame list */
	frames = EHCI_PERIODIC_FRAMES ( ehci->flsize );
	len = ( frames * sizeof ( ehci->frame[0] ) );
	ehci->frame = malloc_dma ( len, EHCI_PAGE_ALIGN );
	if ( ! ehci->frame ) {
		rc = -ENOMEM;
		goto err_alloc_frame;
	}
	if ( ( rc = ehci_ctrl_reachable ( ehci, ehci->frame ) ) != 0 ) {
		DBGC ( ehci, "EHCI %s frame list unreachable\n", ehci->name );
		goto err_unreachable_frame;
	}
	ehci_periodic_schedule ( ehci );
	writel ( virt_to_phys ( ehci->frame ),
		 ehci->op + EHCI_OP_PERIODICLISTBASE );

	/* Start controller */
	ehci_run ( ehci );

	return 0;

	ehci_stop ( ehci );
 err_unreachable_frame:
	free_dma ( ehci->frame, len );
 err_alloc_frame:
 err_ctrldssegment:
	free_dma ( ehci->head, sizeof ( *ehci->head ) );
 err_alloc_head:
	return rc;
}

/**
 * Close USB bus
 *
 * @v bus		USB bus
 */
static void ehci_bus_close ( struct usb_bus *bus ) {
	struct ehci_device *ehci = usb_bus_get_hostdata ( bus );
	unsigned int frames = EHCI_PERIODIC_FRAMES ( ehci->flsize );

	/* Sanity checks */
	assert ( list_empty ( &ehci->async ) );
	assert ( list_empty ( &ehci->periodic ) );

	/* Stop controller */
	ehci_stop ( ehci );

	/* Free periodic frame list */
	free_dma ( ehci->frame, ( frames * sizeof ( ehci->frame[0] ) ) );

	/* Free asynchronous schedule */
	free_dma ( ehci->head, sizeof ( *ehci->head ) );
}

/**
 * Poll USB bus
 *
 * @v bus		USB bus
 */
static void ehci_bus_poll ( struct usb_bus *bus ) {
	struct ehci_device *ehci = usb_bus_get_hostdata ( bus );
	struct usb_hub *hub = bus->hub;
	struct ehci_endpoint *endpoint;
	unsigned int i;
	uint32_t usbsts;
	uint32_t change;

	/* Do nothing unless something has changed */
	usbsts = readl ( ehci->op + EHCI_OP_USBSTS );
	assert ( usbsts & EHCI_USBSTS_ASYNC );
	assert ( usbsts & EHCI_USBSTS_PERIODIC );
	assert ( ! ( usbsts & EHCI_USBSTS_HCH ) );
	change = ( usbsts & EHCI_USBSTS_CHANGE );
	if ( ! change )
		return;

	/* Acknowledge changes */
	writel ( usbsts, ehci->op + EHCI_OP_USBSTS );

	/* Process completions, if applicable */
	if ( change & ( EHCI_USBSTS_USBINT | EHCI_USBSTS_USBERRINT ) ) {

		/* Iterate over all endpoints looking for completed
		 * descriptors.  We trust that completion handlers are
		 * minimal and will not do anything that could
		 * plausibly affect the endpoint list itself.
		 */
		list_for_each_entry ( endpoint, &ehci->endpoints, list )
			ehci_endpoint_poll ( endpoint );
	}

	/* Process port status changes, if applicable */
	if ( change & EHCI_USBSTS_PORT ) {

		/* Iterate over all ports looking for status changes */
		for ( i = 1 ; i <= ehci->ports ; i++ )
			ehci_root_poll ( hub, usb_port ( hub, i ) );
	}

	/* Report fatal errors */
	if ( change & EHCI_USBSTS_SYSERR )
		DBGC ( ehci, "EHCI %s host system error\n", ehci->name );
}

/******************************************************************************
 *
 * PCI interface
 *
 ******************************************************************************
 */

/** USB host controller operations */
static struct usb_host_operations ehci_operations = {
	.endpoint = {
		.open = ehci_endpoint_open,
		.close = ehci_endpoint_close,
		.reset = ehci_endpoint_reset,
		.mtu = ehci_endpoint_mtu,
		.message = ehci_endpoint_message,
		.stream = ehci_endpoint_stream,
	},
	.device = {
		.open = ehci_device_open,
		.close = ehci_device_close,
		.address = ehci_device_address,
	},
	.bus = {
		.open = ehci_bus_open,
		.close = ehci_bus_close,
		.poll = ehci_bus_poll,
	},
	.hub = {
		.open = ehci_hub_open,
		.close = ehci_hub_close,
	},
	.root = {
		.open = ehci_root_open,
		.close = ehci_root_close,
		.enable = ehci_root_enable,
		.disable = ehci_root_disable,
		.speed = ehci_root_speed,
		.clear_tt = ehci_root_clear_tt,
	},
};

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 */
static int ehci_probe ( struct pci_device *pci ) {
	struct ehci_device *ehci;
	struct usb_port *port;
	unsigned long bar_start;
	size_t bar_size;
	unsigned int i;
	int rc;

	/* Allocate and initialise structure */
	ehci = zalloc ( sizeof ( *ehci ) );
	if ( ! ehci ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	ehci->name = pci->dev.name;
	INIT_LIST_HEAD ( &ehci->endpoints );
	INIT_LIST_HEAD ( &ehci->async );
	INIT_LIST_HEAD ( &ehci->periodic );

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Map registers */
	bar_start = pci_bar_start ( pci, EHCI_BAR );
	bar_size = pci_bar_size ( pci, EHCI_BAR );
	ehci->regs = ioremap ( bar_start, bar_size );
	if ( ! ehci->regs ) {
		rc = -ENODEV;
		goto err_ioremap;
	}

	/* Initialise EHCI device */
	ehci_init ( ehci, ehci->regs );

	/* Initialise USB legacy support and claim ownership */
	ehci_legacy_init ( ehci, pci );
	ehci_legacy_claim ( ehci, pci );

	/* Reset device */
	if ( ( rc = ehci_reset ( ehci ) ) != 0 )
		goto err_reset;

	/* Allocate USB bus */
	ehci->bus = alloc_usb_bus ( &pci->dev, ehci->ports, EHCI_MTU,
				    &ehci_operations );
	if ( ! ehci->bus ) {
		rc = -ENOMEM;
		goto err_alloc_bus;
	}
	usb_bus_set_hostdata ( ehci->bus, ehci );
	usb_hub_set_drvdata ( ehci->bus->hub, ehci );

	/* Set port protocols */
	for ( i = 1 ; i <= ehci->ports ; i++ ) {
		port = usb_port ( ehci->bus->hub, i );
		port->protocol = USB_PROTO_2_0;
	}

	/* Register USB bus */
	if ( ( rc = register_usb_bus ( ehci->bus ) ) != 0 )
		goto err_register;

	pci_set_drvdata ( pci, ehci );
	return 0;

	unregister_usb_bus ( ehci->bus );
 err_register:
	free_usb_bus ( ehci->bus );
 err_alloc_bus:
	ehci_reset ( ehci );
 err_reset:
	ehci_legacy_release ( ehci, pci );
	iounmap ( ehci->regs );
 err_ioremap:
	free ( ehci );
 err_alloc:
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci		PCI device
 */
static void ehci_remove ( struct pci_device *pci ) {
	struct ehci_device *ehci = pci_get_drvdata ( pci );
	struct usb_bus *bus = ehci->bus;

	unregister_usb_bus ( bus );
	assert ( list_empty ( &ehci->async ) );
	assert ( list_empty ( &ehci->periodic ) );
	free_usb_bus ( bus );
	ehci_reset ( ehci );
	ehci_legacy_release ( ehci, pci );
	iounmap ( ehci->regs );
	free ( ehci );
}

/** EHCI PCI device IDs */
static struct pci_device_id ehci_ids[] = {
	PCI_ROM ( 0xffff, 0xffff, "ehci", "EHCI", 0 ),
};

/** EHCI PCI driver */
struct pci_driver ehci_driver __pci_driver = {
	.ids = ehci_ids,
	.id_count = ( sizeof ( ehci_ids ) / sizeof ( ehci_ids[0] ) ),
	.class = PCI_CLASS_ID ( PCI_CLASS_SERIAL, PCI_CLASS_SERIAL_USB,
				PCI_CLASS_SERIAL_USB_EHCI ),
	.probe = ehci_probe,
	.remove = ehci_remove,
};

/**
 * Prepare for exit
 *
 * @v booting		System is shutting down for OS boot
 */
static void ehci_shutdown ( int booting ) {
	/* If we are shutting down to boot an OS, then prevent the
	 * release of ownership back to BIOS.
	 */
	ehci_legacy_prevent_release = booting;
}

/** Startup/shutdown function */
struct startup_fn ehci_startup __startup_fn ( STARTUP_LATE ) = {
	.shutdown = ehci_shutdown,
};
