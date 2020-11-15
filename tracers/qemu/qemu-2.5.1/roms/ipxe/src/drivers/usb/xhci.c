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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/malloc.h>
#include <ipxe/umalloc.h>
#include <ipxe/pci.h>
#include <ipxe/usb.h>
#include <ipxe/init.h>
#include <ipxe/profile.h>
#include "xhci.h"

/** @file
 *
 * USB eXtensible Host Controller Interface (xHCI) driver
 *
 */

/** Message transfer profiler */
static struct profiler xhci_message_profiler __profiler =
	{ .name = "xhci.message" };

/** Stream transfer profiler */
static struct profiler xhci_stream_profiler __profiler =
	{ .name = "xhci.stream" };

/** Event ring profiler */
static struct profiler xhci_event_profiler __profiler =
	{ .name = "xhci.event" };

/** Transfer event profiler */
static struct profiler xhci_transfer_profiler __profiler =
	{ .name = "xhci.transfer" };

/* Disambiguate the various error causes */
#define EIO_DATA							\
	__einfo_error ( EINFO_EIO_DATA )
#define EINFO_EIO_DATA							\
	__einfo_uniqify ( EINFO_EIO, ( 2 - 0 ),				\
			  "Data buffer error" )
#define EIO_BABBLE							\
	__einfo_error ( EINFO_EIO_BABBLE )
#define EINFO_EIO_BABBLE						\
	__einfo_uniqify ( EINFO_EIO, ( 3 - 0 ),				\
			  "Babble detected" )
#define EIO_USB								\
	__einfo_error ( EINFO_EIO_USB )
#define EINFO_EIO_USB							\
	__einfo_uniqify ( EINFO_EIO, ( 4 - 0 ),				\
			  "USB transaction error" )
#define EIO_TRB								\
	__einfo_error ( EINFO_EIO_TRB )
#define EINFO_EIO_TRB							\
	__einfo_uniqify ( EINFO_EIO, ( 5 - 0 ),				\
			  "TRB error" )
#define EIO_STALL							\
	__einfo_error ( EINFO_EIO_STALL )
#define EINFO_EIO_STALL							\
	__einfo_uniqify ( EINFO_EIO, ( 6 - 0 ),				\
			  "Stall error" )
#define EIO_RESOURCE							\
	__einfo_error ( EINFO_EIO_RESOURCE )
#define EINFO_EIO_RESOURCE						\
	__einfo_uniqify ( EINFO_EIO, ( 7 - 0 ),				\
			  "Resource error" )
#define EIO_BANDWIDTH							\
	__einfo_error ( EINFO_EIO_BANDWIDTH )
#define EINFO_EIO_BANDWIDTH						\
	__einfo_uniqify ( EINFO_EIO, ( 8 - 0 ),				\
			  "Bandwidth error" )
#define EIO_NO_SLOTS							\
	__einfo_error ( EINFO_EIO_NO_SLOTS )
#define EINFO_EIO_NO_SLOTS						\
	__einfo_uniqify ( EINFO_EIO, ( 9 - 0 ),				\
			  "No slots available" )
#define EIO_STREAM_TYPE							\
	__einfo_error ( EINFO_EIO_STREAM_TYPE )
#define EINFO_EIO_STREAM_TYPE						\
	__einfo_uniqify ( EINFO_EIO, ( 10 - 0 ),			\
			  "Invalid stream type" )
#define EIO_SLOT							\
	__einfo_error ( EINFO_EIO_SLOT )
#define EINFO_EIO_SLOT							\
	__einfo_uniqify ( EINFO_EIO, ( 11 - 0 ),			\
			  "Slot not enabled" )
#define EIO_ENDPOINT							\
	__einfo_error ( EINFO_EIO_ENDPOINT )
#define EINFO_EIO_ENDPOINT						\
	__einfo_uniqify ( EINFO_EIO, ( 12 - 0 ),			\
			  "Endpoint not enabled" )
#define EIO_SHORT							\
	__einfo_error ( EINFO_EIO_SHORT )
#define EINFO_EIO_SHORT							\
	__einfo_uniqify ( EINFO_EIO, ( 13 - 0 ),			\
			  "Short packet" )
#define EIO_UNDERRUN							\
	__einfo_error ( EINFO_EIO_UNDERRUN )
#define EINFO_EIO_UNDERRUN						\
	__einfo_uniqify ( EINFO_EIO, ( 14 - 0 ),			\
			  "Ring underrun" )
#define EIO_OVERRUN							\
	__einfo_error ( EINFO_EIO_OVERRUN )
#define EINFO_EIO_OVERRUN						\
	__einfo_uniqify ( EINFO_EIO, ( 15 - 0 ),			\
			  "Ring overrun" )
#define EIO_VF_RING_FULL						\
	__einfo_error ( EINFO_EIO_VF_RING_FULL )
#define EINFO_EIO_VF_RING_FULL						\
	__einfo_uniqify ( EINFO_EIO, ( 16 - 0 ),			\
			  "Virtual function event ring full" )
#define EIO_PARAMETER							\
	__einfo_error ( EINFO_EIO_PARAMETER )
#define EINFO_EIO_PARAMETER						\
	__einfo_uniqify ( EINFO_EIO, ( 17 - 0 ),			\
			  "Parameter error" )
#define EIO_BANDWIDTH_OVERRUN						\
	__einfo_error ( EINFO_EIO_BANDWIDTH_OVERRUN )
#define EINFO_EIO_BANDWIDTH_OVERRUN					\
	__einfo_uniqify ( EINFO_EIO, ( 18 - 0 ),			\
			  "Bandwidth overrun" )
#define EIO_CONTEXT							\
	__einfo_error ( EINFO_EIO_CONTEXT )
#define EINFO_EIO_CONTEXT						\
	__einfo_uniqify ( EINFO_EIO, ( 19 - 0 ),			\
			  "Context state error" )
#define EIO_NO_PING							\
	__einfo_error ( EINFO_EIO_NO_PING )
#define EINFO_EIO_NO_PING						\
	__einfo_uniqify ( EINFO_EIO, ( 20 - 0 ),			\
			  "No ping response" )
#define EIO_RING_FULL							\
	__einfo_error ( EINFO_EIO_RING_FULL )
#define EINFO_EIO_RING_FULL						\
	__einfo_uniqify ( EINFO_EIO, ( 21 - 0 ),			\
			  "Event ring full" )
#define EIO_INCOMPATIBLE						\
	__einfo_error ( EINFO_EIO_INCOMPATIBLE )
#define EINFO_EIO_INCOMPATIBLE						\
	__einfo_uniqify ( EINFO_EIO, ( 22 - 0 ),			\
			  "Incompatible device" )
#define EIO_MISSED							\
	__einfo_error ( EINFO_EIO_MISSED )
#define EINFO_EIO_MISSED						\
	__einfo_uniqify ( EINFO_EIO, ( 23 - 0 ),			\
			  "Missed service error" )
#define EIO_CMD_STOPPED							\
	__einfo_error ( EINFO_EIO_CMD_STOPPED )
#define EINFO_EIO_CMD_STOPPED						\
	__einfo_uniqify ( EINFO_EIO, ( 24 - 0 ),			\
			  "Command ring stopped" )
#define EIO_CMD_ABORTED							\
	__einfo_error ( EINFO_EIO_CMD_ABORTED )
#define EINFO_EIO_CMD_ABORTED						\
	__einfo_uniqify ( EINFO_EIO, ( 25 - 0 ),			\
			  "Command aborted" )
#define EIO_STOP							\
	__einfo_error ( EINFO_EIO_STOP )
#define EINFO_EIO_STOP							\
	__einfo_uniqify ( EINFO_EIO, ( 26 - 0 ),			\
			  "Stopped" )
#define EIO_STOP_LEN							\
	__einfo_error ( EINFO_EIO_STOP_LEN )
#define EINFO_EIO_STOP_LEN						\
	__einfo_uniqify ( EINFO_EIO, ( 27 - 0 ),			\
			  "Stopped - length invalid" )
#define EIO_STOP_SHORT							\
	__einfo_error ( EINFO_EIO_STOP_SHORT )
#define EINFO_EIO_STOP_SHORT						\
	__einfo_uniqify ( EINFO_EIO, ( 28 - 0 ),			\
			  "Stopped - short packet" )
#define EIO_LATENCY							\
	__einfo_error ( EINFO_EIO_LATENCY )
#define EINFO_EIO_LATENCY						\
	__einfo_uniqify ( EINFO_EIO, ( 29 - 0 ),			\
			  "Maximum exit latency too large" )
#define EIO_ISOCH							\
	__einfo_error ( EINFO_EIO_ISOCH )
#define EINFO_EIO_ISOCH							\
	__einfo_uniqify ( EINFO_EIO, ( 31 - 0 ),			\
			  "Isochronous buffer overrun" )
#define EPROTO_LOST							\
	__einfo_error ( EINFO_EPROTO_LOST )
#define EINFO_EPROTO_LOST						\
	__einfo_uniqify ( EINFO_EPROTO, ( 32 - 32 ),			\
			  "Event lost" )
#define EPROTO_UNDEFINED						\
	__einfo_error ( EINFO_EPROTO_UNDEFINED )
#define EINFO_EPROTO_UNDEFINED						\
	__einfo_uniqify ( EINFO_EPROTO, ( 33 - 32 ),			\
			  "Undefined error" )
#define EPROTO_STREAM_ID						\
	__einfo_error ( EINFO_EPROTO_STREAM_ID )
#define EINFO_EPROTO_STREAM_ID						\
	__einfo_uniqify ( EINFO_EPROTO, ( 34 - 32 ),			\
			  "Invalid stream ID" )
#define EPROTO_SECONDARY						\
	__einfo_error ( EINFO_EPROTO_SECONDARY )
#define EINFO_EPROTO_SECONDARY						\
	__einfo_uniqify ( EINFO_EPROTO, ( 35 - 32 ),			\
			  "Secondary bandwidth error" )
#define EPROTO_SPLIT							\
	__einfo_error ( EINFO_EPROTO_SPLIT )
#define EINFO_EPROTO_SPLIT						\
	__einfo_uniqify ( EINFO_EPROTO, ( 36 - 32 ),			\
			  "Split transaction error" )
#define ECODE(code)							\
	( ( (code) < 32 ) ?						\
	  EUNIQ ( EINFO_EIO, ( (code) & 31 ), EIO_DATA, EIO_BABBLE,	\
		  EIO_USB, EIO_TRB, EIO_STALL, EIO_RESOURCE,		\
		  EIO_BANDWIDTH, EIO_NO_SLOTS, EIO_STREAM_TYPE,		\
		  EIO_SLOT, EIO_ENDPOINT, EIO_SHORT, EIO_UNDERRUN,	\
		  EIO_OVERRUN, EIO_VF_RING_FULL, EIO_PARAMETER,		\
		  EIO_BANDWIDTH_OVERRUN, EIO_CONTEXT, EIO_NO_PING,	\
		  EIO_RING_FULL, EIO_INCOMPATIBLE, EIO_MISSED,		\
		  EIO_CMD_STOPPED, EIO_CMD_ABORTED, EIO_STOP,		\
		  EIO_STOP_LEN, EIO_STOP_SHORT, EIO_LATENCY,		\
		  EIO_ISOCH ) :						\
	  ( (code) < 64 ) ?						\
	  EUNIQ ( EINFO_EPROTO, ( (code) & 31 ), EPROTO_LOST,		\
		  EPROTO_UNDEFINED, EPROTO_STREAM_ID,			\
		  EPROTO_SECONDARY, EPROTO_SPLIT ) :			\
	  EFAULT )

/******************************************************************************
 *
 * Register access
 *
 ******************************************************************************
 */

/**
 * Initialise device
 *
 * @v xhci		xHCI device
 * @v regs		MMIO registers
 */
static void xhci_init ( struct xhci_device *xhci, void *regs ) {
	uint32_t hcsparams1;
	uint32_t hcsparams2;
	uint32_t hccparams1;
	uint32_t pagesize;
	size_t caplength;
	size_t rtsoff;
	size_t dboff;

	/* Locate capability, operational, runtime, and doorbell registers */
	xhci->cap = regs;
	caplength = readb ( xhci->cap + XHCI_CAP_CAPLENGTH );
	rtsoff = readl ( xhci->cap + XHCI_CAP_RTSOFF );
	dboff = readl ( xhci->cap + XHCI_CAP_DBOFF );
	xhci->op = ( xhci->cap + caplength );
	xhci->run = ( xhci->cap + rtsoff );
	xhci->db = ( xhci->cap + dboff );
	DBGC2 ( xhci, "XHCI %s cap %08lx op %08lx run %08lx db %08lx\n",
		xhci->name, virt_to_phys ( xhci->cap ),
		virt_to_phys ( xhci->op ), virt_to_phys ( xhci->run ),
		virt_to_phys ( xhci->db ) );

	/* Read structural parameters 1 */
	hcsparams1 = readl ( xhci->cap + XHCI_CAP_HCSPARAMS1 );
	xhci->slots = XHCI_HCSPARAMS1_SLOTS ( hcsparams1 );
	xhci->intrs = XHCI_HCSPARAMS1_INTRS ( hcsparams1 );
	xhci->ports = XHCI_HCSPARAMS1_PORTS ( hcsparams1 );
	DBGC ( xhci, "XHCI %s has %d slots %d intrs %d ports\n",
	       xhci->name, xhci->slots, xhci->intrs, xhci->ports );

	/* Read structural parameters 2 */
	hcsparams2 = readl ( xhci->cap + XHCI_CAP_HCSPARAMS2 );
	xhci->scratchpads = XHCI_HCSPARAMS2_SCRATCHPADS ( hcsparams2 );
	DBGC2 ( xhci, "XHCI %s needs %d scratchpads\n",
		xhci->name, xhci->scratchpads );

	/* Read capability parameters 1 */
	hccparams1 = readl ( xhci->cap + XHCI_CAP_HCCPARAMS1 );
	xhci->addr64 = XHCI_HCCPARAMS1_ADDR64 ( hccparams1 );
	xhci->csz_shift = XHCI_HCCPARAMS1_CSZ_SHIFT ( hccparams1 );
	xhci->xecp = XHCI_HCCPARAMS1_XECP ( hccparams1 );

	/* Read page size */
	pagesize = readl ( xhci->op + XHCI_OP_PAGESIZE );
	xhci->pagesize = XHCI_PAGESIZE ( pagesize );
	assert ( xhci->pagesize != 0 );
	assert ( ( ( xhci->pagesize ) & ( xhci->pagesize - 1 ) ) == 0 );
	DBGC2 ( xhci, "XHCI %s page size %zd bytes\n",
		xhci->name, xhci->pagesize );
}

/**
 * Find extended capability
 *
 * @v xhci		xHCI device
 * @v id		Capability ID
 * @v offset		Offset to previous extended capability instance, or zero
 * @ret offset		Offset to extended capability, or zero if not found
 */
static unsigned int xhci_extended_capability ( struct xhci_device *xhci,
					       unsigned int id,
					       unsigned int offset ) {
	uint32_t xecp;
	unsigned int next;

	/* Locate the extended capability */
	while ( 1 ) {

		/* Locate first or next capability as applicable */
		if ( offset ) {
			xecp = readl ( xhci->cap + offset );
			next = XHCI_XECP_NEXT ( xecp );
		} else {
			next = xhci->xecp;
		}
		if ( ! next )
			return 0;
		offset += next;

		/* Check if this is the requested capability */
		xecp = readl ( xhci->cap + offset );
		if ( XHCI_XECP_ID ( xecp ) == id )
			return offset;
	}
}

/**
 * Write potentially 64-bit register
 *
 * @v xhci		xHCI device
 * @v value		Value
 * @v reg		Register address
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
xhci_writeq ( struct xhci_device *xhci, physaddr_t value, void *reg ) {

	/* If this is a 32-bit build, then this can never fail
	 * (allowing the compiler to optimise out the error path).
	 */
	if ( sizeof ( value ) <= sizeof ( uint32_t ) ) {
		writel ( value, reg );
		writel ( 0, ( reg + sizeof ( uint32_t ) ) );
		return 0;
	}

	/* If the device does not support 64-bit addresses and this
	 * address is outside the 32-bit address space, then fail.
	 */
	if ( ( value & ~0xffffffffULL ) && ! xhci->addr64 ) {
		DBGC ( xhci, "XHCI %s cannot access address %lx\n",
		       xhci->name, value );
		return -ENOTSUP;
	}

	/* If this is a 64-bit build, then writeq() is available */
	writeq ( value, reg );
	return 0;
}

/**
 * Calculate buffer alignment
 *
 * @v len		Length
 * @ret align		Buffer alignment
 *
 * Determine alignment required for a buffer which must be aligned to
 * at least XHCI_MIN_ALIGN and which must not cross a page boundary.
 */
static inline size_t xhci_align ( size_t len ) {
	size_t align;

	/* Align to own length (rounded up to a power of two) */
	align = ( 1 << fls ( len - 1 ) );

	/* Round up to XHCI_MIN_ALIGN if needed */
	if ( align < XHCI_MIN_ALIGN )
		align = XHCI_MIN_ALIGN;

	return align;
}

/**
 * Calculate device context offset
 *
 * @v xhci		xHCI device
 * @v ctx		Context index
 */
static inline size_t xhci_device_context_offset ( struct xhci_device *xhci,
						  unsigned int ctx ) {

	return ( XHCI_DCI ( ctx ) << xhci->csz_shift );
}

/**
 * Calculate input context offset
 *
 * @v xhci		xHCI device
 * @v ctx		Context index
 */
static inline size_t xhci_input_context_offset ( struct xhci_device *xhci,
						 unsigned int ctx ) {

	return ( XHCI_ICI ( ctx ) << xhci->csz_shift );
}

/******************************************************************************
 *
 * Diagnostics
 *
 ******************************************************************************
 */

/**
 * Dump host controller registers
 *
 * @v xhci		xHCI device
 */
static inline void xhci_dump ( struct xhci_device *xhci ) {
	uint32_t usbcmd;
	uint32_t usbsts;
	uint32_t pagesize;
	uint32_t dnctrl;
	uint32_t config;

	/* Do nothing unless debugging is enabled */
	if ( ! DBG_LOG )
		return;

	/* Dump USBCMD */
	usbcmd = readl ( xhci->op + XHCI_OP_USBCMD );
	DBGC ( xhci, "XHCI %s USBCMD %08x%s%s\n", xhci->name, usbcmd,
	       ( ( usbcmd & XHCI_USBCMD_RUN ) ? " run" : "" ),
	       ( ( usbcmd & XHCI_USBCMD_HCRST ) ? " hcrst" : "" ) );

	/* Dump USBSTS */
	usbsts = readl ( xhci->op + XHCI_OP_USBSTS );
	DBGC ( xhci, "XHCI %s USBSTS %08x%s\n", xhci->name, usbsts,
	       ( ( usbsts & XHCI_USBSTS_HCH ) ? " hch" : "" ) );

	/* Dump PAGESIZE */
	pagesize = readl ( xhci->op + XHCI_OP_PAGESIZE );
	DBGC ( xhci, "XHCI %s PAGESIZE %08x\n", xhci->name, pagesize );

	/* Dump DNCTRL */
	dnctrl = readl ( xhci->op + XHCI_OP_DNCTRL );
	DBGC ( xhci, "XHCI %s DNCTRL %08x\n", xhci->name, dnctrl );

	/* Dump CONFIG */
	config = readl ( xhci->op + XHCI_OP_CONFIG );
	DBGC ( xhci, "XHCI %s CONFIG %08x\n", xhci->name, config );
}

/**
 * Dump port registers
 *
 * @v xhci		xHCI device
 * @v port		Port number
 */
static inline void xhci_dump_port ( struct xhci_device *xhci,
				    unsigned int port ) {
	uint32_t portsc;
	uint32_t portpmsc;
	uint32_t portli;
	uint32_t porthlpmc;

	/* Do nothing unless debugging is enabled */
	if ( ! DBG_LOG )
		return;

	/* Dump PORTSC */
	portsc = readl ( xhci->op + XHCI_OP_PORTSC ( port ) );
	DBGC ( xhci, "XHCI %s-%d PORTSC %08x%s%s%s%s psiv=%d\n",
	       xhci->name, port, portsc,
	       ( ( portsc & XHCI_PORTSC_CCS ) ? " ccs" : "" ),
	       ( ( portsc & XHCI_PORTSC_PED ) ? " ped" : "" ),
	       ( ( portsc & XHCI_PORTSC_PR ) ? " pr" : "" ),
	       ( ( portsc & XHCI_PORTSC_PP ) ? " pp" : "" ),
	       XHCI_PORTSC_PSIV ( portsc ) );

	/* Dump PORTPMSC */
	portpmsc = readl ( xhci->op + XHCI_OP_PORTPMSC ( port ) );
	DBGC ( xhci, "XHCI %s-%d PORTPMSC %08x\n", xhci->name, port, portpmsc );

	/* Dump PORTLI */
	portli = readl ( xhci->op + XHCI_OP_PORTLI ( port ) );
	DBGC ( xhci, "XHCI %s-%d PORTLI %08x\n", xhci->name, port, portli );

	/* Dump PORTHLPMC */
	porthlpmc = readl ( xhci->op + XHCI_OP_PORTHLPMC ( port ) );
	DBGC ( xhci, "XHCI %s-%d PORTHLPMC %08x\n",
	       xhci->name, port, porthlpmc );
}

/******************************************************************************
 *
 * USB legacy support
 *
 ******************************************************************************
 */

/** Prevent the release of ownership back to BIOS */
static int xhci_legacy_prevent_release;

/**
 * Initialise USB legacy support
 *
 * @v xhci		xHCI device
 */
static void xhci_legacy_init ( struct xhci_device *xhci ) {
	unsigned int legacy;
	uint8_t bios;

	/* Locate USB legacy support capability (if present) */
	legacy = xhci_extended_capability ( xhci, XHCI_XECP_ID_LEGACY, 0 );
	if ( ! legacy ) {
		/* Not an error; capability may not be present */
		DBGC ( xhci, "XHCI %s has no USB legacy support capability\n",
		       xhci->name );
		return;
	}

	/* Check if legacy USB support is enabled */
	bios = readb ( xhci->cap + legacy + XHCI_USBLEGSUP_BIOS );
	if ( ! ( bios & XHCI_USBLEGSUP_BIOS_OWNED ) ) {
		/* Not an error; already owned by OS */
		DBGC ( xhci, "XHCI %s USB legacy support already disabled\n",
		       xhci->name );
		return;
	}

	/* Record presence of USB legacy support capability */
	xhci->legacy = legacy;
}

/**
 * Claim ownership from BIOS
 *
 * @v xhci		xHCI device
 */
static void xhci_legacy_claim ( struct xhci_device *xhci ) {
	uint32_t ctlsts;
	uint8_t bios;
	unsigned int i;

	/* Do nothing unless legacy support capability is present */
	if ( ! xhci->legacy )
		return;

	/* Claim ownership */
	writeb ( XHCI_USBLEGSUP_OS_OWNED,
		 xhci->cap + xhci->legacy + XHCI_USBLEGSUP_OS );

	/* Wait for BIOS to release ownership */
	for ( i = 0 ; i < XHCI_USBLEGSUP_MAX_WAIT_MS ; i++ ) {

		/* Check if BIOS has released ownership */
		bios = readb ( xhci->cap + xhci->legacy + XHCI_USBLEGSUP_BIOS );
		if ( ! ( bios & XHCI_USBLEGSUP_BIOS_OWNED ) ) {
			DBGC ( xhci, "XHCI %s claimed ownership from BIOS\n",
			       xhci->name );
			ctlsts = readl ( xhci->cap + xhci->legacy +
					 XHCI_USBLEGSUP_CTLSTS );
			if ( ctlsts ) {
				DBGC ( xhci, "XHCI %s warning: BIOS retained "
				       "SMIs: %08x\n", xhci->name, ctlsts );
			}
			return;
		}

		/* Delay */
		mdelay ( 1 );
	}

	/* BIOS did not release ownership.  Claim it forcibly by
	 * disabling all SMIs.
	 */
	DBGC ( xhci, "XHCI %s could not claim ownership from BIOS: forcibly "
	       "disabling SMIs\n", xhci->name );
	writel ( 0, xhci->cap + xhci->legacy + XHCI_USBLEGSUP_CTLSTS );
}

/**
 * Release ownership back to BIOS
 *
 * @v xhci		xHCI device
 */
static void xhci_legacy_release ( struct xhci_device *xhci ) {

	/* Do nothing unless legacy support capability is present */
	if ( ! xhci->legacy )
		return;

	/* Do nothing if releasing ownership is prevented */
	if ( xhci_legacy_prevent_release ) {
		DBGC ( xhci, "XHCI %s not releasing ownership to BIOS\n",
		       xhci->name );
		return;
	}

	/* Release ownership */
	writeb ( 0, xhci->cap + xhci->legacy + XHCI_USBLEGSUP_OS );
	DBGC ( xhci, "XHCI %s released ownership to BIOS\n", xhci->name );
}

/******************************************************************************
 *
 * Supported protocols
 *
 ******************************************************************************
 */

/**
 * Transcribe port speed (for debugging)
 *
 * @v psi		Protocol speed ID
 * @ret speed		Transcribed speed
 */
static inline const char * xhci_speed_name ( uint32_t psi ) {
	static const char *exponents[4] = { "", "k", "M", "G" };
	static char buf[ 10 /* "xxxxxXbps" + NUL */ ];
	unsigned int mantissa;
	unsigned int exponent;

	/* Extract mantissa and exponent */
	mantissa = XHCI_SUPPORTED_PSI_MANTISSA ( psi );
	exponent = XHCI_SUPPORTED_PSI_EXPONENT ( psi );

	/* Transcribe speed */
	snprintf ( buf, sizeof ( buf ), "%d%sbps",
		   mantissa, exponents[exponent] );
	return buf;
}

/**
 * Find supported protocol extended capability for a port
 *
 * @v xhci		xHCI device
 * @v port		Port number
 * @ret supported	Offset to extended capability, or zero if not found
 */
static unsigned int xhci_supported_protocol ( struct xhci_device *xhci,
					      unsigned int port ) {
	unsigned int supported = 0;
	unsigned int offset;
	unsigned int count;
	uint32_t ports;

	/* Iterate over all supported protocol structures */
	while ( ( supported = xhci_extended_capability ( xhci,
							 XHCI_XECP_ID_SUPPORTED,
							 supported ) ) ) {

		/* Determine port range */
		ports = readl ( xhci->cap + supported + XHCI_SUPPORTED_PORTS );
		offset = XHCI_SUPPORTED_PORTS_OFFSET ( ports );
		count = XHCI_SUPPORTED_PORTS_COUNT ( ports );

		/* Check if port lies within this range */
		if ( ( port - offset ) < count )
			return supported;
	}

	DBGC ( xhci, "XHCI %s-%d has no supported protocol\n",
	       xhci->name, port );
	return 0;
}

/**
 * Find port protocol
 *
 * @v xhci		xHCI device
 * @v port		Port number
 * @ret protocol	USB protocol, or zero if not found
 */
static unsigned int xhci_port_protocol ( struct xhci_device *xhci,
					 unsigned int port ) {
	unsigned int supported = xhci_supported_protocol ( xhci, port );
	union {
		uint32_t raw;
		char text[5];
	} name;
	unsigned int protocol;
	unsigned int type;
	unsigned int psic;
	unsigned int psiv;
	unsigned int i;
	uint32_t revision;
	uint32_t ports;
	uint32_t slot;
	uint32_t psi;

	/* Fail if there is no supported protocol */
	if ( ! supported )
		return 0;

	/* Determine protocol version */
	revision = readl ( xhci->cap + supported + XHCI_SUPPORTED_REVISION );
	protocol = XHCI_SUPPORTED_REVISION_VER ( revision );

	/* Describe port protocol */
	if ( DBG_EXTRA ) {
		name.raw = cpu_to_le32 ( readl ( xhci->cap + supported +
						 XHCI_SUPPORTED_NAME ) );
		name.text[4] = '\0';
		slot = readl ( xhci->cap + supported + XHCI_SUPPORTED_SLOT );
		type = XHCI_SUPPORTED_SLOT_TYPE ( slot );
		DBGC2 ( xhci, "XHCI %s-%d %sv%04x type %d",
			xhci->name, port, name.text, protocol, type );
		ports = readl ( xhci->cap + supported + XHCI_SUPPORTED_PORTS );
		psic = XHCI_SUPPORTED_PORTS_PSIC ( ports );
		if ( psic ) {
			DBGC2 ( xhci, " speeds" );
			for ( i = 0 ; i < psic ; i++ ) {
				psi = readl ( xhci->cap + supported +
					      XHCI_SUPPORTED_PSI ( i ) );
				psiv = XHCI_SUPPORTED_PSI_VALUE ( psi );
				DBGC2 ( xhci, " %d:%s", psiv,
					xhci_speed_name ( psi ) );
			}
		}
		if ( xhci->quirks & XHCI_BAD_PSIV )
			DBGC2 ( xhci, " (ignored)" );
		DBGC2 ( xhci, "\n" );
	}

	return protocol;
}

/**
 * Find port slot type
 *
 * @v xhci		xHCI device
 * @v port		Port number
 * @ret type		Slot type, or negative error
 */
static int xhci_port_slot_type ( struct xhci_device *xhci, unsigned int port ) {
	unsigned int supported = xhci_supported_protocol ( xhci, port );
	unsigned int type;
	uint32_t slot;

	/* Fail if there is no supported protocol */
	if ( ! supported )
		return -ENOTSUP;

	/* Get slot type */
	slot = readl ( xhci->cap + supported + XHCI_SUPPORTED_SLOT );
	type = XHCI_SUPPORTED_SLOT_TYPE ( slot );

	return type;
}

/**
 * Find port speed
 *
 * @v xhci		xHCI device
 * @v port		Port number
 * @v psiv		Protocol speed ID value
 * @ret speed		Port speed, or negative error
 */
static int xhci_port_speed ( struct xhci_device *xhci, unsigned int port,
			     unsigned int psiv ) {
	unsigned int supported = xhci_supported_protocol ( xhci, port );
	unsigned int psic;
	unsigned int mantissa;
	unsigned int exponent;
	unsigned int speed;
	unsigned int i;
	uint32_t ports;
	uint32_t psi;

	/* Fail if there is no supported protocol */
	if ( ! supported )
		return -ENOTSUP;

	/* Get protocol speed ID count */
	ports = readl ( xhci->cap + supported + XHCI_SUPPORTED_PORTS );
	psic = XHCI_SUPPORTED_PORTS_PSIC ( ports );

	/* Use the default mappings if applicable */
	if ( ( psic == 0 ) || ( xhci->quirks & XHCI_BAD_PSIV ) ) {
		switch ( psiv ) {
		case XHCI_SPEED_LOW :	return USB_SPEED_LOW;
		case XHCI_SPEED_FULL :	return USB_SPEED_FULL;
		case XHCI_SPEED_HIGH :	return USB_SPEED_HIGH;
		case XHCI_SPEED_SUPER :	return USB_SPEED_SUPER;
		default:
			DBGC ( xhci, "XHCI %s-%d non-standard PSI value %d\n",
			       xhci->name, port, psiv );
			return -ENOTSUP;
		}
	}

	/* Iterate over PSI dwords looking for a match */
	for ( i = 0 ; i < psic ; i++ ) {
		psi = readl ( xhci->cap + supported + XHCI_SUPPORTED_PSI ( i ));
		if ( psiv == XHCI_SUPPORTED_PSI_VALUE ( psi ) ) {
			mantissa = XHCI_SUPPORTED_PSI_MANTISSA ( psi );
			exponent = XHCI_SUPPORTED_PSI_EXPONENT ( psi );
			speed = USB_SPEED ( mantissa, exponent );
			return speed;
		}
	}

	DBGC ( xhci, "XHCI %s-%d spurious PSI value %d\n",
	       xhci->name, port, psiv );
	return -ENOENT;
}

/**
 * Find protocol speed ID value
 *
 * @v xhci		xHCI device
 * @v port		Port number
 * @v speed		USB speed
 * @ret psiv		Protocol speed ID value, or negative error
 */
static int xhci_port_psiv ( struct xhci_device *xhci, unsigned int port,
			    unsigned int speed ) {
	unsigned int supported = xhci_supported_protocol ( xhci, port );
	unsigned int psic;
	unsigned int mantissa;
	unsigned int exponent;
	unsigned int psiv;
	unsigned int i;
	uint32_t ports;
	uint32_t psi;

	/* Fail if there is no supported protocol */
	if ( ! supported )
		return -ENOTSUP;

	/* Get protocol speed ID count */
	ports = readl ( xhci->cap + supported + XHCI_SUPPORTED_PORTS );
	psic = XHCI_SUPPORTED_PORTS_PSIC ( ports );

	/* Use the default mappings if applicable */
	if ( ( psic == 0 ) || ( xhci->quirks & XHCI_BAD_PSIV ) ) {
		switch ( speed ) {
		case USB_SPEED_LOW :	return XHCI_SPEED_LOW;
		case USB_SPEED_FULL :	return XHCI_SPEED_FULL;
		case USB_SPEED_HIGH :	return XHCI_SPEED_HIGH;
		case USB_SPEED_SUPER :	return XHCI_SPEED_SUPER;
		default:
			DBGC ( xhci, "XHCI %s-%d non-standard speed %d\n",
			       xhci->name, port, speed );
			return -ENOTSUP;
		}
	}

	/* Iterate over PSI dwords looking for a match */
	for ( i = 0 ; i < psic ; i++ ) {
		psi = readl ( xhci->cap + supported + XHCI_SUPPORTED_PSI ( i ));
		mantissa = XHCI_SUPPORTED_PSI_MANTISSA ( psi );
		exponent = XHCI_SUPPORTED_PSI_EXPONENT ( psi );
		if ( speed == USB_SPEED ( mantissa, exponent ) ) {
			psiv = XHCI_SUPPORTED_PSI_VALUE ( psi );
			return psiv;
		}
	}

	DBGC ( xhci, "XHCI %s-%d unrepresentable speed %#x\n",
	       xhci->name, port, speed );
	return -ENOENT;
}

/******************************************************************************
 *
 * Device context base address array
 *
 ******************************************************************************
 */

/**
 * Allocate device context base address array
 *
 * @v xhci		xHCI device
 * @ret rc		Return status code
 */
static int xhci_dcbaa_alloc ( struct xhci_device *xhci ) {
	size_t len;
	physaddr_t dcbaap;
	int rc;

	/* Allocate and initialise structure.  Must be at least
	 * 64-byte aligned and must not cross a page boundary, so
	 * align on its own size (rounded up to a power of two and
	 * with a minimum of 64 bytes).
	 */
	len = ( ( xhci->slots + 1 ) * sizeof ( xhci->dcbaa[0] ) );
	xhci->dcbaa = malloc_dma ( len, xhci_align ( len ) );
	if ( ! xhci->dcbaa ) {
		DBGC ( xhci, "XHCI %s could not allocate DCBAA\n", xhci->name );
		rc = -ENOMEM;
		goto err_alloc;
	}
	memset ( xhci->dcbaa, 0, len );

	/* Program DCBAA pointer */
	dcbaap = virt_to_phys ( xhci->dcbaa );
	if ( ( rc = xhci_writeq ( xhci, dcbaap,
				  xhci->op + XHCI_OP_DCBAAP ) ) != 0 )
		goto err_writeq;

	DBGC2 ( xhci, "XHCI %s DCBAA at [%08lx,%08lx)\n",
		xhci->name, dcbaap, ( dcbaap + len ) );
	return 0;

 err_writeq:
	free_dma ( xhci->dcbaa, len );
 err_alloc:
	return rc;
}

/**
 * Free device context base address array
 *
 * @v xhci		xHCI device
 */
static void xhci_dcbaa_free ( struct xhci_device *xhci ) {
	size_t len;
	unsigned int i;

	/* Sanity check */
	for ( i = 0 ; i <= xhci->slots ; i++ )
		assert ( xhci->dcbaa[i] == 0 );

	/* Clear DCBAA pointer */
	xhci_writeq ( xhci, 0, xhci->op + XHCI_OP_DCBAAP );

	/* Free DCBAA */
	len = ( ( xhci->slots + 1 ) * sizeof ( xhci->dcbaa[0] ) );
	free_dma ( xhci->dcbaa, len );
}

/******************************************************************************
 *
 * Scratchpad buffers
 *
 ******************************************************************************
 */

/**
 * Allocate scratchpad buffers
 *
 * @v xhci		xHCI device
 * @ret rc		Return status code
 */
static int xhci_scratchpad_alloc ( struct xhci_device *xhci ) {
	size_t array_len;
	size_t len;
	physaddr_t phys;
	unsigned int i;
	int rc;

	/* Do nothing if no scratchpad buffers are used */
	if ( ! xhci->scratchpads )
		return 0;

	/* Allocate scratchpads */
	len = ( xhci->scratchpads * xhci->pagesize );
	xhci->scratchpad = umalloc ( len );
	if ( ! xhci->scratchpad ) {
		DBGC ( xhci, "XHCI %s could not allocate scratchpad buffers\n",
		       xhci->name );
		rc = -ENOMEM;
		goto err_alloc;
	}
	memset_user ( xhci->scratchpad, 0, 0, len );

	/* Allocate scratchpad array */
	array_len = ( xhci->scratchpads * sizeof ( xhci->scratchpad_array[0] ));
	xhci->scratchpad_array =
		malloc_dma ( array_len, xhci_align ( array_len ) );
	if ( ! xhci->scratchpad_array ) {
		DBGC ( xhci, "XHCI %s could not allocate scratchpad buffer "
		       "array\n", xhci->name );
		rc = -ENOMEM;
		goto err_alloc_array;
	}

	/* Populate scratchpad array */
	for ( i = 0 ; i < xhci->scratchpads ; i++ ) {
		phys = user_to_phys ( xhci->scratchpad, ( i * xhci->pagesize ));
		xhci->scratchpad_array[i] = phys;
	}

	/* Set scratchpad array pointer */
	assert ( xhci->dcbaa != NULL );
	xhci->dcbaa[0] = cpu_to_le64 ( virt_to_phys ( xhci->scratchpad_array ));

	DBGC2 ( xhci, "XHCI %s scratchpad [%08lx,%08lx) array [%08lx,%08lx)\n",
		xhci->name, user_to_phys ( xhci->scratchpad, 0 ),
		user_to_phys ( xhci->scratchpad, len ),
		virt_to_phys ( xhci->scratchpad_array ),
		( virt_to_phys ( xhci->scratchpad_array ) + array_len ) );
	return 0;

	free_dma ( xhci->scratchpad_array, array_len );
 err_alloc_array:
	ufree ( xhci->scratchpad );
 err_alloc:
	return rc;
}

/**
 * Free scratchpad buffers
 *
 * @v xhci		xHCI device
 */
static void xhci_scratchpad_free ( struct xhci_device *xhci ) {
	size_t array_len;

	/* Do nothing if no scratchpad buffers are used */
	if ( ! xhci->scratchpads )
		return;

	/* Clear scratchpad array pointer */
	assert ( xhci->dcbaa != NULL );
	xhci->dcbaa[0] = 0;

	/* Free scratchpad array */
	array_len = ( xhci->scratchpads * sizeof ( xhci->scratchpad_array[0] ));
	free_dma ( xhci->scratchpad_array, array_len );

	/* Free scratchpads */
	ufree ( xhci->scratchpad );
}

/******************************************************************************
 *
 * Run / stop / reset
 *
 ******************************************************************************
 */

/**
 * Start xHCI device
 *
 * @v xhci		xHCI device
 */
static void xhci_run ( struct xhci_device *xhci ) {
	uint32_t config;
	uint32_t usbcmd;

	/* Configure number of device slots */
	config = readl ( xhci->op + XHCI_OP_CONFIG );
	config &= ~XHCI_CONFIG_MAX_SLOTS_EN_MASK;
	config |= XHCI_CONFIG_MAX_SLOTS_EN ( xhci->slots );
	writel ( config, xhci->op + XHCI_OP_CONFIG );

	/* Set run/stop bit */
	usbcmd = readl ( xhci->op + XHCI_OP_USBCMD );
	usbcmd |= XHCI_USBCMD_RUN;
	writel ( usbcmd, xhci->op + XHCI_OP_USBCMD );
}

/**
 * Stop xHCI device
 *
 * @v xhci		xHCI device
 * @ret rc		Return status code
 */
static int xhci_stop ( struct xhci_device *xhci ) {
	uint32_t usbcmd;
	uint32_t usbsts;
	unsigned int i;

	/* Clear run/stop bit */
	usbcmd = readl ( xhci->op + XHCI_OP_USBCMD );
	usbcmd &= ~XHCI_USBCMD_RUN;
	writel ( usbcmd, xhci->op + XHCI_OP_USBCMD );

	/* Wait for device to stop */
	for ( i = 0 ; i < XHCI_STOP_MAX_WAIT_MS ; i++ ) {

		/* Check if device is stopped */
		usbsts = readl ( xhci->op + XHCI_OP_USBSTS );
		if ( usbsts & XHCI_USBSTS_HCH )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( xhci, "XHCI %s timed out waiting for stop\n", xhci->name );
	return -ETIMEDOUT;
}

/**
 * Reset xHCI device
 *
 * @v xhci		xHCI device
 * @ret rc		Return status code
 */
static int xhci_reset ( struct xhci_device *xhci ) {
	uint32_t usbcmd;
	unsigned int i;
	int rc;

	/* The xHCI specification states that resetting a running
	 * device may result in undefined behaviour, so try stopping
	 * it first.
	 */
	if ( ( rc = xhci_stop ( xhci ) ) != 0 ) {
		/* Ignore errors and attempt to reset the device anyway */
	}

	/* Reset device */
	writel ( XHCI_USBCMD_HCRST, xhci->op + XHCI_OP_USBCMD );

	/* Wait for reset to complete */
	for ( i = 0 ; i < XHCI_RESET_MAX_WAIT_MS ; i++ ) {

		/* Check if reset is complete */
		usbcmd = readl ( xhci->op + XHCI_OP_USBCMD );
		if ( ! ( usbcmd & XHCI_USBCMD_HCRST ) )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( xhci, "XHCI %s timed out waiting for reset\n", xhci->name );
	return -ETIMEDOUT;
}

/******************************************************************************
 *
 * Transfer request blocks
 *
 ******************************************************************************
 */

/**
 * Allocate transfer request block ring
 *
 * @v xhci		xHCI device
 * @v ring		TRB ring
 * @v shift		Ring size (log2)
 * @v slot		Device slot
 * @v target		Doorbell target
 * @v stream		Doorbell stream ID
 * @ret rc		Return status code
 */
static int xhci_ring_alloc ( struct xhci_device *xhci,
			     struct xhci_trb_ring *ring,
			     unsigned int shift, unsigned int slot,
			     unsigned int target, unsigned int stream ) {
	struct xhci_trb_link *link;
	unsigned int count;
	int rc;

	/* Sanity check */
	assert ( shift > 0 );

	/* Initialise structure */
	memset ( ring, 0, sizeof ( *ring ) );
	ring->shift = shift;
	count = ( 1U << shift );
	ring->mask = ( count - 1 );
	ring->len = ( ( count + 1 /* Link TRB */ ) * sizeof ( ring->trb[0] ) );
	ring->db = ( xhci->db + ( slot * sizeof ( ring->dbval ) ) );
	ring->dbval = XHCI_DBVAL ( target, stream );

	/* Allocate I/O buffers */
	ring->iobuf = zalloc ( count * sizeof ( ring->iobuf[0] ) );
	if ( ! ring->iobuf ) {
		rc = -ENOMEM;
		goto err_alloc_iobuf;
	}

	/* Allocate TRBs */
	ring->trb = malloc_dma ( ring->len, xhci_align ( ring->len ) );
	if ( ! ring->trb ) {
		rc = -ENOMEM;
		goto err_alloc_trb;
	}
	memset ( ring->trb, 0, ring->len );

	/* Initialise Link TRB */
	link = &ring->trb[count].link;
	link->next = cpu_to_le64 ( virt_to_phys ( ring->trb ) );
	link->flags = XHCI_TRB_TC;
	link->type = XHCI_TRB_LINK;
	ring->link = link;

	return 0;

	free_dma ( ring->trb, ring->len );
 err_alloc_trb:
	free ( ring->iobuf );
 err_alloc_iobuf:
	return rc;
}

/**
 * Reset transfer request block ring
 *
 * @v ring		TRB ring
 */
static void xhci_ring_reset ( struct xhci_trb_ring *ring ) {
	unsigned int count = ( 1U << ring->shift );

	/* Reset producer and consumer counters */
	ring->prod = 0;
	ring->cons = 0;

	/* Reset TRBs (except Link TRB) */
	memset ( ring->trb, 0, ( count * sizeof ( ring->trb[0] ) ) );
}

/**
 * Free transfer request block ring
 *
 * @v ring		TRB ring
 */
static void xhci_ring_free ( struct xhci_trb_ring *ring ) {
	unsigned int count = ( 1U << ring->shift );
	unsigned int i;

	/* Sanity checks */
	assert ( ring->cons == ring->prod );
	for ( i = 0 ; i < count ; i++ )
		assert ( ring->iobuf[i] == NULL );

	/* Free TRBs */
	free_dma ( ring->trb, ring->len );

	/* Free I/O buffers */
	free ( ring->iobuf );
}

/**
 * Enqueue a transfer request block
 *
 * @v ring		TRB ring
 * @v iobuf		I/O buffer (if any)
 * @v trb		Transfer request block (with empty Cycle flag)
 * @ret rc		Return status code
 *
 * This operation does not implicitly ring the doorbell register.
 */
static int xhci_enqueue ( struct xhci_trb_ring *ring, struct io_buffer *iobuf,
			  const union xhci_trb *trb ) {
	union xhci_trb *dest;
	unsigned int prod;
	unsigned int mask;
	unsigned int index;
	unsigned int cycle;

	/* Sanity check */
	assert ( ! ( trb->common.flags & XHCI_TRB_C ) );

	/* Fail if ring is full */
	if ( ! xhci_ring_remaining ( ring ) )
		return -ENOBUFS;

	/* Update producer counter (and link TRB, if applicable) */
	prod = ring->prod++;
	mask = ring->mask;
	cycle = ( ( ~( prod >> ring->shift ) ) & XHCI_TRB_C );
	index = ( prod & mask );
	if ( index == 0 )
		ring->link->flags = ( XHCI_TRB_TC | ( cycle ^ XHCI_TRB_C ) );

	/* Record I/O buffer */
	ring->iobuf[index] = iobuf;

	/* Enqueue TRB */
	dest = &ring->trb[index];
	dest->template.parameter = trb->template.parameter;
	dest->template.status = trb->template.status;
	wmb();
	dest->template.control = ( trb->template.control |
				   cpu_to_le32 ( cycle ) );

	return 0;
}

/**
 * Dequeue a transfer request block
 *
 * @v ring		TRB ring
 * @ret iobuf		I/O buffer
 */
static struct io_buffer * xhci_dequeue ( struct xhci_trb_ring *ring ) {
	struct io_buffer *iobuf;
	unsigned int cons;
	unsigned int mask;
	unsigned int index;

	/* Sanity check */
	assert ( xhci_ring_fill ( ring ) != 0 );

	/* Update consumer counter */
	cons = ring->cons++;
	mask = ring->mask;
	index = ( cons & mask );

	/* Retrieve I/O buffer */
	iobuf = ring->iobuf[index];
	ring->iobuf[index] = NULL;

	return iobuf;
}

/**
 * Enqueue multiple transfer request blocks
 *
 * @v ring		TRB ring
 * @v iobuf		I/O buffer
 * @v trbs		Transfer request blocks (with empty Cycle flag)
 * @v count		Number of transfer request blocks
 * @ret rc		Return status code
 *
 * This operation does not implicitly ring the doorbell register.
 */
static int xhci_enqueue_multi ( struct xhci_trb_ring *ring,
				struct io_buffer *iobuf,
				const union xhci_trb *trbs,
				unsigned int count ) {
	const union xhci_trb *trb = trbs;
	int rc;

	/* Sanity check */
	assert ( iobuf != NULL );

	/* Fail if ring does not have sufficient space */
	if ( xhci_ring_remaining ( ring ) < count )
		return -ENOBUFS;

	/* Enqueue each TRB, recording the I/O buffer with the final TRB */
	while ( count-- ) {
		rc = xhci_enqueue ( ring, ( count ? NULL : iobuf ), trb++ );
		assert ( rc == 0 ); /* Should never be able to fail */
	}

	return 0;
}

/**
 * Dequeue multiple transfer request blocks
 *
 * @v ring		TRB ring
 * @ret iobuf		I/O buffer
 */
static struct io_buffer * xhci_dequeue_multi ( struct xhci_trb_ring *ring ) {
	struct io_buffer *iobuf;

	/* Dequeue TRBs until we reach the final TRB for an I/O buffer */
	do {
		iobuf = xhci_dequeue ( ring );
	} while ( iobuf == NULL );

	return iobuf;
}

/**
 * Ring doorbell register
 *
 * @v ring		TRB ring
 */
static inline __attribute__ (( always_inline )) void
xhci_doorbell ( struct xhci_trb_ring *ring ) {

	wmb();
	writel ( ring->dbval, ring->db );
}

/******************************************************************************
 *
 * Command and event rings
 *
 ******************************************************************************
 */

/**
 * Allocate command ring
 *
 * @v xhci		xHCI device
 * @ret rc		Return status code
 */
static int xhci_command_alloc ( struct xhci_device *xhci ) {
	physaddr_t crp;
	int rc;

	/* Allocate TRB ring */
	if ( ( rc = xhci_ring_alloc ( xhci, &xhci->command, XHCI_CMD_TRBS_LOG2,
				      0, 0, 0 ) ) != 0 )
		goto err_ring_alloc;

	/* Program command ring control register */
	crp = virt_to_phys ( xhci->command.trb );
	if ( ( rc = xhci_writeq ( xhci, ( crp | XHCI_CRCR_RCS ),
				  xhci->op + XHCI_OP_CRCR ) ) != 0 )
		goto err_writeq;

	DBGC2 ( xhci, "XHCI %s CRCR at [%08lx,%08lx)\n",
		xhci->name, crp, ( crp + xhci->command.len ) );
	return 0;

 err_writeq:
	xhci_ring_free ( &xhci->command );
 err_ring_alloc:
	return rc;
}

/**
 * Free command ring
 *
 * @v xhci		xHCI device
 */
static void xhci_command_free ( struct xhci_device *xhci ) {

	/* Sanity check */
	assert ( ( readl ( xhci->op + XHCI_OP_CRCR ) & XHCI_CRCR_CRR ) == 0 );

	/* Clear command ring control register */
	xhci_writeq ( xhci, 0, xhci->op + XHCI_OP_CRCR );

	/* Free TRB ring */
	xhci_ring_free ( &xhci->command );
}

/**
 * Allocate event ring
 *
 * @v xhci		xHCI device
 * @ret rc		Return status code
 */
static int xhci_event_alloc ( struct xhci_device *xhci ) {
	struct xhci_event_ring *event = &xhci->event;
	unsigned int count;
	size_t len;
	int rc;

	/* Allocate event ring */
	count = ( 1 << XHCI_EVENT_TRBS_LOG2 );
	len = ( count * sizeof ( event->trb[0] ) );
	event->trb = malloc_dma ( len, xhci_align ( len ) );
	if ( ! event->trb ) {
		rc = -ENOMEM;
		goto err_alloc_trb;
	}
	memset ( event->trb, 0, len );

	/* Allocate event ring segment table */
	event->segment = malloc_dma ( sizeof ( event->segment[0] ),
				      xhci_align ( sizeof (event->segment[0])));
	if ( ! event->segment ) {
		rc = -ENOMEM;
		goto err_alloc_segment;
	}
	memset ( event->segment, 0, sizeof ( event->segment[0] ) );
	event->segment[0].base = cpu_to_le64 ( virt_to_phys ( event->trb ) );
	event->segment[0].count = cpu_to_le32 ( count );

	/* Program event ring registers */
	writel ( 1, xhci->run + XHCI_RUN_ERSTSZ ( 0 ) );
	if ( ( rc = xhci_writeq ( xhci, virt_to_phys ( event->trb ),
				  xhci->run + XHCI_RUN_ERDP ( 0 ) ) ) != 0 )
		goto err_writeq_erdp;
	if ( ( rc = xhci_writeq ( xhci, virt_to_phys ( event->segment ),
				  xhci->run + XHCI_RUN_ERSTBA ( 0 ) ) ) != 0 )
		goto err_writeq_erstba;

	DBGC2 ( xhci, "XHCI %s event ring [%08lx,%08lx) table [%08lx,%08lx)\n",
		xhci->name, virt_to_phys ( event->trb ),
		( virt_to_phys ( event->trb ) + len ),
		virt_to_phys ( event->segment ),
		( virt_to_phys ( event->segment ) +
		  sizeof (event->segment[0] ) ) );
	return 0;

	xhci_writeq ( xhci, 0, xhci->run + XHCI_RUN_ERSTBA ( 0 ) );
 err_writeq_erstba:
	xhci_writeq ( xhci, 0, xhci->run + XHCI_RUN_ERDP ( 0 ) );
 err_writeq_erdp:
	free_dma ( event->trb, len );
 err_alloc_segment:
	free_dma ( event->segment, sizeof ( event->segment[0] ) );
 err_alloc_trb:
	return rc;
}

/**
 * Free event ring
 *
 * @v xhci		xHCI device
 */
static void xhci_event_free ( struct xhci_device *xhci ) {
	struct xhci_event_ring *event = &xhci->event;
	unsigned int count;
	size_t len;

	/* Clear event ring registers */
	writel ( 0, xhci->run + XHCI_RUN_ERSTSZ ( 0 ) );
	xhci_writeq ( xhci, 0, xhci->run + XHCI_RUN_ERSTBA ( 0 ) );
	xhci_writeq ( xhci, 0, xhci->run + XHCI_RUN_ERDP ( 0 ) );

	/* Free event ring segment table */
	free_dma ( event->segment, sizeof ( event->segment[0] ) );

	/* Free event ring */
	count = ( 1 << XHCI_EVENT_TRBS_LOG2 );
	len = ( count * sizeof ( event->trb[0] ) );
	free_dma ( event->trb, len );
}

/**
 * Handle transfer event
 *
 * @v xhci		xHCI device
 * @v trb		Transfer event TRB
 */
static void xhci_transfer ( struct xhci_device *xhci,
			    struct xhci_trb_transfer *trb ) {
	struct xhci_slot *slot;
	struct xhci_endpoint *endpoint;
	struct io_buffer *iobuf;
	int rc;

	/* Profile transfer events */
	profile_start ( &xhci_transfer_profiler );

	/* Identify slot */
	if ( ( trb->slot > xhci->slots ) ||
	     ( ( slot = xhci->slot[trb->slot] ) == NULL ) ) {
		DBGC ( xhci, "XHCI %s transfer event invalid slot %d:\n",
		       xhci->name, trb->slot );
		DBGC_HDA ( xhci, 0, trb, sizeof ( *trb ) );
		return;
	}

	/* Identify endpoint */
	if ( ( trb->endpoint > XHCI_CTX_END ) ||
	     ( ( endpoint = slot->endpoint[trb->endpoint] ) == NULL ) ) {
		DBGC ( xhci, "XHCI %s slot %d transfer event invalid epid "
		       "%d:\n", xhci->name, slot->id, trb->endpoint );
		DBGC_HDA ( xhci, 0, trb, sizeof ( *trb ) );
		return;
	}

	/* Dequeue TRB(s) */
	iobuf = xhci_dequeue_multi ( &endpoint->ring );
	assert ( iobuf != NULL );

	/* Check for errors */
	if ( ! ( ( trb->code == XHCI_CMPLT_SUCCESS ) ||
		 ( trb->code == XHCI_CMPLT_SHORT ) ) ) {

		/* Construct error */
		rc = -ECODE ( trb->code );
		DBGC ( xhci, "XHCI %s slot %d ctx %d failed (code %d): %s\n",
		       xhci->name, slot->id, endpoint->ctx, trb->code,
		       strerror ( rc ) );
		DBGC_HDA ( xhci, 0, trb, sizeof ( *trb ) );

		/* Sanity check */
		assert ( ( endpoint->context->state & XHCI_ENDPOINT_STATE_MASK )
			 != XHCI_ENDPOINT_RUNNING );

		/* Report failure to USB core */
		usb_complete_err ( endpoint->ep, iobuf, rc );
		return;
	}

	/* Record actual transfer size */
	iob_unput ( iobuf, le16_to_cpu ( trb->residual ) );

	/* Sanity check (for successful completions only) */
	assert ( xhci_ring_consumed ( &endpoint->ring ) ==
		 le64_to_cpu ( trb->transfer ) );

	/* Report completion to USB core */
	usb_complete ( endpoint->ep, iobuf );
	profile_stop ( &xhci_transfer_profiler );
}

/**
 * Handle command completion event
 *
 * @v xhci		xHCI device
 * @v trb		Command completion event
 */
static void xhci_complete ( struct xhci_device *xhci,
			    struct xhci_trb_complete *trb ) {
	int rc;

	/* Ignore "command ring stopped" notifications */
	if ( trb->code == XHCI_CMPLT_CMD_STOPPED ) {
		DBGC2 ( xhci, "XHCI %s command ring stopped\n", xhci->name );
		return;
	}

	/* Ignore unexpected completions */
	if ( ! xhci->pending ) {
		rc = -ECODE ( trb->code );
		DBGC ( xhci, "XHCI %s unexpected completion (code %d): %s\n",
		       xhci->name, trb->code, strerror ( rc ) );
		DBGC_HDA ( xhci, 0, trb, sizeof ( *trb ) );
		return;
	}

	/* Dequeue command TRB */
	xhci_dequeue ( &xhci->command );

	/* Sanity check */
	assert ( xhci_ring_consumed ( &xhci->command ) ==
		 le64_to_cpu ( trb->command ) );

	/* Record completion */
	memcpy ( xhci->pending, trb, sizeof ( *xhci->pending ) );
	xhci->pending = NULL;
}

/**
 * Handle port status event
 *
 * @v xhci		xHCI device
 * @v trb		Port status event
 */
static void xhci_port_status ( struct xhci_device *xhci,
			       struct xhci_trb_port_status *trb ) {
	struct usb_port *port = usb_port ( xhci->bus->hub, trb->port );
	uint32_t portsc;

	/* Sanity check */
	assert ( ( trb->port > 0 ) && ( trb->port <= xhci->ports ) );

	/* Record disconnections and clear changes */
	portsc = readl ( xhci->op + XHCI_OP_PORTSC ( trb->port ) );
	port->disconnected |= ( portsc & XHCI_PORTSC_CSC );
	portsc &= ( XHCI_PORTSC_PRESERVE | XHCI_PORTSC_CHANGE );
	writel ( portsc, xhci->op + XHCI_OP_PORTSC ( trb->port ) );

	/* Report port status change */
	usb_port_changed ( port );
}

/**
 * Handle host controller event
 *
 * @v xhci		xHCI device
 * @v trb		Host controller event
 */
static void xhci_host_controller ( struct xhci_device *xhci,
				   struct xhci_trb_host_controller *trb ) {
	int rc;

	/* Construct error */
	rc = -ECODE ( trb->code );
	DBGC ( xhci, "XHCI %s host controller event (code %d): %s\n",
	       xhci->name, trb->code, strerror ( rc ) );
}

/**
 * Poll event ring
 *
 * @v xhci		xHCI device
 */
static void xhci_event_poll ( struct xhci_device *xhci ) {
	struct xhci_event_ring *event = &xhci->event;
	union xhci_trb *trb;
	unsigned int shift = XHCI_EVENT_TRBS_LOG2;
	unsigned int count = ( 1 << shift );
	unsigned int mask = ( count - 1 );
	unsigned int consumed;
	unsigned int type;

	/* Poll for events */
	profile_start ( &xhci_event_profiler );
	for ( consumed = 0 ; ; consumed++ ) {

		/* Stop if we reach an empty TRB */
		rmb();
		trb = &event->trb[ event->cons & mask ];
		if ( ! ( ( trb->common.flags ^
			   ( event->cons >> shift ) ) & XHCI_TRB_C ) )
			break;

		/* Handle TRB */
		type = ( trb->common.type & XHCI_TRB_TYPE_MASK );
		switch ( type ) {

		case XHCI_TRB_TRANSFER :
			xhci_transfer ( xhci, &trb->transfer );
			break;

		case XHCI_TRB_COMPLETE :
			xhci_complete ( xhci, &trb->complete );
			break;

		case XHCI_TRB_PORT_STATUS:
			xhci_port_status ( xhci, &trb->port );
			break;

		case XHCI_TRB_HOST_CONTROLLER:
			xhci_host_controller ( xhci, &trb->host );
			break;

		default:
			DBGC ( xhci, "XHCI %s unrecognised event %#x\n:",
			       xhci->name, event->cons );
			DBGC_HDA ( xhci, virt_to_phys ( trb ),
				   trb, sizeof ( *trb ) );
			break;
		}

		/* Consume this TRB */
		event->cons++;
	}

	/* Update dequeue pointer if applicable */
	if ( consumed ) {
		xhci_writeq ( xhci, virt_to_phys ( trb ),
			      xhci->run + XHCI_RUN_ERDP ( 0 ) );
		profile_stop ( &xhci_event_profiler );
	}
}

/**
 * Abort command
 *
 * @v xhci		xHCI device
 */
static void xhci_abort ( struct xhci_device *xhci ) {
	physaddr_t crp;

	/* Abort the command */
	DBGC2 ( xhci, "XHCI %s aborting command\n", xhci->name );
	xhci_writeq ( xhci, XHCI_CRCR_CA, xhci->op + XHCI_OP_CRCR );

	/* Allow time for command to abort */
	mdelay ( XHCI_COMMAND_ABORT_DELAY_MS );

	/* Sanity check */
	assert ( ( readl ( xhci->op + XHCI_OP_CRCR ) & XHCI_CRCR_CRR ) == 0 );

	/* Consume (and ignore) any final command status */
	xhci_event_poll ( xhci );

	/* Reset the command ring control register */
	xhci_ring_reset ( &xhci->command );
	crp = virt_to_phys ( xhci->command.trb );
	xhci_writeq ( xhci, ( crp | XHCI_CRCR_RCS ), xhci->op + XHCI_OP_CRCR );
}

/**
 * Issue command and wait for completion
 *
 * @v xhci		xHCI device
 * @v trb		Transfer request block (with empty Cycle flag)
 * @ret rc		Return status code
 *
 * On a successful completion, the TRB will be overwritten with the
 * completion.
 */
static int xhci_command ( struct xhci_device *xhci, union xhci_trb *trb ) {
	struct xhci_trb_complete *complete = &trb->complete;
	unsigned int i;
	int rc;

	/* Record the pending command */
	xhci->pending = trb;

	/* Enqueue the command */
	if ( ( rc = xhci_enqueue ( &xhci->command, NULL, trb ) ) != 0 )
		goto err_enqueue;

	/* Ring the command doorbell */
	xhci_doorbell ( &xhci->command );

	/* Wait for the command to complete */
	for ( i = 0 ; i < XHCI_COMMAND_MAX_WAIT_MS ; i++ ) {

		/* Poll event ring */
		xhci_event_poll ( xhci );

		/* Check for completion */
		if ( ! xhci->pending ) {
			if ( complete->code != XHCI_CMPLT_SUCCESS ) {
				rc = -ECODE ( complete->code );
				DBGC ( xhci, "XHCI %s command failed (code "
				       "%d): %s\n", xhci->name, complete->code,
				       strerror ( rc ) );
				DBGC_HDA ( xhci, 0, trb, sizeof ( *trb ) );
				return rc;
			}
			return 0;
		}

		/* Delay */
		mdelay ( 1 );
	}

	/* Timeout */
	DBGC ( xhci, "XHCI %s timed out waiting for completion\n", xhci->name );
	rc = -ETIMEDOUT;

	/* Abort command */
	xhci_abort ( xhci );

 err_enqueue:
	xhci->pending = NULL;
	return rc;
}

/**
 * Issue NOP and wait for completion
 *
 * @v xhci		xHCI device
 * @ret rc		Return status code
 */
static inline int xhci_nop ( struct xhci_device *xhci ) {
	union xhci_trb trb;
	struct xhci_trb_common *nop = &trb.common;
	int rc;

	/* Construct command */
	memset ( nop, 0, sizeof ( *nop ) );
	nop->flags = XHCI_TRB_IOC;
	nop->type = XHCI_TRB_NOP_CMD;

	/* Issue command and wait for completion */
	if ( ( rc = xhci_command ( xhci, &trb ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Enable slot
 *
 * @v xhci		xHCI device
 * @v type		Slot type
 * @ret slot		Device slot ID, or negative error
 */
static inline int xhci_enable_slot ( struct xhci_device *xhci,
				     unsigned int type ) {
	union xhci_trb trb;
	struct xhci_trb_enable_slot *enable = &trb.enable;
	struct xhci_trb_complete *enabled = &trb.complete;
	unsigned int slot;
	int rc;

	/* Construct command */
	memset ( enable, 0, sizeof ( *enable ) );
	enable->slot = type;
	enable->type = XHCI_TRB_ENABLE_SLOT;

	/* Issue command and wait for completion */
	if ( ( rc = xhci_command ( xhci, &trb ) ) != 0 ) {
		DBGC ( xhci, "XHCI %s could not enable new slot: %s\n",
		       xhci->name, strerror ( rc ) );
		return rc;
	}

	/* Extract slot number */
	slot = enabled->slot;

	DBGC2 ( xhci, "XHCI %s slot %d enabled\n", xhci->name, slot );
	return slot;
}

/**
 * Disable slot
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @ret rc		Return status code
 */
static inline int xhci_disable_slot ( struct xhci_device *xhci,
				      unsigned int slot ) {
	union xhci_trb trb;
	struct xhci_trb_disable_slot *disable = &trb.disable;
	int rc;

	/* Construct command */
	memset ( disable, 0, sizeof ( *disable ) );
	disable->type = XHCI_TRB_DISABLE_SLOT;
	disable->slot = slot;

	/* Issue command and wait for completion */
	if ( ( rc = xhci_command ( xhci, &trb ) ) != 0 ) {
		DBGC ( xhci, "XHCI %s could not disable slot %d: %s\n",
		       xhci->name, slot, strerror ( rc ) );
		return rc;
	}

	DBGC2 ( xhci, "XHCI %s slot %d disabled\n", xhci->name, slot );
	return 0;
}

/**
 * Issue context-based command and wait for completion
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @v type		TRB type
 * @v populate		Input context populater
 * @ret rc		Return status code
 */
static int xhci_context ( struct xhci_device *xhci, struct xhci_slot *slot,
			  struct xhci_endpoint *endpoint, unsigned int type,
			  void ( * populate ) ( struct xhci_device *xhci,
						struct xhci_slot *slot,
						struct xhci_endpoint *endpoint,
						void *input ) ) {
	union xhci_trb trb;
	struct xhci_trb_context *context = &trb.context;
	size_t len;
	void *input;
	int rc;

	/* Allocate an input context */
	len = xhci_input_context_offset ( xhci, XHCI_CTX_END );
	input = malloc_dma ( len, xhci_align ( len ) );
	if ( ! input ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	memset ( input, 0, len );

	/* Populate input context */
	populate ( xhci, slot, endpoint, input );

	/* Construct command */
	memset ( context, 0, sizeof ( *context ) );
	context->type = type;
	context->input = cpu_to_le64 ( virt_to_phys ( input ) );
	context->slot = slot->id;

	/* Issue command and wait for completion */
	if ( ( rc = xhci_command ( xhci, &trb ) ) != 0 )
		goto err_command;

 err_command:
	free_dma ( input, len );
 err_alloc:
	return rc;
}

/**
 * Populate address device input context
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @v input		Input context
 */
static void xhci_address_device_input ( struct xhci_device *xhci,
					struct xhci_slot *slot,
					struct xhci_endpoint *endpoint,
					void *input ) {
	struct xhci_control_context *control_ctx;
	struct xhci_slot_context *slot_ctx;
	struct xhci_endpoint_context *ep_ctx;

	/* Sanity checks */
	assert ( endpoint->ctx == XHCI_CTX_EP0 );

	/* Populate control context */
	control_ctx = input;
	control_ctx->add = cpu_to_le32 ( ( 1 << XHCI_CTX_SLOT ) |
					 ( 1 << XHCI_CTX_EP0 ) );

	/* Populate slot context */
	slot_ctx = ( input + xhci_input_context_offset ( xhci, XHCI_CTX_SLOT ));
	slot_ctx->info = cpu_to_le32 ( XHCI_SLOT_INFO ( 1, 0, slot->psiv,
							slot->route ) );
	slot_ctx->port = slot->port;
	slot_ctx->tt_id = slot->tt_id;
	slot_ctx->tt_port = slot->tt_port;

	/* Populate control endpoint context */
	ep_ctx = ( input + xhci_input_context_offset ( xhci, XHCI_CTX_EP0 ) );
	ep_ctx->type = XHCI_EP_TYPE_CONTROL;
	ep_ctx->burst = endpoint->ep->burst;
	ep_ctx->mtu = cpu_to_le16 ( endpoint->ep->mtu );
	ep_ctx->dequeue = cpu_to_le64 ( virt_to_phys ( endpoint->ring.trb ) |
					XHCI_EP_DCS );
	ep_ctx->trb_len = cpu_to_le16 ( XHCI_EP0_TRB_LEN );
}

/**
 * Address device
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @ret rc		Return status code
 */
static inline int xhci_address_device ( struct xhci_device *xhci,
					struct xhci_slot *slot ) {
	struct usb_device *usb = slot->usb;
	struct xhci_slot_context *slot_ctx;
	int rc;

	/* Assign device address */
	if ( ( rc = xhci_context ( xhci, slot, slot->endpoint[XHCI_CTX_EP0],
				   XHCI_TRB_ADDRESS_DEVICE,
				   xhci_address_device_input ) ) != 0 )
		return rc;

	/* Get assigned address */
	slot_ctx = ( slot->context +
		     xhci_device_context_offset ( xhci, XHCI_CTX_SLOT ) );
	usb->address = slot_ctx->address;
	DBGC2 ( xhci, "XHCI %s assigned address %d to %s\n",
		xhci->name, usb->address, usb->name );

	return 0;
}

/**
 * Populate configure endpoint input context
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @v input		Input context
 */
static void xhci_configure_endpoint_input ( struct xhci_device *xhci,
					    struct xhci_slot *slot,
					    struct xhci_endpoint *endpoint,
					    void *input ) {
	struct xhci_control_context *control_ctx;
	struct xhci_slot_context *slot_ctx;
	struct xhci_endpoint_context *ep_ctx;

	/* Populate control context */
	control_ctx = input;
	control_ctx->add = cpu_to_le32 ( ( 1 << XHCI_CTX_SLOT ) |
					 ( 1 << endpoint->ctx ) );

	/* Populate slot context */
	slot_ctx = ( input + xhci_input_context_offset ( xhci, XHCI_CTX_SLOT ));
	slot_ctx->info = cpu_to_le32 ( XHCI_SLOT_INFO ( ( XHCI_CTX_END - 1 ),
							( slot->ports ? 1 : 0 ),
							slot->psiv, 0 ) );
	slot_ctx->ports = slot->ports;

	/* Populate endpoint context */
	ep_ctx = ( input + xhci_input_context_offset ( xhci, endpoint->ctx ) );
	ep_ctx->interval = endpoint->interval;
	ep_ctx->type = endpoint->type;
	ep_ctx->burst = endpoint->ep->burst;
	ep_ctx->mtu = cpu_to_le16 ( endpoint->ep->mtu );
	ep_ctx->dequeue = cpu_to_le64 ( virt_to_phys ( endpoint->ring.trb ) |
					XHCI_EP_DCS );
	ep_ctx->trb_len = cpu_to_le16 ( endpoint->ep->mtu ); /* best guess */
}

/**
 * Configure endpoint
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @ret rc		Return status code
 */
static inline int xhci_configure_endpoint ( struct xhci_device *xhci,
					    struct xhci_slot *slot,
					    struct xhci_endpoint *endpoint ) {
	int rc;

	/* Configure endpoint */
	if ( ( rc = xhci_context ( xhci, slot, endpoint,
				   XHCI_TRB_CONFIGURE_ENDPOINT,
				   xhci_configure_endpoint_input ) ) != 0 )
		return rc;

	DBGC2 ( xhci, "XHCI %s slot %d ctx %d configured\n",
		xhci->name, slot->id, endpoint->ctx );
	return 0;
}

/**
 * Populate deconfigure endpoint input context
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @v input		Input context
 */
static void
xhci_deconfigure_endpoint_input ( struct xhci_device *xhci __unused,
				  struct xhci_slot *slot __unused,
				  struct xhci_endpoint *endpoint,
				  void *input ) {
	struct xhci_control_context *control_ctx;
	struct xhci_slot_context *slot_ctx;

	/* Populate control context */
	control_ctx = input;
	control_ctx->add = cpu_to_le32 ( 1 << XHCI_CTX_SLOT );
	control_ctx->drop = cpu_to_le32 ( 1 << endpoint->ctx );

	/* Populate slot context */
	slot_ctx = ( input + xhci_input_context_offset ( xhci, XHCI_CTX_SLOT ));
	slot_ctx->info = cpu_to_le32 ( XHCI_SLOT_INFO ( ( XHCI_CTX_END - 1 ),
							0, 0, 0 ) );
}

/**
 * Deconfigure endpoint
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @ret rc		Return status code
 */
static inline int xhci_deconfigure_endpoint ( struct xhci_device *xhci,
					      struct xhci_slot *slot,
					      struct xhci_endpoint *endpoint ) {
	int rc;

	/* Deconfigure endpoint */
	if ( ( rc = xhci_context ( xhci, slot, endpoint,
				   XHCI_TRB_CONFIGURE_ENDPOINT,
				   xhci_deconfigure_endpoint_input ) ) != 0 )
		return rc;

	DBGC2 ( xhci, "XHCI %s slot %d ctx %d deconfigured\n",
		xhci->name, slot->id, endpoint->ctx );
	return 0;
}

/**
 * Populate evaluate context input context
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @v input		Input context
 */
static void xhci_evaluate_context_input ( struct xhci_device *xhci,
					  struct xhci_slot *slot __unused,
					  struct xhci_endpoint *endpoint,
					  void *input ) {
	struct xhci_control_context *control_ctx;
	struct xhci_slot_context *slot_ctx;
	struct xhci_endpoint_context *ep_ctx;

	/* Populate control context */
	control_ctx = input;
	control_ctx->add = cpu_to_le32 ( ( 1 << XHCI_CTX_SLOT ) |
					 ( 1 << endpoint->ctx ) );

	/* Populate slot context */
	slot_ctx = ( input + xhci_input_context_offset ( xhci, XHCI_CTX_SLOT ));
	slot_ctx->info = cpu_to_le32 ( XHCI_SLOT_INFO ( ( XHCI_CTX_END - 1 ),
							0, 0, 0 ) );

	/* Populate endpoint context */
	ep_ctx = ( input + xhci_input_context_offset ( xhci, endpoint->ctx ) );
	ep_ctx->mtu = cpu_to_le16 ( endpoint->ep->mtu );
}

/**
 * Evaluate context
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @ret rc		Return status code
 */
static inline int xhci_evaluate_context ( struct xhci_device *xhci,
					  struct xhci_slot *slot,
					  struct xhci_endpoint *endpoint ) {
	int rc;

	/* Configure endpoint */
	if ( ( rc = xhci_context ( xhci, slot, endpoint,
				   XHCI_TRB_EVALUATE_CONTEXT,
				   xhci_evaluate_context_input ) ) != 0 )
		return rc;

	DBGC2 ( xhci, "XHCI %s slot %d ctx %d (re-)evaluated\n",
		xhci->name, slot->id, endpoint->ctx );
	return 0;
}

/**
 * Reset endpoint
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @ret rc		Return status code
 */
static inline int xhci_reset_endpoint ( struct xhci_device *xhci,
					struct xhci_slot *slot,
					struct xhci_endpoint *endpoint ) {
	union xhci_trb trb;
	struct xhci_trb_reset_endpoint *reset = &trb.reset;
	int rc;

	/* Construct command */
	memset ( reset, 0, sizeof ( *reset ) );
	reset->slot = slot->id;
	reset->endpoint = endpoint->ctx;
	reset->type = XHCI_TRB_RESET_ENDPOINT;

	/* Issue command and wait for completion */
	if ( ( rc = xhci_command ( xhci, &trb ) ) != 0 ) {
		DBGC ( xhci, "XHCI %s slot %d ctx %d could not reset endpoint "
		       "in state %d: %s\n", xhci->name, slot->id, endpoint->ctx,
		       endpoint->context->state, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Stop endpoint
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @ret rc		Return status code
 */
static inline int xhci_stop_endpoint ( struct xhci_device *xhci,
				       struct xhci_slot *slot,
				       struct xhci_endpoint *endpoint ) {
	union xhci_trb trb;
	struct xhci_trb_stop_endpoint *stop = &trb.stop;
	int rc;

	/* Construct command */
	memset ( stop, 0, sizeof ( *stop ) );
	stop->slot = slot->id;
	stop->endpoint = endpoint->ctx;
	stop->type = XHCI_TRB_STOP_ENDPOINT;

	/* Issue command and wait for completion */
	if ( ( rc = xhci_command ( xhci, &trb ) ) != 0 ) {
		DBGC ( xhci, "XHCI %s slot %d ctx %d could not stop endpoint "
		       "in state %d: %s\n", xhci->name, slot->id, endpoint->ctx,
		       endpoint->context->state, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Set transfer ring dequeue pointer
 *
 * @v xhci		xHCI device
 * @v slot		Device slot
 * @v endpoint		Endpoint
 * @ret rc		Return status code
 */
static inline int
xhci_set_tr_dequeue_pointer ( struct xhci_device *xhci,
			      struct xhci_slot *slot,
			      struct xhci_endpoint *endpoint ) {
	union xhci_trb trb;
	struct xhci_trb_set_tr_dequeue_pointer *dequeue = &trb.dequeue;
	struct xhci_trb_ring *ring = &endpoint->ring;
	unsigned int cons;
	unsigned int mask;
	unsigned int index;
	unsigned int dcs;
	int rc;

	/* Construct command */
	memset ( dequeue, 0, sizeof ( *dequeue ) );
	cons = ring->cons;
	mask = ring->mask;
	dcs = ( ( ~( cons >> ring->shift ) ) & XHCI_EP_DCS );
	index = ( cons & mask );
	dequeue->dequeue =
		cpu_to_le64 ( virt_to_phys ( &ring->trb[index] ) | dcs );
	dequeue->slot = slot->id;
	dequeue->endpoint = endpoint->ctx;
	dequeue->type = XHCI_TRB_SET_TR_DEQUEUE_POINTER;

	/* Issue command and wait for completion */
	if ( ( rc = xhci_command ( xhci, &trb ) ) != 0 ) {
		DBGC ( xhci, "XHCI %s slot %d ctx %d could not set TR dequeue "
		       "pointer in state %d: %s\n", xhci->name, slot->id,
		       endpoint->ctx, endpoint->context->state, strerror ( rc));
		return rc;
	}

	return 0;
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
static int xhci_endpoint_open ( struct usb_endpoint *ep ) {
	struct usb_device *usb = ep->usb;
	struct xhci_slot *slot = usb_get_hostdata ( usb );
	struct xhci_device *xhci = slot->xhci;
	struct xhci_endpoint *endpoint;
	unsigned int ctx;
	unsigned int type;
	unsigned int interval;
	int rc;

	/* Calculate context index */
	ctx = XHCI_CTX ( ep->address );
	assert ( slot->endpoint[ctx] == NULL );

	/* Calculate endpoint type */
	type = XHCI_EP_TYPE ( ep->attributes & USB_ENDPOINT_ATTR_TYPE_MASK );
	if ( type == XHCI_EP_TYPE ( USB_ENDPOINT_ATTR_CONTROL ) )
		type = XHCI_EP_TYPE_CONTROL;
	if ( ep->address & USB_DIR_IN )
		type |= XHCI_EP_TYPE_IN;

	/* Calculate interval */
	if ( type & XHCI_EP_TYPE_PERIODIC ) {
		interval = ( fls ( ep->interval ) - 1 );
	} else {
		interval = ep->interval;
	}

	/* Allocate and initialise structure */
	endpoint = zalloc ( sizeof ( *endpoint ) );
	if ( ! endpoint ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	usb_endpoint_set_hostdata ( ep, endpoint );
	slot->endpoint[ctx] = endpoint;
	endpoint->xhci = xhci;
	endpoint->slot = slot;
	endpoint->ep = ep;
	endpoint->ctx = ctx;
	endpoint->type = type;
	endpoint->interval = interval;
	endpoint->context = ( ( ( void * ) slot->context ) +
			      xhci_device_context_offset ( xhci, ctx ) );

	/* Allocate transfer ring */
	if ( ( rc = xhci_ring_alloc ( xhci, &endpoint->ring,
				      XHCI_TRANSFER_TRBS_LOG2,
				      slot->id, ctx, 0 ) ) != 0 )
		goto err_ring_alloc;

	/* Configure endpoint, if applicable */
	if ( ( ctx != XHCI_CTX_EP0 ) &&
	     ( ( rc = xhci_configure_endpoint ( xhci, slot, endpoint ) ) != 0 ))
		goto err_configure_endpoint;

	DBGC2 ( xhci, "XHCI %s slot %d ctx %d ring [%08lx,%08lx)\n",
		xhci->name, slot->id, ctx, virt_to_phys ( endpoint->ring.trb ),
		( virt_to_phys ( endpoint->ring.trb ) + endpoint->ring.len ) );
	return 0;

	xhci_deconfigure_endpoint ( xhci, slot, endpoint );
 err_configure_endpoint:
	xhci_ring_free ( &endpoint->ring );
 err_ring_alloc:
	slot->endpoint[ctx] = NULL;
	free ( endpoint );
 err_alloc:
	return rc;
}

/**
 * Close endpoint
 *
 * @v ep		USB endpoint
 */
static void xhci_endpoint_close ( struct usb_endpoint *ep ) {
	struct xhci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct xhci_slot *slot = endpoint->slot;
	struct xhci_device *xhci = slot->xhci;
	struct io_buffer *iobuf;
	unsigned int ctx = endpoint->ctx;

	/* Deconfigure endpoint, if applicable */
	if ( ctx != XHCI_CTX_EP0 )
		xhci_deconfigure_endpoint ( xhci, slot, endpoint );

	/* Cancel any incomplete transfers */
	while ( xhci_ring_fill ( &endpoint->ring ) ) {
		iobuf = xhci_dequeue_multi ( &endpoint->ring );
		usb_complete_err ( ep, iobuf, -ECANCELED );
	}

	/* Free endpoint */
	xhci_ring_free ( &endpoint->ring );
	slot->endpoint[ctx] = NULL;
	free ( endpoint );
}

/**
 * Reset endpoint
 *
 * @v ep		USB endpoint
 * @ret rc		Return status code
 */
static int xhci_endpoint_reset ( struct usb_endpoint *ep ) {
	struct xhci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct xhci_slot *slot = endpoint->slot;
	struct xhci_device *xhci = slot->xhci;
	int rc;

	/* Reset endpoint context */
	if ( ( rc = xhci_reset_endpoint ( xhci, slot, endpoint ) ) != 0 )
		return rc;

	/* Set transfer ring dequeue pointer */
	if ( ( rc = xhci_set_tr_dequeue_pointer ( xhci, slot, endpoint ) ) != 0)
		return rc;

	/* Ring doorbell to resume processing */
	xhci_doorbell ( &endpoint->ring );

	DBGC ( xhci, "XHCI %s slot %d ctx %d reset\n",
	       xhci->name, slot->id, endpoint->ctx );
	return 0;
}

/**
 * Update MTU
 *
 * @v ep		USB endpoint
 * @ret rc		Return status code
 */
static int xhci_endpoint_mtu ( struct usb_endpoint *ep ) {
	struct xhci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct xhci_slot *slot = endpoint->slot;
	struct xhci_device *xhci = slot->xhci;
	int rc;

	/* Evalulate context */
	if ( ( rc = xhci_evaluate_context ( xhci, slot, endpoint ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Enqueue message transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int xhci_endpoint_message ( struct usb_endpoint *ep,
				   struct io_buffer *iobuf ) {
	struct xhci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	struct usb_setup_packet *packet;
	unsigned int input;
	size_t len;
	union xhci_trb trbs[ 1 /* setup */ + 1 /* possible data */ +
			     1 /* status */ ];
	union xhci_trb *trb = trbs;
	struct xhci_trb_setup *setup;
	struct xhci_trb_data *data;
	struct xhci_trb_status *status;
	int rc;

	/* Profile message transfers */
	profile_start ( &xhci_message_profiler );

	/* Construct setup stage TRB */
	memset ( trbs, 0, sizeof ( trbs ) );
	assert ( iob_len ( iobuf ) >= sizeof ( *packet ) );
	packet = iobuf->data;
	iob_pull ( iobuf, sizeof ( *packet ) );
	setup = &(trb++)->setup;
	memcpy ( &setup->packet, packet, sizeof ( setup->packet ) );
	setup->len = cpu_to_le32 ( sizeof ( *packet ) );
	setup->flags = XHCI_TRB_IDT;
	setup->type = XHCI_TRB_SETUP;
	len = iob_len ( iobuf );
	input = ( packet->request & cpu_to_le16 ( USB_DIR_IN ) );
	if ( len )
		setup->direction = ( input ? XHCI_SETUP_IN : XHCI_SETUP_OUT );

	/* Construct data stage TRB, if applicable */
	if ( len ) {
		data = &(trb++)->data;
		data->data = cpu_to_le64 ( virt_to_phys ( iobuf->data ) );
		data->len = cpu_to_le32 ( len );
		data->type = XHCI_TRB_DATA;
		data->direction = ( input ? XHCI_DATA_IN : XHCI_DATA_OUT );
	}

	/* Construct status stage TRB */
	status = &(trb++)->status;
	status->flags = XHCI_TRB_IOC;
	status->type = XHCI_TRB_STATUS;
	status->direction =
		( ( len && input ) ? XHCI_STATUS_OUT : XHCI_STATUS_IN );

	/* Enqueue TRBs */
	if ( ( rc = xhci_enqueue_multi ( &endpoint->ring, iobuf, trbs,
					 ( trb - trbs ) ) ) != 0 )
		return rc;

	/* Ring the doorbell */
	xhci_doorbell ( &endpoint->ring );

	profile_stop ( &xhci_message_profiler );
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
static int xhci_endpoint_stream ( struct usb_endpoint *ep,
				  struct io_buffer *iobuf, int terminate ) {
	struct xhci_endpoint *endpoint = usb_endpoint_get_hostdata ( ep );
	union xhci_trb trbs[ 1 /* Normal */ + 1 /* Possible zero-length */ ];
	union xhci_trb *trb = trbs;
	struct xhci_trb_normal *normal;
	size_t len = iob_len ( iobuf );
	int rc;

	/* Profile stream transfers */
	profile_start ( &xhci_stream_profiler );

	/* Construct normal TRBs */
	memset ( &trbs, 0, sizeof ( trbs ) );
	normal = &(trb++)->normal;
	normal->data = cpu_to_le64 ( virt_to_phys ( iobuf->data ) );
	normal->len = cpu_to_le32 ( len );
	normal->type = XHCI_TRB_NORMAL;
	if ( terminate && ( ( len & ( ep->mtu - 1 ) ) == 0 ) ) {
		normal->flags = XHCI_TRB_CH;
		normal = &(trb++)->normal;
		normal->type = XHCI_TRB_NORMAL;
	}
	normal->flags = XHCI_TRB_IOC;

	/* Enqueue TRBs */
	if ( ( rc = xhci_enqueue_multi ( &endpoint->ring, iobuf, trbs,
					 ( trb - trbs ) ) ) != 0 )
		return rc;

	/* Ring the doorbell */
	xhci_doorbell ( &endpoint->ring );

	profile_stop ( &xhci_stream_profiler );
	return 0;
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
static int xhci_device_open ( struct usb_device *usb ) {
	struct xhci_device *xhci = usb_bus_get_hostdata ( usb->port->hub->bus );
	struct usb_port *tt = usb_transaction_translator ( usb );
	struct xhci_slot *slot;
	struct xhci_slot *tt_slot;
	size_t len;
	int type;
	int id;
	int rc;

	/* Determine applicable slot type */
	type = xhci_port_slot_type ( xhci, usb->port->address );
	if ( type < 0 ) {
		rc = type;
		DBGC ( xhci, "XHCI %s-%d has no slot type\n",
		       xhci->name, usb->port->address );
		goto err_type;
	}

	/* Allocate a device slot number */
	id = xhci_enable_slot ( xhci, type );
	if ( id < 0 ) {
		rc = id;
		goto err_enable_slot;
	}
	assert ( ( id > 0 ) && ( ( unsigned int ) id <= xhci->slots ) );
	assert ( xhci->slot[id] == NULL );

	/* Allocate and initialise structure */
	slot = zalloc ( sizeof ( *slot ) );
	if ( ! slot ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	usb_set_hostdata ( usb, slot );
	xhci->slot[id] = slot;
	slot->xhci = xhci;
	slot->usb = usb;
	slot->id = id;
	if ( tt ) {
		tt_slot = usb_get_hostdata ( tt->hub->usb );
		slot->tt_id = tt_slot->id;
		slot->tt_port = tt->address;
	}

	/* Allocate a device context */
	len = xhci_device_context_offset ( xhci, XHCI_CTX_END );
	slot->context = malloc_dma ( len, xhci_align ( len ) );
	if ( ! slot->context ) {
		rc = -ENOMEM;
		goto err_alloc_context;
	}
	memset ( slot->context, 0, len );

	/* Set device context base address */
	assert ( xhci->dcbaa[id] == 0 );
	xhci->dcbaa[id] = cpu_to_le64 ( virt_to_phys ( slot->context ) );

	DBGC2 ( xhci, "XHCI %s slot %d device context [%08lx,%08lx) for %s\n",
		xhci->name, slot->id, virt_to_phys ( slot->context ),
		( virt_to_phys ( slot->context ) + len ), usb->name );
	return 0;

	xhci->dcbaa[id] = 0;
	free_dma ( slot->context, len );
 err_alloc_context:
	xhci->slot[id] = NULL;
	free ( slot );
 err_alloc:
	xhci_disable_slot ( xhci, id );
 err_enable_slot:
 err_type:
	return rc;
}

/**
 * Close device
 *
 * @v usb		USB device
 */
static void xhci_device_close ( struct usb_device *usb ) {
	struct xhci_slot *slot = usb_get_hostdata ( usb );
	struct xhci_device *xhci = slot->xhci;
	size_t len = xhci_device_context_offset ( xhci, XHCI_CTX_END );
	unsigned int id = slot->id;
	int rc;

	/* Disable slot */
	if ( ( rc = xhci_disable_slot ( xhci, id ) ) != 0 ) {
		/* Slot is still enabled.  Leak the slot context,
		 * since the controller may still write to this
		 * memory, and leave the DCBAA entry intact.
		 *
		 * If the controller later reports that this same slot
		 * has been re-enabled, then some assertions will be
		 * triggered.
		 */
		DBGC ( xhci, "XHCI %s slot %d leaking context memory\n",
		       xhci->name, slot->id );
		slot->context = NULL;
	}

	/* Free slot */
	if ( slot->context ) {
		free_dma ( slot->context, len );
		xhci->dcbaa[id] = 0;
	}
	xhci->slot[id] = NULL;
	free ( slot );
}

/**
 * Assign device address
 *
 * @v usb		USB device
 * @ret rc		Return status code
 */
static int xhci_device_address ( struct usb_device *usb ) {
	struct xhci_slot *slot = usb_get_hostdata ( usb );
	struct xhci_device *xhci = slot->xhci;
	struct usb_port *port = usb->port;
	struct usb_port *root_port;
	int psiv;
	int rc;

	/* Calculate route string */
	slot->route = usb_route_string ( usb );

	/* Calculate root hub port number */
	root_port = usb_root_hub_port ( usb );
	slot->port = root_port->address;

	/* Calculate protocol speed ID */
	psiv = xhci_port_psiv ( xhci, slot->port, port->speed );
	if ( psiv < 0 ) {
		rc = psiv;
		return rc;
	}
	slot->psiv = psiv;

	/* Address device */
	if ( ( rc = xhci_address_device ( xhci, slot ) ) != 0 )
		return rc;

	return 0;
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
static int xhci_bus_open ( struct usb_bus *bus ) {
	struct xhci_device *xhci = usb_bus_get_hostdata ( bus );
	int rc;

	/* Allocate device slot array */
	xhci->slot = zalloc ( ( xhci->slots + 1 ) * sizeof ( xhci->slot[0] ) );
	if ( ! xhci->slot ) {
		rc = -ENOMEM;
		goto err_slot_alloc;
	}

	/* Allocate device context base address array */
	if ( ( rc = xhci_dcbaa_alloc ( xhci ) ) != 0 )
		goto err_dcbaa_alloc;

	/* Allocate scratchpad buffers */
	if ( ( rc = xhci_scratchpad_alloc ( xhci ) ) != 0 )
		goto err_scratchpad_alloc;

	/* Allocate command ring */
	if ( ( rc = xhci_command_alloc ( xhci ) ) != 0 )
		goto err_command_alloc;

	/* Allocate event ring */
	if ( ( rc = xhci_event_alloc ( xhci ) ) != 0 )
		goto err_event_alloc;

	/* Start controller */
	xhci_run ( xhci );

	return 0;

	xhci_stop ( xhci );
	xhci_event_free ( xhci );
 err_event_alloc:
	xhci_command_free ( xhci );
 err_command_alloc:
	xhci_scratchpad_free ( xhci );
 err_scratchpad_alloc:
	xhci_dcbaa_free ( xhci );
 err_dcbaa_alloc:
	free ( xhci->slot );
 err_slot_alloc:
	return rc;
}

/**
 * Close USB bus
 *
 * @v bus		USB bus
 */
static void xhci_bus_close ( struct usb_bus *bus ) {
	struct xhci_device *xhci = usb_bus_get_hostdata ( bus );
	unsigned int i;

	/* Sanity checks */
	assert ( xhci->slot != NULL );
	for ( i = 0 ; i <= xhci->slots ; i++ )
		assert ( xhci->slot[i] == NULL );

	xhci_stop ( xhci );
	xhci_event_free ( xhci );
	xhci_command_free ( xhci );
	xhci_scratchpad_free ( xhci );
	xhci_dcbaa_free ( xhci );
	free ( xhci->slot );
}

/**
 * Poll USB bus
 *
 * @v bus		USB bus
 */
static void xhci_bus_poll ( struct usb_bus *bus ) {
	struct xhci_device *xhci = usb_bus_get_hostdata ( bus );

	/* Poll event ring */
	xhci_event_poll ( xhci );
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
static int xhci_hub_open ( struct usb_hub *hub ) {
	struct xhci_slot *slot;

	/* Do nothing if this is the root hub */
	if ( ! hub->usb )
		return 0;

	/* Get device slot */
	slot = usb_get_hostdata ( hub->usb );

	/* Update device slot hub parameters.  We don't inform the
	 * hardware of this information until the hub's interrupt
	 * endpoint is opened, since the only mechanism for so doing
	 * provided by the xHCI specification is a Configure Endpoint
	 * command, and we can't issue that command until we have a
	 * non-EP0 endpoint to configure.
	 */
	slot->ports = hub->ports;

	return 0;
}

/**
 * Close hub
 *
 * @v hub		USB hub
 */
static void xhci_hub_close ( struct usb_hub *hub __unused ) {

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
static int xhci_root_open ( struct usb_hub *hub ) {
	struct usb_bus *bus = hub->bus;
	struct xhci_device *xhci = usb_bus_get_hostdata ( bus );
	struct usb_port *port;
	uint32_t portsc;
	unsigned int i;

	/* Enable power to all ports */
	for ( i = 1 ; i <= xhci->ports ; i++ ) {
		portsc = readl ( xhci->op + XHCI_OP_PORTSC ( i ) );
		portsc &= XHCI_PORTSC_PRESERVE;
		portsc |= XHCI_PORTSC_PP;
		writel ( portsc, xhci->op + XHCI_OP_PORTSC ( i ) );
	}

	/* xHCI spec requires us to potentially wait 20ms after
	 * enabling power to a port.
	 */
	mdelay ( XHCI_PORT_POWER_DELAY_MS );

	/* USB3 ports may power up as Disabled */
	for ( i = 1 ; i <= xhci->ports ; i++ ) {
		portsc = readl ( xhci->op + XHCI_OP_PORTSC ( i ) );
		port = usb_port ( hub, i );
		if ( ( port->protocol >= USB_PROTO_3_0 ) &&
		     ( ( portsc & XHCI_PORTSC_PLS_MASK ) ==
		       XHCI_PORTSC_PLS_DISABLED ) ) {
			/* Force link state to RxDetect */
			portsc &= XHCI_PORTSC_PRESERVE;
			portsc |= ( XHCI_PORTSC_PLS_RXDETECT | XHCI_PORTSC_LWS);
			writel ( portsc, xhci->op + XHCI_OP_PORTSC ( i ) );
		}
	}

	/* Some xHCI cards seem to require an additional delay after
	 * setting the link state to RxDetect.
	 */
	mdelay ( XHCI_LINK_STATE_DELAY_MS );

	/* Record hub driver private data */
	usb_hub_set_drvdata ( hub, xhci );

	return 0;
}

/**
 * Close root hub
 *
 * @v hub		USB hub
 */
static void xhci_root_close ( struct usb_hub *hub ) {

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
static int xhci_root_enable ( struct usb_hub *hub, struct usb_port *port ) {
	struct xhci_device *xhci = usb_hub_get_drvdata ( hub );
	uint32_t portsc;
	unsigned int i;

	/* Reset port */
	portsc = readl ( xhci->op + XHCI_OP_PORTSC ( port->address ) );
	portsc &= XHCI_PORTSC_PRESERVE;
	portsc |= XHCI_PORTSC_PR;
	writel ( portsc, xhci->op + XHCI_OP_PORTSC ( port->address ) );

	/* Wait for port to become enabled */
	for ( i = 0 ; i < XHCI_PORT_RESET_MAX_WAIT_MS ; i++ ) {

		/* Check port status */
		portsc = readl ( xhci->op + XHCI_OP_PORTSC ( port->address ) );
		if ( portsc & XHCI_PORTSC_PED )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( xhci, "XHCI %s-%d timed out waiting for port to enable\n",
	       xhci->name, port->address );
	return -ETIMEDOUT;
}

/**
 * Disable port
 *
 * @v hub		USB hub
 * @v port		USB port
 * @ret rc		Return status code
 */
static int xhci_root_disable ( struct usb_hub *hub, struct usb_port *port ) {
	struct xhci_device *xhci = usb_hub_get_drvdata ( hub );
	uint32_t portsc;

	/* Disable port */
	portsc = readl ( xhci->op + XHCI_OP_PORTSC ( port->address ) );
	portsc &= XHCI_PORTSC_PRESERVE;
	portsc |= XHCI_PORTSC_PED;
	writel ( portsc, xhci->op + XHCI_OP_PORTSC ( port->address ) );

	return 0;
}

/**
 * Update root hub port speed
 *
 * @v hub		USB hub
 * @v port		USB port
 * @ret rc		Return status code
 */
static int xhci_root_speed ( struct usb_hub *hub, struct usb_port *port ) {
	struct xhci_device *xhci = usb_hub_get_drvdata ( hub );
	uint32_t portsc;
	unsigned int psiv;
	int ccs;
	int ped;
	int csc;
	int speed;
	int rc;

	/* Read port status */
	portsc = readl ( xhci->op + XHCI_OP_PORTSC ( port->address ) );
	DBGC2 ( xhci, "XHCI %s-%d status is %08x\n",
		xhci->name, port->address, portsc );
	ccs = ( portsc & XHCI_PORTSC_CCS );
	ped = ( portsc & XHCI_PORTSC_PED );
	csc = ( portsc & XHCI_PORTSC_CSC );
	psiv = XHCI_PORTSC_PSIV ( portsc );

	/* Record disconnections and clear changes */
	port->disconnected |= csc;
	portsc &= ( XHCI_PORTSC_PRESERVE | XHCI_PORTSC_CHANGE );
	writel ( portsc, xhci->op + XHCI_OP_PORTSC ( port->address ) );

	/* Port speed is not valid unless port is connected */
	if ( ! ccs ) {
		port->speed = USB_SPEED_NONE;
		return 0;
	}

	/* For USB2 ports, the PSIV field is not valid until the port
	 * completes reset and becomes enabled.
	 */
	if ( ( port->protocol < USB_PROTO_3_0 ) && ! ped ) {
		port->speed = USB_SPEED_FULL;
		return 0;
	}

	/* Get port speed and map to generic USB speed */
	speed = xhci_port_speed ( xhci, port->address, psiv );
	if ( speed < 0 ) {
		rc = speed;
		return rc;
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
static int xhci_root_clear_tt ( struct usb_hub *hub, struct usb_port *port,
				struct usb_endpoint *ep ) {
	struct xhci_device *xhci = usb_hub_get_drvdata ( hub );

	/* Should never be called; this is a root hub */
	DBGC ( xhci, "XHCI %s-%d nonsensical CLEAR_TT for %s %s\n", xhci->name,
	       port->address, ep->usb->name, usb_endpoint_name ( ep ) );

	return -ENOTSUP;
}

/******************************************************************************
 *
 * PCI interface
 *
 ******************************************************************************
 */

/** USB host controller operations */
static struct usb_host_operations xhci_operations = {
	.endpoint = {
		.open = xhci_endpoint_open,
		.close = xhci_endpoint_close,
		.reset = xhci_endpoint_reset,
		.mtu = xhci_endpoint_mtu,
		.message = xhci_endpoint_message,
		.stream = xhci_endpoint_stream,
	},
	.device = {
		.open = xhci_device_open,
		.close = xhci_device_close,
		.address = xhci_device_address,
	},
	.bus = {
		.open = xhci_bus_open,
		.close = xhci_bus_close,
		.poll = xhci_bus_poll,
	},
	.hub = {
		.open = xhci_hub_open,
		.close = xhci_hub_close,
	},
	.root = {
		.open = xhci_root_open,
		.close = xhci_root_close,
		.enable = xhci_root_enable,
		.disable = xhci_root_disable,
		.speed = xhci_root_speed,
		.clear_tt = xhci_root_clear_tt,
	},
};

/**
 * Fix Intel PCH-specific quirks
 *
 * @v xhci		xHCI device
 * @v pci		PCI device
 */
static void xhci_pch_fix ( struct xhci_device *xhci, struct pci_device *pci ) {
	struct xhci_pch *pch = &xhci->pch;
	uint32_t xusb2pr;
	uint32_t xusb2prm;
	uint32_t usb3pssen;
	uint32_t usb3prm;

	/* Enable SuperSpeed capability.  Do this before rerouting
	 * USB2 ports, so that USB3 devices connect at SuperSpeed.
	 */
	pci_read_config_dword ( pci, XHCI_PCH_USB3PSSEN, &usb3pssen );
	pci_read_config_dword ( pci, XHCI_PCH_USB3PRM, &usb3prm );
	if ( usb3prm & ~usb3pssen ) {
		DBGC ( xhci, "XHCI %s enabling SuperSpeed on ports %08x\n",
		       xhci->name, ( usb3prm & ~usb3pssen ) );
	}
	pch->usb3pssen = usb3pssen;
	usb3pssen |= usb3prm;
	pci_write_config_dword ( pci, XHCI_PCH_USB3PSSEN, usb3pssen );

	/* Route USB2 ports from EHCI to xHCI */
	pci_read_config_dword ( pci, XHCI_PCH_XUSB2PR, &xusb2pr );
	pci_read_config_dword ( pci, XHCI_PCH_XUSB2PRM, &xusb2prm );
	if ( xusb2prm & ~xusb2pr ) {
		DBGC ( xhci, "XHCI %s routing ports %08x from EHCI to xHCI\n",
		       xhci->name, ( xusb2prm & ~xusb2pr ) );
	}
	pch->xusb2pr = xusb2pr;
	xusb2pr |= xusb2prm;
	pci_write_config_dword ( pci, XHCI_PCH_XUSB2PR, xusb2pr );
}

/**
 * Undo Intel PCH-specific quirk fixes
 *
 * @v xhci		xHCI device
 * @v pci		PCI device
 */
static void xhci_pch_undo ( struct xhci_device *xhci, struct pci_device *pci ) {
	struct xhci_pch *pch = &xhci->pch;

	/* Restore USB2 port routing to original state */
	pci_write_config_dword ( pci, XHCI_PCH_XUSB2PR, pch->xusb2pr );

	/* Restore SuperSpeed capability to original state */
	pci_write_config_dword ( pci, XHCI_PCH_USB3PSSEN, pch->usb3pssen );
}

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 */
static int xhci_probe ( struct pci_device *pci ) {
	struct xhci_device *xhci;
	struct usb_port *port;
	unsigned long bar_start;
	size_t bar_size;
	unsigned int i;
	int rc;

	/* Allocate and initialise structure */
	xhci = zalloc ( sizeof ( *xhci ) );
	if ( ! xhci ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	xhci->name = pci->dev.name;
	xhci->quirks = pci->id->driver_data;

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Map registers */
	bar_start = pci_bar_start ( pci, XHCI_BAR );
	bar_size = pci_bar_size ( pci, XHCI_BAR );
	xhci->regs = ioremap ( bar_start, bar_size );
	if ( ! xhci->regs ) {
		rc = -ENODEV;
		goto err_ioremap;
	}

	/* Initialise xHCI device */
	xhci_init ( xhci, xhci->regs );

	/* Initialise USB legacy support and claim ownership */
	xhci_legacy_init ( xhci );
	xhci_legacy_claim ( xhci );

	/* Fix Intel PCH-specific quirks, if applicable */
	if ( xhci->quirks & XHCI_PCH )
		xhci_pch_fix ( xhci, pci );

	/* Reset device */
	if ( ( rc = xhci_reset ( xhci ) ) != 0 )
		goto err_reset;

	/* Allocate USB bus */
	xhci->bus = alloc_usb_bus ( &pci->dev, xhci->ports, XHCI_MTU,
				    &xhci_operations );
	if ( ! xhci->bus ) {
		rc = -ENOMEM;
		goto err_alloc_bus;
	}
	usb_bus_set_hostdata ( xhci->bus, xhci );
	usb_hub_set_drvdata ( xhci->bus->hub, xhci );

	/* Set port protocols */
	for ( i = 1 ; i <= xhci->ports ; i++ ) {
		port = usb_port ( xhci->bus->hub, i );
		port->protocol = xhci_port_protocol ( xhci, i );
	}

	/* Register USB bus */
	if ( ( rc = register_usb_bus ( xhci->bus ) ) != 0 )
		goto err_register;

	pci_set_drvdata ( pci, xhci );
	return 0;

	unregister_usb_bus ( xhci->bus );
 err_register:
	free_usb_bus ( xhci->bus );
 err_alloc_bus:
	xhci_reset ( xhci );
 err_reset:
	if ( xhci->quirks & XHCI_PCH )
		xhci_pch_undo ( xhci, pci );
	xhci_legacy_release ( xhci );
	iounmap ( xhci->regs );
 err_ioremap:
	free ( xhci );
 err_alloc:
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci		PCI device
 */
static void xhci_remove ( struct pci_device *pci ) {
	struct xhci_device *xhci = pci_get_drvdata ( pci );
	struct usb_bus *bus = xhci->bus;

	unregister_usb_bus ( bus );
	free_usb_bus ( bus );
	xhci_reset ( xhci );
	if ( xhci->quirks & XHCI_PCH )
		xhci_pch_undo ( xhci, pci );
	xhci_legacy_release ( xhci );
	iounmap ( xhci->regs );
	free ( xhci );
}

/** XHCI PCI device IDs */
static struct pci_device_id xhci_ids[] = {
	PCI_ROM ( 0x8086, 0x9d2f, "xhci-skylake", "xHCI (Skylake)", ( XHCI_PCH | XHCI_BAD_PSIV ) ),
	PCI_ROM ( 0x8086, 0xffff, "xhci-pch", "xHCI (Intel PCH)", XHCI_PCH ),
	PCI_ROM ( 0xffff, 0xffff, "xhci", "xHCI", 0 ),
};

/** XHCI PCI driver */
struct pci_driver xhci_driver __pci_driver = {
	.ids = xhci_ids,
	.id_count = ( sizeof ( xhci_ids ) / sizeof ( xhci_ids[0] ) ),
	.class = PCI_CLASS_ID ( PCI_CLASS_SERIAL, PCI_CLASS_SERIAL_USB,
				PCI_CLASS_SERIAL_USB_XHCI ),
	.probe = xhci_probe,
	.remove = xhci_remove,
};

/**
 * Prepare for exit
 *
 * @v booting		System is shutting down for OS boot
 */
static void xhci_shutdown ( int booting ) {
	/* If we are shutting down to boot an OS, then prevent the
	 * release of ownership back to BIOS.
	 */
	xhci_legacy_prevent_release = booting;
}

/** Startup/shutdown function */
struct startup_fn xhci_startup __startup_fn ( STARTUP_LATE ) = {
	.shutdown = xhci_shutdown,
};
