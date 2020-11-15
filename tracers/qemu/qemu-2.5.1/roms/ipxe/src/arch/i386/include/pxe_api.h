#ifndef PXE_API_H
#define PXE_API_H

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
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
 *
 * As an alternative, at your option, you may use this file under the
 * following terms, known as the "MIT license":
 *
 * Copyright (c) 2005-2009 Michael Brown <mbrown@fensystems.co.uk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/** @file
 *
 * Preboot eXecution Environment (PXE) API
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include "pxe_types.h"

/** @addtogroup pxe Preboot eXecution Environment (PXE) API
 *  @{
 */

/** @defgroup pxe_api_call PXE entry points
 *
 * PXE entry points and calling conventions
 *
 *  @{
 */

/** The PXENV+ structure */
struct s_PXENV {
	/** Signature
	 *
	 * Contains the bytes 'P', 'X', 'E', 'N', 'V', '+'.
	 */
	UINT8_t		Signature[6];
	/** PXE API version
	 *
	 * MSB is major version number, LSB is minor version number.
	 * If the API version number is 0x0201 or greater, the !PXE
	 * structure pointed to by #PXEPtr should be used instead of
	 * this data structure.
	 */
	UINT16_t	Version;
	UINT8_t		Length;		/**< Length of this structure */
	/** Checksum
	 *
	 * The byte checksum of this structure (using the length in
	 * #Length) must be zero.
	 */
	UINT8_t		Checksum;
	SEGOFF16_t	RMEntry;	/**< Real-mode PXENV+ entry point */
	/** Protected-mode PXENV+ entry point offset
	 *
	 * PXE 2.1 deprecates this entry point.  For protected-mode
	 * API calls, use the !PXE structure pointed to by #PXEPtr
	 * instead.
	 */
	UINT32_t	PMOffset;
	/** Protected-mode PXENV+ entry point segment selector
	 *
	 * PXE 2.1 deprecates this entry point.  For protected-mode
	 * API calls, use the !PXE structure pointed to by #PXEPtr
	 * instead.
	 */
	SEGSEL_t	PMSelector;
	SEGSEL_t	StackSeg;	/**< Stack segment selector */
	UINT16_t	StackSize;	/**< Stack segment size */
	SEGSEL_t	BC_CodeSeg;	/**< Base-code code segment selector */
	UINT16_t	BC_CodeSize;	/**< Base-code code segment size */
	SEGSEL_t	BC_DataSeg;	/**< Base-code data segment selector */
	UINT16_t	BC_DataSize;	/**< Base-code data segment size */
	SEGSEL_t	UNDIDataSeg;	/**< UNDI data segment selector */
	UINT16_t	UNDIDataSize;	/**< UNDI data segment size */
	SEGSEL_t	UNDICodeSeg;	/**< UNDI code segment selector */
	UINT16_t	UNDICodeSize;	/**< UNDI code segment size */
	/** Address of the !PXE structure
	 *
	 * This field is present only if #Version is 0x0201 or
	 * greater.  If present, it points to a struct s_PXE.
	 */
	SEGOFF16_t	PXEPtr;
} __attribute__ (( packed ));

typedef struct s_PXENV PXENV_t;

/** The !PXE structure */
struct s_PXE {
	/** Signature
	 *
	 * Contains the bytes '!', 'P', 'X', 'E'.
	 */
	UINT8_t		Signature[4];
	UINT8_t		StructLength;	/**< Length of this structure */
	/** Checksum
	 *
	 * The byte checksum of this structure (using the length in
	 * #StructLength) must be zero.
	 */
	UINT8_t		StructCksum;
	/** Revision of this structure
	 *
	 * For PXE version 2.1, this field must be zero.
	 */
	UINT8_t		StructRev;
	UINT8_t		reserved_1;	/**< Must be zero */
	/** Address of the UNDI ROM ID structure
	 *
	 * This is a pointer to a struct s_UNDI_ROM_ID.
	 */
	SEGOFF16_t	UNDIROMID;
	/** Address of the Base Code ROM ID structure
	 *
	 * This is a pointer to a struct s_BC_ROM_ID.
	 */
	SEGOFF16_t	BaseROMID;
	/** 16-bit !PXE entry point
	 *
	 * This is the entry point for either real mode, or protected
	 * mode with a 16-bit stack segment.
	 */
	SEGOFF16_t	EntryPointSP;
	/** 32-bit !PXE entry point
	 *
	 * This is the entry point for protected mode with a 32-bit
	 * stack segment.
	 */
	SEGOFF16_t	EntryPointESP;
	/** Status call-out function
	 *
	 * @v 0		(if in a time-out loop)
	 * @v n		Number of a received TFTP packet
	 * @ret 0	Continue operation
	 * @ret 1	Cancel operation
	 *
	 * This function will be called whenever the PXE stack is in
	 * protected mode, is waiting for an event (e.g. a DHCP reply)
	 * and wishes to allow the user to cancel the operation.
	 * Parameters are passed in register %ax; the return value
	 * must also be placed in register %ax.  All other registers
	 * and flags @b must be preserved.
	 *
	 * In real mode, an internal function (that checks for a
	 * keypress) will be used.
	 *
	 * If this field is set to -1, no status call-out function
	 * will be used and consequently the user will not be allowed
	 * to interrupt operations.
	 *
	 * @note The PXE specification version 2.1 defines the
	 * StatusCallout field, mentions it 11 times, but nowhere
	 * defines what it actually does or how it gets called.
	 * Fortunately, the WfM specification version 1.1a deigns to
	 * inform us of such petty details.
	 */
	SEGOFF16_t	StatusCallout;
	UINT8_t		reserved_2;	/**< Must be zero */
	/** Number of segment descriptors
	 *
	 * If this number is greater than 7, the remaining descriptors
	 * follow immediately after #BC_CodeWrite.
	 */
	UINT8_t		SegDescCnt;
	/** First protected-mode selector
	 *
	 * This is the segment selector value for the first segment
	 * assigned to PXE.  Protected-mode selectors must be
	 * consecutive, according to the PXE 2.1 specification, though
	 * no reason is given.  Each #SEGDESC_t includes a field for
	 * the segment selector, so this information is entirely
	 * redundant.
	 */
	SEGSEL_t	FirstSelector;
	/** Stack segment descriptor */
	SEGDESC_t	Stack;
	/** UNDI data segment descriptor */
	SEGDESC_t	UNDIData;
	/** UNDI code segment descriptor */
	SEGDESC_t	UNDICode;
	/** UNDI writable code segment descriptor */
	SEGDESC_t	UNDICodeWrite;
	/** Base-code data segment descriptor */
	SEGDESC_t	BC_Data;
	/** Base-code code segment descriptor */
	SEGDESC_t	BC_Code;
	/** Base-code writable code segment descriptor */
	SEGDESC_t	BC_CodeWrite;
} __attribute__ (( packed ));

typedef struct s_PXE PXE_t;

/** @} */ /* pxe_api_call */

/** @defgroup pxe_preboot_api PXE Preboot API
 *
 * General high-level functions: #PXENV_UNLOAD_STACK, #PXENV_START_UNDI etc.
 *
 * @{
 */

/** @defgroup pxenv_unload_stack PXENV_UNLOAD_STACK
 *
 *  UNLOAD BASE CODE STACK
 *
 *  @{
 */

/** PXE API function code for pxenv_unload_stack() */
#define	PXENV_UNLOAD_STACK		0x0070

/** Parameter block for pxenv_unload_stack() */
struct s_PXENV_UNLOAD_STACK {
	PXENV_STATUS_t Status;			/**< PXE status code */
	UINT8_t reserved[10];			/**< Must be zero */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNLOAD_STACK PXENV_UNLOAD_STACK_t;

/** @} */ /* pxenv_unload_stack */

/** @defgroup pxenv_get_cached_info PXENV_GET_CACHED_INFO
 *
 *  GET CACHED INFO
 *
 *  @{
 */

/** PXE API function code for pxenv_get_cached_info() */
#define	PXENV_GET_CACHED_INFO		0x0071

/** The client's DHCPDISCOVER packet */
#define PXENV_PACKET_TYPE_DHCP_DISCOVER	1

/** The DHCP server's DHCPACK packet */
#define PXENV_PACKET_TYPE_DHCP_ACK	2

/** The Boot Server's Discover Reply packet
 *
 * This packet contains DHCP option 60 set to "PXEClient", a valid
 * boot file name, and may or may not contain MTFTP options.
 */
#define PXENV_PACKET_TYPE_CACHED_REPLY	3

/** Parameter block for pxenv_get_cached_info() */
struct s_PXENV_GET_CACHED_INFO {
	PXENV_STATUS_t Status;			/**< PXE status code */
	/** Packet type.
	 *
	 * Valid values are #PXENV_PACKET_TYPE_DHCP_DISCOVER,
	 * #PXENV_PACKET_TYPE_DHCP_ACK or #PXENV_PACKET_TYPE_CACHED_REPLY
	 */
	UINT16_t PacketType;
	UINT16_t BufferSize;			/**< Buffer size */
	SEGOFF16_t Buffer;			/**< Buffer address */
	UINT16_t BufferLimit;			/**< Maximum buffer size */
} __attribute__ (( packed ));

typedef struct s_PXENV_GET_CACHED_INFO PXENV_GET_CACHED_INFO_t;

#define BOOTP_REQ	1	/**< A BOOTP request packet */
#define BOOTP_REP	2	/**< A BOOTP reply packet */

/** DHCP broadcast flag
 *
 * Request a broadcast response (DHCPOFFER or DHCPACK) from the DHCP
 * server.
 */
#define BOOTP_BCAST	0x8000

#define VM_RFC1048	0x63825363L	/**< DHCP magic cookie */

/** Maximum length of DHCP options */
#define BOOTP_DHCPVEND	1024

/** Format of buffer filled in by pxenv_get_cached_info()
 *
 * This somewhat convoluted data structure simply describes the layout
 * of a DHCP packet.  Refer to RFC2131 section 2 for a full
 * description.
 */
struct bootph {
	/** Message opcode.
	 *
	 * Valid values are #BOOTP_REQ and #BOOTP_REP.
	 */
	UINT8_t opcode;
	/** NIC hardware type.
	 *
	 * Valid values are as for s_PXENV_UNDI_GET_INFORMATION::HwType.
	 */
	UINT8_t Hardware;
	UINT8_t Hardlen;		/**< MAC address length */
	/** Gateway hops
	 *
	 * Zero in packets sent by the client.  May be non-zero in
	 * replies from the DHCP server, if the reply comes via a DHCP
	 * relay agent.
	 */
	UINT8_t Gatehops;
	UINT32_t ident;			/**< DHCP transaction id (xid) */
	/** Elapsed time
	 *
	 * Number of seconds since the client began the DHCP
	 * transaction.
	 */
	UINT16_t seconds;
	/** Flags
	 *
	 * This is the bitwise-OR of any of the following values:
	 * #BOOTP_BCAST.
	 */
	UINT16_t Flags;
	/** Client IP address
	 *
	 * Set only if the client already has an IP address.
	 */
	IP4_t cip;
	/** Your IP address
	 *
	 * This is the IP address that the server assigns to the
	 * client.
	 */
	IP4_t yip;
	/** Server IP address
	 *
	 * This is the IP address of the BOOTP/DHCP server.
	 */
	IP4_t sip;
	/** Gateway IP address
	 *
	 * This is the IP address of the BOOTP/DHCP relay agent, if
	 * any.  It is @b not (necessarily) the address of the default
	 * gateway for routing purposes.
	 */
	IP4_t gip;
	MAC_ADDR_t CAddr;		/**< Client MAC address */
	UINT8_t Sname[64];		/**< Server host name */
	UINT8_t bootfile[128];		/**< Boot file name */
	/** DHCP options
	 *
	 * Don't ask.  Just laugh.  Then burn a copy of the PXE
	 * specification and send Intel an e-mail asking them if
	 * they've figured out what a "union" does in C yet.
	 */
	union bootph_vendor {
		UINT8_t d[BOOTP_DHCPVEND]; /**< DHCP options */
		/** DHCP options */
		struct bootph_vendor_v {
			/** DHCP magic cookie
			 *
			 * Should have the value #VM_RFC1048.
			 */
			UINT8_t magic[4];
			UINT32_t flags;	/**< BOOTP flags/opcodes */
			/** "End of BOOTP vendor extensions"
			 *
			 * Abandon hope, all ye who consider the
			 * purpose of this field.
			 */
			UINT8_t pad[56];
		} v;
	} vendor;
} __attribute__ (( packed ));

typedef struct bootph BOOTPLAYER_t;

/** @} */ /* pxenv_get_cached_info */

/** @defgroup pxenv_restart_tftp PXENV_RESTART_TFTP
 *
 *  RESTART TFTP
 *
 *  @{
 */

/** PXE API function code for pxenv_restart_tftp() */
#define	PXENV_RESTART_TFTP		0x0073

/** Parameter block for pxenv_restart_tftp() */
struct s_PXENV_TFTP_READ_FILE;

typedef struct s_PXENV_RESTART_TFTP PXENV_RESTART_TFTP_t;

/** @} */ /* pxenv_restart_tftp */

/** @defgroup pxenv_start_undi PXENV_START_UNDI
 *
 *  START UNDI
 *
 *  @{
 */

/** PXE API function code for pxenv_start_undi() */
#define	PXENV_START_UNDI		0x0000

/** Parameter block for pxenv_start_undi() */
struct s_PXENV_START_UNDI {
	PXENV_STATUS_t Status;			/**< PXE status code */
	/** %ax register as passed to the Option ROM initialisation routine.
	 *
	 * For a PCI device, this should contain the bus:dev:fn value
	 * that uniquely identifies the PCI device in the system.  For
	 * a non-PCI device, this field is not defined.
	 */
	UINT16_t AX;
	/** %bx register as passed to the Option ROM initialisation routine.
	 *
	 * For an ISAPnP device, this should contain the Card Select
	 * Number assigned to the ISAPnP card.  For non-ISAPnP
	 * devices, this should contain 0xffff.
	 */
	UINT16_t BX;
	/** %dx register as passed to the Option ROM initialisation routine.
	 *
	 * For an ISAPnP device, this should contain the ISAPnP Read
	 * Port address as currently set in all ISAPnP cards.  If
	 * there are no ISAPnP cards, this should contain 0xffff.  (If
	 * this is a non-ISAPnP device, but there are ISAPnP cards in
	 * the system, this value is not well defined.)
	 */
	UINT16_t DX;
	/** %di register as passed to the Option ROM initialisation routine.
	 *
	 * This contains the #OFF16_t portion of a struct #s_SEGOFF16
	 * that points to the System BIOS Plug and Play Installation
	 * Check Structure.  (Refer to section 4.4 of the Plug and
	 * Play BIOS specification for a description of this
	 * structure.)
	 *
	 * @note The PXE specification defines the type of this field
	 * as #UINT16_t.  For x86, #OFF16_t and #UINT16_t are
	 * equivalent anyway; for other architectures #OFF16_t makes
	 * more sense.
	 */
	OFF16_t DI;
	/** %es register as passed to the Option ROM initialisation routine.
	 *
	 * This contains the #SEGSEL_t portion of a struct #s_SEGOFF16
	 * that points to the System BIOS Plug and Play Installation
	 * Check Structure.  (Refer to section 4.4 of the Plug and
	 * Play BIOS specification for a description of this
	 * structure.)
	 *
	 * @note The PXE specification defines the type of this field
	 * as #UINT16_t.  For x86, #SEGSEL_t and #UINT16_t are
	 * equivalent anyway; for other architectures #SEGSEL_t makes
	 * more sense.
	 */
	SEGSEL_t ES;
} __attribute__ (( packed ));

typedef struct s_PXENV_START_UNDI PXENV_START_UNDI_t;

/** @} */ /* pxenv_start_undi */

/** @defgroup pxenv_stop_undi PXENV_STOP_UNDI
 *
 *  STOP UNDI
 *
 *  @{
 */

/** PXE API function code for pxenv_stop_undi() */
#define	PXENV_STOP_UNDI			0x0015

/** Parameter block for pxenv_stop_undi() */
struct s_PXENV_STOP_UNDI {
	PXENV_STATUS_t Status;			/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_STOP_UNDI PXENV_STOP_UNDI_t;

/** @} */ /* pxenv_stop_undi */

/** @defgroup pxenv_start_base PXENV_START_BASE
 *
 *  START BASE
 *
 *  @{
 */

/** PXE API function code for pxenv_start_base() */
#define	PXENV_START_BASE		0x0075

/** Parameter block for pxenv_start_base() */
struct s_PXENV_START_BASE {
	PXENV_STATUS_t Status;			/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_START_BASE PXENV_START_BASE_t;

/** @} */ /* pxenv_start_base */

/** @defgroup pxenv_stop_base PXENV_STOP_BASE
 *
 *  STOP BASE
 *
 *  @{
 */

/** PXE API function code for pxenv_stop_base() */
#define	PXENV_STOP_BASE			0x0076

/** Parameter block for pxenv_stop_base() */
struct s_PXENV_STOP_BASE {
	PXENV_STATUS_t Status;			/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_STOP_BASE PXENV_STOP_BASE_t;

/** @} */ /* pxenv_stop_base */

/** @} */ /* pxe_preboot_api */

/** @defgroup pxe_tftp_api PXE TFTP API
 *
 * Download files via TFTP or MTFTP
 *
 * @{
 */

/** @defgroup pxenv_tftp_open PXENV_TFTP_OPEN
 *
 *  TFTP OPEN
 *
 *  @{
 */

/** PXE API function code for pxenv_tftp_open() */
#define	PXENV_TFTP_OPEN			0x0020

/** Parameter block for pxenv_tftp_open() */
struct s_PXENV_TFTP_OPEN {
	PXENV_STATUS_t Status;			/**< PXE status code */
	IP4_t ServerIPAddress;			/**< TFTP server IP address */
	IP4_t GatewayIPAddress;			/**< Relay agent IP address */
	UINT8_t FileName[128];			/**< File name */
	UDP_PORT_t TFTPPort;			/**< TFTP server UDP port */
	/** Requested size of TFTP packets
	 *
	 * This is the TFTP "blksize" option.  This must be at least
	 * 512, since servers that do not support TFTP options cannot
	 * negotiate blocksizes smaller than this.
	 */
	UINT16_t PacketSize;
} __attribute__ (( packed ));

typedef struct s_PXENV_TFTP_OPEN PXENV_TFTP_OPEN_t;

/** @} */ /* pxenv_tftp_open */

/** @defgroup pxenv_tftp_close PXENV_TFTP_CLOSE
 *
 *  TFTP CLOSE
 *
 *  @{
 */

/** PXE API function code for pxenv_tftp_close() */
#define	PXENV_TFTP_CLOSE		0x0021

/** Parameter block for pxenv_tftp_close() */
struct s_PXENV_TFTP_CLOSE {
	PXENV_STATUS_t Status;			/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_TFTP_CLOSE PXENV_TFTP_CLOSE_t;

/** @} */ /* pxenv_tftp_close */

/** @defgroup pxenv_tftp_read PXENV_TFTP_READ
 *
 *  TFTP READ
 *
 *  @{
 */

/** PXE API function code for pxenv_tftp_read() */
#define	PXENV_TFTP_READ			0x0022

/** Parameter block for pxenv_tftp_read() */
struct s_PXENV_TFTP_READ {
	PXENV_STATUS_t Status;			/**< PXE status code */
	UINT16_t PacketNumber;			/**< TFTP packet number */
	UINT16_t BufferSize;			/**< Size of data buffer */
	SEGOFF16_t Buffer;			/**< Address of data buffer */
} __attribute__ (( packed ));

typedef struct s_PXENV_TFTP_READ PXENV_TFTP_READ_t;

/** @} */ /* pxenv_tftp_read */

/** @defgroup pxenv_tftp_read_file PXENV_TFTP_READ_FILE
 *
 *  TFTP/MTFTP READ FILE
 *
 *  @{
 */

/** PXE API function code for pxenv_tftp_read_file() */
#define	PXENV_TFTP_READ_FILE		0x0023

/** Parameter block for pxenv_tftp_read_file() */
struct s_PXENV_TFTP_READ_FILE {
	PXENV_STATUS_t Status;			/**< PXE status code */
	UINT8_t FileName[128];			/**< File name */
	UINT32_t BufferSize;			/**< Size of data buffer */
	ADDR32_t Buffer;			/**< Address of data buffer */
	IP4_t ServerIPAddress;			/**< TFTP server IP address */
	IP4_t GatewayIPAddress;			/**< Relay agent IP address */
	/** File multicast IP address */
	IP4_t McastIPAddress;
	/** Client multicast listening port */
	UDP_PORT_t TFTPClntPort;
	/** Server multicast listening port */
	UDP_PORT_t TFTPSrvPort;
	/** TFTP open timeout.
	 *
	 * This is the timeout for receiving the first DATA or ACK
	 * packets during the MTFTP Listen phase.
	 */
	UINT16_t TFTPOpenTimeOut;
	/** TFTP reopen timeout.
	 *
	 * This is the timeout for receiving an ACK packet while in
	 * the MTFTP Listen phase (when at least one ACK packet has
	 * already been seen).
	 */
	UINT16_t TFTPReopenDelay;
} __attribute__ (( packed ));

typedef struct s_PXENV_TFTP_READ_FILE PXENV_TFTP_READ_FILE_t;

/** @} */ /* pxenv_tftp_read_file */

/** @defgroup pxenv_tftp_get_fsize PXENV_TFTP_GET_FSIZE
 *
 *  TFTP GET FILE SIZE
 *
 *  @{
 */

/** PXE API function code for pxenv_tftp_get_fsize() */
#define	PXENV_TFTP_GET_FSIZE		0x0025

/** Parameter block for pxenv_tftp_get_fsize() */
struct s_PXENV_TFTP_GET_FSIZE {
	PXENV_STATUS_t Status;			/**< PXE status code */
	IP4_t ServerIPAddress;			/**< TFTP server IP address */
	IP4_t GatewayIPAddress;			/**< Relay agent IP address */
	UINT8_t FileName[128];			/**< File name */
	UINT32_t FileSize;			/**< Size of the file */
} __attribute__ (( packed ));

typedef struct s_PXENV_TFTP_GET_FSIZE PXENV_TFTP_GET_FSIZE_t;

/** @} */ /* pxenv_tftp_get_fsize */

/** @} */ /* pxe_tftp_api */

/** @defgroup pxe_udp_api PXE UDP API
 *
 * Transmit and receive UDP packets
 *
 * @{
 */

/** @defgroup pxenv_udp_open PXENV_UDP_OPEN
 *
 *  UDP OPEN
 *
 *  @{
 */

/** PXE API function code for pxenv_udp_open() */
#define	PXENV_UDP_OPEN			0x0030

/** Parameter block for pxenv_udp_open() */
struct s_PXENV_UDP_OPEN {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	IP4_t		src_ip;		/**< IP address of this station */
} __attribute__ (( packed ));

typedef struct s_PXENV_UDP_OPEN PXENV_UDP_OPEN_t;

/** @} */ /* pxenv_udp_open */

/** @defgroup pxenv_udp_close PXENV_UDP_CLOSE
 *
 *  UDP CLOSE
 *
 *  @{
 */

/** PXE API function code for pxenv_udp_close() */
#define	PXENV_UDP_CLOSE			0x0031

/** Parameter block for pxenv_udp_close() */
struct s_PXENV_UDP_CLOSE {
	PXENV_STATUS_t	Status;		/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_UDP_CLOSE PXENV_UDP_CLOSE_t;

/** @} */ /* pxenv_udp_close */

/** @defgroup pxenv_udp_write PXENV_UDP_WRITE
 *
 *  UDP WRITE
 *
 *  @{
 */

/** PXE API function code for pxenv_udp_write() */
#define	PXENV_UDP_WRITE			0x0033

/** Parameter block for pxenv_udp_write() */
struct s_PXENV_UDP_WRITE {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	IP4_t		ip;		/**< Destination IP address */
	IP4_t		gw;		/**< Relay agent IP address */
	UDP_PORT_t	src_port;	/**< Source UDP port */
	UDP_PORT_t	dst_port;	/**< Destination UDP port */
	UINT16_t	buffer_size;	/**< UDP payload buffer size */
	SEGOFF16_t	buffer;		/**< UDP payload buffer address */
} __attribute__ (( packed ));

typedef struct s_PXENV_UDP_WRITE PXENV_UDP_WRITE_t;

/** @} */ /* pxenv_udp_write */

/** @defgroup pxenv_udp_read PXENV_UDP_READ
 *
 *  UDP READ
 *
 *  @{
 */

/** PXE API function code for pxenv_udp_read() */
#define	PXENV_UDP_READ			0x0032

/** Parameter block for pxenv_udp_read() */
struct s_PXENV_UDP_READ {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	IP4_t		src_ip;		/**< Source IP address */
	IP4_t		dest_ip;	/**< Destination IP address */
	UDP_PORT_t	s_port;		/**< Source UDP port */
	UDP_PORT_t	d_port;		/**< Destination UDP port */
	UINT16_t	buffer_size;	/**< UDP payload buffer size */
	SEGOFF16_t	buffer;		/**< UDP payload buffer address */
} __attribute__ (( packed ));

typedef struct s_PXENV_UDP_READ PXENV_UDP_READ_t;

/** @} */ /* pxenv_udp_read */

/** @} */ /* pxe_udp_api */

/** @defgroup pxe_undi_api PXE UNDI API
 *
 * Direct control of the network interface card
 *
 * @{
 */

/** @defgroup pxenv_undi_startup PXENV_UNDI_STARTUP
 *
 *  UNDI STARTUP
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_startup() */
#define	PXENV_UNDI_STARTUP		0x0001

#define PXENV_BUS_ISA		0	/**< ISA bus type */
#define PXENV_BUS_EISA		1	/**< EISA bus type */
#define PXENV_BUS_MCA		2	/**< MCA bus type */
#define PXENV_BUS_PCI		3	/**< PCI bus type */
#define PXENV_BUS_VESA		4	/**< VESA bus type */
#define PXENV_BUS_PCMCIA	5	/**< PCMCIA bus type */

/** Parameter block for pxenv_undi_startup() */
struct s_PXENV_UNDI_STARTUP {
	PXENV_STATUS_t	Status;		/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_STARTUP PXENV_UNDI_STARTUP_t;

/** @} */ /* pxenv_undi_startup */

/** @defgroup pxenv_undi_cleanup PXENV_UNDI_CLEANUP
 *
 *  UNDI CLEANUP
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_cleanup() */
#define	PXENV_UNDI_CLEANUP		0x0002

/** Parameter block for pxenv_undi_cleanup() */
struct s_PXENV_UNDI_CLEANUP {
	PXENV_STATUS_t	Status;		/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_CLEANUP PXENV_UNDI_CLEANUP_t;

/** @} */ /* pxenv_undi_cleanup */

/** @defgroup pxenv_undi_initialize PXENV_UNDI_INITIALIZE
 *
 *  UNDI INITIALIZE
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_initialize() */
#define	PXENV_UNDI_INITIALIZE		0x0003

/** Parameter block for pxenv_undi_initialize() */
struct s_PXENV_UNDI_INITIALIZE {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	/** NDIS 2.0 configuration information, or NULL
	 *
	 * This is a pointer to the data structure returned by the
	 * NDIS 2.0 GetProtocolManagerInfo() API call.  The data
	 * structure is documented, in a rather haphazard way, in
	 * section 4-17 of the NDIS 2.0 specification.
	 */
	ADDR32_t ProtocolIni;
	UINT8_t reserved[8];		/**< Must be zero */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_INITIALIZE PXENV_UNDI_INITIALIZE_t;

/** @} */ /* pxenv_undi_initialize */

/** @defgroup pxenv_undi_reset_adapter PXENV_UNDI_RESET_ADAPTER
 *
 *  UNDI RESET ADAPTER
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_reset_adapter() */
#define	PXENV_UNDI_RESET_ADAPTER	0x0004

/** Maximum number of multicast MAC addresses */
#define MAXNUM_MCADDR	8

/** List of multicast MAC addresses */
struct s_PXENV_UNDI_MCAST_ADDRESS {
	/** Number of multicast MAC addresses */
	UINT16_t MCastAddrCount;
	/** List of up to #MAXNUM_MCADDR multicast MAC addresses */
	MAC_ADDR_t McastAddr[MAXNUM_MCADDR];
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_MCAST_ADDRESS PXENV_UNDI_MCAST_ADDRESS_t;

/** Parameter block for pxenv_undi_reset_adapter() */
struct s_PXENV_UNDI_RESET {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	/** Multicast MAC addresses */
	struct s_PXENV_UNDI_MCAST_ADDRESS R_Mcast_Buf;
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_RESET PXENV_UNDI_RESET_t;

/** @} */ /* pxenv_undi_reset_adapter */

/** @defgroup pxenv_undi_shutdown PXENV_UNDI_SHUTDOWN
 *
 *  UNDI SHUTDOWN
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_shutdown() */
#define	PXENV_UNDI_SHUTDOWN		0x0005

/** Parameter block for pxenv_undi_shutdown() */
struct s_PXENV_UNDI_SHUTDOWN {
	PXENV_STATUS_t	Status;		/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_SHUTDOWN PXENV_UNDI_SHUTDOWN_t;

/** @} */ /* pxenv_undi_shutdown */

/** @defgroup pxenv_undi_open PXENV_UNDI_OPEN
 *
 *  UNDI OPEN
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_open() */
#define	PXENV_UNDI_OPEN			0x0006

/** Accept "directed" packets
 *
 * These are packets addresses to either this adapter's MAC address or
 * to any of the configured multicast MAC addresses (see
 * #s_PXENV_UNDI_MCAST_ADDRESS).
 */
#define FLTR_DIRECTED	0x0001
/** Accept broadcast packets */
#define FLTR_BRDCST	0x0002
/** Accept all packets; listen in promiscuous mode */
#define FLTR_PRMSCS	0x0004
/** Accept source-routed packets */
#define FLTR_SRC_RTG	0x0008

/** Parameter block for pxenv_undi_open() */
struct s_PXENV_UNDI_OPEN {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	/** Open flags as defined in NDIS 2.0
	 *
	 * This is the OpenOptions field as passed to the NDIS 2.0
	 * OpenAdapter() API call.  It is defined to be "adapter
	 * specific", though 0 is guaranteed to be a valid value.
	 */
	UINT16_t OpenFlag;
	/** Receive packet filter
	 *
	 * This is the bitwise-OR of any of the following flags:
	 * #FLTR_DIRECTED, #FLTR_BRDCST, #FLTR_PRMSCS and
	 * #FLTR_SRC_RTG.
	 */
	UINT16_t PktFilter;
	/** Multicast MAC addresses */
	struct s_PXENV_UNDI_MCAST_ADDRESS R_Mcast_Buf;
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_OPEN PXENV_UNDI_OPEN_t;

/** @} */ /* pxenv_undi_open */

/** @defgroup pxenv_undi_close PXENV_UNDI_CLOSE
 *
 *  UNDI CLOSE
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_close() */
#define	PXENV_UNDI_CLOSE		0x0007

/** Parameter block for pxenv_undi_close() */
struct s_PXENV_UNDI_CLOSE {
	PXENV_STATUS_t	Status;		/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_CLOSE PXENV_UNDI_CLOSE_t;

/** @} */ /* pxenv_undi_close */

/** @defgroup pxenv_undi_transmit PXENV_UNDI_TRANSMIT
 *
 *  UNDI TRANSMIT PACKET
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_transmit() */
#define	PXENV_UNDI_TRANSMIT		0x0008

#define P_UNKNOWN	0		/**< Media header already filled in */
#define P_IP		1		/**< IP protocol */
#define P_ARP		2		/**< ARP protocol */
#define P_RARP		3		/**< RARP protocol */
#define P_OTHER		4		/**< Other protocol */

#define XMT_DESTADDR	0x0000		/**< Unicast packet */
#define XMT_BROADCAST	0x0001		/**< Broadcast packet */

/** Maximum number of data blocks in a transmit buffer descriptor */
#define MAX_DATA_BLKS	8

/** A transmit buffer descriptor, as pointed to by s_PXENV_UNDI_TRANSMIT::TBD
 */
struct s_PXENV_UNDI_TBD {
	UINT16_t ImmedLength;		/**< Length of the transmit buffer */
	SEGOFF16_t Xmit;		/**< Address of the transmit buffer */
	UINT16_t DataBlkCount;
	/** Array of up to #MAX_DATA_BLKS additional transmit buffers */
	struct DataBlk {
		/** Always 1
		 *
		 * A value of 0 would indicate that #TDDataPtr were an
		 * #ADDR32_t rather than a #SEGOFF16_t.  The PXE
		 * specification version 2.1 explicitly states that
		 * this is not supported; #TDDataPtr will always be a
		 * #SEGOFF16_t.
		 */
		UINT8_t TDPtrType;
		UINT8_t TDRsvdByte;	/**< Must be zero */
		UINT16_t TDDataLen;	/**< Length of this transmit buffer */
		SEGOFF16_t TDDataPtr;	/**< Address of this transmit buffer */
	} DataBlock[MAX_DATA_BLKS];
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_TBD PXENV_UNDI_TBD_t;

/** Parameter block for pxenv_undi_transmit() */
struct s_PXENV_UNDI_TRANSMIT {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	/** Protocol
	 *
	 * Valid values are #P_UNKNOWN, #P_IP, #P_ARP or #P_RARP.  If
	 * the caller has already filled in the media header, this
	 * field must be set to #P_UNKNOWN.
	 */
	UINT8_t Protocol;
	/** Unicast/broadcast flag
	 *
	 * Valid values are #XMT_DESTADDR or #XMT_BROADCAST.
	 */
	UINT8_t XmitFlag;
	SEGOFF16_t DestAddr;		/**< Destination MAC address */
	/** Address of the Transmit Buffer Descriptor
	 *
	 * This is a pointer to a struct s_PXENV_UNDI_TBD.
	 */
	SEGOFF16_t TBD;
	UINT32_t Reserved[2];		/**< Must be zero */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_TRANSMIT PXENV_UNDI_TRANSMIT_t;

/** @} */ /* pxenv_undi_transmit */

/** @defgroup pxenv_undi_set_mcast_address PXENV_UNDI_SET_MCAST_ADDRESS
 *
 *  UNDI SET MULTICAST ADDRESS
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_set_mcast_address() */
#define	PXENV_UNDI_SET_MCAST_ADDRESS	0x0009

/** Parameter block for pxenv_undi_set_mcast_address() */
struct s_PXENV_UNDI_SET_MCAST_ADDRESS {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	/** List of multicast addresses */
	struct s_PXENV_UNDI_MCAST_ADDRESS R_Mcast_Buf;
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_SET_MCAST_ADDRESS PXENV_UNDI_SET_MCAST_ADDRESS_t;

/** @} */ /* pxenv_undi_set_mcast_address */

/** @defgroup pxenv_undi_set_station_address PXENV_UNDI_SET_STATION_ADDRESS
 *
 *  UNDI SET STATION ADDRESS
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_set_station_address() */
#define	PXENV_UNDI_SET_STATION_ADDRESS	0x000a

/** Parameter block for pxenv_undi_set_station_address() */
struct s_PXENV_UNDI_SET_STATION_ADDRESS {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	MAC_ADDR_t StationAddress;	/**< Station MAC address */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_SET_STATION_ADDRESS PXENV_UNDI_SET_STATION_ADDRESS_t;

/** @} */ /* pxenv_undi_set_station_address */

/** @defgroup pxenv_undi_set_packet_filter PXENV_UNDI_SET_PACKET_FILTER
 *
 *  UNDI SET PACKET FILTER
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_set_packet_filter() */
#define	PXENV_UNDI_SET_PACKET_FILTER	0x000b

/** Parameter block for pxenv_undi_set_packet_filter() */
struct s_PXENV_UNDI_SET_PACKET_FILTER {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	/** Receive packet filter
	 *
	 * This field takes the same values as
	 * s_PXENV_UNDI_OPEN::PktFilter.
	 *
	 * @note Yes, this field is a different size to
	 * s_PXENV_UNDI_OPEN::PktFilter.  Blame "the managers at Intel
	 * who apparently let a consultant come up with the spec
	 * without any kind of adult supervision" (quote from hpa).
	 */
	UINT8_t filter;
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_SET_PACKET_FILTER PXENV_UNDI_SET_PACKET_FILTER_t;

/** @} */ /* pxenv_undi_set_packet_filter */

/** @defgroup pxenv_undi_get_information PXENV_UNDI_GET_INFORMATION
 *
 *  UNDI GET INFORMATION
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_get_information() */
#define	PXENV_UNDI_GET_INFORMATION	0x000c

#define ETHER_TYPE		1	/**< Ethernet (10Mb) */
#define EXP_ETHER_TYPE		2	/**< Experimental Ethernet (3Mb) */
#define AX25_TYPE		3	/**< Amateur Radio AX.25 */
#define TOKEN_RING_TYPE		4	/**< Proteon ProNET Token Ring */
#define CHAOS_TYPE		5	/**< Chaos */
#define IEEE_TYPE		6	/**< IEEE 802 Networks */
#define ARCNET_TYPE		7	/**< ARCNET */

/** Parameter block for pxenv_undi_get_information() */
struct s_PXENV_UNDI_GET_INFORMATION {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	UINT16_t BaseIo;		/**< I/O base address */
	UINT16_t IntNumber;		/**< IRQ number */
	UINT16_t MaxTranUnit;		/**< Adapter MTU */
	/** Hardware type
	 *
	 * Valid values are defined in RFC1010 ("Assigned numbers"),
	 * and are #ETHER_TYPE, #EXP_ETHER_TYPE, #AX25_TYPE,
	 * #TOKEN_RING_TYPE, #CHAOS_TYPE, #IEEE_TYPE or #ARCNET_TYPE.
	 */
	UINT16_t HwType;
	UINT16_t HwAddrLen;		/**< MAC address length */
	MAC_ADDR_t CurrentNodeAddress;	/**< Current MAC address */
	MAC_ADDR_t PermNodeAddress;	/**< Permanent (EEPROM) MAC address */
	SEGSEL_t ROMAddress;		/**< Real-mode ROM segment address */
	UINT16_t RxBufCt;		/**< Receive queue length */
	UINT16_t TxBufCt;		/**< Transmit queue length */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_GET_INFORMATION PXENV_UNDI_GET_INFORMATION_t;

/** @} */ /* pxenv_undi_get_information */

/** @defgroup pxenv_undi_get_statistics PXENV_UNDI_GET_STATISTICS
 *
 *  UNDI GET STATISTICS
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_get_statistics() */
#define	PXENV_UNDI_GET_STATISTICS	0x000d

/** Parameter block for pxenv_undi_get_statistics() */
struct s_PXENV_UNDI_GET_STATISTICS {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	UINT32_t XmtGoodFrames;		/**< Successful transmission count */
	UINT32_t RcvGoodFrames;		/**< Successful reception count */
	UINT32_t RcvCRCErrors;		/**< Receive CRC error count */
	UINT32_t RcvResourceErrors;	/**< Receive queue overflow count */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_GET_STATISTICS PXENV_UNDI_GET_STATISTICS_t;

/** @} */ /* pxenv_undi_get_statistics */

/** @defgroup pxenv_undi_clear_statistics PXENV_UNDI_CLEAR_STATISTICS
 *
 *  UNDI CLEAR STATISTICS
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_clear_statistics() */
#define	PXENV_UNDI_CLEAR_STATISTICS	0x000e

/** Parameter block for pxenv_undi_clear_statistics() */
struct s_PXENV_UNDI_CLEAR_STATISTICS {
	PXENV_STATUS_t	Status;		/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_CLEAR_STATISTICS PXENV_UNDI_CLEAR_STATISTICS_t;

/** @} */ /* pxenv_undi_clear_statistics */

/** @defgroup pxenv_undi_initiate_diags PXENV_UNDI_INITIATE_DIAGS
 *
 *  UNDI INITIATE DIAGS
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_initiate_diags() */
#define	PXENV_UNDI_INITIATE_DIAGS	0x000f

/** Parameter block for pxenv_undi_initiate_diags() */
struct s_PXENV_UNDI_INITIATE_DIAGS {
	PXENV_STATUS_t	Status;		/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_INITIATE_DIAGS PXENV_UNDI_INITIATE_DIAGS_t;

/** @} */ /* pxenv_undi_initiate_diags */

/** @defgroup pxenv_undi_force_interrupt PXENV_UNDI_FORCE_INTERRUPT
 *
 *  UNDI FORCE INTERRUPT
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_force_interrupt() */
#define	PXENV_UNDI_FORCE_INTERRUPT	0x0010

/** Parameter block for pxenv_undi_force_interrupt() */
struct s_PXENV_UNDI_FORCE_INTERRUPT {
	PXENV_STATUS_t	Status;		/**< PXE status code */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_FORCE_INTERRUPT PXENV_UNDI_FORCE_INTERRUPT_t;

/** @} */ /* pxenv_undi_force_interrupt */

/** @defgroup pxenv_undi_get_mcast_address PXENV_UNDI_GET_MCAST_ADDRESS
 *
 *  UNDI GET MULTICAST ADDRESS
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_get_mcast_address() */
#define	PXENV_UNDI_GET_MCAST_ADDRESS	0x0011

/** Parameter block for pxenv_undi_get_mcast_address() */
struct s_PXENV_UNDI_GET_MCAST_ADDRESS {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	IP4_t InetAddr;			/**< Multicast IP address */
	MAC_ADDR_t MediaAddr;		/**< Multicast MAC address */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_GET_MCAST_ADDRESS PXENV_UNDI_GET_MCAST_ADDRESS_t;

/** @} */ /* pxenv_undi_get_mcast_address */

/** @defgroup pxenv_undi_get_nic_type PXENV_UNDI_GET_NIC_TYPE
 *
 *  UNDI GET NIC TYPE
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_get_nic_type() */
#define	PXENV_UNDI_GET_NIC_TYPE		0x0012

#define PCI_NIC		2		/**< PCI network card */
#define PnP_NIC		3		/**< ISAPnP network card */
#define CardBus_NIC	4		/**< CardBus network card */

/** Information for a PCI or equivalent NIC */
struct pci_nic_info {
	UINT16_t Vendor_ID;		/**< PCI vendor ID */
	UINT16_t Dev_ID;		/**< PCI device ID */
	UINT8_t Base_Class;		/**< PCI base class */
	UINT8_t Sub_Class;		/**< PCI sub class */
	UINT8_t Prog_Intf;		/**< PCI programming interface */
	UINT8_t Rev;			/**< PCI revision */
	UINT16_t BusDevFunc;		/**< PCI bus:dev:fn address */
	UINT16_t SubVendor_ID;		/**< PCI subvendor ID */
	UINT16_t SubDevice_ID;		/**< PCI subdevice ID */
} __attribute__ (( packed ));
 
/** Information for an ISAPnP or equivalent NIC */
struct pnp_nic_info {
	UINT32_t EISA_Dev_ID;		/**< EISA device ID */
	UINT8_t Base_Class;		/**< Base class */
	UINT8_t Sub_Class;		/**< Sub class */
	UINT8_t Prog_Intf;		/**< Programming interface */
	/** Card Select Number assigned to card */
	UINT16_t CardSelNum;
} __attribute__ (( packed ));

/** Parameter block for pxenv_undi_get_nic_type() */
struct s_PXENV_UNDI_GET_NIC_TYPE {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	/** NIC type
	 *
	 * Valid values are #PCI_NIC, #PnP_NIC or #CardBus_NIC.
	 */
	UINT8_t NicType;
	/** NIC information */
	union nic_type_info {
		/** NIC information (if #NicType==#PCI_NIC) */
		struct pci_nic_info pci;
		/** NIC information (if #NicType==#CardBus_NIC) */
		struct pci_nic_info cardbus;
		/** NIC information (if #NicType==#PnP_NIC) */
		struct pnp_nic_info pnp;
	} info;
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_GET_NIC_TYPE PXENV_UNDI_GET_NIC_TYPE_t;

/** @} */ /* pxenv_undi_get_nic_type */

/** @defgroup pxenv_undi_get_iface_info PXENV_UNDI_GET_IFACE_INFO
 *
 *  UNDI GET IFACE INFO
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_get_iface_info() */
#define	PXENV_UNDI_GET_IFACE_INFO	0x0013

/** Broadcast supported */
#define SUPPORTED_BROADCAST		0x0001
/** Multicast supported */
#define SUPPORTED_MULTICAST		0x0002
/** Functional/group addressing supported */
#define SUPPORTED_GROUP			0x0004
/** Promiscuous mode supported */
#define SUPPORTED_PROMISCUOUS		0x0008
/** Software settable station address */
#define SUPPORTED_SET_STATION_ADDRESS	0x0010
/** InitiateDiagnostics supported */
#define SUPPORTED_DIAGNOSTICS		0x0040
/** Reset MAC supported */
#define SUPPORTED_RESET			0x0400
/** Open / Close Adapter supported */
#define SUPPORTED_OPEN_CLOSE		0x0800
/** Interrupt Request supported */
#define SUPPORTED_IRQ			0x1000

/** Parameter block for pxenv_undi_get_iface_info() */
struct s_PXENV_UNDI_GET_IFACE_INFO {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	/** Interface type
	 *
	 * This is defined in the NDIS 2.0 specification to be one of
	 * the strings "802.3", "802.4", "802.5", "802.6", "DIX",
	 * "DIX+802.3", "APPLETALK", "ARCNET", "FDDI", "SDLC", "BSC",
	 * "HDLC", or "ISDN".
	 *
	 * "Normal" Ethernet, for various historical reasons, is
	 * "DIX+802.3".
	 */
	UINT8_t IfaceType[16];
	UINT32_t LinkSpeed;		/**< Link speed, in bits per second */
	/** Service flags
	 *
	 * These are the "service flags" defined in the "MAC
	 * Service-Specific Characteristics" table in the NDIS 2.0
	 * specification.  Almost all of them are irrelevant to PXE.
	 */
	UINT32_t ServiceFlags;
	UINT32_t Reserved[4];		/**< Must be zero */
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_GET_IFACE_INFO PXENV_UNDI_GET_IFACE_INFO_t;

/** @} */ /* pxenv_undi_get_iface_info */

/** @defgroup pxenv_undi_get_state PXENV_UNDI_GET_STATE
 *
 *  UNDI GET STATE
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_get_state() */
#define PXENV_UNDI_GET_STATE		0x0015

/** pxenv_start_undi() has been called */
#define PXE_UNDI_GET_STATE_STARTED	1
/** pxenv_undi_initialize() has been called */
#define PXE_UNDI_GET_STATE_INITIALIZED	2
/** pxenv_undi_open() has been called */
#define PXE_UNDI_GET_STATE_OPENED	3

/** Parameter block for pxenv_undi_get_state() */
struct s_PXENV_UNDI_GET_STATE {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	/** Current state of the UNDI driver
	 *
	 * Valid values are #PXE_UNDI_GET_STATE_STARTED,
	 * #PXE_UNDI_GET_STATE_INITIALIZED or
	 * #PXE_UNDI_GET_STATE_OPENED.
	 */
	UINT8_t UNDIstate;
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_GET_STATE PXENV_UNDI_GET_STATE_t;

/** @} */ /* pxenv_undi_get_state */

/** @defgroup pxenv_undi_isr PXENV_UNDI_ISR
 *
 *  UNDI ISR
 *
 *  @{
 */

/** PXE API function code for pxenv_undi_isr() */
#define	PXENV_UNDI_ISR			0x0014

/** Determine whether or not this is our interrupt */
#define PXENV_UNDI_ISR_IN_START		1
/** Start processing interrupt */
#define PXENV_UNDI_ISR_IN_PROCESS	2
/** Continue processing interrupt */
#define PXENV_UNDI_ISR_IN_GET_NEXT	3
/** This interrupt was ours */
#define PXENV_UNDI_ISR_OUT_OURS		0
/** This interrupt was not ours */
#define PXENV_UNDI_ISR_OUT_NOT_OURS	1
/** Finished processing interrupt */
#define PXENV_UNDI_ISR_OUT_DONE		0
/** A packet transmission has completed */
#define PXENV_UNDI_ISR_OUT_TRANSMIT	2
/** A packet has been received */
#define PXENV_UNDI_ISR_OUT_RECEIVE	3
/** We are already in the middle of processing an interrupt */
#define PXENV_UNDI_ISR_OUT_BUSY		4

/** Unicast packet (or packet captured in promiscuous mode) */
#define P_DIRECTED	0
/** Broadcast packet */
#define P_BROADCAST	1
/** Multicast packet */
#define P_MULTICAST	2

/** Parameter block for pxenv_undi_isr() */
struct s_PXENV_UNDI_ISR {
	PXENV_STATUS_t	Status;		/**< PXE status code */
	/** Function flag
	 *
	 * Valid values are #PXENV_UNDI_ISR_IN_START,
	 * #PXENV_UNDI_ISR_IN_PROCESS, #PXENV_UNDI_ISR_IN_GET_NEXT,
	 * #PXENV_UNDI_ISR_OUT_OURS, #PXENV_UNDI_ISR_OUT_NOT_OURS,
	 * #PXENV_UNDI_ISR_OUT_DONE, #PXENV_UNDI_ISR_OUT_TRANSMIT,
	 * #PXENV_UNDI_ISR_OUT_RECEIVE or #PXENV_UNDI_ISR_OUT_BUSY.
	 */
	UINT16_t FuncFlag;
	UINT16_t BufferLength;		/**< Data buffer length */
	UINT16_t FrameLength;		/**< Total frame length */
	UINT16_t FrameHeaderLength;	/**< Frame header length */
	SEGOFF16_t Frame;		/**< Data buffer address */
	/** Protocol type
	 *
	 * Valid values are #P_IP, #P_ARP, #P_RARP or #P_OTHER.
	 */
	UINT8_t ProtType;
	/** Packet type
	 *
	 * Valid values are #P_DIRECTED, #P_BROADCAST or #P_MULTICAST.
	 */
	UINT8_t PktType;
} __attribute__ (( packed ));

typedef struct s_PXENV_UNDI_ISR PXENV_UNDI_ISR_t;

/** @} */ /* pxenv_undi_isr */

/** @} */ /* pxe_undi_api */

/** @defgroup pxe_file_api PXE FILE API
 *
 * POSIX-like file operations
 *
 * @{
 */

/** Minimum possible opcode used within PXE FILE API */
#define PXENV_FILE_MIN 0x00e0

/** Minimum possible opcode used within PXE FILE API */
#define PXENV_FILE_MAX 0x00ef

/** @defgroup pxenv_file_open PXENV_FILE_OPEN
 *
 * FILE OPEN
 *
 * @{
 */

/** PXE API function code for pxenv_file_open() */
#define PXENV_FILE_OPEN			0x00e0

/** Parameter block for pxenv_file_open() */
struct s_PXENV_FILE_OPEN {
	PXENV_STATUS_t Status;		/**< PXE status code */
	UINT16_t FileHandle;		/**< File handle */
	SEGOFF16_t FileName;		/**< File URL */
	UINT32_t Reserved;		/**< Reserved */
} __attribute__ (( packed ));

typedef struct s_PXENV_FILE_OPEN PXENV_FILE_OPEN_t;

/** @} */ /* pxenv_file_open */

/** @defgroup pxenv_file_close PXENV_FILE_CLOSE
 *
 * FILE CLOSE
 *
 * @{
 */

/** PXE API function code for pxenv_file_close() */
#define PXENV_FILE_CLOSE		0x00e1

/** Parameter block for pxenv_file_close() */
struct s_PXENV_FILE_CLOSE {
	PXENV_STATUS_t Status;		/**< PXE status code */
	UINT16_t FileHandle;		/**< File handle */
} __attribute__ (( packed ));

typedef struct s_PXENV_FILE_CLOSE PXENV_FILE_CLOSE_t;

/** @} */ /* pxenv_file_close */

/** @defgroup pxenv_file_select PXENV_FILE_SELECT
 *
 * FILE SELECT
 *
 * @{
 */

/** PXE API function code for pxenv_file_select() */
#define PXENV_FILE_SELECT		0x00e2

/** File is ready for reading */
#define RDY_READ			0x0001

/** Parameter block for pxenv_file_select() */
struct s_PXENV_FILE_SELECT {
	PXENV_STATUS_t Status;		/**< PXE status code */
	UINT16_t FileHandle;		/**< File handle */
	UINT16_t Ready;			/**< Indication of readiness */
} __attribute__ (( packed ));

typedef struct s_PXENV_FILE_SELECT PXENV_FILE_SELECT_t;

/** @} */ /* pxenv_file_select */

/** @defgroup pxenv_file_read PXENV_FILE_READ
 *
 * FILE READ
 *
 * @{
 */

/** PXE API function code for pxenv_file_read() */
#define PXENV_FILE_READ		0x00e3

/** Parameter block for pxenv_file_read() */
struct s_PXENV_FILE_READ {
	PXENV_STATUS_t Status;		/**< PXE status code */
	UINT16_t FileHandle;		/**< File handle */
	UINT16_t BufferSize;		/**< Data buffer size */
	SEGOFF16_t Buffer;		/**< Data buffer */
} __attribute__ (( packed ));

typedef struct s_PXENV_FILE_READ PXENV_FILE_READ_t;

/** @} */ /* pxenv_file_read */

/** @defgroup pxenv_get_file_size PXENV_GET_FILE_SIZE
 *
 * GET FILE SIZE
 *
 * @{
 */

/** PXE API function code for pxenv_get_file_size() */
#define PXENV_GET_FILE_SIZE		0x00e4

/** Parameter block for pxenv_get_file_size() */
struct s_PXENV_GET_FILE_SIZE {
	PXENV_STATUS_t Status;		/**< PXE status code */
	UINT16_t FileHandle;		/**< File handle */
	UINT32_t FileSize;		/**< File size */
} __attribute__ (( packed ));

typedef struct s_PXENV_GET_FILE_SIZE PXENV_GET_FILE_SIZE_t;

/** @} */ /* pxenv_get_file_size */

/** @defgroup pxenv_file_exec PXENV_FILE_EXEC
 *
 * FILE EXEC
 *
 * @{
 */

/** PXE API function code for pxenv_file_exec() */
#define PXENV_FILE_EXEC			0x00e5

/** Parameter block for pxenv_file_exec() */
struct s_PXENV_FILE_EXEC {
	PXENV_STATUS_t Status;		/**< PXE status code */
	SEGOFF16_t Command;		/**< Command to execute */
} __attribute__ (( packed ));

typedef struct s_PXENV_FILE_EXEC PXENV_FILE_EXEC_t;

/** @} */ /* pxenv_file_exec */

/** @defgroup pxenv_file_api_check PXENV_FILE_API_CHECK
 *
 * FILE API CHECK
 *
 * @{
 */

/** PXE API function code for pxenv_file_api_check() */
#define PXENV_FILE_API_CHECK		0x00e6

/** Parameter block for pxenv_file_api_check() */
struct s_PXENV_FILE_API_CHECK {
	PXENV_STATUS_t Status;		/**< PXE status code */
	UINT16_t Size;			/**< Size of structure  */
	UINT32_t Magic;			/**< Magic number */
	UINT32_t Provider;		/**< Implementation identifier */
	UINT32_t APIMask;		/**< Supported API functions */
	UINT32_t Flags;			/**< Reserved for the future */
} __attribute__ (( packed ));

typedef struct s_PXENV_FILE_API_CHECK PXENV_FILE_API_CHECK_t;

/** @} */ /* pxenv_file_api_check */

/** @defgroup pxenv_file_exit_hook PXENV_FILE_EXIT_HOOK
 *
 * FILE EXIT HOOK
 *
 * @{
 */

/** PXE API function code for pxenv_file_exit_hook() */
#define PXENV_FILE_EXIT_HOOK			0x00e7

/** Parameter block for pxenv_file_exit_hook() */
struct s_PXENV_FILE_EXIT_HOOK {
	PXENV_STATUS_t Status;		/**< PXE status code */
	SEGOFF16_t Hook;		/**< SEG16:OFF16 to jump to */
} __attribute__ (( packed ));

typedef struct s_PXENV_FILE_EXIT_HOOK PXENV_FILE_EXIT_HOOK_t;

/** @} */ /* pxenv_file_exit_hook */

/** @defgroup pxenv_file_cmdline PXENV_FILE_CMDLINE
 *
 * FILE CMDLINE
 *
 * @{
 */

/** PXE API function code for pxenv_file_cmdline() */
#define PXENV_FILE_CMDLINE			0x00e8

/** Parameter block for pxenv_file_cmdline() */
struct s_PXENV_FILE_CMDLINE {
	PXENV_STATUS_t Status;		/**< PXE status code */
	UINT16_t BufferSize;		/**< Data buffer size */
	SEGOFF16_t Buffer;		/**< Data buffer */
} __attribute__ (( packed ));

typedef struct s_PXENV_FILE_CMDLINE PXENV_FILE_CMDLINE_t;

/** @} */ /* pxe_file_cmdline */

/** @} */ /* pxe_file_api */

/** @defgroup pxe_loader_api PXE Loader API
 *
 * The UNDI ROM loader API
 *
 * @{
 */

/** Parameter block for undi_loader() */
struct s_UNDI_LOADER {
	/** PXE status code */
	PXENV_STATUS_t Status;
	/** %ax register as for PXENV_START_UNDI */
	UINT16_t AX;
	/** %bx register as for PXENV_START_UNDI */
	UINT16_t BX;
	/** %dx register as for PXENV_START_UNDI */
	UINT16_t DX;
	/** %di register as for PXENV_START_UNDI */
	OFF16_t DI;
	/** %es register as for PXENV_START_UNDI */
	SEGSEL_t ES;
	/** UNDI data segment
	 *
	 * @note The PXE specification defines the type of this field
	 * as #UINT16_t.  For x86, #SEGSEL_t and #UINT16_t are
	 * equivalent anyway; for other architectures #SEGSEL_t makes
	 * more sense.
	 */
	SEGSEL_t UNDI_DS;
	/** UNDI code segment
	 *
	 * @note The PXE specification defines the type of this field
	 * as #UINT16_t.  For x86, #SEGSEL_t and #UINT16_t are
	 * equivalent anyway; for other architectures #SEGSEL_t makes
	 * more sense.
	 */
	SEGSEL_t UNDI_CS;
	/** Address of the !PXE structure (a struct s_PXE) */
	SEGOFF16_t PXEptr;
	/** Address of the PXENV+ structure (a struct s_PXENV) */
	SEGOFF16_t PXENVptr;
} __attribute__ (( packed ));

typedef struct s_UNDI_LOADER UNDI_LOADER_t;

/** @} */ /* pxe_loader_api */

/** @} */ /* pxe */

/** @page pxe_notes Etherboot PXE implementation notes

@section pxe_routing IP routing

Several PXE API calls (e.g. pxenv_tftp_open() and pxenv_udp_write())
allow for the caller to specify a "relay agent IP address", often in a
field called "gateway" or similar.  The PXE specification states that
"The IP layer should provide space for a minimum of four routing
entries obtained from the default router and static route DHCP option
tags in the DHCPACK message, plus any non-zero giaddr field from the
DHCPOFFER message(s) accepted by the client".

The DHCP static route option ("option static-routes" in dhcpd.conf)
works only for classed IP routing (i.e. it provides no way to specify
a subnet mask).  Since virtually everything now uses classless IP
routing, the DHCP static route option is almost totally useless, and
is (according to the dhcp-options man page) not implemented by any of
the popular DHCP clients.

This leaves the caller-specified "relay agent IP address", the giaddr
field from the DHCPOFFER message(s) and the default gateway(s)
provided via the routers option ("option routers" in dhcpd.conf) in
the DHCPACK message.  Each of these is a default gateway address.
It's a fair bet that the routers option should take priority over the
giaddr field, since the routers option has to be explicitly specified
by the DHCP server operator.  Similarly, it's fair to assume that the
caller-specified "relay agent IP address", if present, should take
priority over any other routing table entries.

@bug Etherboot currently ignores all potential sources of routing
information other than the first router provided to it by a DHCP
routers option.

@section pxe_x86_modes x86 processor mode restrictions

On the x86 platform, different PXE API calls have different
restrictions on the processor modes (real or protected) that can be
used.  See the individual API call descriptions for the restrictions
that apply to any particular call.

@subsection pxe_x86_pmode16 Real mode, or protected-mode with 16-bit stack

The PXE specification states that the API function can be called in
protected mode only if the s_PXE::StatusCallout field is set to a
non-zero value, and that the API function cannot be called with a
32-bit stack segment.

Etherboot does not enforce either of these restrictions; they seem (as
with so much of the PXE specification) to be artifacts of the Intel
implementation.

*/

#endif /* PXE_API_H */
