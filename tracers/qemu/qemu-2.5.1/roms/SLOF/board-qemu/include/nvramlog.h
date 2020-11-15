/******************************************************************************
 * Copyright (c) 2004, 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef NVRAMLOG_H
	#define NVRAMLOG_H

/* ----------------------------------------------------------------------------
 *	NVRAM Log-Partition header design:
 *
 *	Partition Header
 *	00h	- signature	( 1 byte)
 *	01h	- checksum	( 1 byte)
 *	02h	- length	( 2 byte) value = 1st_byte*256 + 2nd_byte
 *	04h	- name		(12 byte)
 *	space for partiton header = 16 byte
 *
 *	Log Header
 *	10h	- offset	( 2 byte) from Partition Header to Data Section
 *	12h	- flags		( 2 byte) control flags
 *	14h	- pointer	( 4 byte) pointer to first free byte in Data Section
 *					  relative to the beginning of the data section
 *	18h	- zero		( 32 byte) reserved as stack for four  64 bit register
 *	38h - reserved		(  8 byte) reserved for 64 bit CRC (not implemented yet)
 *	space for header = 64 byte
 *	Data Section
 *	40h	- cyclic data
 * -------------------------------------------------------------------------------- */

	// initial values
	#define LLFW_LOG_BE0_SIGNATURE		0x51			// signature for general firmware usage
	#define LLFW_LOG_BE0_NAME_PREFIX	0x69626D2C		// first 4 bytes of name: "ibm,"
	#define LLFW_LOG_BE0_NAME		0x435055306C6F6700	// remaining 8 bytes	: "CPU0log\0"
	#define LLFW_LOG_BE0_LENGTH		0x200			// Partition length in block of 16 bytes
	#define LLFW_LOG_BE0_DATA_OFFSET	0x40			// offset in bytes between header and data
	#define LLFW_LOG_BE0_FLAGS		0			// unused

	#define LLFW_LOG_BE1_SIGNATURE		0x51			// signature for general firmware usage
	#define LLFW_LOG_BE1_NAME_PREFIX	0x69626D2C		// first 4 bytes of name: "ibm,"
	#define LLFW_LOG_BE1_NAME		0x435055316C6F6700	// remaining 8 bytes	: "CPU1log\0\0"
	#define LLFW_LOG_BE1_LENGTH		0x80			// Partition length in block of 16 bytes
	#define LLFW_LOG_BE1_DATA_OFFSET	0x40			// offset in bytes between header and data
	#define LLFW_LOG_BE1_FLAGS		0x0			// unused

	// positions of the initial values
	#define LLFW_LOG_POS_CHECKSUM	0x01			// 1
	#define LLFW_LOG_POS_LENGTH	0x02			// 2
	#define LLFW_LOG_POS_NAME	0x04			// 4
	#define LLFW_LOG_POS_DATA_OFFSET 0x10			// 16
	#define LLFW_LOG_POS_FLAGS	0x12			// 18
	#define LLFW_LOG_POS_POINTER	0x14			// 20

	// NVRAM info
	#define NVRAM_EMPTY_PATTERN	0x0000000000000000	// Pattern (64-bit) used to overwrite NVRAM

#endif
