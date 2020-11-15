/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/
#ifndef CALCULATECRC_H
#define CALCULATECRC_H

	#define FLASHFS_DATADDR 0x18                // uint64_t position of pointer to data
	#define FLASHFS_FILE_SIZE_ADDR 0x08         // uint64_t pos of total flashimage size value relative to data
	#define FLASHFS_HEADER_SIZE_ADDR 0x08       // uint64_t position of total flash header size value

	#ifdef __ASSEMBLER__
		// "CRC_GENERATOR" must contain equal inforamtion as "CRC_METHODE"
		#define CRC_GENERATOR 0x0000000004C11DB7
		#define CRC_REGISTERMASK 0x00000000FFFFFFFF
		#define CRC_REGISTERLENGTH 32
	#endif		/* __ASSEMBLER__ */

	#ifndef __ASSEMBLER__
		#define FLASHFS_ROMADDR 0x00		// uint64_t position of pointer to next file
		#define FLASHFS_HEADER_DATA_SIZE 0x68	// 104 bytes of total header data size
		#define CRC_METHODE Ethernet_32		// define the CRc genarator (CRC 16 bit to 64 is supported)

	//--- header format ---------------------------------
		struct stH {
				char magic[8];            // (generic!) headerfile
				uint64_t flashlen;        // dyn
				char version[16];         // $DRIVER_INFO alignment!
				char platform_name[32];   // (hardware)   headerfile
				char date[6];             // dyn (format -> JB)
				char padding1[2];         // padding byte
				char mdate[6];            // modify date
				char padding2[2];         // padding byte
				char platform_revision[4];// (hardware)   headerfile
				uint32_t padding;
				uint64_t ui64CRC;         // insert calculated CRC here
				uint64_t ui64FileEnd;     // = 0xFFFF FFFF FFFF FFFF
		};
	#endif		/* __ASSEMBLER__ */

#endif		/* CALCULATECRC_H */

/*--- supported CRC Generators -------------------------
+	Name						length		usage						Generator
+	Tap_16						16 bit		Tape						0x00008005	
+	Floppy_16					16 bit		Floppy						0x00001021
+	Ethernet_32					32 bit		Ethernet					0x04C11DB7
+	SPTrEMBL_64					64 bit		white noise like date		0x0000001B
+	SPTrEMBL_improved_64   		64 bit		DNA code like date			0xAD93D23594C9362D
+	DLT1_64						64 bit		Tape						0x42F0E1EBA9EA3693
+	
+	CRC_REGISTERLENGTH 	= bit length
+	CRC_REGISTERMASK 	= -1 for a n-bit numer where n = bit length
+		example TAP_16:		CRC_REGSISTERLENGTH = 16
+							CRC_REGISTERMASK = 0xFFFFFFFF = (-1 if 16 bit number is used)
+
+	TrEMBL see also	http://www.cs.ud.ac.uk/staff/D.Jones/crcbote.pdf
+	DLT1 se also 	http://www.ecma-international.org/publications/files/ECMA-ST/Ecma-182.pdf
+--------------------------------------------------------*/
