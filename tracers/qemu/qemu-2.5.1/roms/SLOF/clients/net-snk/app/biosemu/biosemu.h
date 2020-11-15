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

#ifndef _BIOSEMU_BIOSEMU_H_
#define _BIOSEMU_BIOSEMU_H_

#define MIN_REQUIRED_VMEM_SIZE 0x100000	// 1MB

//define default segments for different components
#define STACK_SEGMENT 0x1000	//1000:xxxx
#define STACK_START_OFFSET 0xfffe

#define DATA_SEGMENT 0x2000
#define VBE_SEGMENT 0x3000

#define PMM_CONV_SEGMENT 0x4000	// 4000:xxxx is PMM conventional memory area, extended memory area
				// will be anything beyound MIN_REQUIRED_MEMORY_SIZE
#define PNP_DATA_SEGMENT 0x5000

#define OPTION_ROM_CODE_SEGMENT 0xc000

#define BIOS_DATA_SEGMENT 0xF000
// both EBDA values are _initial_ values, they may (and will be) changed at runtime by option ROMs!!
#define INITIAL_EBDA_SEGMENT 0xF600	// segment of the Extended BIOS Data Area
#define INITIAL_EBDA_SIZE 0x400	// size of the EBDA (at least 1KB!! since size is stored in KB!)

#define PMM_INT_NUM 0xFC	// we misuse INT FC for PMM functionality, at the PMM Entry Point
				// Address, there will only be a call to this INT and a RETF
#define PNP_INT_NUM 0xFD

uint32_t biosemu(char argc, char **argv);

#endif
