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

#include <cpu.h>
#include "types.h"

#define PAGE_SIZE 4096
#define HEAP_SIZE 0x800000

#ifdef CPU_PPC970
#define SET_CI set_ci()
#define CLR_CI clr_ci()
#else
#define SET_CI
#define CLR_CI
#endif

// The big Forth source file that contains everything but the core engine.
// We include it as a hunk of data into the C part of SLOF; at startup
// time, this will be EVALUATE'd.
extern char _binary_OF_fsi_start[], _binary_OF_fsi_end[];

extern cell the_mem[];   /* Space for the dictionary / the HERE pointer */

extern cell *restrict dp;
extern cell *restrict rp;

void client_entry_point();

extern unsigned long call_client(cell);
extern long c_romfs_lookup(long, long, void *);
extern long writeLogByte(long, long);
