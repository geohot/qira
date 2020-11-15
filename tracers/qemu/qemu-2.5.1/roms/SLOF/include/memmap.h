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
#ifndef MEMMAP_H
#define MEMMAP_H

#define MEG			0x100000

#define SLAVELOOP_LOADBASE	0x0000000000003f00
#define STAGE2_LOADBASE		(60 * MEG)
#define OF_LOADBASE		0x000000000000a000

#define MEM_HALF		(512 * MEG)

/* BE Engines Offsets */
#define BE_MIC_BASE 0x50A000

#endif
