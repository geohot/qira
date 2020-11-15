/******************************************************************************
 * Copyright (c) 2007, 2012, 2013 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef _ALLOCATOR_H
#define _ALLOCATOR_H

extern void SLOF_bm_print(unsigned long handle);
extern unsigned long SLOF_bm_allocator_init(unsigned long start,
					unsigned long size,
					unsigned long blocksize);
extern unsigned long SLOF_bm_alloc(unsigned long handle, unsigned long size);
extern void SLOF_bm_free(unsigned long handle, unsigned long ptr, unsigned long size);

#endif /* _ALLOCATOR_H */
