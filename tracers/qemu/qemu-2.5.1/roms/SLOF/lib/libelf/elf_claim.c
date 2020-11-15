/******************************************************************************
 * Copyright (c) 2009, 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <string.h>
#include <libelf.h>
#include "../../slof/paflof.h"


/**
 * Call Forth code to try to claim the memory region
 */
int
elf_forth_claim(void *addr, long size)
{
	forth_push((long)addr);
	forth_push(size);
	forth_eval("elf-claim-segment");
	return forth_pop();
}
