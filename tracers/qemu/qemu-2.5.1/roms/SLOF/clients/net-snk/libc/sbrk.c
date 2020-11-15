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

#include <unistd.h>

#define HEAP_SIZE 0x200000


static char heap[HEAP_SIZE];
static char *actptr;

void *sbrk(int increment)
{
	char *oldptr;

	/* Called for the first time? Then init the actual pointer */
	if (!actptr) {
		actptr = heap;
	}

	if (actptr + increment > heap + HEAP_SIZE) {
		/* Out of memory */
		return (void *)-1;
	}

	oldptr = actptr;
	actptr += increment;

	return oldptr;
}
