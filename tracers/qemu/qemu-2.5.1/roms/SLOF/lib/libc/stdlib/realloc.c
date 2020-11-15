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


#include "stdlib.h"
#include "string.h"
#include "malloc_defs.h"

void *
realloc(void *ptr, size_t size)
{
	struct chunk *header;
	char *newptr, *start;

	header = (struct chunk *) ptr;
	header--;

	if (size <= header->length)
		return ptr;

	newptr = (char *) malloc(size);
	if (newptr == NULL)
		return 0;

	start = newptr;
	memcpy((void *) newptr, (const void *) ptr, header->length);

	header->inuse = 0;

	return start;
}
