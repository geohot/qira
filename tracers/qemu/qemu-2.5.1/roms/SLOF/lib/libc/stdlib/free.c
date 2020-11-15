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
#include "malloc_defs.h"

void
free(void *ptr)
{
	struct chunk *header;

	header = (struct chunk *) ptr;
	header--;
	header->inuse = 0;

}
