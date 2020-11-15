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

#include "string.h"


void *
memmove(void *dest, const void *src, size_t n)
{
	char *cdest;
	const char *csrc;
	int i;

	/* Do the buffers overlap in a bad way? */
	if (src < dest && src + n >= dest) {
		/* Copy from end to start */
		cdest = dest + n - 1;
		csrc = src + n - 1;
		for (i = 0; i < n; i++) {
			*cdest-- = *csrc--;
		}
	}
	else {
		/* Normal copy is possible */
		cdest = dest;
		csrc = src;
		for (i = 0; i < n; i++) {
			*cdest++ = *csrc++;
		}
	}

	return dest;
}
