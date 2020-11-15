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
memset(void *dest, int c, size_t size)
{
	unsigned char *d = (unsigned char *)dest;

	while (size-- > 0) {
		*d++ = (unsigned char)c;
	}

	return dest;
}
