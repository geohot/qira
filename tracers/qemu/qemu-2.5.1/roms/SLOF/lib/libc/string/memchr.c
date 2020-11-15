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
memchr(const void *ptr, int c, size_t n)
{
	unsigned char ch = (unsigned char)c;
	const unsigned char *p = ptr;

	while (n-- > 0) {
		if (*p == ch)
			return (void *)p;
		p += 1;
	}

	return NULL;
}
