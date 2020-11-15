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

#include <string.h>

char *
strncpy(char *dst, const char *src, size_t n)
{
	char *ret = dst;

	/* Copy string */
	while (*src != 0 && n > 0) {
		*dst++ = *src++;
		n -= 1;
	}

	/* strncpy always clears the rest of destination string... */
	while (n > 0) {
		*dst++ = 0;
		n -= 1;
	}

	return ret;
}
