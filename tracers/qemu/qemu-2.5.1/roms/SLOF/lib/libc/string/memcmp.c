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


int
memcmp(const void *ptr1, const void *ptr2, size_t n)
{
	const unsigned char *p1 = ptr1;
	const unsigned char *p2 = ptr2;

	while (n-- > 0) {
		if (*p1 != *p2)
			return (*p1 - *p2);
		p1 += 1;
		p2 += 1;
	}

	return 0;
}
