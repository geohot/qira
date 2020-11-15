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
strchr(const char *s, int c)
{
	char cb = c;

	while (*s != 0) {
		if (*s == cb) {
			return (char *)s;
		}
		s += 1;
	}

	return NULL;
}
