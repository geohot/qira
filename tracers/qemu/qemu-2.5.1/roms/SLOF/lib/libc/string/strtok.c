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
strtok(char *src, const char *pattern)
{
	static char *nxtTok;
	char *retVal = NULL;

	if (!src)
		src = nxtTok;

	while (*src) {
		const char *pp = pattern;
		while (*pp) {
			if (*pp == *src) {
				break;
			}
			pp++;
		}
		if (!*pp) {
			if (!retVal)
				retVal = src;
			else if (!src[-1])
				break;
		} else
			*src = '\0';
		src++;
	}

	nxtTok = src;

	return retVal;
}
