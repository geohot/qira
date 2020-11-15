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

#include <stdio.h>

int
scanf(const char *fmt, ...)
{
	int count;
	va_list ap;

	va_start(ap, fmt);
	count = vfscanf(stdin, fmt, ap);
	va_end(ap);

	return count;
}
