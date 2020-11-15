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

#include "stdio.h"
#include "unistd.h"


int vfprintf(FILE *stream, const char *fmt, va_list ap)
{
	int count;
	char buffer[320];

	count = vsnprintf(buffer, sizeof(buffer), fmt, ap);
	write(stream->fd, buffer, count);

	return count;
}

