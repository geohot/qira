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

int
putc(int ch, FILE *stream)
{
	unsigned char outchar = ch;

	if (write(stream->fd, &outchar, 1) == 1)
		return outchar;
	else
		return EOF;
}
