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

int setvbuf(FILE *stream, char *buf, int mode , size_t size)
{
	if (mode != _IONBF && mode != _IOLBF && mode != _IOFBF)
		return -1;
	stream->buf = buf;
	stream->mode = mode;
	stream->bufsiz = size;
	return 0;
}

void setbuf(FILE *stream, char *buf)
{
	setvbuf(stream, buf, buf ? _IOFBF : _IONBF, BUFSIZ);
}
