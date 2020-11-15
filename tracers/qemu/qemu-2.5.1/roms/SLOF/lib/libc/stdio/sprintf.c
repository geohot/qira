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


int sprintf(char *buff, const char *format, ...)
{
	va_list ar;
	int count;

	if ((buff==NULL) || (format==NULL))
		return(-1);

	va_start(ar, format);
	count = vsprintf(buff, format, ar);
	va_end(ar);
	
	return(count);
}

