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

#include <ctype.h>

int isspace(int ch)
{
	switch (ch) {
	 case ' ':
	 case '\f':
	 case '\n':
	 case '\r':
	 case '\t':
	 case '\v':
		return 1;
	
	 default:
		return 0;
	}
}
