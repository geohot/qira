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

int isdigit(int ch)
{
	switch (ch) {
	 case '0': case '1': case '2': case '3': case '4':
	 case '5': case '6': case '7': case '8': case '9':
		return 1;
	
	 default:
		return 0;
	}
}
