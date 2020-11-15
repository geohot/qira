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

#include <stdlib.h>


static unsigned long _rand = 1;

int
rand(void)
{
	_rand = _rand * 25364735 + 34563;

	return ((unsigned int) (_rand << 16) & RAND_MAX);
}
