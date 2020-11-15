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

#include <romfs.h>

int romfs_stat(char *filename, struct romfs_t *hnd)
{
	asm volatile ("":::"3","4","5","6","7","9","10");
	asm volatile ("":::"11","12");
	asm volatile ("":::"13","14","15","16","17","18");

	return romfs_stat_file(filename, hnd);
}
