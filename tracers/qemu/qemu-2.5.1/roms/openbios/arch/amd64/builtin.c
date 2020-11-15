/* tag: openbios forth starter for builtin dictionary for amd64
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include <asm/types.h>
#include "libopenbios/sys_info.h"

/*
 * wrap an array around the hex'ed dictionary file
 */

#include "static-dict.h"

void collect_multiboot_info(struct sys_info *info);
void collect_multiboot_info(struct sys_info *info)
{
	info->dict_start=(unsigned long *)forth_dictionary;
	info->dict_end=(unsigned long *)((ucell)forth_dictionary +
			sizeof(forth_dictionary));
}
