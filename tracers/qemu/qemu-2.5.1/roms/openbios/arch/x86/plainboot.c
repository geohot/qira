/* tag: openbios fixed address forth starter
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "libopenbios/sys_info.h"
#include "multiboot.h"

#define FIXED_DICTSTART 0xfffe0000
#define FIXED_DICTEND   0xfffeffff

void collect_multiboot_info(struct sys_info *info);
void collect_multiboot_info(struct sys_info *info)
{
	info->dict_start=(unsigned long *)FIXED_DICTSTART;
	info->dict_end=(unsigned long *)FIXED_DICTEND;
}
