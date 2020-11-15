/* tag: openbios forth starter for builtin dictionary for sparc32
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "asm/types.h"
#include "libopenbios/sys_info.h"

/*
 * wrap an array around the hex'ed dictionary file
 */

/* 256K for the dictionary */
#define DICTIONARY_SIZE (256 * 1024 / sizeof(ucell))
#define DICTIONARY_BASE ((ucell)((char *)&forth_dictionary))

static ucell forth_dictionary[DICTIONARY_SIZE] = {
#include "static-dict.h"
};

void collect_multiboot_info(struct sys_info *info);
void collect_multiboot_info(struct sys_info *info)
{
	info->dict_start=(unsigned long *)forth_dictionary;
        info->dict_end = (unsigned long *)FORTH_DICTIONARY_END;
        info->dict_last = (ucell *)((unsigned char *)forth_dictionary +
                                            FORTH_DICTIONARY_LAST);
        info->dict_limit = sizeof(forth_dictionary);
}
