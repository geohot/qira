/*
 *   Creation Date: <2001/05/05 16:44:17 samuel>
 *   Time-stamp: <2003/10/22 23:18:42 samuel>
 *
 *	<elfload.h>
 *
 *	Elf loader
 *
 *   Copyright (C) 2001, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_ELFLOAD
#define _H_ELFLOAD

#include "arch/common/elf.h"
#include "asm/elf.h"
#include "libopenbios/sys_info.h"

extern int 		elf_load(struct sys_info *info, ihandle_t dev, const char *cmdline, void **boot_notes);
extern void 		elf_init_program(void);
extern int		is_elf(Elf_ehdr *ehdr);
extern int		find_elf(Elf_ehdr *ehdr);

extern Elf_phdr *	elf_readhdrs(int offset, Elf_ehdr *ehdr);

#endif   /* _H_ELFLOAD */
