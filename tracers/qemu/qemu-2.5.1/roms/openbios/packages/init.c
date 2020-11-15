/*
 *   Creation Date: <2003/12/23 00:28:05 samuel>
 *   Time-stamp: <2003/12/28 19:43:41 samuel>
 *
 *	<init.c>
 *
 *	Module intialization
 *
 *   Copyright (C) 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "kernel/kernel.h"
#include "packages.h"

void
modules_init( void )
{
#ifdef CONFIG_CMDLINE
	cmdline_init();
#endif
#ifdef CONFIG_DEBLOCKER
	deblocker_init();
#endif
#ifdef CONFIG_DISK_LABEL
	disklabel_init();
#endif
#ifdef CONFIG_HFSP
	hfsp_init();
#endif
#ifdef CONFIG_HFS
	hfs_init();
#endif
#ifdef CONFIG_EXT2
	ext2_init();
#endif
#ifdef CONFIG_ISO9660
	iso9660_init();
#endif
#ifdef CONFIG_GRUBFS
	grubfs_init();
#endif
#ifdef CONFIG_MAC_PARTS
	macparts_init();
#endif
#ifdef CONFIG_PC_PARTS
	pcparts_init();
#endif
#ifdef CONFIG_SUN_PARTS
	sunparts_init();
#endif
#ifdef CONFIG_LOADER_XCOFF
	xcoff_loader_init();
#endif
#ifdef CONFIG_LOADER_ELF
	elf_loader_init();
#endif
#ifdef CONFIG_LOADER_BOOTINFO
	bootinfo_loader_init();
#endif

}
