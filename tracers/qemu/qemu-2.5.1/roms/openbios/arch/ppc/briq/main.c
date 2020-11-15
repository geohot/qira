/*
 *   Creation Date: <2004/08/28 18:38:22 greg>
 *   Time-stamp: <2004/08/28 18:38:22 greg>
 *
 *	<main.c>
 *
 *   Copyright (C) 2004 Greg Watson
 *
 *   Based on MOL specific code which is
 *   Copyright (C) 2002, 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */


#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/elfload.h"
#include "arch/common/nvram.h"
#include "libc/diskio.h"
#include "libc/vsprintf.h"
#include "briq/briq.h"
#include "libopenbios/ofmem.h"

static void
transfer_control_to_elf( unsigned long entry )
{
	extern void call_elf( unsigned long entry );
	printk("Starting ELF image at 0x%08lX\n", entry);
	call_elf( 0x400000 );
	//call_elf( entry );

	fatal_error("call_elf returned unexpectedly\n");
}

static int
load_elf_rom( unsigned long *entry, int fd )
{
	int i, lszz_offs, elf_offs;
	char buf[128], *addr;
	Elf_ehdr ehdr;
	Elf_phdr *phdr;
	size_t s;

	printk("Loading '%s'\n", get_file_path(fd));

	/* the ELF-image (usually) starts at offset 0x4000 */
	if( (elf_offs=find_elf(fd)) < 0 ) {
		printk("----> %s is not an ELF image\n", buf );
		exit(1);
	}
	if( !(phdr=elf_readhdrs(fd, elf_offs, &ehdr)) )
		fatal_error("elf_readhdrs failed\n");

	*entry = ehdr.e_entry;

	/* load segments. Compressed ROM-image assumed to be located immediately
	 * after the last segment */
	lszz_offs = elf_offs;
	for( i=0; i<ehdr.e_phnum; i++ ) {
		/* p_memsz, p_flags */
		s = MIN( phdr[i].p_filesz, phdr[i].p_memsz );
		seek_io( fd, elf_offs + phdr[i].p_offset );

		/* printk("filesz: %08lX memsz: %08lX p_offset: %08lX p_vaddr %08lX\n",
		   phdr[i].p_filesz, phdr[i].p_memsz, phdr[i].p_offset,
		   phdr[i].p_vaddr ); */

		if( phdr[i].p_vaddr != phdr[i].p_paddr )
			printk("WARNING: ELF segment virtual addr != physical addr\n");
		lszz_offs = MAX( lszz_offs, elf_offs + phdr[i].p_offset + phdr[i].p_filesz );
		if( !s )
			continue;
		if( ofmem_claim( phdr[i].p_vaddr, phdr[i].p_memsz, 0 ) == -1 )
			fatal_error("Claim failed!\n");

		addr = (char*)phdr[i].p_vaddr;
		if( read_io(fd, addr, s) != s )
			fatal_error("read failed\n");

#if 0
		/* patch CODE segment */
		if( *entry >= phdr[i].p_vaddr && *entry < phdr[i].p_vaddr + s ) {
			patch_newworld_rom( (char*)phdr[i].p_vaddr, s );
			newworld_timer_hack( (char*)phdr[i].p_vaddr, s );
		}
#endif
		flush_icache_range( addr, addr+s );

		/*printk("ELF ROM-section loaded at %08lX (size %08lX)\n",
		   (unsigned long)phdr[i].p_vaddr, (unsigned long)phdr[i].p_memsz );*/
	}
	free( phdr );
	return lszz_offs;
}


static void
encode_bootpath( const char *spec, const char *args )
{
	phandle_t chosen_ph = find_dev("/chosen");
	set_property( chosen_ph, "bootpath", spec, strlen(spec)+1 );
	set_property( chosen_ph, "bootargs", args, strlen(args)+1 );
}

/************************************************************************/
/*	briq booting							*/
/************************************************************************/

static void
briq_startup( void )
{
	const char *paths[] = { "hd:0,\\zImage.chrp", NULL };
	const char *args[] = { "root=/dev/hda2 console=ttyS0,115200", NULL };
	unsigned long entry;
	int i, fd;

	for( i=0; paths[i]; i++ ) {
		if( (fd=open_io(paths[i])) == -1 )
			continue;
		(void) load_elf_rom( &entry, fd );
		close_io( fd );
		encode_bootpath( paths[i], args[i] );

		update_nvram();
		transfer_control_to_elf( entry );
		/* won't come here */
	}
	printk("*** Boot failure! No secondary bootloader specified ***\n");
}


/************************************************************************/
/*	entry								*/
/************************************************************************/

void
boot( void )
{
	fword("update-chosen");
	briq_startup();
}
