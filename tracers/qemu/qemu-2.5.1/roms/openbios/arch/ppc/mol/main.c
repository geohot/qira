/*
 *   Creation Date: <2002/10/02 22:24:24 samuel>
 *   Time-stamp: <2004/03/27 01:57:55 samuel>
 *
 *	<main.c>
 *
 *
 *
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
#include "mol/mol.h"
#include "libopenbios/ofmem.h"
#include "osi_calls.h"
#include "ablk_sh.h"
#include "boothelper_sh.h"


static void	patch_newworld_rom( char *start, size_t size );
static void	newworld_timer_hack( char *start, size_t size );

static void
transfer_control_to_elf( unsigned long entry )
{
	extern void call_elf( unsigned long entry );
	printk("Starting ELF boot loader\n");
	call_elf( entry );

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

	printk("Loading '%s' from '%s'\n", get_file_path(fd),
	       get_volume_name(fd) );

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

		/* patch CODE segment */
		if( *entry >= phdr[i].p_vaddr && *entry < phdr[i].p_vaddr + s ) {
			patch_newworld_rom( (char*)phdr[i].p_vaddr, s );
			newworld_timer_hack( (char*)phdr[i].p_vaddr, s );
		}
		flush_icache_range( addr, addr+s );

		/* printk("ELF ROM-section loaded at %08lX (size %08lX)\n",
		   (unsigned long)phdr[i].p_vaddr, (unsigned long)phdr[i].p_memsz );*/
	}
	free( phdr );
	return lszz_offs;
}


/************************************************************************/
/*	newworld ROM loading						*/
/************************************************************************/

#define ROM_BASE	0x1100000		/* where we decide to put things */

/* fix bug present in the 2.4 and the 3.0 Apple ROM */
static void
patch_newworld_rom( char *start, size_t size )
{
	int s;
	unsigned long mark[] = { 0x7c7d1b78, 		/* mr r29,r3 */
                                 0x7c9c2378,		/* mr r28,r4 */
                                 0x7cc33378,		/* mr r3,r6 */
                                 0x7c864214,		/* add r4,r6,r8   <------ BUG -- */
                                 0x80b10000,		/* lwz r5,0(r17) */
                                 0x38a500e8 };		/* addi r5,r5,232 */

	/* Correcting add r4,r6,r8  ---->  addi r4,r6,8 */
	for( s=0; s<size-sizeof(mark); s+=4 )
		if( memcmp( start+s, mark, sizeof(mark)) == 0 ) {
			printk("FIXING ROM BUG @ %X!\n", s+12);
			((unsigned long*)(start+s))[3] = 0x38860008;	/* addi r4,r6,8 */
		}
}

/* This hack is only needed on machines with a timebase slower than 12.5 MHz
 * (50 MHz bus frequency). Typically only old, accelerated machines fall
 * into this category. The cause of the problem is an overflow in Apple's
 * calibration routine.
 */
static void
newworld_timer_hack( char *start, size_t size )
{
	int s;
	unsigned long mark[] = { 0x7d0000a6, 0x5507045e, 0x7ce00124, 0x4c00012c,
                                 0x38e00000, 0x3c80000f, 0x6084ffff, 0x98830c00,
                                 0x7c0006ac, 0x98830a00, 0x7c0006ac, 0x7c9603a6,
                                 0x4c00012c, 0x7cb602a6, 0x2c050000, 0x4181fff8,
                                 0x7c0004ac, 0x88830a00, 0x7c0006ac, 0x88a30800,
                                 0x7c0006ac, 0x88c30a00, 0x7c0006ac, 0x7c043040,
                                 0x40a2ffe4, 0x5085442e, 0x7ca500d0, 0x54a5043e,
                                 0x7c053840, 0x7ca72b78, 0x4082ff9c, 0x7ca32b78,
                                 0x7d000124, 0x4c00012c, 0x4e800020
	};

	/* return #via ticks corresponding to 0xfffff DEC ticks (VIA frequency == 47/60 MHz) */
	for( s=0; s < size-sizeof(mark); s+=4 ) {
		if( !memcmp( start+s, mark, sizeof(mark)) ) {
			extern char timer_calib_start[], timer_calib_end[];
			extern unsigned long nw_dec_calibration;
			int hz = OSI_UsecsToMticks(1000);
			nw_dec_calibration = OSI_MticksToUsecs(0xfffff*47)/60;
			memcpy( start + s, timer_calib_start, timer_calib_end - timer_calib_start );

			printk("Timer calibration fix: %d.%02d MHz [%ld]\n",
			       hz/1000, (hz/10)%100, nw_dec_calibration );
			break;
		}
	}
}

static unsigned long
load_newworld_rom( int fd )
{
	int lszz_offs, lszz_size;
	unsigned long entry, data[2];
	phandle_t ph;

	lszz_offs = load_elf_rom( &entry, fd );
	seek_io( fd, -1 );
	lszz_size = tell(fd) - lszz_offs;
	seek_io( fd, lszz_offs );

	/* printk("Compressed ROM image: offset %08X, size %08X loaded at %08x\n",
	   lszz_offs, lszz_size, ROM_BASE ); */

	if( ofmem_claim(ROM_BASE, lszz_size, 0) == -1 )
		fatal_error("Claim failure (lszz)!\n");

	read_io( fd, (char*)ROM_BASE, lszz_size );

	/* Fix the /rom/macos/AAPL,toolbox-image,lzss property (phys, size) */
#if 0
	if( (ph=prom_create_node("/rom/macos/")) == -1 )
		fatal_error("Failed creating /rom/macos/");
#else
	ph = find_dev("/rom/macos");
#endif
	data[0] = ROM_BASE;
	data[1] = lszz_size;
	set_property( ph, "AAPL,toolbox-image,lzss", (char*)data, sizeof(data) );

	/* The 7.8 rom (MacOS 9.2) uses AAPL,toolbox-parcels instead of
	 * AAPL,toolbox-image,lzss. It probably doesn't hurt to have it
	 * always present (we don't have an easy way to determine ROM version...)
	 */
	set_property( ph, "AAPL,toolbox-parcels", (char*)data, sizeof(data) );
	return entry;
}

static int
search_nwrom( int fd, int fast )
{
	char *s, buf[128];
	int found = 0;

	if( fast ) {
		int ind;
		found = !reopen( fd, "\\\\:tbxi" );
		for( ind=0; !found && (s=BootHGetStrResInd("macos_rompath", buf, sizeof(buf), ind++, 0)) ; )
			found = !reopen( fd, s );
		for( ind=0; !found && (s=BootHGetStrResInd("macos_rompath_", buf, sizeof(buf), ind++, 0)) ; )
			found = !reopen( fd, s );
	} else {
		printk("Searching %s for a 'Mac OS ROM' file\n", get_volume_name(fd) );
		if( !(found=reopen_nwrom(fd)) ) {
			printk(" \n**** HINT ***************************************************\n");
			printk("*  The booting can be speeded up by adding the line\n");
			printk("*      macos_rompath: '%s'\n", get_file_path(fd) );
			printk("*  to the /etc/mol/molrc.macos (recommended).\n");
			printk("*************************************************************\n \n");
		}
	}
	return found;
}

static void
encode_bootpath( const char *spec, const char *args )
{
	phandle_t chosen_ph = find_dev("/chosen");
	set_property( chosen_ph, "bootpath", spec, strlen(spec)+1 );
	set_property( chosen_ph, "bootargs", args, strlen(args)+1 );
}

static char *
newworld_load( const char *node_path, const char *spec, int do_search )
{
	char *p, *entry, buf[80];
	int fd, len;

	if( (fd=open_io(spec)) == -1 )
		return NULL;

	if( !search_nwrom(fd, do_search) ) {
		close_io(fd);
		return NULL;
	}
	printk("Boot Disk: %s [%s]\n", spec, get_fstype(fd) );

	entry = (char*)load_newworld_rom( fd );

#if 1
	PUSH_ih( get_ih_from_fd(fd) );
	fword("get-instance-path");
	len = POP();
	p = (char*)POP();
	buf[0] = 0;
	if( len < sizeof(buf) ) {
		memcpy( buf, p, len );
		buf[len] =0;
	}
	strcat( buf, "/x@:" );
	printk("boot_path: %s\n", buf );
	encode_bootpath( buf, "" );
#endif
	close_io( fd );
	return entry;
}

static void
newworld_startup( void )
{
	int i, j, bootunit, type, fd;
	ablk_disk_info_t info;
	char *entry = NULL;
	char spec[80];
	phandle_t ph;

	char path[]="/pci/pci-bridge/mol-blk";
	if( !(ph=find_dev(path)) )
		fatal_error("MOLBlockDriver node not found\n");

	/* user-specified newworld ROMs take precedence */
	if( (fd=open_io("pseudo:,nwrom")) >= 0 ) {
		entry = (char*)load_newworld_rom( fd );
		close_io( fd );
	}

	/* determine boot volume */
	for( bootunit=-1, type=0; bootunit==-1 && type<3 ; type++ ) {
		for( i=0; !OSI_ABlkDiskInfo(0, i, &info) ; i++ ) {
			if( type<=1 && !(info.flags & ABLK_BOOT_HINT) )
				continue;
			if( type>1 && (info.flags & ABLK_BOOT_HINT) )
				continue;

			for( j=0; !entry && j<32; j++ ) {
                                snprintf( spec, sizeof(spec), "%s/disk@%x:%d",
                                          path, i, j );
				entry = newworld_load( path, spec, (!type || type==2) );
			}
			if( entry ) {
				bootunit = i;
				break;
			}
		}
	}

	if( entry ) {
		OSI_ABlkBlessDisk( 0 /*channel*/, bootunit );

		update_nvram();
		transfer_control_to_elf( (unsigned long)entry );
		/* won't come here */
		return;
	}

	printk("\n--- No bootable disk was found! -----------------------------\n");
	printk("If this is an oldworld machine, try booting from the MacOS\n");
	printk("install CD and install MacOS from within MOL.\n");
	printk("-------------------------------------------------------------\n");
	exit(1);
}


/************************************************************************/
/*	yaboot booting							*/
/************************************************************************/

static void
yaboot_startup( void )
{
	const char *paths[] = { "pseudo:,ofclient", "pseudo:,yaboot", NULL };
	unsigned long entry;
	int i, fd;

	for( i=0; paths[i]; i++ ) {
		if( (fd=open_io(paths[i])) == -1 )
			continue;
		(void) load_elf_rom( &entry, fd );
		close_io( fd );
		encode_bootpath( paths[i], "" );

		update_nvram();
		transfer_control_to_elf( entry );
		/* won't come here */
	}
	printk("*** Boot failure! No secondary bootloader specified ***\n");
	exit(1);
}


/************************************************************************/
/*	entry								*/
/************************************************************************/

void
boot( void )
{
	fword("update-chosen");
	if( find_dev("/mol-platform") )
		yaboot_startup();
	else
		newworld_startup();
}
