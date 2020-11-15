/*
 *   Creation Date: <1999/11/07 19:02:11 samuel>
 *   Time-stamp: <2004/01/07 19:42:36 samuel>
 *
 *	<ofmem.c>
 *
 *	OF Memory manager
 *
 *   Copyright (C) 1999-2004 Samuel Rydh (samuel@ibrium.se)
 *   Copyright (C) 2004 Stefan Reinauer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

/* TODO: Clean up MOLisms in a decent way */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/string.h"
#include "libopenbios/ofmem.h"
#include "kernel.h"
#ifdef I_WANT_MOLISMS
#include "mol/prom.h"
#include "mol/mol.h"
#endif
#include "mmutypes.h"
#include "asm/processor.h"
#ifdef I_WANT_MOLISMS
#include "osi_calls.h"
#endif

#define BIT(n)		(1U<<(31-(n)))

/* called from assembly */
extern void	dsi_exception( void );
extern void	isi_exception( void );
extern void	setup_mmu( unsigned long code_base, unsigned long code_size, unsigned long ramsize );

/****************************************************************
 * Memory usage (before of_quiesce is called)
 *
 *			Physical
 *
 *	0x00000000	Exception vectors
 *	0x00004000	Free space
 *	0x01e00000	Open Firmware (us)
 *	0x01f00000	OF allocations
 *	0x01ff0000	PTE Hash
 *	0x02000000-	Free space
 *
 * Allocations grow downwards from 0x01e00000
 *
 ****************************************************************/

#define HASH_SIZE		(2 << 15)
#define SEGR_BASE		0x400		/* segment number range to use */

#define FREE_BASE_1		0x00004000
#define OF_CODE_START		0x01e00000
/* #define OF_MALLOC_BASE	0x01f00000 */
extern char _end[];
#define OF_MALLOC_BASE		_end

#define HASH_BASE		(0x02000000 - HASH_SIZE)
#define FREE_BASE_2		0x02000000

#define RAMSIZE			0x02000000	/* XXXXXXXXXXXXXXXXXXX FIXME XXXXXXXXXXXXXXX */

static ofmem_t s_ofmem;

#define IO_BASE			0x80000000
#define OFMEM (&s_ofmem)

static inline unsigned long
get_hash_base( void )
{
	return HASH_BASE;
}

static inline unsigned long
get_hash_size( void )
{
	return HASH_SIZE;
}

static ucell get_heap_top( void )
{
	return HASH_BASE;
}

static inline size_t ALIGN_SIZE(size_t x, size_t a)
{
    return (x + a - 1) & ~(a-1);
}

ofmem_t* ofmem_arch_get_private(void)
{
	return OFMEM;
}

void* ofmem_arch_get_malloc_base(void)
{
	return OF_MALLOC_BASE;
}

ucell ofmem_arch_get_heap_top(void)
{
	return get_heap_top();
}

ucell ofmem_arch_get_virt_top(void)
{
	return IO_BASE;
}

void ofmem_arch_unmap_pages(ucell virt, ucell size)
{
	/* kill page mappings in provided range */
}

void ofmem_arch_map_pages(ucell phys, ucell virt, ucell size, ucell mode)
{
	/* none yet */
}

/************************************************************************/
/*	OF private allocations						*/
/************************************************************************/

void *
malloc( int size )
{
	return ofmem_malloc(size);
}

void
free( void *ptr )
{
	return ofmem_free(ptr);
}

void *
realloc( void *ptr, size_t size )
{
	return ofmem_realloc(ptr, size);
}


/************************************************************************/
/*	misc								*/
/************************************************************************/

ucell ofmem_arch_default_translation_mode( ucell phys )
{
	/* XXX: Guard bit not set as it should! */
	if( phys < IO_BASE || phys >= 0xffc00000 )
		return 0x02;	/*0xa*/	/* wim GxPp */
	return 0x6a;		/* WIm GxPp, I/O */
}


/************************************************************************/
/*	page fault handler						*/
/************************************************************************/

static ucell
ea_to_phys( ucell ea, ucell *mode )
{
	ucell phys;

	/* hardcode our translation needs */
	if( ea >= OF_CODE_START && ea < FREE_BASE_2 ) {
		*mode = ofmem_arch_default_translation_mode( ea );
		return ea;
	}

	phys = ofmem_translate(ea, mode);
	if( phys == (ucell)-1 ) {
#ifdef I_WANT_MOLISMS
		if( ea != 0x80816c00 )
			printk("ea_to_phys: no translation for %08lx, using 1-1\n", ea );
#endif
		phys = ea;
		*mode = ofmem_arch_default_translation_mode( phys );

#ifdef I_WANT_MOLISMS
		forth_segv_handler( (char*)ea );
		OSI_Debugger(1);
#endif
		/* print_virt_range(); */
		/* print_phys_range(); */
		/* print_trans(); */
	}
	return phys;
}

static void
hash_page( ucell ea, ucell phys, ucell mode )
{
	static int next_grab_slot=0;
	unsigned long *upte, cmp, hash1;
	int i, vsid, found;
	mPTE_t *pp;

	vsid = (ea>>28) + SEGR_BASE;
	cmp = BIT(0) | (vsid << 7) | ((ea & 0x0fffffff) >> 22);

	hash1 = vsid;
	hash1 ^= (ea >> 12) & 0xffff;
	hash1 &= (get_hash_size() - 1) >> 6;

	pp = (mPTE_t*)(get_hash_base() + (hash1 << 6));
	upte = (unsigned long*)pp;

	/* replace old translation */
	for( found=0, i=0; !found && i<8; i++ )
		if( cmp == upte[i*2] )
			found=1;

	/* otherwise use a free slot */
	for( i=0; !found && i<8; i++ )
		if( !pp[i].v )
			found=1;

	/* out of slots, just evict one */
	if( !found ) {
		i = next_grab_slot + 1;
		next_grab_slot = (next_grab_slot + 1) % 8;
	}
	i--;
	upte[i*2] = cmp;
	upte[i*2+1] = (phys & ~0xfff) | mode;

	asm volatile( "tlbie %0"  :: "r"(ea) );
}

void
dsi_exception( void )
{
	unsigned long dar, dsisr;
	ucell mode;
	ucell phys;

	asm volatile("mfdar %0" : "=r" (dar) : );
	asm volatile("mfdsisr %0" : "=r" (dsisr) : );

	//printk("dsi-exception @ %08lx <%08lx>\n", dar, dsisr );

	phys = ea_to_phys(dar, &mode);
	hash_page( dar, phys, mode );
}

void
isi_exception( void )
{
	unsigned long nip, srr1;
	ucell mode;
	ucell phys;

	asm volatile("mfsrr0 %0" : "=r" (nip) : );
	asm volatile("mfsrr1 %0" : "=r" (srr1) : );

	//printk("isi-exception @ %08lx <%08lx>\n", nip, srr1 );

	phys = ea_to_phys(nip, &mode);
	hash_page( nip, phys, mode );
}


/************************************************************************/
/*	init / cleanup							*/
/************************************************************************/

void
setup_mmu( unsigned long code_base, unsigned long code_size, unsigned long ramsize )
{
	unsigned long sdr1 = HASH_BASE | ((HASH_SIZE-1) >> 16);
	unsigned long sr_base = (0x20 << 24) | SEGR_BASE;
	unsigned long msr;
	int i;

	asm volatile("mtsdr1 %0" :: "r" (sdr1) );
	for( i=0; i<16; i++ ) {
		int j = i << 28;
		asm volatile("mtsrin %0,%1" :: "r" (sr_base + i), "r" (j) );
	}
	asm volatile("mfmsr %0" : "=r" (msr) : );
	msr |= MSR_IR | MSR_DR;
	asm volatile("mtmsr %0" :: "r" (msr) );
}

void
ofmem_init( void )
{
	ofmem_t *ofmem = OFMEM;
	/* In case we can't rely on memory being zero initialized */
	memset(ofmem, 0, sizeof(ofmem));

	ofmem->ramsize = RAMSIZE;

	ofmem_claim_phys( 0, FREE_BASE_1, 0 );
	ofmem_claim_virt( 0, FREE_BASE_1, 0 );
	ofmem_claim_phys( OF_CODE_START, FREE_BASE_2 - OF_CODE_START, 0 );
	ofmem_claim_virt( OF_CODE_START, FREE_BASE_2 - OF_CODE_START, 0 );
}
