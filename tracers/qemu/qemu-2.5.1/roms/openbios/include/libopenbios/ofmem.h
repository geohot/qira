/*
 *   Creation Date: <1999/11/16 00:47:06 samuel>
 *   Time-stamp: <2003/10/18 13:28:14 samuel>
 *
 *	<ofmem.h>
 *
 *
 *
 *   Copyright (C) 1999, 2002 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_OFMEM
#define _H_OFMEM

#include "kernel/stack.h"

typedef struct alloc_desc {
	struct alloc_desc 	*next;
	ucell			size;			/* size (including) this struct */
} alloc_desc_t;

typedef struct mem_range {
	struct mem_range	*next;
	phys_addr_t		start;			/* sizeof(phys) >= sizeof(virt), e.g SPARC32 */
	ucell			size;
} range_t;

typedef struct trans {
	struct trans		*next;
	ucell			virt;			/* chain is sorted by virt */
	ucell			size;
	phys_addr_t		phys;
	ucell			mode;
} translation_t;

/* ofmem private data */
typedef struct {
	ucell			ramsize;
	char 			*next_malloc;
	alloc_desc_t	*mfree;		/* list of free malloc blocks */

	range_t			*phys_range;
	range_t			*virt_range;
	range_t			*io_range;

	translation_t	*trans;		/* this is really a translation_t */
} ofmem_t;

/* structure for retained data */
typedef struct {
	ucell			magic;
	ucell			numentries;
	range_t			retain_phys_range[8];	/* physical memory that should survive a warm reset */
} retain_t;

/* TODO: temporary migration interface */
extern ofmem_t* 	ofmem_arch_get_private(void);
extern void*    	ofmem_arch_get_malloc_base(void);
extern ucell    	ofmem_arch_get_heap_top(void);
extern ucell    	ofmem_arch_get_virt_top(void);
extern ucell		ofmem_arch_get_iomem_base(void);
extern ucell		ofmem_arch_get_iomem_top(void);
extern retain_t*	ofmem_arch_get_retained(void);
extern int		ofmem_arch_get_physaddr_cellsize(void);
extern int		ofmem_arch_encode_physaddr(ucell *p, phys_addr_t value);
extern int		ofmem_arch_get_available_entry_size(phandle_t ph);
extern void 		ofmem_arch_create_available_entry(phandle_t ph, ucell *availentry, phys_addr_t start, ucell size);
extern int 		ofmem_arch_get_translation_entry_size(void);
extern void 		ofmem_arch_create_translation_entry(ucell *transentry, translation_t *t);
extern ucell    	ofmem_arch_default_translation_mode( phys_addr_t phys );
extern ucell    	ofmem_arch_io_translation_mode( phys_addr_t phys );
extern void     	ofmem_arch_map_pages(phys_addr_t phys, ucell virt, ucell size,
                                           ucell mode);
extern void     	ofmem_arch_unmap_pages(ucell virt, ucell size);
/* sparc64 uses this method */
extern int      	ofmem_map_page_range( phys_addr_t phys, ucell virt, ucell size,
                                      ucell mode );

/* Private functions for mapping between physical/virtual addresses */ 
extern phys_addr_t va2pa(unsigned long va);
extern unsigned long pa2va(phys_addr_t pa);
				      
/* malloc interface */
extern int ofmem_posix_memalign( void **memptr, size_t alignment, size_t size );
extern void* ofmem_malloc( size_t size );
extern void  ofmem_free( void *ptr );
extern void* ofmem_realloc( void *ptr, size_t size );

/* ofmem_common.c */

extern void	ofmem_cleanup( void );
extern void	ofmem_init( void );

/*
 * register /memory and /virtual-memory handles
 * ofmem module will update "available" and "translations" properties
 * using these handles
 *
 * to disable updating /memory properties  pass zero memory handle
 */
extern void ofmem_register( phandle_t ph_memory, phandle_t ph_mmu );

extern ucell ofmem_claim( ucell addr, ucell size, ucell align );
extern phys_addr_t ofmem_claim_phys( phys_addr_t mphys, ucell size, ucell align );
extern ucell ofmem_claim_virt( ucell mvirt, ucell size, ucell align );
extern ucell ofmem_claim_io( ucell virt, ucell size, ucell align );

extern phys_addr_t ofmem_retain( phys_addr_t phys, ucell size, ucell align );

extern int   ofmem_map( phys_addr_t phys, ucell virt, ucell size, ucell mode );
extern int   ofmem_unmap( ucell virt, ucell size );
extern ucell ofmem_map_io( phys_addr_t phys, ucell size );

extern void  ofmem_release( ucell virt, ucell size );
extern void  ofmem_release_phys( phys_addr_t phys, ucell size );
extern void  ofmem_release_virt( ucell virt, ucell size );
extern void  ofmem_release_io( ucell virt, ucell size );
extern phys_addr_t ofmem_translate( ucell virt, ucell *ret_mode );

/* memory and virtual-memory nodes */
extern phandle_t s_phandle_memory;
extern phandle_t s_phandle_mmu;

#define PAGE_SIZE    (1 << PAGE_SHIFT)
#define PAGE_MASK    (~(PAGE_SIZE - 1))
#define PAGE_ALIGN(addr)  (((addr) + PAGE_SIZE - 1) & PAGE_MASK)

#if defined(CONFIG_DEBUG_OFMEM)
    #define DEBUG_OFMEM 1
#else
    #define DEBUG_OFMEM 0
#endif

#define OFMEM_TRACE(fmt, ...) do { \
    if (DEBUG_OFMEM) { \
        printk("OFMEM: " fmt, ## __VA_ARGS__); \
    } \
} while (0);

#endif   /* _H_OFMEM */
