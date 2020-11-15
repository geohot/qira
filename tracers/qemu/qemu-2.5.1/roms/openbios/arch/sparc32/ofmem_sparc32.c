/*
 *	<ofmem_sparc32.c>
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

#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/string.h"
#include "arch/sparc32/ofmem_sparc32.h"
#include "asm/asi.h"
#include "pgtsrmmu.h"

#define OF_MALLOC_BASE		((char*)OFMEM + ALIGN_SIZE(sizeof(ofmem_t), 8))

#define MEMSIZE (256 * 1024)
static union {
	char memory[MEMSIZE];
	ofmem_t ofmem;
} s_ofmem_data;

#define OFMEM      	(&s_ofmem_data.ofmem)
#define TOP_OF_RAM 	(s_ofmem_data.memory + MEMSIZE)

#define OFMEM_PHYS_RESERVED	0x1000000

translation_t **g_ofmem_translations = &s_ofmem_data.ofmem.trans;

extern uint32_t qemu_mem_size;

static inline size_t ALIGN_SIZE(size_t x, size_t a)
{
    return (x + a - 1) & ~(a-1);
}

static ucell get_heap_top( void )
{
	return (ucell)TOP_OF_RAM;
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
	return (ucell)OFMEM_VIRT_TOP;
}

ucell ofmem_arch_get_iomem_base(void)
{
	return pointer2cell(&_end);
}

ucell ofmem_arch_get_iomem_top(void)
{
	return pointer2cell(&_iomem);
}

retain_t *ofmem_arch_get_retained(void)
{
	/* Not used */
	return 0;
}

int ofmem_arch_get_physaddr_cellsize(void)
{
	return 2;
}

int ofmem_arch_encode_physaddr(ucell *p, phys_addr_t value)
{
	int n = 0;

	p[n++] = value >> 32;
	p[n++] = value;

	return n;
}

int ofmem_arch_get_translation_entry_size(void)
{
	/* Return size of a single MMU package translation property entry in cells */
	return 3;
}

void ofmem_arch_create_translation_entry(ucell *transentry, translation_t *t)
{
	/* Generate translation property entry for SPARC. While there is no
	formal documentation for this, both Linux kernel and OpenSolaris sources
	expect a translation property entry to have the following layout:

		virtual address
		length
		mode
	*/

	transentry[0] = t->virt;
	transentry[1] = t->size;
	transentry[2] = t->mode;
}

/* Return the size of a memory available entry given the phandle in cells */
int ofmem_arch_get_available_entry_size(phandle_t ph)
{
	return 1 + ofmem_arch_get_physaddr_cellsize();
}

/* Generate memory available property entry for Sparc32 */
void ofmem_arch_create_available_entry(phandle_t ph, ucell *availentry, phys_addr_t start, ucell size)
{
  int i = 0;

	i += ofmem_arch_encode_physaddr(availentry, start);
	availentry[i] = size;
}

/* Unmap a set of pages */
void ofmem_arch_unmap_pages(ucell virt, ucell size)
{
	unsigned long pa;
	ucell i;

	for (i = 0; i < size; i += PAGE_SIZE) {
		pa = find_pte(virt, 0);
		*(uint32_t *)pa = 0;
		virt += PAGE_SIZE;
	}

	srmmu_flush_whole_tlb(); 
}

/* Map a set of pages */
void ofmem_arch_map_pages(phys_addr_t phys, ucell virt, ucell size, ucell mode)
{
	unsigned long npages, off;
	uint32_t pte;
	unsigned long pa;

	off = phys & (PAGE_SIZE - 1);
	npages = (off + (size - 1) + (PAGE_SIZE - 1)) / PAGE_SIZE;
	phys &= ~(uint64_t)(PAGE_SIZE - 1);

	while (npages-- != 0) {
		pa = find_pte(virt, 1);

		pte = SRMMU_ET_PTE | ((phys & PAGE_MASK) >> 4);
		pte |= mode;

		*(uint32_t *)pa = pte;

		virt += PAGE_SIZE;
		phys += PAGE_SIZE;
	}
}

/* Architecture-specific OFMEM helpers */
unsigned long
find_pte(unsigned long va, int alloc)
{
    uint32_t pte;
    void *p;
    unsigned long pa;
    int ret;

    pte = l1[(va >> SRMMU_PGDIR_SHIFT) & (SRMMU_PTRS_PER_PGD - 1)];
    if ((pte & SRMMU_ET_MASK) == SRMMU_ET_INVALID) {
        if (alloc) {
            ret = ofmem_posix_memalign(&p, SRMMU_PTRS_PER_PMD * sizeof(int),
                                 SRMMU_PTRS_PER_PMD * sizeof(int));
            if (ret != 0)
                return ret;
            pte = SRMMU_ET_PTD | ((va2pa((unsigned long)p)) >> 4);
            l1[(va >> SRMMU_PGDIR_SHIFT) & (SRMMU_PTRS_PER_PGD - 1)] = pte;
            /* barrier() */
        } else {
            return -1;
        }
    }

    pa = (pte & 0xFFFFFFF0) << 4;
    pa += ((va >> SRMMU_PMD_SHIFT) & (SRMMU_PTRS_PER_PMD - 1)) << 2;
    pte = *(uint32_t *)pa2va(pa);
    if ((pte & SRMMU_ET_MASK) == SRMMU_ET_INVALID) {
        if (alloc) {
            ret = ofmem_posix_memalign(&p, SRMMU_PTRS_PER_PTE * sizeof(void *),
                                 SRMMU_PTRS_PER_PTE * sizeof(void *));
            if (ret != 0)
                return ret;
            pte = SRMMU_ET_PTD | ((va2pa((unsigned int)p)) >> 4);
            *(uint32_t *)pa2va(pa) = pte;
        } else {
            return -2;
        }
    }

    pa = (pte & 0xFFFFFFF0) << 4;
    pa += ((va >> PAGE_SHIFT) & (SRMMU_PTRS_PER_PTE - 1)) << 2;

    return pa2va(pa);
}

/************************************************************************/
/* misc                                                                 */
/************************************************************************/

ucell ofmem_arch_default_translation_mode( phys_addr_t phys )
{
	return SRMMU_REF | SRMMU_CACHE | SRMMU_PRIV;
}

ucell ofmem_arch_io_translation_mode( phys_addr_t phys )
{
	return SRMMU_REF | SRMMU_PRIV;
}

/************************************************************************/
/* init / cleanup                                                       */
/************************************************************************/

void ofmem_init( void )
{
	memset(&s_ofmem_data, 0, sizeof(s_ofmem_data));
	s_ofmem_data.ofmem.ramsize = qemu_mem_size;
	
	/* Mark the first page as non-free */
	ofmem_claim_virt(0, PAGE_SIZE, 0);
	
	/* Claim reserved physical addresses at top of RAM */
	ofmem_claim_phys(s_ofmem_data.ofmem.ramsize - OFMEM_PHYS_RESERVED, OFMEM_PHYS_RESERVED, 0);
	
	/* Claim OpenBIOS reserved space */
	ofmem_claim_virt(0xffd00000, 0x200000, 0);
}
