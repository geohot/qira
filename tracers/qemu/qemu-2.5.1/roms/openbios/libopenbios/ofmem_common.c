/*
 *	<ofmem_common.c>
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
#include "libopenbios/ofmem.h"

/* Default size of memory allocated for each of the MMU properties (in bytes) */
#define OFMEM_DEFAULT_PROP_SIZE 2048

/*
 * define OFMEM_FILL_RANGE to claim any unclaimed virtual and
 * physical memory in the range for ofmem_map
 *
 * TODO: remove this macro and wrapped code if not needed by implementations
 */
//#define OFMEM_FILL_RANGE


static inline size_t align_size(size_t x, size_t a)
{
    return (x + a - 1) & ~(a - 1);
}

static inline phys_addr_t align_ptr(uintptr_t x, size_t a)
{
    return (x + a - 1) & ~(a - 1);
}

static ucell get_ram_size( void )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	return ofmem->ramsize;
}

/************************************************************************/
/* debug                                                                */
/************************************************************************/

#if 0
static void
print_range( range_t *r, const char *str )
{
	printk("--- Range %s ---\n", str );
	for( ; r; r=r->next )
		printk("%p : " FMT_plx " - " FMT_plx "\n", r, r->start, r->start + r->size - 1);
	printk("\n");
}

static void
print_phys_range(void)
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	print_range( ofmem->phys_range, "phys" );
}

static void
print_virt_range(void)
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	print_range( ofmem->virt_range, "virt" );
}

static void
print_trans( void )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	translation_t *t = ofmem->trans;

	printk("--- Translations ---\n");
	for( ; t; t=t->next )
		printk("%p : " FMT_ucellx " -> " FMT_plx " [size " FMT_ucellx "]\n", t, t->virt, t->phys, t->size);
	printk("\n");
}
#endif

/************************************************************************/
/* OF private allocations                                               */
/************************************************************************/

int ofmem_posix_memalign( void **memptr, size_t alignment, size_t size )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	alloc_desc_t *d, **pp;
	void *ret;
	ucell top;
	phys_addr_t pa;

	if( !size )
		return ENOMEM;

	if( !ofmem->next_malloc )
		ofmem->next_malloc = (char*)ofmem_arch_get_malloc_base();

	size = align_size(size + sizeof(alloc_desc_t), alignment);

	/* look in the freelist */
	for( pp=&ofmem->mfree; *pp && (**pp).size < size; pp = &(**pp).next ) {
	}

	/* waste at most 4K by taking an entry from the freelist */
	if( *pp && (**pp).size > size + 0x1000 ) {
		/* Alignment should be on physical not virtual address */
		pa = va2pa((uintptr_t)*pp + sizeof(alloc_desc_t));
		pa = align_ptr(pa, alignment);
		ret = (void *)pa2va(pa);

		memset( ret, 0, (**pp).size - sizeof(alloc_desc_t) );
		*pp = (**pp).next;

		*memptr = ret;
		return 0;
	}

	top = ofmem_arch_get_heap_top();

	/* Alignment should be on physical not virtual address */
	pa = va2pa((uintptr_t)ofmem->next_malloc + sizeof(alloc_desc_t));
	pa = align_ptr(pa, alignment);
	ret = (void *)pa2va(pa);

	if( pointer2cell(ret) + size > top ) {
		printk("out of malloc memory (%x)!\n", size );
		return ENOMEM;
	}

	d = (alloc_desc_t*)((uintptr_t)ret - sizeof(alloc_desc_t));
	ofmem->next_malloc += size;

	d->next = NULL;
	d->size = size;

	memset( ret, 0, size - sizeof(alloc_desc_t) );

	*memptr = ret;
	return 0;
}

void* ofmem_malloc( size_t size )
{
	void *memptr;
	int res;
	
	res = ofmem_posix_memalign( &memptr, CONFIG_OFMEM_MALLOC_ALIGN, size );
	if (!res) {
		/* Success */
		return memptr;
	} else {
		/* Failure */
		return NULL;
	}
}

void ofmem_free( void *ptr )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	alloc_desc_t **pp, *d;

	/* it is legal to free NULL pointers (size zero allocations) */
	if( !ptr )
		return;

	d = (alloc_desc_t*)((char *)ptr - sizeof(alloc_desc_t));
	d->next = ofmem->mfree;

	/* insert in the (sorted) freelist */
	for( pp=&ofmem->mfree; *pp && (**pp).size < d->size ; pp = &(**pp).next ) {
	}

	d->next = *pp;
	*pp = d;
}

void* ofmem_realloc( void *ptr, size_t size )
{
	alloc_desc_t *d = (alloc_desc_t*)((char *)ptr - sizeof(alloc_desc_t));
	char *p;

	if( !ptr )
		return malloc( size );
	if( !size ) {
		free( ptr );
		return NULL;
	}
	p = malloc( size );
	memcpy( p, ptr, MIN(d->size - sizeof(alloc_desc_t),size) );
	free( ptr );
	return p;
}


/************************************************************************/
/* "translations" and "available" property tracking                     */
/************************************************************************/

static int trans_prop_size = 0, phys_range_prop_size = 0, virt_range_prop_size = 0;
static int trans_prop_used = 0, phys_range_prop_used = 0, virt_range_prop_used = 0;
static ucell *trans_prop, *phys_range_prop, *virt_range_prop;

static void
ofmem_set_property( phandle_t ph, const char *name, const char *buf, int len )
{
	/* This is very similar to set_property() in libopenbios/bindings.c but allows
	   us to set the property pointer directly, rather than having to copy it
	   into the Forth dictonary every time we update the memory properties */
	if( !ph ) {
		printk("ofmem_set_property: NULL phandle\n");
		return;
	}
	PUSH(pointer2cell(buf));
	PUSH(len);
	push_str(name);
	PUSH_ph(ph);
	fword("encode-property");
}

phandle_t s_phandle_memory = 0;
phandle_t s_phandle_mmu = 0;

static void ofmem_update_mmu_translations( void )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	translation_t *t;
	int ncells, prop_used, prop_size;

	if (s_phandle_mmu == 0)
		return;

	for( t = ofmem->trans, ncells = 0; t ; t=t->next, ncells++ ) {
	}

	/* Get the current number of bytes required for the MMU translation property */
	prop_used = ncells * sizeof(ucell) * ofmem_arch_get_translation_entry_size();

	if (prop_used > trans_prop_size) {

		/* The property doesn't fit within the existing space, so keep doubling it
		   until it does */
		prop_size = trans_prop_size;
		while (prop_size < prop_used) {
			prop_size *= 2;
		} 

		/* Allocate the new memory and copy all of the existing information across */
		trans_prop = realloc(trans_prop, prop_size);
		trans_prop_size = prop_size;
		trans_prop_used = prop_used;
	}

	if (trans_prop == NULL) {
		/* out of memory! */
		printk("Unable to allocate memory for translations property!\n");
		return;
	}

	/* Call architecture-specific routines to generate translation entries */
	for( t = ofmem->trans, ncells = 0 ; t ; t=t->next ) {
		ofmem_arch_create_translation_entry(&trans_prop[ncells], t);
		ncells += ofmem_arch_get_translation_entry_size();
	}

	ofmem_set_property(s_phandle_mmu, "translations",
			(char*)trans_prop, ncells * sizeof(trans_prop[0]));

}


static void ofmem_update_memory_available( phandle_t ph, range_t *range,
		ucell **mem_prop, int *mem_prop_size, int *mem_prop_used, u64 top_address )
{
	range_t *r;
	int ncells, prop_used, prop_size;
	phys_addr_t start;
	ucell size, *prop;

	if (s_phandle_memory == 0)
		return;

	/* count phys_range list entries */
	for( r = range, ncells = 0; r ; r=r->next, ncells++ ) {
	}

	/* inverse of phys_range list could take 2 or more additional cells for the tail
	   For /memory, physical addresses may be wider than one ucell. */
	prop_used = (ncells + 1) * sizeof(ucell) * ofmem_arch_get_available_entry_size(ph) + 1;

	if (prop_used > *mem_prop_size) {

		/* The property doesn't fit within the existing space, so keep doubling it
		   until it does */
		prop_size = *mem_prop_size;
		while (prop_size < prop_used) {
			prop_size *= 2;
		}

		/* Allocate the new memory and copy all of the existing information across */
		*mem_prop = realloc(*mem_prop, prop_size);
		*mem_prop_size = prop_size;
		*mem_prop_used = prop_used;
	}

	if (*mem_prop == NULL) {
		/* out of memory! */
		printk("Unable to allocate memory for memory range property!\n");
		return;
	}

	start = 0;
	ncells = 0;
	prop = *mem_prop;

	for (r = range; r; r=r->next) {
		if (r->start >= top_address) {
			break;
		}

		size = r->start - start;
		if (size) {
			ofmem_arch_create_available_entry(ph, &prop[ncells], start, size);
			ncells += ofmem_arch_get_available_entry_size(ph);
		}
		start = r->start + r->size;
	}

	/* tail */
	if ((start - 1) < top_address) {
		ofmem_arch_create_available_entry(ph, &prop[ncells], start, top_address - start + 1);
		ncells += ofmem_arch_get_available_entry_size(ph);
	}

	ofmem_set_property(ph, "available",
			(char*)prop, ncells * sizeof(prop[0]));
}

static void ofmem_update_translations( void )
{
	ofmem_t *ofmem = ofmem_arch_get_private();

	ofmem_update_memory_available(s_phandle_memory, ofmem->phys_range, 
			&phys_range_prop, &phys_range_prop_size, &phys_range_prop_used, get_ram_size() - 1);
	ofmem_update_memory_available(s_phandle_mmu, ofmem->virt_range, 
			&virt_range_prop, &virt_range_prop_size, &virt_range_prop_used, (ucell)-1);
	ofmem_update_mmu_translations();
}


/************************************************************************/
/* client interface                                                     */
/************************************************************************/

static int is_free( phys_addr_t ea, ucell size, range_t *r )
{
	if( size == 0 )
		return 1;
	for( ; r ; r=r->next ) {
		if( r->start + r->size - 1 >= ea && r->start <= ea )
			return 0;
		if( r->start >= ea && r->start <= ea + size - 1 )
			return 0;
	}
	return 1;
}

static void add_entry_( phys_addr_t ea, ucell size, range_t **r )
{
	range_t *nr;

	for( ; *r && (**r).start < ea; r=&(**r).next ) {
	}

	nr = (range_t*)malloc( sizeof(range_t) );
	nr->next = *r;
	nr->start = ea;
	nr->size = size;
	*r = nr;
}

static int add_entry( phys_addr_t ea, ucell size, range_t **r )
{
	if( !is_free( ea, size, *r ) ) {
		OFMEM_TRACE("add_entry: range not free!\n");
		return -1;
	}
	add_entry_( ea, size, r );
	return 0;
}

#if defined(OFMEM_FILL_RANGE)
static void join_ranges( range_t **rr )
{
	range_t *n, *r = *rr;
	while( r ) {
		if( !(n=r->next) )
			break;

		if( r->start + r->size - 1 >= n->start -1 ) {
			int s = n->size + (n->start - r->start - r->size);
			if( s > 0 )
				r->size += s;
			r->next = n->next;
			free( n );
			continue;
		}
		r=r->next;
	}
}

static void fill_range( phys_addr_t ea, ucell size, range_t **rr )
{
	add_entry_( ea, size, rr );
	join_ranges( rr );
}
#endif

static ucell find_area( ucell align, ucell size, range_t *r,
		phys_addr_t min, phys_addr_t max, int reverse )
{
	phys_addr_t base = min;
	range_t *r2;
	ucell old_align = align;
	int i;

	if( (align < PAGE_SIZE) ) {
		
		/* Minimum alignment is page size */
		align = PAGE_SIZE;
		
		OFMEM_TRACE("warning: bad alignment " FMT_ucellx " rounded up to " FMT_ucellx "\n", old_align, align);
	}

	if( (align & (align-1)) ) {
	
		/* As per IEEE1275 specification, round up to the nearest power of 2 */
		align--;
		for (i = 1; i < sizeof(ucell) * 8; i<<=1) {
			align |= align >> i;
		}
		align++;
		
		OFMEM_TRACE("warning: bad alignment " FMT_ucellx " rounded up to " FMT_ucellx "\n", old_align, align);
	}

	base = reverse ? max - size : min;
	r2 = reverse ? NULL : r;

	for( ;; ) {
		if( !reverse ) {
			base = (base + align - 1) & ~(align-1);
			if( base < min )
				base = min;
			if( base + size - 1 >= max -1 )
				break;
		} else {
			if( base > max - size )
				base = max - size;
			base -= base & (align-1);
		}
		if( is_free( base, size, r ) )
			return base;

		if( !reverse ) {
			if( !r2 )
				break;
			base = r2->start + r2->size;
			r2 = r2->next;
		} else {
			range_t *rp;

			for( rp=r; rp && rp->next != r2 ; rp=rp->next ) {
			}

			r2 = rp;
			if( !r2 )
				break;
			base = r2->start - size;
		}
	}
	return -1;
}

static phys_addr_t ofmem_claim_phys_( phys_addr_t phys, ucell size, ucell align,
		phys_addr_t min, phys_addr_t max, int reverse )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	if( !align ) {
		if( !is_free( phys, size, ofmem->phys_range ) ) {
			OFMEM_TRACE("Non-free physical memory claimed!\n");
			return -1;
		}
		add_entry( phys, size, &ofmem->phys_range );
		ofmem_update_translations();
		return phys;
	}
	phys = find_area( align, size, ofmem->phys_range, min, max, reverse );
	if( phys == -1 ) {
		printk("ofmem_claim_phys - out of space (failed request for " FMT_ucellx " bytes)\n", size);
		return -1;
	}
	add_entry( phys, size, &ofmem->phys_range );

	ofmem_update_translations();

	return phys;
}

/* if align != 0, phys is ignored. Returns -1 on error */
phys_addr_t ofmem_claim_phys( phys_addr_t phys, ucell size, ucell align )
{
    OFMEM_TRACE("ofmem_claim_phys phys=" FMT_plx " size=" FMT_ucellx
                " align=" FMT_ucellx "\n",
                phys, size, align);

	return ofmem_claim_phys_( phys, size, align, 0, get_ram_size(), 1 );
}

static ucell ofmem_claim_virt_( ucell virt, ucell size, ucell align,
		ucell min, ucell max, int reverse )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	if( !align ) {
		if( !is_free( virt, size, ofmem->virt_range ) ) {
			OFMEM_TRACE("Non-free virtual memory claimed!\n");
			return -1;
		}
		add_entry( virt, size, &ofmem->virt_range );
		ofmem_update_translations();
		return virt;
	}

	virt = find_area( align, size, ofmem->virt_range, min, max, reverse );
	if( virt == -1 ) {
		printk("ofmem_claim_virt - out of space (failed request for " FMT_ucellx " bytes)\n", size);
		return -1;
	}
	add_entry( virt, size, &ofmem->virt_range );
	
	ofmem_update_translations();
	
	return virt;
}

ucell ofmem_claim_virt( ucell virt, ucell size, ucell align )
{
    OFMEM_TRACE("ofmem_claim_virt virt=" FMT_ucellx " size=" FMT_ucellx
                " align=" FMT_ucellx "\n",
                virt, size, align);

	/* printk("+ ofmem_claim virt %08lx %lx %ld\n", virt, size, align ); */
	return ofmem_claim_virt_( virt, size, align,
			get_ram_size(), ofmem_arch_get_virt_top(), 1 );
}

static ucell ofmem_claim_io_( ucell virt, ucell size, ucell align,
		ucell min, ucell max, int reverse )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	if( !align ) {
		if( !is_free( virt, size, ofmem->io_range ) ) {
			OFMEM_TRACE("Non-free I/O memory claimed!\n");
			return -1;
		}
		add_entry( virt, size, &ofmem->io_range );
		return virt;
	}

	virt = find_area( align, size, ofmem->io_range, min, max, reverse );
	if( virt == -1 ) {
		printk("ofmem_claim_io - out of space (failed request for " FMT_ucellx " bytes)\n", size);
		return -1;
	}
	add_entry( virt, size, &ofmem->io_range );
	return virt;
}

ucell ofmem_claim_io( ucell virt, ucell size, ucell align )
{
	/* Claim a section of memory from the I/O range */
	return ofmem_claim_io_( virt, size, align,
			ofmem_arch_get_iomem_base(), ofmem_arch_get_iomem_top(), 0 );
}

/* if align != 0, phys is ignored. Returns -1 on error */
phys_addr_t ofmem_retain( phys_addr_t phys, ucell size, ucell align )
{
    retain_t *retained = ofmem_arch_get_retained();
    phys_addr_t retain_phys;

    OFMEM_TRACE("ofmem_retain phys=" FMT_plx " size=" FMT_ucellx
                " align=" FMT_ucellx "\n",
                phys, size, align);

	retain_phys = ofmem_claim_phys_( phys, size, align, 0, get_ram_size(), 1 /* reverse */ );

	/* Add to the retain_phys_range list */
	retained->retain_phys_range[retained->numentries].next = NULL;
	retained->retain_phys_range[retained->numentries].start = retain_phys;
	retained->retain_phys_range[retained->numentries].size = size;
	retained->numentries++;

	return retain_phys;
}

/* allocate both physical and virtual space and add a translation */
ucell ofmem_claim( ucell addr, ucell size, ucell align )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	ucell virt;
	phys_addr_t phys;
	ucell offs = addr & (PAGE_SIZE - 1);

	OFMEM_TRACE("ofmem_claim " FMT_ucellx " " FMT_ucellx " " FMT_ucellx "\n", addr, size, align );
	virt = phys = 0;
	if( !align ) {
		if( is_free(addr, size, ofmem->virt_range) &&
		    is_free(addr, size, ofmem->phys_range) ) {
			ofmem_claim_phys_( addr, size, 0, 0, 0, 0 );
			ofmem_claim_virt_( addr, size, 0, 0, 0, 0 );
			virt = phys = addr;
		} else {
			OFMEM_TRACE("**** ofmem_claim failure ***!\n");
			return -1;
		}
	} else {
		if( align < PAGE_SIZE )
			align = PAGE_SIZE;
		phys = ofmem_claim_phys_( -1, size, align, 0, get_ram_size(), 1 /* reverse */ );
		virt = ofmem_claim_virt_( phys, size, 0, 0, 0, 0 );
		if( phys == -1 || virt == -1 ) {
			OFMEM_TRACE("ofmem_claim failed\n");
			return -1;
		}
		/* printk("...phys = %08lX, virt = %08lX, size = %08lX\n", phys, virt, size ); */
	}

	/* align */
	if( phys & (PAGE_SIZE - 1) ) {
		size += (phys & (PAGE_SIZE - 1));
		virt -= (phys & (PAGE_SIZE - 1));
		phys &= PAGE_MASK;
	}
	if( size & (PAGE_SIZE - 1) )
		size = (size + (PAGE_SIZE - 1)) & PAGE_MASK;

	/* printk("...free memory found... phys: %08lX, virt: %08lX, size %lX\n", phys, virt, size ); */
	ofmem_map( phys, virt, size, -1 );
	return virt + offs;
}


/************************************************************************/
/* keep track of ea -> phys translations                                */
/************************************************************************/

static void split_trans( ucell virt )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	translation_t *t, *t2;

	for( t=ofmem->trans; t; t=t->next ) {
		if( virt > t->virt && virt < t->virt + t->size-1 ) {
			t2 = (translation_t*)malloc( sizeof(translation_t) );
			t2->virt = virt;
			t2->size = t->size - (virt - t->virt);
			t->size = virt - t->virt;
			t2->phys = t->phys + t->size;
			t2->mode = t->mode;
			t2->next = t->next;
			t->next = t2;
		}
	}
}

int ofmem_map_page_range( phys_addr_t phys, ucell virt, ucell size, ucell mode )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	translation_t *t, **tt;

	OFMEM_TRACE("ofmem_map_page_range " FMT_ucellx
			" -> " FMT_plx " " FMT_ucellx " mode " FMT_ucellx "\n",
			virt, phys, size, mode );

	split_trans( virt );
	split_trans( virt + size );

	/* detect remappings */
	for( t=ofmem->trans; t; ) {
		if( virt == t->virt || (virt < t->virt && virt + size > t->virt )) {
			if( t->phys + virt - t->virt != phys ) {
				OFMEM_TRACE("mapping altered virt=" FMT_ucellx ")\n", t->virt );
			} else if( t->mode != mode ){
				OFMEM_TRACE("mapping mode altered virt=" FMT_ucellx
						" old mode=" FMT_ucellx " new mode=" FMT_ucellx "\n",
						t->virt, t->mode, mode);
			}

			for( tt=&ofmem->trans; *tt != t ; tt=&(**tt).next ) {
			}

			*tt = t->next;

			/* really unmap these pages */
			ofmem_arch_unmap_pages(t->virt, t->size);

			free((char*)t);

			t=ofmem->trans;
			continue;
		}
		t=t->next;
	}

	/* add mapping */
	for( tt=&ofmem->trans; *tt && (**tt).virt < virt ; tt=&(**tt).next ) {
	}

	t = (translation_t*)malloc( sizeof(translation_t) );
	t->virt = virt;
	t->phys = phys;
	t->size = size;
	t->mode = mode;
	t->next = *tt;
	*tt = t;

	ofmem_update_translations();

	return 0;
}

static int unmap_page_range( ucell virt, ucell size )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	translation_t **plink;

	/* make sure there is exactly one matching translation entry */

	split_trans( virt );
	split_trans( virt + size );

	/* find and unlink entries in range */
	plink = &ofmem->trans;

	while (*plink && (*plink)->virt < virt+size) {
		translation_t **plinkentry = plink;
		translation_t *t = *plink;

		/* move ahead */
		plink = &t->next;

		if (t->virt >= virt && t->virt + t->size <= virt+size) {

			/* unlink entry */
			*plinkentry = t->next;

			OFMEM_TRACE("unmap_page_range found "
					FMT_ucellx " -> " FMT_plx " " FMT_ucellx
					" mode " FMT_ucellx "\n",
					t->virt, t->phys, t->size, t->mode );

			// really map these pages
			ofmem_arch_unmap_pages(t->virt, t->size);

			free((char*)t);
		}
	}

	ofmem_update_translations();

	return 0;
}

int ofmem_map( phys_addr_t phys, ucell virt, ucell size, ucell mode )
{
	/* printk("+ofmem_map: %08lX --> %08lX (size %08lX, mode 0x%02X)\n",
	   virt, phys, size, mode ); */

	if( (phys & (PAGE_SIZE - 1)) || (virt & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1)) ) {

		OFMEM_TRACE("ofmem_map: Bad parameters ("
				FMT_plx " " FMT_ucellx " " FMT_ucellx ")\n",
				phys, virt, size );

		phys &= PAGE_MASK;
		virt &= PAGE_MASK;
		size = (size + (PAGE_SIZE - 1)) & PAGE_MASK;
	}

#if defined(OFMEM_FILL_RANGE)
	{
		ofmem_t *ofmem = ofmem_arch_get_private();
		/* claim any unclaimed virtual memory in the range */
		fill_range( virt, size, &ofmem->virt_range );
		/* hmm... we better claim the physical range too */
		fill_range( phys, size, &ofmem->phys_range );
	}
#endif

	if (mode==-1) {
		mode = ofmem_arch_default_translation_mode(phys);
	}

	/* install translations */
	ofmem_map_page_range(phys, virt, size, mode);

	/* allow arch to map the pages */
	ofmem_arch_map_pages(phys, virt, size, mode);

	return 0;
}

int ofmem_unmap( ucell virt, ucell size )
{
	OFMEM_TRACE("ofmem_unmap " FMT_ucellx " " FMT_ucellx "\n",
			virt, size );

	if( (virt & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1)) ) {
		/* printk("ofmem_unmap: Bad parameters (%08lX %08lX)\n",
				virt, size ); */
		virt &= PAGE_MASK;
		size = (size + (PAGE_SIZE - 1)) & PAGE_MASK;
	}

	/* remove translations and unmap pages */
	unmap_page_range(virt, size);

	return 0;
}

ucell ofmem_map_io( phys_addr_t phys, ucell size )
{
	/* Claim virtual memory from the I/O range and map the page-aligned
	   physical address phys to it, returning the newly allocated
	   virtual address */
	ucell virt, mode;
	phys_addr_t off;
	int npages;

	off = phys & (PAGE_SIZE - 1);
	npages = (off + size - 1) / PAGE_SIZE + 1;
	phys &= ~(PAGE_SIZE - 1);

	virt = ofmem_claim_io(-1, npages * PAGE_SIZE, PAGE_SIZE);

	mode = ofmem_arch_io_translation_mode(off);

	ofmem_map_page_range(phys, virt, npages * PAGE_SIZE, mode);
	ofmem_arch_map_pages(phys, virt, npages * PAGE_SIZE, mode);

	return (virt + off);
}

/* virtual -> physical. */
phys_addr_t ofmem_translate( ucell virt, ucell *mode )
{
	ofmem_t *ofmem = ofmem_arch_get_private();
	translation_t *t;

	for( t=ofmem->trans; t && t->virt <= virt ; t=t->next ) {
		ucell offs;
		if( t->virt + t->size - 1 < virt )
			continue;
		offs = virt - t->virt;
		*mode = t->mode;
		return t->phys + offs;
	}

	/*printk("ofmem_translate: no translation defined (%08lx)\n", virt);*/
	/*print_trans();*/
	return -1;
}

static void remove_range_( phys_addr_t ea, ucell size, range_t **r )
{
	range_t **t, *u;

	/* If not an exact match then split the range */
	for (t = r; *t; t = &(**t).next) {
		if (ea > (**t).start && ea < (**t).start + (**t).size - 1) {
			u = (range_t*)malloc(sizeof(range_t));
			u->start = ea;
			u->size = size;
			u->next = (**t).next;

			OFMEM_TRACE("remove_range_ splitting range with addr=" FMT_plx
					" size=" FMT_ucellx " -> addr=" FMT_plx " size=" FMT_ucellx ", "
					"addr=" FMT_plx " size=" FMT_ucellx "\n",
					(**t).start, (**t).size, (**t).start, (**t).size - size,
					u->start, u->size);

			(**t).size = (**t).size - size;
			(**t).next = u;
		}
	}

	for (t = r; *t; t = &(**t).next) {
		if (ea >= (**t).start && ea + size <= (**t).start + (**t).size) {
			OFMEM_TRACE("remove_range_ freeing range with addr=" FMT_plx
					" size=" FMT_ucellx "\n", (**t).start, (**t).size);
			u = *t;
			*t = (**t).next;
			free(u);
			break;
		}
	}
}

static int remove_range( phys_addr_t ea, ucell size, range_t **r )
{
	if( is_free( ea, size, *r ) ) {
		OFMEM_TRACE("remove_range: range isn't occupied\n");
		return -1;
	}
	remove_range_( ea, size, r );
	return 0;
}

/* release memory allocated by ofmem_claim_phys */
void ofmem_release_phys( phys_addr_t phys, ucell size )
{
    OFMEM_TRACE("ofmem_release_phys addr=" FMT_plx " size=" FMT_ucellx "\n",
                phys, size);

    ofmem_t *ofmem = ofmem_arch_get_private();
    remove_range(phys, size, &ofmem->phys_range);
}

/* release memory allocated by ofmem_claim_virt */
void ofmem_release_virt( ucell virt, ucell size )
{
    OFMEM_TRACE("ofmem_release_virt addr=" FMT_ucellx " size=" FMT_ucellx "\n",
                virt, size);

    ofmem_t *ofmem = ofmem_arch_get_private();
    remove_range(virt, size, &ofmem->virt_range);
}

/* release memory allocated by ofmem_claim_io */
void ofmem_release_io( ucell virt, ucell size )
{
    OFMEM_TRACE("ofmem_release_io addr=" FMT_ucellx " size=" FMT_ucellx "\n",
                virt, size);

    ofmem_t *ofmem = ofmem_arch_get_private();
    remove_range(virt, size, &ofmem->io_range);
}

/* release memory allocated by ofmem_claim - 6.3.2.4 */
void ofmem_release( ucell virt, ucell size )
{
    OFMEM_TRACE("%s addr=" FMT_ucellx " size=" FMT_ucellx "\n",
                __func__, virt, size);

    ucell mode;
    phys_addr_t phys = ofmem_translate(virt, &mode);
    if (phys == (phys_addr_t)-1) {
        OFMEM_TRACE("%s: no mapping\n", __func__);
        return;
    }
    ofmem_unmap(virt, size);
    ofmem_release_virt(virt, size);
    ofmem_release_phys(phys, size);
}

/************************************************************************/
/* init / cleanup                                                       */
/************************************************************************/

void ofmem_register( phandle_t ph_memory, phandle_t ph_mmu )
{
	s_phandle_memory = ph_memory;
	s_phandle_mmu = ph_mmu;

	/* Initialise some default property sizes  */
	trans_prop_size = phys_range_prop_size = virt_range_prop_size = OFMEM_DEFAULT_PROP_SIZE;
	trans_prop = malloc(trans_prop_size);
	phys_range_prop = malloc(phys_range_prop_size);
	virt_range_prop = malloc(virt_range_prop_size);

	ofmem_update_translations();
}
