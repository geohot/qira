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

#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/string.h"
#include "libopenbios/ofmem.h"
#include "kernel.h"
#include "mmutypes.h"
#include "asm/processor.h"

#define BIT(n)		(1U << (31 - (n)))

#define SLB_VSID_SHIFT 12

/* called from assembly */
extern void dsi_exception(void);
extern void isi_exception(void);
extern void setup_mmu(unsigned long code_base);

/*
 * From Apple's BootX source comments:
 *
 *  96 MB map (currently unused - 4363357 tracks re-adoption)
 * 00000000 - 00003FFF  : Exception Vectors
 * 00004000 - 03FFFFFF  : Kernel Image, Boot Struct and Drivers (~64 MB)
 * 04000000 - 04FFFFFF  : File Load Area (16 MB)   [80 MB]
 * 05000000 - 053FFFFF  : FS Cache    (4 MB)       [84 MB]
 * 05400000 - 055FFFFF  : Malloc Zone (2 MB)       [86 MB]
 * 05600000 - 057FFFFF  : BootX Image (2 MB)       [88 MB]
 * 05800000 - 05FFFFFF  : Unused/OF   (8 MB)       [96 MB]
 *
 */

#define FREE_BASE		0x00004000UL
#define OF_CODE_START	0xfff00000UL
#define OF_CODE_SIZE    0x00100000
#define IO_BASE			0x80000000UL

#ifdef __powerpc64__
#define HASH_BITS		18
#else
#define HASH_BITS		15
#endif
#define HASH_SIZE		(2 << HASH_BITS)
#define OFMEM_SIZE		(1 * 1024 * 1024 + 512 * 1024)

#define	SEGR_USER		BIT(2)
#define SEGR_BASE		0x0400

static inline unsigned long
get_hash_base(void)
{
    return (mfsdr1() & SDR1_HTABORG_MASK);
}

static inline unsigned long
get_rom_base(void)
{
    ofmem_t *ofmem = ofmem_arch_get_private();
    return ofmem->ramsize - OF_CODE_SIZE;
}

static unsigned long
get_ram_top(void)
{
    return get_hash_base() - (32 + 64 + 64) * 1024 - OFMEM_SIZE;
}

static unsigned long
get_ram_bottom(void)
{
    return FREE_BASE;
}

static unsigned long get_heap_top(void)
{
    return get_hash_base() - (32 + 64 + 64) * 1024;
}

static inline size_t ALIGN_SIZE(size_t x, size_t a)
{
    return (x + a - 1) & ~(a - 1);
}

ofmem_t* ofmem_arch_get_private(void)
{
    return (ofmem_t*)cell2pointer(get_heap_top() - OFMEM_SIZE);
}

void* ofmem_arch_get_malloc_base(void)
{
    return (char*)ofmem_arch_get_private() + ALIGN_SIZE(sizeof(ofmem_t), 4);
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

void ofmem_arch_map_pages(phys_addr_t phys, ucell virt, ucell size, ucell mode)
{
    /* none yet */
}

ucell ofmem_arch_get_iomem_base(void)
{
    /* Currently unused */
    return 0;
}

ucell ofmem_arch_get_iomem_top(void)
{
    /* Currently unused */
    return 0;
}

retain_t *ofmem_arch_get_retained(void)
{
    /* not implemented */
    return NULL;
}

int ofmem_arch_get_physaddr_cellsize(void)
{
#ifdef CONFIG_PPC64
    return 2;
#else
    return 1;
#endif
}

int ofmem_arch_encode_physaddr(ucell *p, phys_addr_t value)
{
    int n = 0;
#ifdef CONFIG_PPC64
    p[n++] = value >> 32;
#endif
    p[n++] = value;
    return n;
}

/* Return size of a single MMU package translation property entry in cells */
int ofmem_arch_get_translation_entry_size(void)
{
    return 3 + ofmem_arch_get_physaddr_cellsize();
}

/* Generate translation property entry for PPC.
 * According to the platform bindings for PPC
 * (http://www.openfirmware.org/1275/bindings/ppc/release/ppc-2_1.html#REF34579)
 * a translation property entry has the following layout:
 *
 *      virtual address
 *      length
 *      physical address
 *      mode
 */
void ofmem_arch_create_translation_entry(ucell *transentry, translation_t *t)
{
    int i = 0;

    transentry[i++] = t->virt;
    transentry[i++] = t->size;
    i += ofmem_arch_encode_physaddr(&transentry[i], t->phys);
    transentry[i++] = t->mode;
}

/* Return the size of a memory available entry given the phandle in cells */
int ofmem_arch_get_available_entry_size(phandle_t ph)
{
    if (ph == s_phandle_memory) {
        return 1 + ofmem_arch_get_physaddr_cellsize();
    } else {
        return 1 + 1;
    }
}

/* Generate memory available property entry for PPC */
void ofmem_arch_create_available_entry(phandle_t ph, ucell *availentry, phys_addr_t start, ucell size)
{
    int i = 0;

    if (ph == s_phandle_memory) {
        i += ofmem_arch_encode_physaddr(availentry, start);
    } else {
	availentry[i++] = start;
    }
    
    availentry[i] = size;
}

/************************************************************************/
/*	OF private allocations						*/
/************************************************************************/

/* Private functions for mapping between physical/virtual addresses */
phys_addr_t
va2pa(unsigned long va)
{
    if (va >= OF_CODE_START && va < OF_CODE_START + OF_CODE_SIZE) {
        return (phys_addr_t)get_rom_base() - OF_CODE_START + va;
    } else {
        return (phys_addr_t)va;
    }
}

unsigned long
pa2va(phys_addr_t pa)
{
    if ((pa - get_rom_base() + OF_CODE_START >= OF_CODE_START) &&
        (pa - get_rom_base() + OF_CODE_START < OF_CODE_START + OF_CODE_SIZE))
        return (unsigned long)pa - get_rom_base() + OF_CODE_START;
    else
        return (unsigned long)pa;
}

void *
malloc(int size)
{
    return ofmem_malloc(size);
}

void
free(void *ptr)
{
    ofmem_free(ptr);
}

void *
realloc(void *ptr, size_t size)
{
    return ofmem_realloc(ptr, size);
}


/************************************************************************/
/*	misc								*/
/************************************************************************/

ucell ofmem_arch_default_translation_mode(phys_addr_t phys)
{
    /* XXX: Guard bit not set as it should! */
    if (phys < IO_BASE)
        return 0x02;	/*0xa*/	/* wim GxPp */
    return 0x6a;		/* WIm GxPp, I/O */
}

ucell ofmem_arch_io_translation_mode(phys_addr_t phys)
{
    return 0x6a;		/* WIm GxPp, I/O */
}

/************************************************************************/
/*	page fault handler						*/
/************************************************************************/

static phys_addr_t
ea_to_phys(unsigned long ea, ucell *mode)
{
    phys_addr_t phys;

    if (ea >= OF_CODE_START && ea <= 0xffffffffUL) {
        /* ROM into RAM */
        ea -= OF_CODE_START;
        phys = get_rom_base() + ea;
        *mode = 0x02;
		return phys;
    }

    phys = ofmem_translate(ea, mode);
    if (phys == -1) {
        phys = ea;
        *mode = ofmem_arch_default_translation_mode(phys);

        /* print_virt_range(); */
        /* print_phys_range(); */
        /* print_trans(); */
    }
    return phys;
}

/* Converts a global variable (from .data or .bss) into a pointer that
   can be accessed from real mode */
static void *
global_ptr_real(void *p)
{
    return (void*)((uintptr_t)p - OF_CODE_START + get_rom_base());
}

/* Return the next slot to evict, in the range of [0..7] */
static int
next_evicted_slot(void)
{
    static int next_grab_slot;
    int *next_grab_slot_va;
    int r;

    next_grab_slot_va = global_ptr_real(&next_grab_slot);
    r = *next_grab_slot_va;
    *next_grab_slot_va = (r + 1) % 8;

    return r;
}

static void
hash_page_64(unsigned long ea, phys_addr_t phys, ucell mode)
{
    uint64_t vsid_mask, page_mask, pgidx, hash;
    uint64_t htab_mask, mask, avpn;
    unsigned long pgaddr;
    int i, found;
    unsigned int vsid, vsid_sh, sdr, sdr_sh, sdr_mask;
    mPTE_64_t *pp;

    vsid = (ea >> 28) + SEGR_BASE;
    vsid_sh = 7;
    vsid_mask = 0x00003FFFFFFFFF80ULL;
    sdr = mfsdr1();
    sdr_sh = 18;
    sdr_mask = 0x3FF80;
    page_mask = 0x0FFFFFFF; // XXX correct?
    pgidx = (ea & page_mask) >> PAGE_SHIFT;
    avpn = (vsid << 12) | ((pgidx >> 4) & 0x0F80);;

    hash = ((vsid ^ pgidx) << vsid_sh) & vsid_mask;
    htab_mask = 0x0FFFFFFF >> (28 - (sdr & 0x1F));
    mask = (htab_mask << sdr_sh) | sdr_mask;
    pgaddr = sdr | (hash & mask);
    pp = (mPTE_64_t *)pgaddr;

    /* replace old translation */
    for (found = 0, i = 0; !found && i < 8; i++)
        if (pp[i].avpn == avpn)
            found = 1;

    /* otherwise use a free slot */
    for (i = 0; !found && i < 8; i++)
        if (!pp[i].v)
            found = 1;

    /* out of slots, just evict one */
    if (!found)
        i = next_evicted_slot() + 1;
    i--;
    {
    mPTE_64_t p = {
        // .avpn_low = avpn,
        .avpn = avpn >> 7,
        .h = 0,
        .v = 1,

        .rpn = (phys & ~0xfffUL) >> 12,
        .r = mode & (1 << 8) ? 1 : 0,
        .c = mode & (1 << 7) ? 1 : 0,
        .w = mode & (1 << 6) ? 1 : 0,
        .i = mode & (1 << 5) ? 1 : 0,
        .m = mode & (1 << 4) ? 1 : 0,
        .g = mode & (1 << 3) ? 1 : 0,
        .n = mode & (1 << 2) ? 1 : 0,
        .pp = mode & 3,
    };
    pp[i] = p;
    }

    asm volatile("tlbie %0" :: "r"(ea));
}

static void
hash_page_32(unsigned long ea, phys_addr_t phys, ucell mode)
{
#ifndef __powerpc64__
    unsigned long *upte, cmp, hash1;
    int i, vsid, found;
    mPTE_t *pp;

    vsid = (ea >> 28) + SEGR_BASE;
    cmp = BIT(0) | (vsid << 7) | ((ea & 0x0fffffff) >> 22);

    hash1 = vsid;
    hash1 ^= (ea >> 12) & 0xffff;
    hash1 &= (((mfsdr1() & 0x1ff) << 16) | 0xffff) >> 6;

    pp = (mPTE_t*)(get_hash_base() + (hash1 << 6));
    upte = (unsigned long*)pp;

    /* replace old translation */
    for (found = 0, i = 0; !found && i < 8; i++)
        if (cmp == upte[i*2])
            found = 1;

    /* otherwise use a free slot */
    for (i = 0; !found && i < 8; i++)
        if (!pp[i].v)
            found = 1;

    /* out of slots, just evict one */
    if (!found)
        i = next_evicted_slot() + 1;
    i--;
    upte[i * 2] = cmp;
    upte[i * 2 + 1] = (phys & ~0xfff) | mode;

    asm volatile("tlbie %0" :: "r"(ea));
#endif
}

static int is_ppc64(void)
{
#ifdef __powerpc64__
    return 1;
#elif defined(CONFIG_PPC_64BITSUPPORT)
    unsigned int pvr = mfpvr();
    return ((pvr >= 0x330000) && (pvr < 0x70330000));
#else
    return 0;
#endif
}

/* XXX Remove these ugly constructs when legacy 64-bit support is dropped. */
static void hash_page(unsigned long ea, phys_addr_t phys, ucell mode)
{
    if (is_ppc64())
        hash_page_64(ea, phys, mode);
    else
        hash_page_32(ea, phys, mode);
}

void
dsi_exception(void)
{
    unsigned long dar, dsisr;
    ucell mode;
    phys_addr_t phys;

    asm volatile("mfdar %0" : "=r" (dar) : );
    asm volatile("mfdsisr %0" : "=r" (dsisr) : );

    phys = ea_to_phys(dar, &mode);
    hash_page(dar, phys, mode);
}

void
isi_exception(void)
{
    unsigned long nip, srr1;
    ucell mode;
    phys_addr_t phys;

    asm volatile("mfsrr0 %0" : "=r" (nip) : );
    asm volatile("mfsrr1 %0" : "=r" (srr1) : );

    phys = ea_to_phys(nip, &mode);
    hash_page(nip, phys, mode);
}


/************************************************************************/
/*	init / cleanup							*/
/************************************************************************/

void
setup_mmu(unsigned long ramsize)
{
    ofmem_t *ofmem;
#ifndef __powerpc64__
    unsigned long sr_base;
#endif
    unsigned long hash_base;
    unsigned long hash_mask = ~0x000fffffUL; /* alignment for ppc64 */
    int i;

    /* SDR1: Storage Description Register 1 */

    hash_base = (ramsize - OF_CODE_SIZE - HASH_SIZE) & hash_mask;
    memset((void *)hash_base, 0, HASH_SIZE);
    if (is_ppc64())
        mtsdr1(hash_base | MAX(HASH_BITS - 18, 0));
    else
        mtsdr1(hash_base | ((HASH_SIZE - 1) >> 16));

#ifdef __powerpc64__

    /* Segment Lookaside Buffer */

    slbia(); /* Invalidate all SLBs except SLB 0 */
    for (i = 0; i < 16; i++) {
        unsigned long rs = (0x400 + i) << SLB_VSID_SHIFT;
        unsigned long rb = ((unsigned long)i << 28) | (1 << 27) | i;
        slbmte(rs, rb);
    }

#else

    /* Segment Register */

    sr_base = SEGR_USER | SEGR_BASE ;
    for (i = 0; i < 16; i++) {
        int j = i << 28;
        asm volatile("mtsrin %0,%1" :: "r" (sr_base + i), "r" (j));
    }

#endif

    ofmem = ofmem_arch_get_private();
    memset(ofmem, 0, sizeof(ofmem_t));
    ofmem->ramsize = ramsize;

    memcpy((void *)get_rom_base(), (void *)OF_CODE_START, OF_CODE_SIZE);

    /* Enable MMU */

    mtmsr(mfmsr() | MSR_IR | MSR_DR);
}

void
ofmem_init(void)
{
    ofmem_t *ofmem = ofmem_arch_get_private();

    /* Map the memory (don't map page 0 to allow catching of NULL dereferences) */
    ofmem_claim_phys(PAGE_SIZE, get_ram_bottom() - PAGE_SIZE, 0);
    ofmem_claim_virt(PAGE_SIZE, get_ram_bottom() - PAGE_SIZE, 0);
    ofmem_map(PAGE_SIZE, PAGE_SIZE, get_ram_bottom() - PAGE_SIZE, 0);

    /* Mark the first page as non-free */
    ofmem_claim_phys(0, PAGE_SIZE, 0);
    ofmem_claim_virt(0, PAGE_SIZE, 0);

    /* Map everything at the top of physical RAM 1:1, minus the OpenBIOS ROM in RAM copy */
    ofmem_claim_phys(get_ram_top(), get_hash_base() + HASH_SIZE - get_ram_top(), 0);
    ofmem_claim_virt(get_ram_top(), get_hash_base() + HASH_SIZE - get_ram_top(), 0);
    ofmem_map(get_ram_top(), get_ram_top(), get_hash_base() + HASH_SIZE - get_ram_top(), 0);
    
    /* Map the OpenBIOS ROM in RAM copy */
    ofmem_claim_phys(ofmem->ramsize - OF_CODE_SIZE, OF_CODE_SIZE, 0);
    ofmem_claim_virt(OF_CODE_START, OF_CODE_SIZE, 0);
    ofmem_map(ofmem->ramsize - OF_CODE_SIZE, OF_CODE_START, OF_CODE_SIZE, 0);
}
