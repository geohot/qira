/* lib.c
 * tag: simple function library
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "libc/vsprintf.h"
#include "libopenbios/bindings.h"
#include "arch/sparc32/ofmem_sparc32.h"
#include "asm/asi.h"
#include "pgtsrmmu.h"
#include "openprom.h"
#include "libopenbios/sys_info.h"
#include "boot.h"
#include "romvec.h"

#define NCTX_SWIFT  0x100
#define LOWMEMSZ 32 * 1024 * 1024

#ifdef CONFIG_DEBUG_MEM
#define DPRINTF(fmt, args...)                   \
    do { printk(fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...)
#endif

/* Format a string and print it on the screen, just like the libc
 * function printf.
 */
int printk( const char *fmt, ... )
{
        char *p, buf[512];
	va_list args;
	int i;

	va_start(args, fmt);
        i = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	for( p=buf; *p; p++ )
		putchar(*p);
	return i;
}

/*
 * Allocatable memory chunk.
 */
struct mem {
    char *start, *uplim;
    char *curp;
};

struct mem cdvmem;              /* Current device virtual memory space */

unsigned int va_shift;
unsigned long *l1;
static unsigned long *context_table;

struct linux_mlist_v0 *ptphys;
struct linux_mlist_v0 *ptmap;
struct linux_mlist_v0 *ptavail;

/* Private functions for mapping between physical/virtual addresses */ 
phys_addr_t
va2pa(unsigned long va)
{
    if ((va >= (unsigned long)&_start) &&
        (va < (unsigned long)&_end))
        return va - va_shift;
    else
        return va;
}

unsigned long
pa2va(phys_addr_t pa)
{
    if ((pa + va_shift >= (unsigned long)&_start) &&
        (pa + va_shift < (unsigned long)&_end))
        return pa + va_shift;
    else
        return pa;
}

void *
malloc(int size)
{
    return ofmem_malloc(size);
}

void *
realloc( void *ptr, size_t size )
{
    return ofmem_realloc(ptr, size);
}

void
free(void *ptr)
{
    ofmem_free(ptr);
}

/*
 * Allocate memory. This is reusable.
 */
void
mem_init(struct mem *t, char *begin, char *limit)
{
    t->start = begin;
    t->uplim = limit;
    t->curp = begin;
}

void *
mem_alloc(struct mem *t, int size, int align)
{
    char *p;
    unsigned long pa;

    // The alignment restrictions refer to physical, not virtual
    // addresses
    pa = va2pa((unsigned long)t->curp) + (align - 1);
    pa &= ~(align - 1);
    p = (char *)pa2va(pa);

    if ((unsigned long)p >= (unsigned long)t->uplim ||
        (unsigned long)p + size > (unsigned long)t->uplim)
        return NULL;
    t->curp = p + size;

    return p;
}

/*
 * D5.3 pgmap@ ( va -- pte )
 */
static void
pgmap_fetch(void)
{
    uint32_t pte;
    unsigned long va, pa;

    va = POP();

    pa = find_pte(va, 0);
    if (pa == 1 || pa == 2)
        goto error;
    pte = *(uint32_t *)pa;
    DPRINTF("pgmap@: va 0x%lx pa 0x%lx pte 0x%x\n", va, pa, pte);

    PUSH(pte);
    return;
 error:
    PUSH(0);
}

/*
 * D5.3 pgmap! ( pte va -- )
 */
static void
pgmap_store(void)
{
    uint32_t pte;
    unsigned long va, pa;

    va = POP();
    pte = POP();

    pa = find_pte(va, 1);
    *(uint32_t *)pa = pte;
    DPRINTF("pgmap!: va 0x%lx pa 0x%lx pte 0x%x\n", va, pa, pte);
}

/*
 * D5.3 map-pages ( pa space va size -- )
 */
static void
ob_map_pages(void)
{
    unsigned long va;
    int size;
    uint64_t pa;

    size = POP();
    va = POP();
    pa = POP();
    pa <<= 32;
    pa |= POP() & 0xffffffff;

    ofmem_arch_map_pages(pa, va, size, ofmem_arch_default_translation_mode(pa));
}

char *obp_dumb_mmap(char *va, int which_io, unsigned int pa,
                    unsigned int size)
{
    uint64_t mpa = ((uint64_t)which_io << 32) | (uint64_t)pa;

    ofmem_arch_map_pages(mpa, (unsigned long)va, size, ofmem_arch_default_translation_mode(mpa));
    return va;
}

void obp_dumb_munmap(__attribute__((unused)) char *va,
                     __attribute__((unused)) unsigned int size)
{
    DPRINTF("obp_dumb_munmap: virta 0x%x, sz %d\n", (unsigned int)va, size);
}

char *obp_memalloc(char *va, unsigned int size, unsigned int align)
{
    phys_addr_t phys;
    ucell virt;

    DPRINTF("obp_memalloc: virta 0x%x, sz %d, align %d\n", (unsigned int)va, size, align);    
    
    /* Claim physical memory */
    phys = ofmem_claim_phys(-1, size, align);

    /* Claim virtual memory */
    virt = ofmem_claim_virt(pointer2cell(va), size, 0);

    /* Map the memory */
    ofmem_map(phys, virt, size, ofmem_arch_default_translation_mode(phys));

    return cell2pointer(virt);
}

char *obp_dumb_memalloc(char *va, unsigned int size)
{
    unsigned long align = size;
    phys_addr_t phys;
    ucell virt;
    
    DPRINTF("obp_dumb_memalloc: virta 0x%x, sz %d\n", (unsigned int)va, size);    
    
    /* Solaris seems to assume that the returned value is physically aligned to size.
       e.g. it is used for setting up page tables. */
    
    /* Claim physical memory */
    phys = ofmem_claim_phys(-1, size, align);

    /* Claim virtual memory - if va == NULL then we choose va address */
    if (va == NULL) {
        virt = ofmem_claim_virt((ucell)-1, size, align);        
    } else {
        virt = ofmem_claim_virt(pointer2cell(va), size, 0);
    }

    /* Map the memory */
    ofmem_map(phys, virt, size, ofmem_arch_default_translation_mode(phys));

    return cell2pointer(virt);
}

void obp_dumb_memfree(char *va, unsigned size)
{
    phys_addr_t phys;
    ucell cellmode;

    DPRINTF("obp_dumb_memfree: virta 0x%x, sz %d\n", (unsigned int)va, size);

    phys = ofmem_translate(pointer2cell(va), &cellmode);

    ofmem_unmap(pointer2cell(va), size);
    ofmem_release_virt(pointer2cell(va), size);
    ofmem_release_phys(phys, size);
}

/* Data fault handling routines */

extern unsigned int ignore_dfault;

/* ( -- reg ) */
static void srmmu_get_sfsr(void)
{
    PUSH(srmmu_get_fstatus());
}

/* ( -- addr ) */
static void ignore_dfault_addr(void)
{
    PUSH(pointer2cell(&ignore_dfault));
}

void
ob_init_mmu(void)
{
    ucell *memreg;
    ucell *virtreg;
    phys_addr_t virtregsize;
    ofmem_t *ofmem = ofmem_arch_get_private();

    /* Find the phandles for the /memory and /virtual-memory nodes */
    push_str("/memory");
    fword("find-package");
    POP();
    s_phandle_memory = POP();

    push_str("/virtual-memory");
    fword("find-package");
    POP();
    s_phandle_mmu = POP();

    ofmem_register(s_phandle_memory, s_phandle_mmu);

    /* Setup /memory:reg (totphys) property */
    memreg = malloc(3 * sizeof(ucell));
    ofmem_arch_encode_physaddr(memreg, 0); /* physical base */
    memreg[2] = (ucell)ofmem->ramsize; /* size */

    push_str("/memory");
    fword("find-device");
    PUSH(pointer2cell(memreg));
    PUSH(3 * sizeof(ucell));
    push_str("reg");
    PUSH_ph(s_phandle_memory);
    fword("encode-property");

    /* Setup /virtual-memory:reg property */
    virtregsize = ((phys_addr_t)((ucell)-1) + 1) / 2;
    
    virtreg = malloc(6 * sizeof(ucell));
    ofmem_arch_encode_physaddr(virtreg, 0);
    virtreg[2] = virtregsize;
    ofmem_arch_encode_physaddr(&virtreg[3], virtregsize);
    virtreg[5] = virtregsize;
    
    push_str("/virtual-memory");
    fword("find-device");
    PUSH(pointer2cell(virtreg));
    PUSH(6 * sizeof(ucell));
    push_str("reg");
    PUSH_ph(s_phandle_mmu);
    fword("encode-property");
    
    PUSH(0);
    fword("active-package!");
    bind_func("pgmap@", pgmap_fetch);
    bind_func("pgmap!", pgmap_store);
    bind_func("map-pages", ob_map_pages);

    /* Install data fault handler words for cpeek etc. */
    PUSH_xt(bind_noname_func(srmmu_get_sfsr));
    feval("to sfsr@");
    PUSH_xt(bind_noname_func(ignore_dfault_addr));
    feval("to ignore-dfault");
}

/*
 * Switch page tables.
 */
void
init_mmu_swift(void)
{
    unsigned int addr, i;
    unsigned long pa, va;
    int size;

    ofmem_posix_memalign((void *)&context_table, NCTX_SWIFT * sizeof(int),
                   NCTX_SWIFT * sizeof(int));
    ofmem_posix_memalign((void *)&l1, 256 * sizeof(int), 256 * sizeof(int));

    context_table[0] = (((unsigned long)va2pa((unsigned long)l1)) >> 4) |
        SRMMU_ET_PTD;

    for (i = 1; i < NCTX_SWIFT; i++) {
        context_table[i] = SRMMU_ET_INVALID;
    }
    for (i = 0; i < 256; i++) {
        l1[i] = SRMMU_ET_INVALID;
    }

    // text, rodata, data, and bss mapped to end of RAM
    va = (unsigned long)&_start;
    size = (unsigned long)&_end - (unsigned long)&_start;
    pa = va2pa(va);
    ofmem_arch_map_pages(pa, va, size, ofmem_arch_default_translation_mode(pa));
    ofmem_map_page_range(pa, va, size, ofmem_arch_default_translation_mode(pa));

    // 1:1 mapping for RAM (don't map page 0 to allow catching of NULL dereferences)                                                                                                                                            
    ofmem_arch_map_pages(PAGE_SIZE, PAGE_SIZE, LOWMEMSZ - PAGE_SIZE, ofmem_arch_default_translation_mode(0));                                                                                                                   
    ofmem_map_page_range(PAGE_SIZE, PAGE_SIZE, LOWMEMSZ - PAGE_SIZE, ofmem_arch_default_translation_mode(0));

    /*
     * Flush cache
     */
    for (addr = 0; addr < 0x2000; addr += 0x10) {
        __asm__ __volatile__ ("sta %%g0, [%0] %1\n\t" : :
                              "r" (addr), "i" (ASI_M_DATAC_TAG));
        __asm__ __volatile__ ("sta %%g0, [%0] %1\n\t" : :
                              "r" (addr<<1), "i" (ASI_M_TXTC_TAG));
    }
    srmmu_set_context(0);
    srmmu_set_ctable_ptr(va2pa((unsigned long)context_table));
    srmmu_flush_whole_tlb();
}
