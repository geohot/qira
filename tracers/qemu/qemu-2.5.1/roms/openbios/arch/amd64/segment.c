/* Segmentation of the AMD64 architecture.
 *
 * 2003-07 by SONE Takeshi
 */

#include "config.h"
#include "kernel/kernel.h"
#include "libopenbios/sys_info.h"
#include "relocate.h"
#include "segment.h"

#define printf printk
#ifdef CONFIG_DEBUG_BOOT
#define debug printk
#else
#define debug(x...)
#endif

/* i386 lgdt argument */
struct gdtarg {
    unsigned short limit;
    unsigned int base;
} __attribute__((packed));

/* How far the virtual address (used in C) is different from physical
 * address. Since we start in flat mode, the initial value is zero. */
unsigned long virt_offset = 0;

/* GDT, the global descriptor table */
struct segment_desc gdt[NUM_SEG] = {
    /* 0x00: null segment */
    {0, 0, 0, 0, 0, 0},
    /* 0x08: flat code segment */
    {0xffff, 0, 0, 0x9f, 0xcf, 0},
    /* 0x10: flat data segment */
    {0xffff, 0, 0, 0x93, 0xcf, 0},
    /* 0x18: code segment for relocated execution */
    {0xffff, 0, 0, 0x9f, 0xcf, 0},
    /* 0x20: data segment for relocated execution */
    {0xffff, 0, 0, 0x93, 0xcf, 0},
};

extern char _start[], _end[];

void relocate(struct sys_info *info)
{
    int i;
    unsigned long prog_addr;
    unsigned long prog_size;
    unsigned long addr, new_base;
    unsigned long long segsize;
    unsigned long new_offset;
    unsigned d0, d1, d2;
    struct gdtarg gdtarg;
#define ALIGNMENT 16

    prog_addr = virt_to_phys(&_start);
    prog_size = virt_to_phys(&_end) - virt_to_phys(&_start);
    debug("Current location: %#lx-%#lx\n", prog_addr, prog_addr+prog_size-1);

    new_base = 0;
    for (i = 0; i < info->n_memranges; i++) {
	if (info->memrange[i].base >= 1ULL<<32)
	    continue;
	segsize = info->memrange[i].size;
	if (info->memrange[i].base + segsize > 1ULL<<32)
	    segsize = (1ULL<<32) - info->memrange[i].base;
	if (segsize < prog_size+ALIGNMENT)
	    continue;
	addr = info->memrange[i].base + segsize - prog_size;
	addr &= ~(ALIGNMENT-1);
	if (addr >= prog_addr && addr < prog_addr + prog_size)
	    continue;
	if (prog_addr >= addr && prog_addr < addr + prog_size)
	    continue;
	if (addr > new_base)
	    new_base = addr;
    }
    if (new_base == 0) {
	printf("Can't find address to relocate\n");
	return;
    }

    debug("Relocating to %#lx-%#lx... ",
	    new_base, new_base + prog_size - 1);

    /* New virtual address offset */
    new_offset = new_base - (unsigned long) &_start;

    /* Tweak the GDT */
    gdt[RELOC_CODE].base_0 = (unsigned short) new_offset;
    gdt[RELOC_CODE].base_16 = (unsigned char) (new_offset>>16);
    gdt[RELOC_CODE].base_24 = (unsigned char) (new_offset>>24);
    gdt[RELOC_DATA].base_0 = (unsigned short) new_offset;
    gdt[RELOC_DATA].base_16 = (unsigned char) (new_offset>>16);
    gdt[RELOC_DATA].base_24 = (unsigned char) (new_offset>>24);

    /* Load new GDT and reload segments */
    gdtarg.base = new_offset + (unsigned long) gdt;
    gdtarg.limit = GDT_LIMIT;
    __asm__ __volatile__ (
	    "rep; movsb\n\t" /* copy everything */
	    "lgdt %3\n\t"
	    "ljmp %4, $1f\n1:\t"
	    "movw %5, %%ds\n\t"
	    "movw %5, %%es\n\t"
	    "movw %5, %%fs\n\t"
	    "movw %5, %%gs\n\t"
	    "movw %5, %%ss\n"
	    : "=&S" (d0), "=&D" (d1), "=&c" (d2)
	    : "m" (gdtarg), "n" (RELOC_CS), "q" ((unsigned short) RELOC_DS),
	    "0" (&_start), "1" (new_base), "2" (prog_size));

    virt_offset = new_offset;
    debug("ok\n");
}

#if 0
/* Copy GDT to new location and reload it */
void move_gdt(unsigned long newgdt)
{
    struct gdtarg gdtarg;

    debug("Moving GDT to %#lx...", newgdt);
    memcpy(phys_to_virt(newgdt), gdt, sizeof gdt);
    gdtarg.base = newgdt;
    gdtarg.limit = GDT_LIMIT;
    debug("reloading GDT...");
    __asm__ __volatile__ ("lgdt %0\n\t" : : "m" (gdtarg));
    debug("reloading CS for fun...");
    __asm__ __volatile__ ("ljmp %0, $1f\n1:" : : "n" (RELOC_CS));
    debug("ok\n");
}
#endif
