/* Support for Multiboot */

#include "config.h"
#include "asm/io.h"
#include "libopenbios/sys_info.h"
#include "multiboot.h"

#ifdef CONFIG_DEBUG_BOOT
#define debug printk
#else
#define debug(x...)
#endif

struct mbheader {
    unsigned int magic, flags, checksum;
};

static const struct mbheader multiboot_header
	__attribute__((section (".hdr"))) =
{
    MULTIBOOT_HEADER_MAGIC,
    MULTIBOOT_HEADER_FLAGS,
    -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)
};

/* Multiboot information structure, provided by loader to us */

struct multiboot_mmap {
	unsigned entry_size;
	unsigned base_lo, base_hi;
	unsigned size_lo, size_hi;
	unsigned type;
};

#define MULTIBOOT_MEM_VALID       0x01
#define MULTIBOOT_BOOT_DEV_VALID  0x02
#define MULTIBOOT_CMDLINE_VALID   0x04
#define MULTIBOOT_MODS_VALID      0x08
#define MULTIBOOT_AOUT_SYMS_VALID 0x10
#define MULTIBOOT_ELF_SYMS_VALID  0x20
#define MULTIBOOT_MMAP_VALID      0x40

void collect_multiboot_info(struct sys_info *info);
void collect_multiboot_info(struct sys_info *info)
{
    struct multiboot_info *mbinfo;
    struct multiboot_mmap *mbmem;
    unsigned mbcount, mbaddr;
    int i;
    struct memrange *mmap;
    int mmap_count;
    module_t *mod;

    if (info->boot_type != 0x2BADB002)
	return;

    debug("Using Multiboot information at %#lx\n", info->boot_data);

    mbinfo = phys_to_virt(info->boot_data);

    if (mbinfo->mods_count != 1) {
	    printk("multiboot: no dictionary\n");
	    return;
    }

    mod = (module_t *) mbinfo->mods_addr;
    info->dict_start=(unsigned long *)mod->mod_start;
    info->dict_end=(unsigned long *)mod->mod_end;
    debug("multiboot: dictionary at %p-%p\n",
		    info->dict_start, info->dict_end);

    if (mbinfo->flags & MULTIBOOT_MMAP_VALID) {
	/* convert mmap records */
	mbmem = phys_to_virt(mbinfo->mmap_addr);
	mbcount = mbinfo->mmap_length / (mbmem->entry_size + 4);
	mmap = malloc(mbcount * sizeof(struct memrange));
	mmap_count = 0;
	mbaddr = mbinfo->mmap_addr;
	for (i = 0; i < mbcount; i++) {
	    mbmem = phys_to_virt(mbaddr);
	    debug("%08x%08x %08x%08x (%d)\n",
		    mbmem->base_hi,
		    mbmem->base_lo,
		    mbmem->size_hi,
		    mbmem->size_lo,
		    mbmem->type);
	    if (mbmem->type == 1) { /* Only normal RAM */
		mmap[mmap_count].base = mbmem->base_lo
		    + (((unsigned long long) mbmem->base_hi) << 32);
		mmap[mmap_count].size = mbmem->size_lo
		    + (((unsigned long long) mbmem->size_hi) << 32);
		mmap_count++;
	    }
	    mbaddr += mbmem->entry_size + 4;
	    if (mbaddr >= mbinfo->mmap_addr + mbinfo->mmap_length)
		break;
	}
	/* simple sanity check - there should be at least 2 RAM segments
	 * (base 640k and extended) */
	if (mmap_count >= 2)
	    goto got_it;

	printk("Multiboot mmap is broken\n");
	free(mmap);
	/* fall back to mem_lower/mem_upper */
    }

    if (mbinfo->flags & MULTIBOOT_MEM_VALID) {
	/* use mem_lower and mem_upper */
	mmap_count = 2;
	mmap = malloc(2 * sizeof(*mmap));
	mmap[0].base = 0;
	mmap[0].size = mbinfo->mem_lower << 10;
	mmap[1].base = 1 << 20; /* 1MB */
	mmap[1].size = mbinfo->mem_upper << 10;
	goto got_it;
    }

    printk("Can't get memory information from Multiboot\n");
    return;

got_it:
    info->memrange = mmap;
    info->n_memranges = mmap_count;

    return;
}
