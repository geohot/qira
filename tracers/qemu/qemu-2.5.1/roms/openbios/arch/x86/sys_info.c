#include "config.h"
#include "kernel/kernel.h"
#include "libopenbios/sys_info.h"
#include "context.h"

#ifdef CONFIG_DEBUG_BOOT
#define debug printk
#else
#define debug(x...)
#endif

void collect_multiboot_info(struct sys_info *);
void collect_sys_info(struct sys_info *info);

void collect_sys_info(struct sys_info *info)
{
    int i;
    unsigned long long total = 0;
    struct memrange *mmap;

    /* Pick up paramters given by bootloader to us */
    info->boot_type = boot_ctx->eax;
    info->boot_data = boot_ctx->ebx;
    info->boot_arg = boot_ctx->param[0];
    debug("boot eax = %#lx\n", info->boot_type);
    debug("boot ebx = %#lx\n", info->boot_data);
    debug("boot arg = %#lx\n", info->boot_arg);

    collect_elfboot_info(info);
#ifdef CONFIG_LINUXBIOS
    collect_linuxbios_info(info);
#endif
#ifdef CONFIG_IMAGE_ELF_MULTIBOOT
    collect_multiboot_info(info);
#endif

    if (!info->memrange) {
	printk("Can't get memory map from firmware. "
		"Using hardcoded default.\n");
	info->n_memranges = 2;
	info->memrange = malloc(2 * sizeof(struct memrange));
	info->memrange[0].base = 0;
	info->memrange[0].size = 640*1024;
	info->memrange[1].base = 1024*1024;
	info->memrange[1].size = 32*1024*1024
	    - info->memrange[1].base;
    }

    debug("\n");
    mmap=info->memrange;
    for (i = 0; i < info->n_memranges; i++) {
	debug("%016Lx-", mmap[i].base);
	debug("%016Lx\n", mmap[i].base+mmap[i].size);
	total += mmap[i].size;
    }
    debug("RAM %Ld MB\n", (total + 512*1024) >> 20);
}
