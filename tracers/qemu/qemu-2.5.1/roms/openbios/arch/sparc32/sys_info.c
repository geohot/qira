#include "config.h"
#include "kernel/kernel.h"
#include "arch/common/elf_boot.h"
#include "libopenbios/sys_info.h"
#include "context.h"
#include "boot.h"

#define printf printk
#ifdef CONFIG_DEBUG_BOOT
#define debug printk
#else
#define debug(x...)
#endif

unsigned int qemu_mem_size;

void collect_multiboot_info(struct sys_info *);

void collect_sys_info(struct sys_info *info)
{
    int i;
    unsigned long long total = 0;
    struct memrange *mmap;

    /* Pick up paramters given by bootloader to us */
    //info->boot_type = boot_ctx->eax;
    //info->boot_data = boot_ctx->ebx;
    info->boot_arg = boot_ctx->param[0];
    //debug("boot eax = %#lx\n", info->boot_type);
    //debug("boot ebx = %#lx\n", info->boot_data);
    info->boot_type = ELF_BHDR_MAGIC;
    info->boot_data = virt_to_phys(&elf_image_notes);
    debug("boot arg = %#lx\n", info->boot_arg);

    collect_elfboot_info(info);
#ifdef CONFIG_LINUXBIOS
    collect_linuxbios_info(info);
#endif
#ifdef CONFIG_IMAGE_ELF_MULTIBOOT
    collect_multiboot_info(info);
#endif

    if (!info->memrange) {
	info->n_memranges = 1;
	info->memrange = malloc(1 * sizeof(struct memrange));
	info->memrange[0].base = 0;
	info->memrange[0].size = qemu_mem_size;
    }

    debug("\n");
    mmap=info->memrange;
    for (i = 0; i < info->n_memranges; i++) {
	debug("%08lx-", (long)mmap[i].base);
	debug("%08lx\n", (long)mmap[i].base + (long)mmap[i].size);
	total += mmap[i].size;
    }
    debug("RAM %ld MB\n", (long)total >> 20);
}
