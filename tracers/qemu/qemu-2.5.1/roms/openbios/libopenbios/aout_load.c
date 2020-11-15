/* a.out boot loader
 * As we have seek, this implementation can be straightforward.
 * 2003-07 by SONE Takeshi
 */

#include "config.h"
#include "kernel/kernel.h"

#ifdef CONFIG_SPARC64
#define CONFIG_SPARC64_PAGE_SIZE_8KB
#endif

/* NextStep bootloader on SPARC32 expects the a.out header directly
   below load-base (0x4000) */
#ifdef CONFIG_SPARC32
#define AOUT_HEADER_COPY
#endif 

#include "libopenbios/sys_info.h"
#include "libopenbios/bindings.h"
#include "libopenbios/aout_load.h"
#include "libc/diskio.h"
#define printf printk
#define debug printk

#define addr_fixup(addr) ((addr) & 0x00ffffff)

static char *image_name, *image_version;
static int fd;

static int 
check_mem_ranges(struct sys_info *info,
                            unsigned long start,
                            unsigned long size)
{
    int j;
    unsigned long end;
    unsigned long prog_start, prog_end;
    struct memrange *mem;

    prog_start = virt_to_phys(&_start);
    prog_end = virt_to_phys(&_end);

    end = start + size;

    if (start < prog_start && end > prog_start)
        goto conflict;
    if (start < prog_end && end > prog_end)
        goto conflict;
    mem = info->memrange;
    for (j = 0; j < info->n_memranges; j++) {
        if (mem[j].base <= start && mem[j].base + mem[j].size >= end)
            break;
    }
    if (j >= info->n_memranges)
        goto badseg;
    return 1;

 conflict:
    printf("%s occupies [%#lx-%#lx]\n", program_name, prog_start, prog_end);

 badseg:
    printf("A.out file [%#lx-%#lx] doesn't fit into memory\n", start, end - 1);
    return 0;
}

int 
is_aout(struct exec *ehdr)
{
	return ((ehdr->a_info & 0xffff) == OMAGIC
		|| (ehdr->a_info & 0xffff) == NMAGIC
		|| (ehdr->a_info & 0xffff) == ZMAGIC
		|| (ehdr->a_info & 0xffff) == QMAGIC);
}

int 
aout_load(struct sys_info *info, ihandle_t dev)
{
    int retval = -1;
    struct exec ehdr;
    unsigned long start, size;
    unsigned int offset;

    image_name = image_version = NULL;

    /* Mark the saved-program-state as invalid */
    feval("0 state-valid !");

    fd = open_ih(dev);
    if (fd == -1) {
	goto out;
    }

    for (offset = 0; offset < 16 * 512; offset += 512) {
        seek_io(fd, offset);
        if (read_io(fd, &ehdr, sizeof ehdr) != sizeof ehdr) {
            debug("Can't read a.out header\n");
            retval = LOADER_NOT_SUPPORT;
            goto out;
        }
        if (is_aout(&ehdr))
            break;
    }

    if (!is_aout(&ehdr)) {
	debug("Not a bootable a.out image\n");
	retval = LOADER_NOT_SUPPORT;
	goto out;
    }

    if (ehdr.a_text == 0x30800007)
	ehdr.a_text=64*1024;

    if (N_MAGIC(ehdr) == NMAGIC) {
        size = addr_fixup(N_DATADDR(ehdr)) + addr_fixup(ehdr.a_data);
    } else {
        size = addr_fixup(ehdr.a_text) + addr_fixup(ehdr.a_data);
    }

    if (size < 7680)
        size = 7680;

    fword("load-base");
    start = POP(); // N_TXTADDR(ehdr);

    if (!check_mem_ranges(info, start, size))
	goto out;

    printf("Loading a.out %s...\n", image_name ? image_name : "image");

    seek_io(fd, offset + N_TXTOFF(ehdr));

    if (N_MAGIC(ehdr) == NMAGIC) {
        if ((size_t)read_io(fd, (void *)start, ehdr.a_text) != ehdr.a_text) {
            printf("Can't read program text segment (size 0x" FMT_aout_ehdr ")\n", ehdr.a_text);
            goto out;
        }
        if ((size_t)read_io(fd, (void *)(start + N_DATADDR(ehdr)), ehdr.a_data) != ehdr.a_data) {
            printf("Can't read program data segment (size 0x" FMT_aout_ehdr ")\n", ehdr.a_data);
            goto out;
        }
    } else {
        if ((size_t)read_io(fd, (void *)start, size) != size) {
            printf("Can't read program (size 0x" FMT_sizet ")\n", size);
            goto out;
        }
    }

    debug("Loaded %lu bytes\n", size);
    debug("entry point is %#lx\n", start);

#ifdef AOUT_HEADER_COPY
    // Copy the a.out header just before start
    memcpy((char *)(start - 0x20), &ehdr, 0x20);
#endif

    // Initialise saved-program-state
    PUSH(addr_fixup(start));
    feval("saved-program-state >sps.entry !");
    PUSH(size);
    feval("saved-program-state >sps.file-size !");
    feval("aout saved-program-state >sps.file-type !");

    feval("-1 state-valid !");

out:
    close_io(fd);
    return retval;
}

void 
aout_init_program(void)
{
	// Currently not implemented
	feval("0 state-valid !");
}
