/* ELF Boot loader
 * As we have seek, this implementation can be straightforward.
 * 2003-07 by SONE Takeshi
 */

#include "config.h"
#include "kernel/kernel.h"
#include "libc/diskio.h"
#include "arch/common/elf_boot.h"
#include "libopenbios/elf_load.h"
#include "libopenbios/sys_info.h"
#include "libopenbios/ipchecksum.h"
#include "libopenbios/bindings.h"
#include "libopenbios/ofmem.h"
#define printf printk
#define debug printk

#define DEBUG		0

#define MAX_HEADERS	0x20
#define BS		0x100	/* smallest step used when looking for the ELF header */

#ifdef CONFIG_PPC
extern void             flush_icache_range( char *start, char *stop );
#endif

/* FreeBSD and possibly others mask the high 8 bits */
#define addr_fixup(addr) ((addr) & 0x00ffffff)

static char *image_name, *image_version;
static int fd;

/* Note: avoid name collision with platforms which have their own version of calloc() */
static void *ob_calloc(size_t nmemb, size_t size)
{
    size_t alloc_size = nmemb * size;
    void *mem;

    if (alloc_size < nmemb || alloc_size < size) {
        printf("calloc overflow: %u, %u\n", nmemb, size);
        return NULL;
    }

    mem = malloc(alloc_size);
    memset(mem, 0, alloc_size);

    return mem;
}

static int check_mem_ranges(struct sys_info *info,
	Elf_phdr *phdr, int phnum)
{
    int i, j;
    unsigned long start, end;
    unsigned long prog_start, prog_end;
    struct memrange *mem;

    prog_start = virt_to_phys(&_start);
    prog_end = virt_to_phys(&_end);

    for (i = 0; i < phnum; i++) {
	if (phdr[i].p_type != PT_LOAD)
	    continue;
	start = addr_fixup(phdr[i].p_paddr);
	end = start + phdr[i].p_memsz;
	if (start < prog_start && end > prog_start)
	    goto conflict;
	if (start < prog_end && end > prog_end)
	    goto conflict;
	mem=info->memrange;
	for (j = 0; j < info->n_memranges; j++) {
	    if (mem[j].base <= start && mem[j].base + mem[j].size >= end)
		break;
	}
	if (j >= info->n_memranges)
	    goto badseg;
    }
    return 1;

conflict:
    printf("%s occupies [%#lx-%#lx]\n", program_name, prog_start, prog_end);

badseg:
    printf("Segment %d [%#lx-%#lx] doesn't fit into memory\n", i, start, end-1);
    return 0;
}

static unsigned long process_image_notes(Elf_phdr *phdr, int phnum,
                                         unsigned short *sum_ptr,
                                         unsigned int offset)
{
    int i;
    char *buf = NULL;
    int retval = 0;
    unsigned long addr, end;
    Elf_Nhdr *nhdr;
    const char *name;
    void *desc;

    for (i = 0; i < phnum; i++) {
	if (phdr[i].p_type != PT_NOTE)
	    continue;
	buf = malloc(phdr[i].p_filesz);
	seek_io(fd, offset + phdr[i].p_offset);
	if ((size_t)read_io(fd, buf, phdr[i].p_filesz) != phdr[i].p_filesz) {
	    printf("Can't read note segment\n");
	    goto out;
	}
	addr = (unsigned long) buf;
	end = addr + phdr[i].p_filesz;
	while (addr < end) {
	    nhdr = (Elf_Nhdr *) addr;
	    addr += sizeof(Elf_Nhdr);
	    name = (const char *) addr;
	    addr += (nhdr->n_namesz+3) & ~3;
	    desc = (void *) addr;
	    addr += (nhdr->n_descsz+3) & ~3;

	    if (nhdr->n_namesz==sizeof(ELF_NOTE_BOOT)
		    && memcmp(name, ELF_NOTE_BOOT, sizeof(ELF_NOTE_BOOT))==0) {
		if (nhdr->n_type == EIN_PROGRAM_NAME) {
		    image_name = ob_calloc(1, nhdr->n_descsz + 1);
		    memcpy(image_name, desc, nhdr->n_descsz);
		}
		if (nhdr->n_type == EIN_PROGRAM_VERSION) {
		    image_version = ob_calloc(1, nhdr->n_descsz + 1);
		    memcpy(image_version, desc, nhdr->n_descsz);
		}
		if (nhdr->n_type == EIN_PROGRAM_CHECKSUM) {
		    *sum_ptr = *(unsigned short *) desc;
		    debug("Image checksum: %#04x\n", *sum_ptr);
		    /* Where in the file */
		    retval = phdr[i].p_offset
			+ (unsigned long) desc - (unsigned long) buf;
		}
	    }
	}
    }
out:
    close_io(fd);
    if (buf)
	free(buf);
    return retval;
}

static int load_segments(Elf_phdr *phdr, int phnum,
                         unsigned long checksum_offset,
                         unsigned int offset, unsigned long *bytes)
{
    //unsigned int start_time, time;
    int i;

    *bytes = 0;
    // start_time = currticks();
    for (i = 0; i < phnum; i++) {
	if (phdr[i].p_type != PT_LOAD)
	    continue;
	debug("segment %d addr:" FMT_elf " file:" FMT_elf " mem:" FMT_elf " ",
              i, addr_fixup(phdr[i].p_paddr), phdr[i].p_filesz, phdr[i].p_memsz);
	seek_io(fd, offset + phdr[i].p_offset);
	debug("loading... ");
	if ((size_t)read_io(fd, phys_to_virt(addr_fixup(phdr[i].p_paddr)), phdr[i].p_filesz)
		!= phdr[i].p_filesz) {
	    printf("Can't read program segment %d\n", i);
	    return 0;
	}
	bytes += phdr[i].p_filesz;
	debug("clearing... ");
	memset(phys_to_virt(addr_fixup(phdr[i].p_paddr) + phdr[i].p_filesz), 0,
		phdr[i].p_memsz - phdr[i].p_filesz);
	if (phdr[i].p_offset <= checksum_offset
		&& phdr[i].p_offset + phdr[i].p_filesz >= checksum_offset+2) {
	    debug("clearing checksum... ");
	    memset(phys_to_virt(addr_fixup(phdr[i].p_paddr) + checksum_offset
			- phdr[i].p_offset), 0, 2);
	}
	debug("ok\n");

    }
    // time = currticks() - start_time;
    //debug("Loaded %lu bytes in %ums (%luKB/s)\n", bytes, time,
    //	    time? bytes/time : 0);
    debug("Loaded %lu bytes \n", *bytes);

    return 1;
}

static int verify_image(Elf_ehdr *ehdr, Elf_phdr *phdr, int phnum,
	unsigned short image_sum)
{
    unsigned short sum, part_sum;
    unsigned long offset;
    int i;

    sum = 0;
    offset = 0;

    part_sum = ipchksum(ehdr, sizeof *ehdr);
    sum = add_ipchksums(offset, sum, part_sum);
    offset += sizeof *ehdr;

    part_sum = ipchksum(phdr, phnum * sizeof(*phdr));
    sum = add_ipchksums(offset, sum, part_sum);
    offset += phnum * sizeof(*phdr);

    for (i = 0; i < phnum; i++) {
	if (phdr[i].p_type != PT_LOAD)
	    continue;
	part_sum = ipchksum(phys_to_virt(addr_fixup(phdr[i].p_paddr)), phdr[i].p_memsz);
	sum = add_ipchksums(offset, sum, part_sum);
	offset += phdr[i].p_memsz;
    }

    if (sum != image_sum) {
	printf("Verify FAILED (image:%#04x vs computed:%#04x)\n",
		image_sum, sum);
	return 0;
    }
    return 1;
}

static inline unsigned padded(unsigned s)
{
    return (s + 3) & ~3;
}

static Elf_Bhdr *add_boot_note(Elf_Bhdr *bhdr, const char *name,
	unsigned type, const char *desc, unsigned descsz)
{
    Elf_Nhdr nhdr;
    unsigned ent_size, new_size, pad;
    char *addr;

    if (!bhdr)
	return NULL;

    nhdr.n_namesz = name? strlen(name)+1 : 0;
    nhdr.n_descsz = descsz;
    nhdr.n_type = type;
    ent_size = sizeof(nhdr) + padded(nhdr.n_namesz) + padded(nhdr.n_descsz);
    if (bhdr->b_size + ent_size > 0xffff) {
	printf("Boot notes too big\n");
	free(bhdr);
	return NULL;
    }
    if (bhdr->b_size + ent_size > bhdr->b_checksum) {
	do {
	    new_size = bhdr->b_checksum * 2;
	} while (new_size < bhdr->b_size + ent_size);
	if (new_size > 0xffff)
	    new_size = 0xffff;
	debug("expanding boot note size to %u\n", new_size);
#ifdef HAVE_REALLOC
	bhdr = realloc(bhdr, new_size);
	bhdr->b_checksum = new_size;
#else
	printf("Boot notes too big\n");
	free(bhdr);
	return NULL;
#endif
    }

    addr = (char *) bhdr;
    addr += bhdr->b_size;
    memcpy(addr, &nhdr, sizeof(nhdr));
    addr += sizeof(nhdr);

    if (name && nhdr.n_namesz) {
        memcpy(addr, name, nhdr.n_namesz);
        addr += nhdr.n_namesz;
        pad = padded(nhdr.n_namesz) - nhdr.n_namesz;
        memset(addr, 0, pad);
        addr += pad;
    }

    memcpy(addr, desc, nhdr.n_descsz);
    addr += nhdr.n_descsz;
    pad = padded(nhdr.n_descsz) - nhdr.n_descsz;
    memset(addr, 0, pad);

    bhdr->b_size += ent_size;
    bhdr->b_records++;
    return bhdr;
}

static inline Elf_Bhdr *add_note_string(Elf_Bhdr *bhdr, const char *name,
	unsigned type, const char *desc)
{
    return add_boot_note(bhdr, name, type, desc, strlen(desc) + 1);
}

static Elf_Bhdr *build_boot_notes(struct sys_info *info, const char *cmdline)
{
    Elf_Bhdr *bhdr;

    bhdr = malloc(256);
    bhdr->b_signature = ELF_BHDR_MAGIC;
    bhdr->b_size = sizeof *bhdr;
    bhdr->b_checksum = 256; /* XXX cache the current buffer size here */
    bhdr->b_records = 0;

    if (info->firmware)
	bhdr = add_note_string(bhdr, NULL, EBN_FIRMWARE_TYPE, info->firmware);
    bhdr = add_note_string(bhdr, NULL, EBN_BOOTLOADER_NAME, program_name);
    bhdr = add_note_string(bhdr, NULL, EBN_BOOTLOADER_VERSION, program_version);
    if (cmdline)
	bhdr = add_note_string(bhdr, NULL, EBN_COMMAND_LINE, cmdline);
    if (!bhdr)
	return bhdr;
    bhdr->b_checksum = 0;
    bhdr->b_checksum = ipchksum(bhdr, bhdr->b_size);
    return bhdr;
}

int
is_elf(Elf_ehdr *ehdr)
{
    return (ehdr->e_ident[EI_MAG0] == ELFMAG0
        && ehdr->e_ident[EI_MAG1] == ELFMAG1
        && ehdr->e_ident[EI_MAG2] == ELFMAG2
        && ehdr->e_ident[EI_MAG3] == ELFMAG3
        && ehdr->e_ident[EI_CLASS] == ARCH_ELF_CLASS
        && ehdr->e_ident[EI_DATA] == ARCH_ELF_DATA
        && ehdr->e_ident[EI_VERSION] == EV_CURRENT
        && ehdr->e_type == ET_EXEC
        && ARCH_ELF_MACHINE_OK(ehdr->e_machine)
        && ehdr->e_version == EV_CURRENT
        && ehdr->e_phentsize == sizeof(Elf_phdr));
}

int
find_elf(Elf_ehdr *ehdr)
{
   int offset;

   for (offset = 0; offset < MAX_HEADERS * BS; offset += BS) {
        if ((size_t)read_io(fd, ehdr, sizeof ehdr) != sizeof ehdr) {
            debug("Can't read ELF header\n");
            return 0;
        }

        if (is_elf(ehdr)) {
            debug("Found ELF header at offset %d\n", offset);
	    return offset;
        }

        seek_io(fd, offset);
    }

    debug("Not a bootable ELF image\n");
    return 0;
}

Elf_phdr *
elf_readhdrs(int offset, Elf_ehdr *ehdr)
{
    unsigned long phdr_size;
    Elf_phdr *phdr;

    phdr_size = ehdr->e_phnum * sizeof(Elf_phdr);
    phdr = malloc(phdr_size);
    seek_io(fd, offset + ehdr->e_phoff);
    if ((size_t)read_io(fd, phdr, phdr_size) != phdr_size) {
	printf("Can't read program header\n");
	return NULL;
    }

    return phdr;
}

int 
elf_load(struct sys_info *info, ihandle_t dev, const char *cmdline, void **boot_notes)
{
    Elf_ehdr ehdr;
    Elf_phdr *phdr = NULL;
    unsigned long checksum_offset, file_size;
    unsigned short checksum = 0;
    int retval = -1;
    unsigned int offset;

    image_name = image_version = NULL;

    /* Mark the saved-program-state as invalid */
    feval("0 state-valid !");

    fd = open_ih(dev);
    if (fd == -1) {
	goto out;
    }

    offset = find_elf(&ehdr);
    if (!offset) {
	retval = LOADER_NOT_SUPPORT;
        goto out;
    }

#if DEBUG
	printk("ELF header:\n");
	printk(" ehdr.e_type    = %d\n", (int)ehdr.e_type);
	printk(" ehdr.e_machine = %d\n", (int)ehdr.e_machine);
	printk(" ehdr.e_version = %d\n", (int)ehdr.e_version);
	printk(" ehdr.e_entry   = 0x%08x\n", (int)ehdr.e_entry);
	printk(" ehdr.e_phoff   = 0x%08x\n", (int)ehdr.e_phoff);
	printk(" ehdr.e_shoff   = 0x%08x\n", (int)ehdr.e_shoff);
	printk(" ehdr.e_flags   = %d\n", (int)ehdr.e_flags);
	printk(" ehdr.e_ehsize  = 0x%08x\n", (int)ehdr.e_ehsize);
	printk(" ehdr.e_phentsize = 0x%08x\n", (int)ehdr.e_phentsize);
	printk(" ehdr.e_phnum   = %d\n", (int)ehdr.e_phnum);
#endif

    if (ehdr.e_phnum > MAX_HEADERS) {
        printk ("elfload: too many program headers (MAX_HEADERS)\n");
        retval = 0;
	goto out;
    }

    phdr = elf_readhdrs(offset, &ehdr);
    if (!phdr)
        goto out;

    if (!check_mem_ranges(info, phdr, ehdr.e_phnum))
	goto out;

    checksum_offset = process_image_notes(phdr, ehdr.e_phnum, &checksum, offset);

    printf("Loading %s", image_name ? image_name : "image");
    if (image_version)
	printf(" version %s", image_version);
    printf("...\n");

    if (!load_segments(phdr, ehdr.e_phnum, checksum_offset, offset, &file_size))
	goto out;

    if (checksum_offset) {
	if (!verify_image(&ehdr, phdr, ehdr.e_phnum, checksum))
	    goto out;
    }

    /* If we are attempting an ELF boot image, we pass a non-NULL pointer
       into boot_notes and mark the image as elf-boot rather than standard
       ELF */
    if (boot_notes) {
        *boot_notes = (void *)virt_to_phys(build_boot_notes(info, cmdline));
        feval("elf-boot saved-program-state >sps.file-type !");
    } else {
        feval("elf saved-program-state >sps.file-type !");
    }

    //debug("current time: %lu\n", currticks());

    debug("entry point is " FMT_elf "\n", addr_fixup(ehdr.e_entry));

    // Initialise saved-program-state
    PUSH(addr_fixup(ehdr.e_entry));
    feval("saved-program-state >sps.entry !");
    PUSH(file_size);
    feval("saved-program-state >sps.file-size !");

    feval("-1 state-valid !");

out:
    close_io(fd);
    if (phdr)
	free(phdr);
    if (image_name)
	free(image_name);
    if (image_version)
	free(image_version);
    return retval;
}

void 
elf_init_program(void)
{
	char *base;
	int i;
	Elf_ehdr *ehdr;
	Elf_phdr *phdr;
	size_t size, total_size = 0;
	char *addr;
	uintptr_t tmp;

	/* TODO: manage ELF notes section */
	feval("0 state-valid !");
	feval("load-base");
	base = (char*)cell2pointer(POP());

	ehdr = (Elf_ehdr *)base;

	if (!is_elf(ehdr)) {
		debug("Not a valid ELF memory image\n");
		return;
	}

	phdr = (Elf_phdr *)(base + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++) {

#if DEBUG
		debug("filesz: %08lX memsz: %08lX p_offset: %08lX "
                        "p_vaddr %08lX\n",
			(unsigned long)phdr[i].p_filesz, (unsigned long)phdr[i].p_memsz,
			(unsigned long)phdr[i].p_offset, (unsigned long)phdr[i].p_vaddr );
#endif

		size = MIN(phdr[i].p_filesz, phdr[i].p_memsz);
		if (!size)
			continue;
#if !defined(CONFIG_SPARC32) && !defined(CONFIG_X86)
		if( ofmem_claim( phdr[i].p_vaddr, phdr[i].p_memsz, 0 ) == -1 ) {
                        printk("Ignoring failed claim for va %lx memsz %lx!\n",
                               (unsigned long)phdr[i].p_vaddr,
                               (unsigned long)phdr[i].p_memsz);
		}
#endif
		/* Workaround for archs where sizeof(int) != pointer size */
		tmp = phdr[i].p_vaddr;
		addr = (char *)tmp;

		memcpy(addr, base + phdr[i].p_offset, size);

		total_size += size;

#ifdef CONFIG_PPC
		flush_icache_range( addr, addr + size );
#endif
	}

	// Initialise saved-program-state
	PUSH(ehdr->e_entry);
	feval("saved-program-state >sps.entry !");
	PUSH(total_size);
	feval("saved-program-state >sps.file-size !");
	feval("elf saved-program-state >sps.file-type !");

	feval("-1 state-valid !");
}
