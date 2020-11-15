/*
 * Linux/i386 loader
 * Supports bzImage, zImage and Image format.
 *
 * Based on work by Steve Gehlbach.
 * Portions are taken from mkelfImage.
 *
 * 2003-09 by SONE Takeshi
 */

#include "config.h"
#include "kernel/kernel.h"
#include "libopenbios/bindings.h"
#include "libopenbios/sys_info.h"
#include "context.h"
#include "segment.h"
#include "libc/diskio.h"
#include "boot.h"

#define printf printk
#define debug printk
#define strtoull_with_suffix strtol

#define LINUX_PARAM_LOC 0x90000
#define COMMAND_LINE_LOC 0x91000
#define GDT_LOC 0x92000
#define STACK_LOC 0x93000

#define E820MAX	32		/* number of entries in E820MAP */
struct e820entry {
	unsigned long long addr;	/* start of memory segment */
	unsigned long long size;	/* size of memory segment */
	unsigned long type;		/* type of memory segment */
#define E820_RAM	1
#define E820_RESERVED	2
#define E820_ACPI	3 /* usable as RAM once ACPI tables have been read */
#define E820_NVS	4
};

/* The header of Linux/i386 kernel */
struct linux_header {
    uint8_t  reserved1[0x1f1];		/* 0x000 */
    uint8_t  setup_sects;		/* 0x1f1 */
    uint16_t root_flags;		/* 0x1f2 */
    uint8_t  reserved2[6];		/* 0x1f4 */
    uint16_t vid_mode;			/* 0x1fa */
    uint16_t root_dev;			/* 0x1fc */
    uint16_t boot_sector_magic;		/* 0x1fe */
    /* 2.00+ */
    uint8_t  reserved3[2];		/* 0x200 */
    uint8_t  header_magic[4];		/* 0x202 */
    uint16_t protocol_version;		/* 0x206 */
    uint32_t realmode_swtch;		/* 0x208 */
    uint16_t start_sys;			/* 0x20c */
    uint16_t kver_addr;			/* 0x20e */
    uint8_t  type_of_loader;		/* 0x210 */
    uint8_t  loadflags;			/* 0x211 */
    uint16_t setup_move_size;		/* 0x212 */
    uint32_t code32_start;		/* 0x214 */
    uint32_t ramdisk_image;		/* 0x218 */
    uint32_t ramdisk_size;		/* 0x21c */
    uint8_t  reserved4[4];		/* 0x220 */
    /* 2.01+ */
    uint16_t heap_end_ptr;		/* 0x224 */
    uint8_t  reserved5[2];		/* 0x226 */
    /* 2.02+ */
    uint32_t cmd_line_ptr;		/* 0x228 */
    /* 2.03+ */
    uint32_t initrd_addr_max;		/* 0x22c */
} __attribute__ ((packed));


/* Paramters passed to 32-bit part of Linux
 * This is another view of the structure above.. */
struct linux_params {
    uint8_t  orig_x;			/* 0x00 */
    uint8_t  orig_y;			/* 0x01 */
    uint16_t ext_mem_k;			/* 0x02 -- EXT_MEM_K sits here */
    uint16_t orig_video_page;		/* 0x04 */
    uint8_t  orig_video_mode;		/* 0x06 */
    uint8_t  orig_video_cols;		/* 0x07 */
    uint16_t unused2;			/* 0x08 */
    uint16_t orig_video_ega_bx;		/* 0x0a */
    uint16_t unused3;			/* 0x0c */
    uint8_t  orig_video_lines;		/* 0x0e */
    uint8_t  orig_video_isVGA;		/* 0x0f */
    uint16_t orig_video_points;		/* 0x10 */

    /* VESA graphic mode -- linear frame buffer */
    uint16_t lfb_width;			/* 0x12 */
    uint16_t lfb_height;		/* 0x14 */
    uint16_t lfb_depth;			/* 0x16 */
    uint32_t lfb_base;			/* 0x18 */
    uint32_t lfb_size;			/* 0x1c */
    uint16_t cl_magic;			/* 0x20 */
#define CL_MAGIC_VALUE 0xA33F
    uint16_t cl_offset;			/* 0x22 */
    uint16_t lfb_linelength;		/* 0x24 */
    uint8_t  red_size;			/* 0x26 */
    uint8_t  red_pos;			/* 0x27 */
    uint8_t  green_size;		/* 0x28 */
    uint8_t  green_pos;			/* 0x29 */
    uint8_t  blue_size;			/* 0x2a */
    uint8_t  blue_pos;			/* 0x2b */
    uint8_t  rsvd_size;			/* 0x2c */
    uint8_t  rsvd_pos;			/* 0x2d */
    uint16_t vesapm_seg;		/* 0x2e */
    uint16_t vesapm_off;		/* 0x30 */
    uint16_t pages;			/* 0x32 */
    uint8_t  reserved4[12];		/* 0x34 -- 0x3f reserved for future expansion */

    //struct apm_bios_info apm_bios_info;	/* 0x40 */
    uint8_t  apm_bios_info[0x40];
    //struct drive_info_struct drive_info;	/* 0x80 */
    uint8_t  drive_info[0x20];
    //struct sys_desc_table sys_desc_table;	/* 0xa0 */
    uint8_t  sys_desc_table[0x140];
    uint32_t alt_mem_k;			/* 0x1e0 */
    uint8_t  reserved5[4];		/* 0x1e4 */
    uint8_t  e820_map_nr;		/* 0x1e8 */
    uint8_t  reserved6[9];		/* 0x1e9 */
    uint16_t mount_root_rdonly;		/* 0x1f2 */
    uint8_t  reserved7[4];		/* 0x1f4 */
    uint16_t ramdisk_flags;		/* 0x1f8 */
#define RAMDISK_IMAGE_START_MASK  	0x07FF
#define RAMDISK_PROMPT_FLAG		0x8000
#define RAMDISK_LOAD_FLAG		0x4000
    uint8_t  reserved8[2];		/* 0x1fa */
    uint16_t orig_root_dev;		/* 0x1fc */
    uint8_t  reserved9[1];		/* 0x1fe */
    uint8_t  aux_device_info;		/* 0x1ff */
    uint8_t  reserved10[2];		/* 0x200 */
    uint8_t  param_block_signature[4];	/* 0x202 */
    uint16_t param_block_version;	/* 0x206 */
    uint8_t  reserved11[8];		/* 0x208 */
    uint8_t  loader_type;		/* 0x210 */
#define LOADER_TYPE_LOADLIN         1
#define LOADER_TYPE_BOOTSECT_LOADER 2
#define LOADER_TYPE_SYSLINUX        3
#define LOADER_TYPE_ETHERBOOT       4
#define LOADER_TYPE_KERNEL          5
    uint8_t  loader_flags;		/* 0x211 */
    uint8_t  reserved12[2];		/* 0x212 */
    uint32_t kernel_start;		/* 0x214 */
    uint32_t initrd_start;		/* 0x218 */
    uint32_t initrd_size;		/* 0x21c */
    uint8_t  reserved12_5[8];		/* 0x220 */
    uint32_t cmd_line_ptr;		/* 0x228 */
    uint8_t  reserved13[164];		/* 0x22c */
    struct e820entry e820_map[E820MAX];	/* 0x2d0 */
    uint8_t  reserved16[688];		/* 0x550 */
#define COMMAND_LINE_SIZE 256
    /* Command line is copied here by 32-bit i386/kernel/head.S.
     * So I will follow the boot protocol, rather than putting it
     * directly here. --ts1 */
    uint8_t  command_line[COMMAND_LINE_SIZE]; /* 0x800 */
    uint8_t  reserved17[1792];		/* 0x900 - 0x1000 */
};

static uint64_t forced_memsize;
static int fd;

static unsigned long file_size(void)
{
	long long fpos, fsize;

	/* Save current position */
	fpos = tell(fd);

	/* Go to end of file and get position */
	seek_io(fd, -1);
	fsize = tell(fd);

	/* Go back to old position */
	seek_io(fd, 0);
	seek_io(fd, fpos);

	return fsize;
}

/* Load the first part the file and check if it's Linux */
static uint32_t load_linux_header(struct linux_header *hdr)
{
    int load_high;
    uint32_t kern_addr;

    if (read_io(fd, hdr, sizeof *hdr) != sizeof *hdr) {
	debug("Can't read Linux header\n");
	return 0;
    }
    if (hdr->boot_sector_magic != 0xaa55) {
	debug("Not a Linux kernel image\n");
	return 0;
    }

    /* Linux is found. Print some information */
    if (memcmp(hdr->header_magic, "HdrS", 4) != 0) {
	/* This may be floppy disk image or something.
	 * Perform a simple (incomplete) sanity check. */
	if (hdr->setup_sects >= 16
		|| file_size() - (hdr->setup_sects<<9) >= 512<<10) {
	    debug("This looks like a bootdisk image but not like Linux...\n");
	    return 0;
	}

	printf("Possible very old Linux");
	/* This kernel does not even have a protocol version.
	 * Force the value. */
	hdr->protocol_version = 0; /* pre-2.00 */
    } else
	printf("Found Linux");
    if (hdr->protocol_version >= 0x200 && hdr->kver_addr) {
	char kver[256];
	seek_io(fd, hdr->kver_addr + 0x200);
	if (read_io(fd, kver, sizeof kver) != 0) {
	    kver[255] = 0;
	    printf(" version %s", kver);
	}
    }
    debug(" (protocol %#x)", hdr->protocol_version);
    load_high = 0;
    if (hdr->protocol_version >= 0x200) {
	debug(" (loadflags %#x)", hdr->loadflags);
	load_high = hdr->loadflags & 1;
    }
    if (load_high) {
	printf(" bzImage");
	kern_addr = 0x100000;
    } else {
	printf(" zImage or Image");
	kern_addr = 0x1000;
    }
    printf(".\n");

    return kern_addr;
}

/* Set up parameters for 32-bit kernel */
static void
init_linux_params(struct linux_params *params, struct linux_header *hdr)
{
    debug("Setting up paramters at %#lx\n", virt_to_phys(params));
    memset(params, 0, sizeof *params);

    /* Copy some useful values from header */
    params->mount_root_rdonly = hdr->root_flags;
    params->orig_root_dev = hdr->root_dev;

    /* Video parameters.
     * This assumes we have VGA in standard 80x25 text mode,
     * just like our vga.c does.
     * Cursor position is filled later to allow some more printf's. */
    params->orig_video_mode = 3;
    params->orig_video_cols = 80;
    params->orig_video_lines = 25;
    params->orig_video_isVGA = 1;
    params->orig_video_points = 16;

    params->loader_type = 0xff; /* Unregistered Linux loader */
}

/* Memory map */
static void
set_memory_size(struct linux_params *params, struct sys_info *info)
{
    int i;
    uint64_t end;
    uint32_t ramtop = 0;
    struct e820entry *linux_map;
    struct memrange *filo_map;

    linux_map = params->e820_map;
    filo_map = info->memrange;
    for (i = 0; i < info->n_memranges; i++, linux_map++, filo_map++) {
	if (i < E820MAX) {
	    /* Convert to BIOS e820 style */
	    linux_map->addr = filo_map->base;
	    linux_map->size = filo_map->size;
	    linux_map->type = E820_RAM;
	    debug("%016Lx - %016Lx\n", linux_map->addr,
		    linux_map->addr + linux_map->size);
	    params->e820_map_nr = i+1;
	}

	/* Find out top of RAM. XXX This ignores hole above 1MB */
	end = filo_map->base + filo_map->size;
	if (end < (1ULL << 32)) { /* don't count memory above 4GB */
	    if (end > ramtop)
		ramtop = (uint32_t) end;
	}
    }
    debug("ramtop=%#x\n", ramtop);
    /* Size of memory above 1MB in KB */
    params->alt_mem_k = (ramtop - (1<<20)) >> 10;
    /* old style, 64MB max */
    if (ramtop >= (64<<20))
	params->ext_mem_k = (63<<10);
    else
	params->ext_mem_k = params->alt_mem_k;
    debug("ext_mem_k=%d, alt_mem_k=%d\n", params->ext_mem_k, params->alt_mem_k);
}

/*
 * Parse command line
 * Some parameters, like initrd=<file>, are not passed to kernel,
 * we are responsible to process them.
 * Parameters for kernel are copied to kern_cmdline. Returns name of initrd.
 */
static char *parse_command_line(const char *orig_cmdline, char *kern_cmdline)
{
    const char *start, *sep, *end, *val;
    char name[64];
    int len;
    int k_len;
    int to_kern;
    char *initrd = NULL;
    int toolong = 0;

    forced_memsize = 0;

    if (!orig_cmdline) {
	*kern_cmdline = 0;
        return NULL;
    }

    k_len = 0;
    debug("original command line: \"%s\"\n", orig_cmdline);
    debug("kernel command line at %#lx\n", virt_to_phys(kern_cmdline));

    start = orig_cmdline;
    while (*start == ' ')
	start++;
    while (*start) {
	end = strchr(start, ' ');
	if (!end)
	    end = start + strlen(start);
	sep = strchr(start, '=');
	if (!sep || sep > end)
	    sep = end;
	len = sep - start;
	if (len >= sizeof(name))
	    len = sizeof(name) - 1;
	memcpy(name, start, len);
	name[len] = 0;

	if (*sep == '=') {
	    val = sep + 1;
	    len = end - val;
	} else {
            val = NULL;
	    len = 0;
	}

	/* Only initrd= and mem= are handled here. vga= is not,
	 * which I believe is a paramter to the realmode part of Linux,
	 * which we don't execute. */
	if (strcmp(name, "initrd") == 0) {
	    if (!val)
		printf("Missing filename to initrd parameter\n");
	    else {
		initrd = malloc(len + 1);
		memcpy(initrd, val, len);
		initrd[len] = 0;
		debug("initrd=%s\n", initrd);
	    }
	    /* Don't pass this to kernel */
	    to_kern = 0;
	} else if (strcmp(name, "mem") == 0) {
	    if (!val)
		printf("Missing value for mem parameter\n");
	    else {
		forced_memsize = strtoull_with_suffix(val, (char**)&val, 0);
		if (forced_memsize == 0)
		    printf("Invalid mem option, ignored\n");
		if (val != end) {
		    printf("Garbage after mem=<size>, ignored\n");
		    forced_memsize = 0;
		}
		debug("mem=%Lu\n", forced_memsize);
	    }
	    /* mem= is for both loader and kernel */
	    to_kern = 1;
	} else
	    to_kern = 1;

	if (to_kern) {
	    /* Copy to kernel command line buffer */
	    if (k_len != 0)
		kern_cmdline[k_len++] = ' '; /* put separator */
	    len = end - start;
	    if (k_len + len >= COMMAND_LINE_SIZE) {
		len = COMMAND_LINE_SIZE - k_len - 1;
		if (!toolong) {
		    printf("Kernel command line is too long; truncated to "
			    "%d bytes\n", COMMAND_LINE_SIZE-1);
		    toolong = 1;
		}
	    }
	    memcpy(kern_cmdline + k_len, start, len);
	    k_len += len;
	}

	start = end;
	while (*start == ' ')
	    start++;
    }
    kern_cmdline[k_len] = 0;
    debug("kernel command line (%d bytes): \"%s\"\n", k_len, kern_cmdline);

    return initrd;
}

/* Set command line location */
static void set_command_line_loc(struct linux_params *params,
	struct linux_header *hdr)
{
    if (hdr->protocol_version >= 0x202) {
	/* new style */
	params->cmd_line_ptr = COMMAND_LINE_LOC;
    } else {
	/* old style */
	params->cl_magic = CL_MAGIC_VALUE;
	params->cl_offset = COMMAND_LINE_LOC - LINUX_PARAM_LOC;
    }
}

/* Load 32-bit part of kernel */
static int load_linux_kernel(struct linux_header *hdr, uint32_t kern_addr)
{
    uint32_t kern_offset, kern_size;

    if (hdr->setup_sects == 0)
	hdr->setup_sects = 4;
    kern_offset = (hdr->setup_sects + 1) * 512;
    seek_io(fd, kern_offset);
    kern_size = file_size() - kern_offset;
    debug("offset=%#x addr=%#x size=%#x\n", kern_offset, kern_addr, kern_size);

#if 0
    if (using_devsize) {
	printf("Attempt to load up to end of device as kernel; "
		"specify the image size\n");
	return 0;
    }
#endif

    printf("Loading kernel... ");
    if (read_io(fd, phys_to_virt(kern_addr), kern_size) != kern_size) {
	printf("Can't read kernel\n");
	return 0;
    }
    printf("ok\n");

    return kern_size;
}

static int load_initrd(struct linux_header *hdr, struct sys_info *info,
	uint32_t kern_end, struct linux_params *params, const char *initrd_file)
{
    uint32_t max;
    uint32_t start, end, size;
    uint64_t forced;

    fd = open_io(initrd_file);
    if (fd == -1) {
	printf("Can't open initrd: %s\n", initrd_file);
	return -1;
    }

#if 0
    if (using_devsize) {
	printf("Attempt to load up to end of device as initrd; "
		"specify the image size\n");
	return -1;
    }
#endif

    size = file_size();


    /* Find out the kernel's restriction on how high the initrd can be
     * placed */
    if (hdr->protocol_version >= 0x203)
	max = hdr->initrd_addr_max;
    else
	max = 0x38000000; /* Hardcoded value for older kernels */

    /* FILO itself is at the top of RAM. (relocated)
     * So, try putting initrd just below us. */
    end = virt_to_phys(_start);
    if (end > max)
	end = max;

    /* If "mem=" option is given, we have to put the initrd within
     * the specified range. */
    if (forced_memsize) {
	forced = forced_memsize;
	if (forced > max)
	    forced = max;
	/* If the "mem=" is lower, it's easy */
	if (forced <= end)
	    end = forced;
	else {
	    /* Otherwise, see if we can put it above us */
	    if (virt_to_phys(_end) + size <= forced)
		end = forced; /* Ok */
	}
    }

    start = end - size;
    start &= ~0xfff; /* page align */
    end = start + size;

    debug("start=%#x end=%#x\n", start, end);

    if (start < kern_end) {
	printf("Initrd is too big to fit in memory\n");
	return -1;
    }

    printf("Loading initrd... ");
    if (read_io(fd, phys_to_virt(start), size) != size) {
	printf("Can't read initrd\n");
	return -1;
    }
    printf("ok\n");

    params->initrd_start = start;
    params->initrd_size = size;

    close_io(fd);

    return 0;
}

static void hardware_setup(void)
{
    /* Disable nmi */
    outb(0x80, 0x70);

    /* Make sure any coprocessor is properly reset.. */
    outb(0, 0xf0);
    outb(0, 0xf1);

    /* we're getting screwed again and again by this problem of the 8259.
     * so we're going to leave this lying around for inclusion into
     * crt0.S on an as-needed basis.
     *
     * well, that went ok, I hope. Now we have to reprogram the interrupts :-(
     * we put them right after the intel-reserved hardware interrupts, at
     * int 0x20-0x2F. There they won't mess up anything. Sadly IBM really
     * messed this up with the original PC, and they haven't been able to
     * rectify it afterwards. Thus the bios puts interrupts at 0x08-0x0f,
     * which is used for the internal hardware interrupts as well. We just
     * have to reprogram the 8259's, and it isn't fun.
     */

    outb(0x11, 0x20);		/* initialization sequence to 8259A-1 */
    outb(0x11, 0xA0);		/* and to 8259A-2 */

    outb(0x20, 0x21);		/* start of hardware int's (0x20) */
    outb(0x28, 0xA1);		/* start of hardware int's 2 (0x28) */

    outb(0x04, 0x21);		/* 8259-1 is master */
    outb(0x02, 0xA1);		/* 8259-2 is slave */

    outb(0x01, 0x21);		/* 8086 mode for both */
    outb(0x01, 0xA1);

    outb(0xFF, 0xA1);		/* mask off all interrupts for now */
    outb(0xFB, 0x21);		/* mask all irq's but irq2 which is cascaded */
}

/* Start Linux */
static int start_linux(uint32_t kern_addr, struct linux_params *params)
{
    struct segment_desc *linux_gdt;
    struct context *ctx;
    //extern int cursor_x, cursor_y;

    ctx = init_context(phys_to_virt(STACK_LOC), 4096, 0);

    /* Linux expects GDT being in low memory */
    linux_gdt = phys_to_virt(GDT_LOC);
    memset(linux_gdt, 0, 13*sizeof(struct segment_desc));
    /* Normal kernel code/data segments */
    linux_gdt[2] = gdt[FLAT_CODE];
    linux_gdt[3] = gdt[FLAT_DATA];
    /* 2.6 kernel uses 12 and 13, but head.S uses backward-compatible
     * segments (2 and 3), so it SHOULD not be a problem.
     * However, some distro kernels (eg. RH9) with backported threading
     * patch use 12 and 13 also when booting... */
    linux_gdt[12] = gdt[FLAT_CODE];
    linux_gdt[13] = gdt[FLAT_DATA];
    ctx->gdt_base = GDT_LOC;
    ctx->gdt_limit = 14*8-1;
    ctx->cs = 0x10;
    ctx->ds = 0x18;
    ctx->es = 0x18;
    ctx->fs = 0x18;
    ctx->gs = 0x18;
    ctx->ss = 0x18;

    /* Parameter location */
    ctx->esi = virt_to_phys(params);

    /* Entry point */
    ctx->eip = kern_addr;

    debug("eip=%#x\n", kern_addr);
    printf("Jumping to entry point...\n");

#ifdef VGA_CONSOLE
    /* Update VGA cursor position.
     * This must be here because the printf changes the value! */
    params->orig_x = cursor_x;
    params->orig_y = cursor_y;
#endif

    /* Go... */
    ctx = switch_to(ctx);

    /* It's impossible but... */
    printf("Returned with eax=%#x\n", ctx->eax);

    return ctx->eax;
}

int linux_load(struct sys_info *info, const char *file, const char *cmdline)
{
    struct linux_header hdr;
    struct linux_params *params;
    uint32_t kern_addr, kern_size;
    char *initrd_file = NULL;

    fd = open_io(file);
    if (fd == -1) {
	return -1;
    }

    kern_addr = load_linux_header(&hdr);
    if (kern_addr == 0)
	return LOADER_NOT_SUPPORT;

    params = phys_to_virt(LINUX_PARAM_LOC);
    init_linux_params(params, &hdr);
    set_memory_size(params, info);
    initrd_file = parse_command_line(cmdline, phys_to_virt(COMMAND_LINE_LOC));
    set_command_line_loc(params, &hdr);

    kern_size = load_linux_kernel(&hdr, kern_addr);
    if (kern_size == 0) {
	if (initrd_file)
	    free(initrd_file);
	return -1;
    }

    if (initrd_file) {
	if (load_initrd(&hdr, info, kern_addr+kern_size, params, initrd_file)
		!= 0) {
	    free(initrd_file);
	    return -1;
	}
	free(initrd_file);
    }

    hardware_setup();

    start_linux(kern_addr, params);
    return 0;
}
