/*
 * Open Hack'Ware BIOS main.
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * Status:
 * - boots Linux 2.4 from floppy and IDE
 * - preliminary residual data support
 * - can find PREP boot images and Apple boot blocs
 *
 * TODO:
 * 1/ Cleanify boot partitions:
 *    allow more than one boot bloc + fix PREP load again
 * 2/ add ATAPI driver
 * 3/ add a prompt to let the user choose its boot device / PREP image
 * 4/ add POST
 * 5/ add VGA driver (SVGA/VESA ?)
 * 6/ add a user accessible setup
 * 7/ add netboot
 */

#include <stdlib.h>
#include <stdio.h>
#include "bios.h"

#include "char.h"

//#define DEBUG_MEMORY 1

/* Version string */
const unsigned char *BIOS_str =
"PPC Open Hack'Ware BIOS for qemu version " BIOS_VERSION "\n";
const unsigned char *copyright = "Copyright 2003-2005 Jocelyn Mayer\n";

uint32_t isa_io_base = ISA_IO_BASE;

/* Temporary hack: boots only from floppy */
int boot_device = 'a';

/* Some other PPC helper */
/* Setup a memory mapping, using BAT0
 * BATU:
 * BEPI  : bloc virtual address
 * BL    : area size bits (128 kB is 0, 256 1, 512 3, ...
 * Vs/Vp
 * BATL:
 * BPRN  : bloc real address align on 4MB boundary
 * WIMG  : cache access mode : not used
 * PP    : protection bits
 */
static void BAT_setup (int nr, uint32_t virtual, uint32_t physical,
                       uint32_t size, int Vs, int Vp, int PP)
{
    uint32_t sz_bits, tmp_sz, align, tmp;
    
    sz_bits = 0;
    align = 131072;
    DPRINTF("Set BAT %d v=%0x p=%0x size=%0x\n", nr, virtual, physical, size);
    if (size < 131072)
        size = 131072;
    for (tmp_sz = size / 131072; tmp_sz != 1; tmp_sz = tmp_sz >> 1) {
        sz_bits = (sz_bits << 1) + 1;
        align = align << 1;
    }
    tmp = virtual & ~(align - 1);  /* Align virtual area start */
    tmp |= sz_bits << 2;           /* Fix BAT size             */
    tmp |= Vs << 1;                /* Supervisor access        */
    tmp |= Vp;                     /* User access              */
    DPRINTF("Set BATU%d to %0x\n", nr, tmp);
    switch (nr) {
    case 0:
        /* Setup IBAT0U */
        MTSPR(528, tmp);
        /* Setup DBAT0U */
        MTSPR(536, tmp);
        break;
    case 1:
        /* Setup DBAT1U */
        MTSPR(538, tmp);
        break;
    case 2:
        /* Setup DBAT2U */
        MTSPR(540, tmp);
        break;
    }
    tmp = physical & ~(align - 1); /* Align physical area start */
    tmp |= 0;                      /* Don't care about WIMG     */
    tmp |= PP;                     /* Protection                */
    DPRINTF("Set BATL%d to %0x\n", nr, tmp);
    switch (nr) {
    case 0:
        /* Setup IBAT0L */
        MTSPR(529, tmp);
        /* Setup DBAT0L */
        MTSPR(537, tmp);
        break;
    case 1:
        /* Setup DBAT1L */
        MTSPR(539, tmp);
        break;
    case 2:
        /* Setup DBAT2L */
        MTSPR(541, tmp);
        break;
    }
}

typedef struct PPC_CPU_t {
    uint32_t pvr;
    uint32_t mask;
    unsigned char *name;
} PPC_CPU_t;

static const PPC_CPU_t CPU_PPC[] = {
    /* For now, know only G3 */
    {
        0x00080000,
        0xFFFF0000,
        "PowerPC,G3",
    },
    {
        0x00000000,
        0x00000000,
        "PowerPC,generic",
    },
};

static const unsigned char *CPU_get_name (uint32_t pvr)
{
    int i;

    for (i = 0;; i++) {
        if ((pvr & CPU_PPC[i].mask) == CPU_PPC[i].pvr)
            return CPU_PPC[i].name;
    }

    return NULL;
}

#define TB_FREQ (10 * 1000 * 1000) // XXX: should calibrate
void usleep (uint32_t usec)
{
#if 0 // Buggy: makes OpenDarwin crash (!)
    uint32_t tb0[2], tb1[2], count[2];
    uint32_t tpu;
    int wrap = 0;

    tpu = TB_FREQ / (1000 * 1000);
    mul64(count, usec, tpu);
    mftb(tb0);
    add64(count, count, tb0);
    if (count[0] < tb0[0])
        wrap = 1;
    while (1) {
        mftb(tb1);
        if (wrap == 1 && tb1[0] < tb0[0])
            wrap = 0;
        if (wrap == 0 &&
            (tb1[0] > count[0] ||
             (tb1[0] == count[0] && tb1[1] >= count[1])))
            break;
        tb0[0] = tb1[0];
    }
#else
    uint32_t i, j;
    
    for (i = 0; i < (usec >> 16) * 50; i++) {
        for (j = 0; j < (usec & 0xFFFF) * 50; j++) {
            continue;
        }
    }
#endif
}

void sleep (int sec)
{
    int i;

    for (i = 0; i < sec; i++)
        usleep(1 * 1000 * 1000);
}

/* Stolen from Linux code */
#define CRCPOLY_LE 0xedb88320

uint32_t crc32 (uint32_t crc, const uint8_t *p, int len)
{
    int i;

    while (len--) {
        crc ^= *p++;
        for (i = 0; i < 8; i++)
            crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
    }

    return crc;
}

/* Fake write */
int write (unused int fd, unused const char *buf, int len)
{
    return len;
}

/* BIOS library functions */
/* Fake memory management (to be removed) */
void *mem_align (unused int align)
{
    return malloc(0);
}
#if 1
void free (unused void *p)
{
}
#endif

void freep (void *p)
{
    void **_p = p;

    free(*_p);
    *_p = NULL;
}

static inline int in_area (const void *buf,
                           const void *start, const void *end)
{
    return buf >= start && buf <= end;
}

#ifdef DEBUG_MEMORY
static void *load_dest, *load_end;
static int relax_check;
#endif

void set_loadinfo (unused void *load_base, unused uint32_t size)
{
#ifdef DEBUG_MEMORY
    load_dest = load_base;
    load_end = (char *)load_dest + size;
#endif
}

void set_check (unused int do_it)
{
#ifdef DEBUG_MEMORY
    relax_check = do_it == 0 ? 1 : 0;
#endif
}

void check_location (unused const void *buf,
                     unused const char *func,
                     unused const char *name)
{
#ifdef DEBUG_MEMORY
    if (relax_check != 0)
        return;
    if (!in_area(buf, &_data_start, &_data_end) &&
        !in_area(buf, &_OF_vars_start, &_OF_vars_end) &&
        !in_area(buf, &_sdata_start, &_sdata_end) &&
        !in_area(buf, &_ro_start, &_ro_end) &&
        !in_area(buf, &_RTAS_data_start, &_RTAS_data_end) &&
        !in_area(buf, &_bss_start, &_bss_end) &&
        !in_area(buf, &_ram_start, malloc_base) &&
        /* Let's say 64 kB of stack is enough */
        !in_area(buf, (void *)0x5ff0000, (void *)0x6000000) &&
        !in_area(buf, load_dest, load_end) &&
        /* IO area */
        !in_area(buf, (void *)0x80000000, (void *)0x88000000)) {
        printf("**************************************************************"
               "**************\n");
        printf("%s: %s: %p\n", func, name, buf);
        printf("    data:       %p %p\n", &_data_start, &_data_end);
        printf("    OF_vars:    %p %p\n", &_OF_vars_start, &_OF_vars_end);
        printf("    sdata:      %p %p\n", &_sdata_start, &_sdata_end);
        printf("    rodata:     %p %p\n", &_ro_start, &_ro_end);
        printf("    RTAS_data:  %p %p\n", &_RTAS_data_start, &_RTAS_data_end);
        printf("    bss:        %p %p\n", &_bss_start, &_bss_end);
        printf("    mallocated: %p %p\n", &_ram_start, malloc_base);
        printf("    stack     : %p %p\n", (void *)0x5ff0000,
               (void *)0x6000000);
        printf("    load image: %p %p\n", load_dest, load_end);
        printf("**************************************************************"
               "**************\n");
        bug();
    }
#endif
}

/* No overflow check here... */
long strtol (const unsigned char *str, unsigned char **end, int base)
{
    long ret = 0, tmp, sign = 1;

    check_location(str, __func__, "str");
    if (base < 0 || base > 36)
        return 0;
    for (; *str == ' '; str++)
        continue;
    if (*str == '-') {
        sign = -1;
        str++;
    }
    for (;; str++) {
        tmp = *str;
        if (tmp < '0')
            break;
        if (base <= 10) {
            if (tmp > '0' + base - 1)
                break;
            tmp -= '0';
        } else {
            if (tmp <= '9') {
                tmp -= '0';
            } else {
                tmp &= ~0x20;
                if (tmp < 'A' || tmp > 'A' + base - 11)
                    break;
                tmp += 10 - 'A';
            }
        }
        ret = (ret * base) + tmp;
    }
    if (sign == -1)
        ret = -ret;
    if (end != NULL)
        *end = (unsigned char *)str;

    return ret;
}

nvram_t *nvram;
int arch;
/* HACK... */
int vga_width, vga_height, vga_depth;

part_t *boot_part;

/* XXX: to fix */
void mm_init (uint32_t memsize);
int page_descrs_init (void);

int main (void)
{
    bloc_device_t *bd;
    pci_host_t *pci_main;
    void *res, *bootinfos;
    void *boot_image, *cmdline, *ramdisk;
    void *load_base, *load_entry, *last_alloc, *load_end;
    uint32_t memsize, boot_image_size, cmdline_size, ramdisk_size;
    uint32_t boot_nb;
    int boot_device, i;
    static const uint32_t isa_base_tab[3] = {
        0x80000000, /* PREP */
        0xFE000000, /* Grackle (Heathrow) */
        0xF2000000, /* UniNorth (Mac99)  */
    };

    /* Retrieve NVRAM configuration */
    for(i = 0; i < 3; i++) {
        isa_io_base = isa_base_tab[i];
    nvram = NVRAM_get_config(&memsize, &boot_device,
                             &boot_image, &boot_image_size,
                             &cmdline, &cmdline_size,
                             &ramdisk, &ramdisk_size);
        if (nvram)
            break;
        }
    if (i == 3) {
        ERROR("Unable to load configuration from NVRAM. Aborting...\n");
        return -1;
    }
#if 1
    mm_init(memsize);
#endif
#if 1
    page_descrs_init();
#endif
#ifdef USE_OPENFIRMWARE
    OF_init();
#endif
    pci_main = pci_init();
    if (pci_main == NULL)
        ERROR("Unable to configure PCI\n");
#ifdef USE_OPENFIRMWARE
    /* XXX: this mess needs a serious cleanup... */
    {
        const unsigned char *cpu_name;
        uint32_t pvr = mfpvr();

        cpu_name = CPU_get_name(pvr);
        OF_register_cpu(cpu_name, 0, pvr,
                        200 * 1000 * 1000, 200 * 1000 * 1000,
                        100 * 1000 * 1000, 100 * 1000 * 1000,
                        0x0092);
    }
    OF_register_memory(memsize, 512 * 1024 /* TOFIX */);
    /* Claim memory used by the BIOS */
    OF_claim_virt(0x05800000, 0x00080000, NULL);
    OF_register_bootargs(cmdline);
#endif
    if (isa_io_base == 0x80000000 || 1) {
        pc_serial_register(0x3F8);
#ifdef USE_OPENFIRMWARE
        OF_register_bus("isa", isa_io_base, "ISA");
        OF_register_serial("isa", "com1", 0x3F8, 4);
        OF_register_stdio("com1", "com1");
#endif
    }
#ifdef USE_OPENFIRMWARE
    RTAS_init();
#endif
    /* Get a console */
    console_open();
    printf("%s", BIOS_str);
    printf("Build " stringify(BUILD_DATE) " " stringify(BUILD_TIME) "\n");
    printf("%s\n", copyright);
    printf("Memory size: %d MB. \nBooting from device %c\n",
           memsize >> 20, boot_device);
    vga_puts(BIOS_str);
    vga_puts("Build " stringify(BUILD_DATE) " " stringify(BUILD_TIME) "\n");
    vga_puts(copyright);
    vga_puts("\n");

#if 0
    /* QEMU is quite incoherent: d is cdrom, not second drive */
    /* XXX: should probe CD-ROM position */
    if (boot_device == 'd')
        boot_device = 'e';
#endif
    /* Open boot device */
    boot_part = bd_probe(boot_device);
    if (boot_device == 'm') {
        bd = bd_get('m');
        if (bd == NULL) {
            ERROR("Unable to get memory bloc device\n");
            return -1;
        }
        printf("boot device: %p image %p size %d\n",
               bd, boot_image, boot_image_size);
        bd_ioctl(bd, MEM_SET_ADDR, boot_image);
        bd_ioctl(bd, MEM_SET_SIZE, &boot_image_size);
        boot_part = part_probe(bd, 1);
        bd_put(bd);
        printf("boot device: %p\n", bd);
    }
    if (boot_part == NULL) {
        ERROR("Found no boot partition!\n");
        return -1;
    }
    ERROR("Found boot partition : %p %p\n", boot_part, part_fs(boot_part));
    mem_align(0x00001000);
    res = malloc(0x4000);
    last_alloc = malloc(0);
    boot_nb = 0;
    DPRINTF("Load base: %p - residual data: %p %p %p %p\n",
            load_base, res, last_alloc, boot_part, part_fs(boot_part));
    /* Load the whole boot image */
    if (bootfile_load((void *)&load_base, (void *)&load_entry,
                      (void *)&load_end, boot_part, -1, NULL, 0) < 0) {
        printf("Unable to load boot file\n");
        return -1;
    }
#ifdef USE_OPENFIRMWARE
    DPRINTF("Boot parameters: res: %p load_base: %p OF: %p entry: %p\n",
            res, load_base, &OF_entry, load_entry);
#else
    DPRINTF("Boot parameters: res: %p load_base: %p OF: %p entry: %p\n",
            res, load_base, NULL, load_entry);
#endif
    DPRINTF("Boot: %0x %0x %0x %0x\n", *(uint32_t *)load_entry,
            *((uint32_t *)load_entry + 1),
            *((uint32_t *)load_entry + 2),
            *((uint32_t *)load_entry + 3));
    /* Fill residual data structure */
    residual_build(res, memsize, (uint32_t)load_base,
                   (uint32_t)boot_nb * part_blocsize(boot_part),
                   (uint32_t)last_alloc);
    /* Fill bootinfos */
    bootinfos = (void *)(((uint32_t)load_end + (1 << 20) - 1) & ~((1 << 20) - 1));
    if (boot_image != NULL && cmdline == NULL) {
        cmdline = bootinfos + 0x1000;
        *(char *)cmdline = '\0';
    }
    set_check(0);
    prepare_bootinfos(bootinfos, memsize, cmdline, ramdisk, ramdisk_size);
    set_check(1);
    if (part_flags(boot_part) & PART_PREP) {
        vga_prep_init();
    }
    /* Format NVRAM */
    NVRAM_format(nvram);
    /* Setup MMU and boot the loaded image */
    DPRINTF("\nSet up MMU context\n");
    /* Map all memory with transparent mapping */
    BAT_setup(0, 0x00000000, 0x00000000, memsize, 1, 0, 2);
    /* Open IO ports */
    BAT_setup(1, isa_io_base, isa_io_base, 0x00800000, 1, 1, 2);
#if 0
    /* Open the frame-buffer area */
    BAT_setup(2, vga_fb_phys_addr, vga_fb_phys_addr, 0x00200000, 1, 1, 2);
#else
    if (pci_main != NULL) {
        uint32_t mem_start, mem_size;
        pci_get_mem_range(pci_main, &mem_start, &mem_size);
        BAT_setup(2, mem_start, mem_start, mem_size, 1, 1, 2);
    }
#endif
    /* Enable MMU */
    MMU_on();
    usleep(500);
    dprintf("Boot: %08x %08x %08x %08x\n", *(uint32_t *)load_base,
            *(uint32_t *)(load_base + 4), *(uint32_t *)(load_base + 8),
            *(uint32_t *)(load_base + 12));
    dprintf("Bootinfos at : %p\n", bootinfos);
    printf("\nNow boot it... (%p)\n\n", malloc(0));
    usleep(500);
    {
        register uint32_t r1 __asm__ ("r1");
        printf("stack: %0x malloc_base: %p 0x05800000 0x06000000\n",
               r1, malloc(0));
    }
    
    if (part_flags(boot_part) & PART_PREP) {
        printf("PREP boot... %p %p\n", load_entry, load_base);
        /* Hack for Linux to boot without OpenFirmware */
        put_be32(load_base, 0xdeadc0de);
    }
    transfer_handler(res                      /* residual data          */,
                     load_base                /* load address           */,
#ifdef USE_OPENFIRMWARE
                     &OF_entry                /* OF entry point         */,
#else
                     NULL,
#endif
                     bootinfos                /* bootinfos for Linux    */,
                     cmdline                  /* command line for Linux */,
                     NULL                     /* unused for now         */,
                     load_entry               /* start address     */,
#if 0
                     mem_align(0x00100000)    /* Stack base             */
#else
                     (void *)0x05800000
#endif
                     );
    /* Should never come here */

    return 0;
}
