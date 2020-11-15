/*
 * <bootinfos.c>
 *
 * Generate boot informations (bootinfos for Linux and residual data).
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

#include <stdlib.h>
#include "bios.h"

#define BI_FIRST		0x1010  /* first record - marker */
#define BI_LAST			0x1011	/* last record - marker */
#define BI_CMD_LINE		0x1012
#define BI_BOOTLOADER_ID	0x1013
#define BI_INITRD		0x1014
#define BI_SYSMAP		0x1015
#define BI_MACHTYPE		0x1016
#define BI_MEMSIZE		0x1017
#define BI_BOARD_INFO		0x1018

static inline void put_long (void *addr, uint32_t l)
{
    char *pos = addr;
    pos[0] = (l >> 24) & 0xFF;
    pos[1] = (l >> 16) & 0xFF;
    pos[2] = (l >> 8) & 0xFF;
    pos[3] = l & 0xFF;
}

static void *set_bootinfo_tag (void *addr, uint32_t tag, uint32_t size,
                               void *data)
{
    char *pos = addr;

    put_long(pos, tag);
    pos += 4;
    put_long(pos, size + 8);
    pos += 4;
    memcpy(pos, data, size);
    pos += size;

    return pos;
}

void prepare_bootinfos (void *p, uint32_t memsize,
                        void *cmdline, void *initrd, uint32_t initrd_size)
{
    uint32_t tmpi[2];

    /* BI_FIRST */
    p = set_bootinfo_tag(p, BI_FIRST, 0, NULL);
    /* BI_CMD_LINE */
    if (cmdline != 0) {
        p = set_bootinfo_tag(p, BI_CMD_LINE, strlen(cmdline), cmdline);
    } else {
        p = set_bootinfo_tag(p, BI_CMD_LINE, 0, NULL);
    }
    /* BI_MEM_SIZE */
    p = set_bootinfo_tag(p, BI_MEMSIZE, 4, &memsize);
    /* BI_INITRD */
    tmpi[0] = (uint32_t)initrd;
    tmpi[1] = initrd_size;
    p = set_bootinfo_tag(p, BI_INITRD, 8, tmpi);
    /* BI_LAST */
    p = set_bootinfo_tag(p, BI_LAST, 0, 0);
}

/* Residual data */
#define MAX_CPUS 16
#define MAX_SEGS 64
#define MAX_MEMS 64
#define MAX_DEVS 256

typedef struct vital_t {
    /* Motherboard dependents */
    uint8_t model[32];
    uint8_t serial[64];
    uint16_t version;
    uint16_t revision;
    uint32_t firmware;
    uint32_t NVRAM_size;
    uint32_t nSIMMslots;
    uint32_t nISAslots;
    uint32_t nPCIslots;
    uint32_t nPCMCIAslots;
    uint32_t nMCAslots;
    uint32_t nEISAslots;
    uint32_t CPUHz;
    uint32_t busHz;
    uint32_t PCIHz;
    uint32_t TBdiv;
    /* CPU infos */
    uint32_t wwidth;
    uint32_t page_size;
    uint32_t ChBlocSize;
    uint32_t GrSize;
    /* Cache and TLBs */
    uint32_t cache_size;
    uint32_t cache_type;
    uint32_t cache_assoc;
    uint32_t cache_lnsize;
    uint32_t Icache_size;
    uint32_t Icache_assoc;
    uint32_t Icache_lnsize;
    uint32_t Dcache_size;
    uint32_t Dcache_assoc;
    uint32_t Dcache_lnsize;
    uint32_t TLB_size;
    uint32_t TLB_type;
    uint32_t TLB_assoc;
    uint32_t ITLB_size;
    uint32_t ITLB_assoc;
    uint32_t DTLB_size;
    uint32_t DTLB_assoc;
    void *ext_vital;
} vital_t;

typedef struct PPC_CPU_t {
    uint32_t pvr;
    uint32_t serial;
    uint32_t L2_size;
    uint32_t L2_assoc;
} PPC_CPU_t;

typedef struct map_t {
    uint32_t usage;
    uint32_t base;
    uint32_t count;
} map_t;

typedef struct PPC_mem_t {
    uint32_t size;
} PPC_mem_t;

typedef struct PPC_device_t {
    uint32_t busID;
    uint32_t devID;
    uint32_t serial;
    uint32_t flags;
    uint32_t type;
    uint32_t subtype;
    uint32_t interface;
    uint32_t spare;
} PPC_device_t;

typedef struct residual_t {
    uint32_t  length;
    uint16_t  version;
    uint16_t  revision;
    vital_t   vital;
    uint32_t  nCPUs;
    PPC_CPU_t CPUs[MAX_CPUS];
    uint32_t  max_mem;
    uint32_t  good_mem;
    uint32_t  nmaps;
    map_t     maps[MAX_SEGS];
    uint32_t  nmems;
    PPC_mem_t memories[MAX_MEMS];
    uint32_t  ndevices;
    PPC_device_t devices[MAX_DEVS];
    /* TOFIX: No PNP devices */
} residual_t;

void residual_build (void *p, uint32_t memsize,
                     uint32_t load_base, uint32_t load_size,
                     uint32_t last_alloc)
{
    const unsigned char model[] = "Qemu\0PPC\0";
    residual_t *res = p;
    int i;

    if (res == NULL)
        return;
    res->length = sizeof(residual_t);
    res->version = 1;
    res->revision = 0;
    memcpy(res->vital.model, model, sizeof(model));
    res->vital.version = 1;
    res->vital.revision = 0;
    res->vital.firmware = 0x1D1;
    res->vital.NVRAM_size = 0x2000;
    res->vital.nSIMMslots = 1;
    res->vital.nISAslots = 0;
    res->vital.nPCIslots = 0;
    res->vital.nPCMCIAslots = 0;
    res->vital.nMCAslots = 0;
    res->vital.nEISAslots = 0;
    res->vital.CPUHz = 200 * 1000 * 1000;
    res->vital.busHz = 100 * 1000 * 1000;
    res->vital.PCIHz = 33 * 1000 * 1000;
    res->vital.TBdiv = 1000;
    res->vital.wwidth = 32;
    res->vital.page_size = 4096;
    res->vital.ChBlocSize = 32;
    res->vital.GrSize = 32;
    res->vital.cache_size = 0;
    res->vital.cache_type = 0; /* No cache */
    res->vital.cache_assoc = 8; /* Same as 601 */
    res->vital.cache_lnsize = 32;
    res->vital.Icache_size = 0;
    res->vital.Icache_assoc = 8;
    res->vital.Icache_lnsize = 32;
    res->vital.Dcache_size = 0;
    res->vital.Dcache_assoc = 8;
    res->vital.Dcache_lnsize = 32;
    res->vital.TLB_size = 0;
    res->vital.TLB_type = 0; /* None */
    res->vital.TLB_assoc = 2;
    res->vital.ITLB_size = 0;
    res->vital.ITLB_assoc = 2;
    res->vital.DTLB_size = 0;
    res->vital.DTLB_assoc = 2;
    res->vital.ext_vital = NULL;
    res->nCPUs = 1;
    res->CPUs[0].pvr = mfpvr();
    res->CPUs[0].serial = 0;
    res->CPUs[0].L2_size = 0;
    res->CPUs[0].L2_assoc = 8;
    /* Memory infos */
    res->max_mem = memsize;
    res->good_mem = memsize;
    /* Memory mappings */
    /* First segment: firmware */
    last_alloc = (last_alloc + 4095) & ~4095;
    res->maps[0].usage = 0x0007;
    res->maps[0].base  = 0x00000000;
    res->maps[0].count = last_alloc >> 12;
    i = 1;
    if (last_alloc != load_base) {
        /* Free memory between firmware and boot image */
        res->maps[1].usage = 0x0010;
        res->maps[1].base = last_alloc >> 12;
        res->maps[1].count = (load_base - last_alloc) >> 12;
        i++;
    }
    /* Boot image */
    load_size = (load_size + 4095) & ~4095;
    res->maps[i].usage = 0x0008;
    res->maps[i].base  = load_base >> 12;
    res->maps[i].count = load_size >> 12;
    i++;
    /* Free memory */
    res->maps[i].usage = 0x0010;
    res->maps[i].base  = (load_base + load_size) >> 12;
    res->maps[i].count = (memsize >> 12) - res->maps[i].base;
    i++;
    /* ISA IO region : 8MB */
    res->maps[i].usage = 0x0040;
    res->maps[i].base  = 0x80000000 >> 12;
    res->maps[i].count = 0x00800000 >> 12;
    i++;
    /* System registers : 8MB */
    res->maps[i].usage = 0x0200;
    res->maps[i].base  = 0xBF800000 >> 12;
    res->maps[i].count = 0x00800000 >> 12;
    i++;
    /* System ROM : 64 kB */
    res->maps[i].usage = 0x2000;
    res->maps[i].base  = 0xFFFF0000 >> 12;
    res->maps[i].count = 0x00010000 >> 12;
    i++;
    res->nmaps = i;
    /* Memory SIMMs */
    res->nmems = 1;
    res->memories[0].size = memsize;
    /* Describe no devices */
    res->ndevices = 0;
}
