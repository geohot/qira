/*
 * <apple.c>
 *
 * Open Hack'Ware BIOS Apple partition type management
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
#include <stdio.h>
#include "bios.h"
#include "libpart.h"

/* Apple partitions handler */
#define HFS_BLOCSIZE (512)

typedef struct Mac_head_t Mac_head_t;
struct Mac_head_t {
    /* 0x000 */
    uint8_t signature[2];
    uint16_t bloc_size;
    uint32_t bloc_count;
    /* 0x008 */
    uint16_t dev_type;
    uint16_t dev_ID;
    uint32_t data;
    /* 0x010 */
    uint16_t driver_cnt;
    uint8_t pad[428];
    /* 0x01BE */
    uint8_t part_table[0x40];
    /* 0x1FE */
    uint8_t magic[2];
    /* 0x0200 */
} __attribute__ ((packed));

typedef struct Mac_driver_entry_t Mac_driver_entry_t;
struct Mac_driver_entry_t {
    uint32_t start;
    uint16_t size;
    uint16_t type;
} __attribute__ ((packed));

typedef enum Mac_partflags_t Mac_partflags_t;
enum Mac_partflags_t {
    MACPART_SPEC2     = 0x0100,
    MACPART_SPEC1     = 0x0080,
    MACPART_PIC       = 0x0040,
    MACPART_WRITABLE  = 0x0020,
    MACPART_READABLE  = 0x0010,
    MACPART_BOOTABLE  = 0x0008,
    MACPART_INUSE     = 0x0004,
    MACPART_ALLOCATED = 0x0002,
    MACPART_VALID     = 0x0001,
};

#define MAC_BOOTABLE_PART (MACPART_VALID | MACPART_INUSE | MACPART_BOOTABLE)

typedef struct Mac_partmap_t Mac_partmap_t;
struct Mac_partmap_t {
    /* 0x000 */
    uint8_t signature[2];
    uint8_t res0[2];
    uint32_t map_cnt;
    /* 0x008 */
    uint32_t start_bloc;
    uint32_t bloc_cnt;
    /* 0x010 */
    uint8_t name[32];
    /* 0x030 */
    uint8_t type[32];
    /* 0x050 */
    uint32_t data_start;
    uint32_t data_cnt;
    /* 0x058 */
    uint32_t flags;
    uint32_t boot_start;
    /* 0x060 */
    uint32_t boot_size;
    uint32_t boot_load;
    /* 0x068 */
    uint32_t boot_load2;
    uint32_t boot_entry;
    /* 0x070 */
    uint32_t boot_entry2;
    uint32_t boot_csum;
    /* 0x078 */
    uint8_t CPU[16];
    /* 0x088 */
    uint8_t boot_args[0x80];
    /* 0x108 */
    uint8_t pad0[0xC8];
    /* 0x1D4  */
    uint16_t ntype;
    uint8_t ff[2];
    /* 0x1D8 */
    uint8_t pad1[0x24];
    /* 0x1FC */
    uint8_t mark[4];
    /* 0x200 */
} __attribute__ ((packed));

int fs_raw_set_bootfile (part_t *part,
                         uint32_t start_bloc, uint32_t start_offset,
                         uint32_t size_bloc, uint32_t size_offset);

part_t *Apple_probe_partitions (bloc_device_t *bd)
{
    unsigned char tmp[33], *name;
    Mac_head_t *head;
    Mac_partmap_t *partmap;
    part_t *part, *boot_part;
    unsigned char *type;
    uint8_t *buffer;
    uint32_t pos, bloc, start, count;
    uint32_t bloc_size, flags;
    int map_count, i, n, len;

    part = NULL;
    boot_part = NULL;
    n = 1;
    buffer = malloc(HFS_BLOCSIZE);
    /* Read first sector */
    bd_seek(bd, 0, 0);
    if (bd_read(bd, buffer, HFS_BLOCSIZE) < 0) {
        ERROR("Unable to read boot sector from boot device. Aborting...\n");
        goto error;
    }
    head = (Mac_head_t *)buffer;
    if (head->signature[0] != 'E' || head->signature[1] != 'R') {
        //        MSG("\rNo Apple boot bloc signature...\n");
        goto error;
    }
    MSG("\rFound Apple partition map...\n");
    bloc = 0;
    bloc_size = bd_seclen(bd);
    map_count = 1;
#if 0
    if (head->magic[0] == 0x55 && head->magic[1] == 0xAA) {
        /* PREP boot image ! Must parse it as MS-DOS boot bloc */
        ERROR("%s PREP head magic\n", __func__);
        goto error;
    }
#endif
    /* Partition table starts in sector 1 */
    for (i = 1; i < (map_count + 1); i++) {
        bloc = (i * HFS_BLOCSIZE) / bloc_size;
        pos = (i * HFS_BLOCSIZE) % bloc_size;
        DPRINTF("Check part %d of %d (%d %d %d)\n",
                i, map_count, bloc, pos, bloc_size);
        bd_seek(bd, bloc, pos);
        if (bd_read(bd, buffer, HFS_BLOCSIZE) < 0) {
            ERROR("%s sector_read failed (%d)\n", __func__, i);
            goto error;
        }
        partmap = (Mac_partmap_t *)buffer;
        if (partmap->signature[0] != 'P' || partmap->signature[1] != 'M' ) {
            ERROR("%s bad partition signature (%c %c)\n",
                  __func__, partmap->signature[0], partmap->signature[1]);
            goto error;
        }
        /* We found at least one Apple partition map,
         * so we won't have to try to parse with other partition mappings.
         */
        for (type = partmap->type; (type - partmap->type) < 32; type++) {
            if (*type != '\0')
                break;
        }
        if (partmap->name[0] == '\0') {
            sprintf(tmp, "part%d", i);
            name = tmp;
        } else {
            name = partmap->name;
        }
        /* Regular Apple partition */
        part = malloc(sizeof(part_t));
        if (part == NULL) {
            ERROR("%s: can't allocate partition\n", __func__);
            return NULL;
        }
        memset(part, 0, sizeof(part_t));
        part->start = partmap->start_bloc;
        part->size = partmap->bloc_cnt;
        part_set_blocsize(bd, part, HFS_BLOCSIZE);
        len = 32 - (type - partmap->type);
        if (len == 0) {
            /* Place holder. Skip it */
            DPRINTF("%s placeholder part\t%d\n", __func__, i);
            part->flags = PART_TYPE_APPLE | PART_FLAG_DUMMY;
            part_register(bd, part, name, i);
        } else if (strncmp("Apple_Void", type, 32) == 0) {
            /* Void partition. Skip it */
            DPRINTF("%s Void part\t%d [%s]\n", __func__, i, type);
            part->flags = PART_TYPE_APPLE | PART_FLAG_DUMMY;
            part_register(bd, part, name, i);
        } else if (strncmp("Apple_Free", type, 32) == 0) {
            /* Free space. Skip it */
            DPRINTF("%s Free part (%d)\n", __func__, i);
            part->flags = PART_TYPE_APPLE | PART_FLAG_DUMMY;
            part_register(bd, part, name, i);
        } else if (strncmp("Apple_partition_map", type, 32) == 0 ||
                   strncmp("Apple_Partition_Map", type, 32) == 0
#if 0 // Is this really used or is it just a mistake ?
                || strncmp("Apple_patition_map", type, 32) == 0
#endif
                   ) {
            DPRINTF("%s Partition map\t%d [%s]\n", __func__, i, type);
            /* We are in the partition map descriptor */
            if (i == 1) {
                /* Get the real map blocs count */
                map_count = partmap->map_cnt;
                DPRINTF("%s: map_count: %d\n", __func__, map_count);
            } else {
                /* Don't about about secondary partition map
                 * Seems to be used, at least on CDROMs, to describe
                 * the same partition map with bloc_size = 2048
                 */
            }
            part->flags = PART_TYPE_APPLE | PART_FLAG_DUMMY;
            part_register(bd, part, name, i);
        } else if (strncmp("Apple_Driver", type, 32) == 0 ||
                   strncmp("Apple_Driver43", type, 32) == 0 ||
                   strncmp("Apple_Driver43_CD", type, 32) == 0 ||
                   strncmp("Apple_Driver_ATA", type, 32) == 0 ||
                   strncmp("Apple_Driver_ATAPI", type, 32) == 0 ||
                   strncmp("Apple_FWDriver", type, 32) == 0 ||
                   strncmp("Apple_Driver_IOKit", type, 32) == 0) {
            /* Drivers. don't care for now */
            DPRINTF("%s Drivers part\t%d [%s]\n", __func__, i, type);
            part->flags = PART_TYPE_APPLE | PART_FLAG_DRIVER;
            part_register(bd, part, name, i);
        } else if (strncmp("Apple_Patches", type, 32) == 0) {
            /* Patches: don't care for now */
            part->flags = PART_TYPE_APPLE | PART_FLAG_PATCH;
            part_register(bd, part, name, i);
            DPRINTF("%s Patches part\t%d [%s]\n", __func__, i, type);
        } else if (strncmp("Apple_HFS", type, 32) == 0 ||
                   strncmp("Apple_MFS", type, 32) == 0 ||
                   strncmp("Apple_UFS", type, 32) == 0 ||
                   strncmp("Apple_PRODOS", type, 32) == 0 ||
                   strncmp("Apple_UNIX_SVR2", type, 32) == 0 ||
                   strncmp("Linux", type, 32) == 0 ||
                   strncmp("NetBSD/macppc", type, 32) == 0 ||
                   strncmp("Apple_boot", type, 32) == 0 ||
                   strncmp("Apple_bootstrap", type, 32) == 0 ||
                   strncmp("Apple_Bootstrap", type, 32) == 0) {
            DPRINTF("%s Fs part\t%d [%s]\n", __func__, i, type);
            /* Filesystems / boot partitions */
            flags = partmap->flags;
            start = partmap->start_bloc * HFS_BLOCSIZE;
            count = partmap->bloc_cnt * HFS_BLOCSIZE;
            if (partmap->boot_size == 0 || partmap->boot_load == 0) {
                printf("Not a bootable partition %d %d (%p %p)\n",
                       partmap->boot_size, partmap->boot_load,
                       boot_part, part);
                part->flags = PART_TYPE_APPLE | PART_FLAG_FS;
            } else {
                part->boot_start.bloc = partmap->boot_start;
                part->boot_start.offset = 0;
                part->boot_size.bloc = partmap->boot_size / HFS_BLOCSIZE;
#if 0
                printf("%0x %0x %0x\n", partmap->boot_size, HFS_BLOCSIZE,
                       part->boot_size.bloc);
#endif
                part->boot_size.offset = (partmap->boot_size) % HFS_BLOCSIZE;
                part->boot_load = partmap->boot_load;
                part->boot_entry = partmap->boot_entry;
                fs_raw_set_bootfile(part, part->boot_start.bloc,
                                    part->boot_start.offset,
                                    part->boot_size.bloc,
                                    part->boot_size.offset);
                boot_part = part;
                part->flags = PART_TYPE_APPLE | PART_FLAG_FS | PART_FLAG_BOOT;
            }
            printf("Partition: %d '%s' '%s' st %0x size %0x",
                    i, name, type, partmap->start_bloc, partmap->bloc_cnt);
#ifndef DEBUG
            printf("\n");
#endif
            DPRINTF(" - %0x %0x %p %p\n",
                    partmap->boot_start, partmap->boot_size, part, part->fs);
            DPRINTF("    boot %0x %0x load %0x entry %0x\n",
                    part->boot_start.bloc, part->boot_size.bloc,
                    part->boot_load, part->boot_entry);
            DPRINTF("                           load %0x entry %0x %0x\n",
                    partmap->boot_load2, partmap->boot_entry2, HFS_BLOCSIZE);
            part_register(bd, part, name, i);
        } else {
            memcpy(tmp, type, 32);
            tmp[32] = '\0';
            ERROR("Unknown partition type [%s]\n", tmp);
            part->flags = PART_TYPE_APPLE | PART_FLAG_DUMMY;
            part_register(bd, part, name, i);
        }
    }
 error:
    free(buffer);

    return boot_part;

}
