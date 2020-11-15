/*
 * <isofs.c>
 *
 * Open Hack'Ware BIOS ISOFS partition type management
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

/* ISO FS partitions handlers */
#define ISOFS_BLOCSIZE (2048)

/* Generic ISO fs descriptor */
typedef struct isofs_desc_t isofs_desc_t;
struct isofs_desc_t {
    uint8_t type;
    uint8_t ID[5];
    uint8_t version;
    uint8_t data[2041];
} __attribute__ ((packed));

typedef struct iso_primary_desc_t iso_primary_desc_t;
struct iso_primary_desc_t {
    uint8_t type;
    uint8_t ID[5];
    uint8_t version;
    uint8_t pad0;
    uint8_t system_id[32];
    uint8_t volume_id[32];
    uint8_t pad1[8];
    uint32_t volume_size;
} __attribute__ ((packed));

/* The only descriptor we're interrested in here
 * is El-torito boot descriptor
 */
typedef struct isofs_bootdesc_t isofs_bootdesc_t;
struct isofs_bootdesc_t {
    uint8_t type;
    uint8_t ID[5];
    uint8_t version;
    uint8_t sys_ID[32];
    uint8_t pad[32];
    uint32_t catalog;
    uint8_t data[1973];
} __attribute__ ((packed));

#define ISO_BOOTABLE 0x88
enum {
    ISOBOOT_IX86 = 0,
    ISOBOOT_PPC  = 1,
    ISOBOOT_MAC  = 2,
};

enum {
    ISOMEDIA_NOEMUL = 0,
    ISOMEDIA_FL12   = 1,
    ISOMEDIA_FL144  = 2,
    ISOMEDIA_FL288  = 3,
    ISOMEDIA_HD     = 4,
};

typedef struct isofs_validdesc_t isofs_validdesc_t;
struct isofs_validdesc_t {
    uint8_t ID;
    uint8_t arch;
    uint8_t pad[2];
    uint8_t name[24];
    uint8_t csum[2];
    uint16_t key;
} __attribute__ ((packed));

typedef struct isofs_bootcat_t isofs_bootcat_t;
struct isofs_bootcat_t {
    uint8_t bootable;
    uint8_t media;
    uint8_t segment[2];
    uint8_t sys_type;
    uint8_t pad;
    uint16_t nsect;
    uint32_t offset;
    uint8_t data[20];
} __attribute__ ((packed));

part_t *isofs_probe_partitions (bloc_device_t *bd)
{
    unsigned char name[32];
    void *buffer;
    union {
        isofs_desc_t desc;
        isofs_bootdesc_t bootdesc;
        iso_primary_desc_t primdesc;
    } *desc;
    isofs_validdesc_t *valid;
    isofs_bootcat_t *bootcat;
    part_t *part;
    uint32_t boot_desc;
    uint32_t nsect, bloc, offset, length;
    int i, end_reached;

    part = NULL;
    buffer = malloc(ISOFS_BLOCSIZE);
    end_reached = 0;
    desc = buffer;
    boot_desc = -1;
    /* The descriptors start at offset 0x8000 */
    for (bloc = 0x8000 / ISOFS_BLOCSIZE; end_reached == 0; bloc++) {
        bd_seek(bd, bloc, 0);
        if (bd_read(bd, buffer, ISOFS_BLOCSIZE) < 0) {
            ERROR("%s bloc_read %d failed\n", __func__, bloc);
            goto error;
        }
        if (strncmp("CD001", desc->desc.ID, 5) != 0) {
            //            MSG("\rNo ISO9660 signature\n");
            goto error;
        }
        /* We found at least one valid descriptor */
        switch (desc->desc.type) {
        case 0x00:
            /* El-torito descriptor, great ! */
            DPRINTF("El-torito descriptor: %08x %d\n", desc->bootdesc.catalog,
                    (char *)&desc->bootdesc.catalog - (char *)desc);
            boot_desc = get_le32(&desc->bootdesc.catalog);
            break;
        case 0x01:
            /* ISOFS primary descriptor */
            DPRINTF("ISOFS primary descriptor (%d %d)\n",
                    get_le32(&desc->primdesc.volume_size) * 2048,
                    get_le32(&desc->primdesc.volume_size));
            break;
        case 0x02:
            /* ISOFS suplementary descriptor */
            DPRINTF("ISOFS suplementary descriptor\n");
            break;
        case 0xFF:
            /* End of descriptor list */
            DPRINTF("End of descriptor list\n");
            end_reached = 1;
            break;
        }
    }
    if (boot_desc != (uint32_t)(-1)) {
        /* Find the validation descriptor */
        bd_seek(bd, boot_desc, 0);
        for (i = 0; i < (ISOFS_BLOCSIZE / 64); i++) {
            DPRINTF("ISO catalog...\n");
            bd_read(bd, buffer, 64);
            valid = buffer;
#if 1
            if (valid->ID != 0x01 || get_le16(&valid->key) != 0xAA55) {
                ERROR("ISO catalog with invalid ID/key: %x %x\n",
                      valid->ID, valid->key);
                continue;
            }
#endif
#if 0
#if defined (__i386__)
            if (valid->arch != ISOBOOT_IX86) {
                ERROR("ISO catalog not for x86: %d\n", valid->arch);
                continue;
            }
#elif defined (__powerpc__) || defined (_ARCH_PPC)
            if (valid->arch != ISOBOOT_PPC && valid->arch != ISOBOOT_MAC) {
                ERROR("ISO catalog not for PPC: %d\n", valid->arch);
                continue;
            }
#else
            ERROR("Unknown host architecture !\n");
            continue;
#endif
#endif
            bootcat = (void *)(valid + 1);
            if (bootcat->bootable != ISO_BOOTABLE) {
                ERROR("Non bootable ISO catalog\n");
                continue;
            }
            nsect = get_le16(&bootcat->nsect);
            switch (bootcat->media) {
            case ISOMEDIA_NOEMUL:
                length = nsect * ISOFS_BLOCSIZE;
                dprintf("No emulation\n");
                break;
            case ISOMEDIA_FL12:
                length = 1200 * 1024;
                dprintf("1.2 MB floppy\n");
                break;
            case ISOMEDIA_FL144:
                length = 1440 * 1024;
                dprintf("1.44 MB floppy\n");
                break;
            case ISOMEDIA_FL288:
                length = 2880 * 1024;
                dprintf("2.88 MB floppy\n");
                break;
            case ISOMEDIA_HD:
                length = nsect * ISOFS_BLOCSIZE;
                dprintf("HD image\n");
                break;
            default:
                ERROR("Unknown media type: %d\n", bootcat->media);
                continue;
            }
            offset = get_le32(&bootcat->offset);
            /* Register boot disc */
            part = malloc(sizeof(part_t));
            part->bd = bd;
            part_set_blocsize(bd, part, ISOFS_BLOCSIZE);
            part->start = offset;
            part->size = (length + ISOFS_BLOCSIZE - 1) / ISOFS_BLOCSIZE;
            part->boot_start.bloc = 0;
            part->boot_start.offset = 0;
            part->boot_size.bloc = length / ISOFS_BLOCSIZE;
            part->boot_size.offset = length % ISOFS_BLOCSIZE;
            part->boot_load = 0;
            part->boot_entry = 0;
            if (valid->name[0] == '\0') {
                strcpy(name, "ISOFS");
            } else {
                memcpy(name, valid->name, sizeof(valid->name));
                name[sizeof(valid->name)] = '\0';
            }
            printf("Partition '%s': %p st %0x size %0x %d\n",
                   name, part, offset, length, bootcat->media);
            printf("    boot %0x %0x load %0x entry %0x\n",
                   part->boot_start.bloc, part->boot_size.bloc,
                   part->boot_load, part->boot_entry);
            part->flags = PART_TYPE_ISO9660 | PART_FLAG_BOOT;
            part_register(bd, part, name, i + 1);
            fs_raw_set_bootfile(part, part->boot_start.bloc,
                                part->boot_start.offset,
                                part->boot_size.bloc,
                                part->boot_size.offset);
            break;
        }
    }
error:
    free(buffer);

    return part;
}
