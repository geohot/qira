/*
 * <prep.c>
 *
 * Open Hack'Ware PREP BIOS partition type management
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

/* PREP image management */
typedef struct MSDOS_part_t MSDOS_part_t;
struct MSDOS_part_t {
    uint8_t  boot_ind;
    uint8_t  start_head;
    uint8_t  start_sect;
    uint8_t  start_cyl;
    uint8_t  sys_ind;
    uint8_t  end_head;
    uint8_t  end_sect;
    uint8_t  end_cyl;
    uint32_t LBA_start;
    uint32_t LBA_end;
}  __attribute__ ((packed));

part_t *PREP_find_partition (bloc_device_t *bd)
{
    MSDOS_part_t *p;
    part_t *part;
    uint8_t *buffer;
    uint32_t boot_offset, boot_size;
    int i;

    part = NULL;
    buffer = malloc(0x200);
    bd_seek(bd, 0, 0);
    if (bd_read(bd, buffer, 0x200) < 0) {
        ERROR("Unable to read boot sector from boot device. Aborting...\n");
        goto error;
    }
    if (buffer[0x1FE] != 0x55 || buffer[0x1FF] != 0xAA) {
        ERROR("No MSDOS signature (%x %x %x %x)\n",
              buffer[0x000], buffer[0x001], buffer[0x1FE], buffer[0x1FF]);
        goto error;
    }
    for (i = 0; i < 4; i++) {
        p = (void *)(&buffer[0x1BE + (0x10 * i)]);
        DPRINTF("partition %d: %x is %sbootable - ", i, p->boot_ind,
                (p->boot_ind & 0x80) ? "" : "not ");
        DPRINTF("start %0x end %0x type %x\n",
                get_le32(&p->LBA_start), get_le32(&p->LBA_end), p->sys_ind);
#if 0
        if (p->boot_ind != 0x80)
            continue;
#endif
        switch (p->sys_ind) {
        case 0x07: /* HPFS/NTFS */
            goto register_nonboot;
        case 0x08: /* AIX */
            goto register_nonboot;
        case 0x09: /* AIX bootable */
            /* Not supported by now */
            break;
        case 0x0A: /* OS/2 boot manager */
            /* Not supported by now */
            break;
        case 0x41: /* PREP boot */
            part = malloc(sizeof(part_t));
            memset(part, 0, sizeof(part_t));
            part->bd = bd;
            part_set_blocsize(bd, part, 0x200);
            /* Convert start and size into LBA */
            if ((p->start_head != 0 || p->start_cyl != 0 ||
                 p->start_sect != 0) && p->LBA_start == 0) {
                DPRINTF("start: use CHS\n");
                part->start = bd_CHS2sect(bd, p->start_cyl,
                                          p->start_head,
                                          p->start_sect);
            } else {
                DPRINTF("start: use LBA\n");
                part->start = get_le32(&p->LBA_start);
            }
            if ((p->end_head != 0 || p->end_cyl != 0 ||
                 p->end_sect != 0) && p->LBA_end == 0) {
                DPRINTF("end: use CHS\n");
                part->size = bd_CHS2sect(bd, p->end_cyl,
                                         p->end_head, p->end_sect);
            } else {
                DPRINTF("end: use LBA\n");
                part->size = get_le32(&p->LBA_end);
            }
            /* XXX: seems that some (AIX !)
             * code the size here instead of partition end
             */
            if (part->size > part->start)
                part->size -= part->start;
            DPRINTF("LBA: start %0x size: %0x\n", part->start, part->size);
            /* Now, find and check boot record */
            part_seek(part, 0, 0);
            if (bd_read(bd, buffer, part->bloc_size) < 0) {
                ERROR("%s sector_read failed (%d)\n", __func__, i);
                freep(&part);
                goto error;
            }
#if 0
            if (buffer[0x1FE] != 0x55 || buffer[0x1FF] != 0xAA) {
                ERROR("No MSDOS signature on PREP boot record\n");
                freep(&part);
                goto error;
            }
#endif
            boot_offset = get_le32(buffer);
            boot_size =  get_le32(buffer + 4);
            if ((boot_offset & 3) || /*(boot_size & 3) ||*/
                boot_offset == 0 || boot_size == 0) {
                DPRINTF("Suspicious PREP boot parameters: %08x %08x %08x %08x\n",
                    part->start, part->start * 0x200, boot_offset, boot_size);
#if 0
                freep(&part);
                goto error;
#else
                /* IBM boot blocs respect the norm better than others... */
                part->start++;
                part_seek(part, 0, 0);
                if (bd_read(bd, buffer, part->bloc_size) < 0) {
                    ERROR("%s sector_read failed (%d)\n", __func__, i);
                    freep(&part);
                    goto error;
                }
                boot_offset = get_le32(buffer);
                boot_size =  get_le32(buffer + 4);
#endif
            }
            DPRINTF("PREP boot parameters: %08x %08x %08x %08x\n",
                    part->start, part->start * 0x200, boot_offset, boot_size);
            if (boot_size > (part->size * part->bloc_size)) {
                ERROR("PREP boot image greater than boot partition: %0x %0x\n",
                      boot_size, part->size * part->bloc_size);
#if 0
                freep(&part);
                goto error;
#endif
            }
            part->boot_start.bloc = 0;
            part->boot_start.offset = 0;
            part->boot_size.bloc = boot_size / part->bloc_size;
            part->boot_size.offset = boot_size % part->bloc_size;
            part->boot_load = 0;
            part->boot_entry = boot_offset - part->bloc_size;
            part->flags = PART_TYPE_PREP | PART_FLAG_BOOT;
            part_register(bd, part, "PREP boot", i);
            fs_raw_set_bootfile(part, part->boot_start.bloc,
                                part->boot_start.offset,
                                part->boot_size.bloc,
                                part->boot_size.offset);
            break;
        case 0x63: /* GNU Hurd */
            goto register_nonboot;
        case 0x83: /* Linux */
            goto register_nonboot;
        case 86 ... 87: /* NFTS volume set */
            /* Not supported by now */
            break;
        case 0x8E: /* Linux LVM */
            /* Not supported by now */
            break;
        case 0x96: /* AIX seems to use this to identify ISO 9660 'partitions' */
            break;
        case 0xA5: /* FreeBSD */
            goto register_nonboot;
        case 0xA6: /* OpenBSD */
            goto register_nonboot;
        case 0xA7: /* NeXTSTEP */
            goto register_nonboot;
        case 0xA8: /* Darwin UFS */
            goto register_nonboot;
        case 0xA9: /* NetBSD */
            goto register_nonboot;
        case 0xAB: /* Darwin boot */
            /* Not supported by now */
            break;
        case 0xBE: /* Solaris boot */
            /* Not supported by now */
            break;
        case 0xEB: /* BeOS fs */
            goto register_nonboot;
        case 0xFD: /* Linux RAID */
            /* Not supported by now */
            break;
        default:
            break;
        register_nonboot:
            break;
        }
    }
 error:
    free(buffer);

    return part;
}
