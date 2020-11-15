/*
 * <part.c>
 *
 * Open Hack'Ware BIOS partitions management
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

/* Bootable partitions detection and management */
part_t *part_open (bloc_device_t *bd,
                   uint32_t start, uint32_t size, uint32_t spb)
{
    part_t *part;

    if (bd_seek(bd, (start + size) * spb, 0) < 0)
        return NULL;
    part = malloc(sizeof(part_t));
    if (part == NULL)
        return NULL;
    part->bd = bd;
    part->start = start;
    part->size = size;
    part->spb = spb;

    return part;
}

int part_seek (part_t *part, uint32_t bloc, uint32_t pos)
{
    if (bloc > part->size) {
        ERROR("bloc: %d part size: %d %p\n", bloc, part->size, part);
        return -1;
    }
    bloc += part->start;
    if (part->spb != 0) {
        bloc *= part->spb;
        pos = pos % part->bloc_size;
    } else {
        pos += (bloc % part->bps) * part->bloc_size;
        bloc /= part->bps;
    }

    return bd_seek(part->bd, bloc, pos);
}

int part_read (part_t *part, void *buffer, int len)
{
    return bd_read(part->bd, buffer, len);
}

int part_write (part_t *part, const void *buffer, int len)
{
    return bd_write(part->bd, buffer, len);
}

void part_close (part_t *part)
{
    part->size = 0;
}

uint32_t part_blocsize (part_t *part)
{
    return part->bloc_size;
}

uint32_t part_flags (part_t *part)
{
    return part->flags;
}

uint32_t part_size (part_t *part)
{
    return part->size;
}

fs_t *part_fs (part_t *part)
{
    return part->fs;
}

void part_private_set (part_t *part, void *private)
{
    part->private = private;
}

void *part_private_get (part_t *part)
{
    return part->private;
}

void part_set_blocsize (bloc_device_t *bd, part_t *part, uint32_t blocsize)
{
    uint32_t seclen;

    part->bloc_size = blocsize;
    seclen = bd_seclen(bd);
    if (blocsize < seclen) {
        part->spb = 0;
        part->bps = bd_seclen(bd) / part->bloc_size;
        DPRINTF("%d part blocs in one sector (%d %d)\n", part->bps,
                part->bloc_size, bd_seclen(bd));
    } else {
        part->spb = part->bloc_size / bd_seclen(bd);
        part->bps = 0;
        DPRINTF("%d sectors in one part bloc (%d %d)\n", part->spb,
                part->bloc_size, bd_seclen(bd));
    }
}

int part_register (bloc_device_t *bd, part_t *partition,
                   const unsigned char *name, int partnum)
{
    part_t **cur;

    DPRINTF("Register partition '%s'\n", name);
    partition->bd = bd;
    partition->next = NULL;
    partition->name = strdup(name);
    partition->partnum = partnum;
    for (cur = _bd_parts(bd); *cur != NULL; cur = &(*cur)->next)
        continue;
    *cur = partition;

    return 0;
}

part_t *part_get (bloc_device_t *bd, int partnum)
{
    part_t **listp, *cur;

    listp = _bd_parts(bd);
    
    for (cur = *listp; cur != NULL; cur = cur->next) {
        if (cur->partnum == partnum)
            break;
    }
    
    return cur;
}

part_t *part_get_raw (bloc_device_t *bd)
{
    part_t *part;
    uint32_t seclen;

    part = malloc(sizeof(part_t));
    part->start = 0;
    seclen = bd_seclen(bd);
    part->size = bd_maxbloc(bd);
    if (seclen > 512) {
        part->size *= seclen / 512;
    } else {
        part->size *= 512 / seclen;
    }
    part->boot_start.bloc = 0;
    part->boot_start.offset = 0;
    part->boot_size.bloc = part->size;
    part->boot_size.offset = 0;
    part->boot_load = 0;
    part->boot_entry = 0;
    part_set_blocsize(bd, part, 512);
    part->bd = bd;
    part->flags = PART_TYPE_RAW | PART_FLAG_BOOT;
    part_register(bd, part, "Raw", 0);

    return part;
}

bloc_device_t *part_get_bd (part_t *part)
{
    return part->bd;
}

part_t *part_probe (bloc_device_t *bd, int set_raw)
{
    part_t *part0 = NULL, *boot_part, **cur;

    /* Try to find a valid boot partition */
    boot_part = Apple_probe_partitions(bd);
    if (boot_part == NULL) {
        boot_part = isofs_probe_partitions(bd);
        if (boot_part == NULL && arch == ARCH_PREP)
            boot_part = PREP_find_partition(bd);
        if (boot_part == NULL && set_raw != 0) {
            dprintf("Use bloc device as raw partition\n");
        }
    }
    if (_bd_parts(bd) == NULL) {
        /* Register the 0 partition: raw partition containing the whole disk */
        part0 = part_get_raw(bd);
    }
    /* Probe filesystem on each found partition */
    for (cur = _bd_parts(bd); *cur != NULL; cur = &(*cur)->next) {
        const unsigned char *map, *type;
        switch ((*cur)->flags & 0x0F) {
        case PART_TYPE_PREP:
            map = "PREP";
            break;
        case PART_TYPE_APPLE:
            map = "Apple";
            break;
        case PART_TYPE_ISO9660:
            map = "ISO9660";
            break;
        default:
            map = "Raw";
            break;
        }
        switch ((*cur)->flags & 0xF0) {
        case PART_FLAG_DUMMY:
            type = "dummy";
            break;
        case PART_FLAG_DRIVER:
            type = "driver";
            break;
        case PART_FLAG_PATCH:
            type = "patches";
            break;
        case PART_FLAG_FS:
            type = "filesystem";
            break;
        default:
            type = "unknown";
            break;
        }
        dprintf("Probe filesystem on %s %s partition '%s' %s %p\n",
                type, map, (*cur)->name,
                ((*cur)->flags) & PART_FLAG_BOOT ? "(bootable)" : "", *cur);
        if (((*cur)->flags) & PART_FLAG_FS) {
            if (((*cur)->flags) & PART_FLAG_BOOT)
                (*cur)->fs = fs_probe(*cur, 1);
            else
                (*cur)->fs = fs_probe(*cur, 0);
        } else if (((*cur)->flags) & PART_TYPE_RAW) {
            (*cur)->fs = fs_probe(*cur, 2);
        } else {
            (*cur)->fs = fs_probe(*cur, 2);
        }
            fs_get_bootfile((*cur)->fs);
        if (((*cur)->flags) & PART_FLAG_BOOT) {
            dprintf("Partition is bootable (%d)\n", (*cur)->partnum);
            bd_set_boot_part(bd, *cur, (*cur)->partnum);
            if (boot_part == NULL)
                boot_part = *cur;
        }
    }
    dprintf("Boot partition: %p %p %p %p\n", boot_part, boot_part->fs,
            part_fs(boot_part), part0);

    return boot_part;
}

int part_set_boot_file (part_t *part, uint32_t start, uint32_t offset,
                        uint32_t size)
{
    part->boot_start.bloc = start;
    part->boot_start.offset = offset;
    part->boot_size.bloc = size;
    part->boot_size.offset = 0;
    part->boot_load = 0;
    part->boot_entry = 0;
    part->flags |= PART_FLAG_BOOT;

    return 0;
}

unsigned int part_get_entry (part_t *part)
{
    return part->boot_entry;
}
