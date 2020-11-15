/*
 * <libpart.h>
 *
 * Open Hack'Ware BIOS partitions management definitions
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

#if !defined (__OHW_LIBPART_H__)
#define __OHW_LIBPART_H__

/* LBA for IDE is 48 bits long.
 * For now, I'll use 32 bits to store bloc nr
 * and 32 bits to store offsets in blocs and will only handle LBA 28.
 * So, I'll be affected with the well known 128 GB disk barrier bug...
 */

struct part_t {
    bloc_device_t *bd;
    int partnum;
    uint32_t start;      /* Partition first bloc             */
    uint32_t size;       /* Partition size, in blocs         */
    uint32_t spb;
    uint32_t bps;
    uint32_t flags;

    uint32_t bloc_size;  /* Bloc size (may be != bd->seclen) */
    /* XXX: broken: to be reworked */
    pos_t boot_start;    /* Boot program start bloc & offset */
    pos_t boot_size;     /* Boot program size                */
    uint32_t boot_load;  /* Boot program address load        */
    uint32_t boot_entry; /* Boot program entry point         */

    unsigned char *name;
    inode_t *boot_file;
    fs_t *fs;

    void *private;

    part_t *next;
    part_t *bnext;
};

int part_register (bloc_device_t *bd, part_t *partition,
                   const unsigned char *name, int partnum);
void part_set_blocsize (bloc_device_t *bd, part_t *part, uint32_t blocsize);
void part_private_set (part_t *part, void *private);
void *part_private_get (part_t *part);

part_t *PREP_find_partition (bloc_device_t *bd);
part_t *Apple_probe_partitions (bloc_device_t *bd);
part_t *isofs_probe_partitions (bloc_device_t *bd);

#endif /* !defined (__OHW_LIBPART_H__) */
