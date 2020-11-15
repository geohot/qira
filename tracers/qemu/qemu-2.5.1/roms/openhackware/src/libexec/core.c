/*
 * <file.c>
 *
 * Open Hack'Ware BIOS executable file loader
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
#include "exec.h"

/*****************************************************************************/
uint32_t file_seek (inode_t *file, uint32_t pos)
{
    uint32_t blocsize, bloc, offset;

    if (file == NULL)
        return -1;
    blocsize = part_blocsize(fs_inode_get_part(file));
    bloc = pos / blocsize;
    offset = pos % blocsize;

    return fs_seek(file, bloc, offset);
}

/*****************************************************************************/
/* Executable file loaders */

enum {
    FILE_TYPE_ELF = 0,
    FILE_TYPE_XCOFF,
    FILE_TYPE_MACHO,
    FILE_TYPE_PEF,
    FILE_TYPE_CHRP,
    FILE_TYPE_PREP,
    FILE_TYPE_FLAT,
};

uint32_t fs_inode_get_size (inode_t *inode);
unsigned int part_get_entry (part_t *part);
/*****************************************************************************/
/* Generic boot file loader */
int _bootfile_load (inode_t *file, void **dest, void **entry, void **end,
                    uint32_t loffset, int type)
{
    int (*do_load)(inode_t *file, void **dest, void **entry, void **end,
                   uint32_t loffset);
    uint32_t size;
    int ret;
    int i;

    if (type == -1)
        i = 0;
    else
        i = type;
    for (;; i++) {
        switch (i) {
        case FILE_TYPE_ELF:
            do_load = &exec_load_elf;
            break;
        case FILE_TYPE_XCOFF:
            do_load = &exec_load_xcoff;
            break;
        case FILE_TYPE_MACHO:
            do_load = &exec_load_macho;
            break;
        case FILE_TYPE_PEF:
            do_load = &exec_load_pef;
            break;
        case FILE_TYPE_CHRP:
            do_load = &exec_load_chrp;
            break;
        case FILE_TYPE_PREP:
            do_load = &exec_load_prep;
            break;
        default:
            if (*dest == NULL)
                *dest = (void *)DEFAULT_LOAD_DEST;
            if (*entry == NULL) {
                if (part_get_entry(fs_inode_get_part(file)) != 0 || 1) {
                    *entry = (char *)*dest +
                        part_get_entry(fs_inode_get_part(file));
                    dprintf("dest %p entry %08x => %p\n",
                            *dest, part_get_entry(fs_inode_get_part(file)),
                            *entry);
                } else {
                    *entry = *dest + 0xC;
                }
            }
            size = fs_inode_get_size(file);
            *end = (char *)*dest + size - loffset;
            printf("Load raw file into memory at %p %d (%08x) %d (%08x)\n",
                   *dest, size, size, loffset, loffset);
            file_seek(file, loffset);
            set_loadinfo(*dest, size);
            if ((uint32_t)fs_read(file, *dest, size) != size) {
                ERROR("Error loading file...\n");
                ret = -1;
            } else {
                ret = 0;
            }
            goto out;
        }
        DPRINTF("Check file type %d at offset %d %p\n", i, loffset, do_load);
        ret = (*do_load)(file, dest, entry, end, loffset);
        if (ret >= -1 || type == i) {
            if (type == i)
                ret = -2;
            break;
        }
    }
 out:

    return ret;
}

int bootfile_load (void **dest, void **entry, void **end,
                   part_t *part, int type, const unsigned char *fname,
                   uint32_t loffset)
{
    inode_t *file;
    int ret;

    DPRINTF("Load file '%s' %p %p type: %d offset: %0x => %d %p\n",
            fname, part, part_fs(part), type, loffset, part_blocsize(part), *dest);
    if (fname == NULL)
        file = fs_get_bootfile(part_fs(part));
    else
        file = fs_open(part_fs(part), fname);
    if (file == NULL)
        return -1;
    ret = _bootfile_load(file, dest, entry, end, loffset, type);
    fs_close(file);

    return ret;
}
