/*
 * <prep.c>
 *
 * Open Hack'Ware BIOS PREP executable file loader
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

/* PREP boot loader */
int exec_load_prep (inode_t *file, unused void **dest,
                    unused void **entry, unused void **end,
                    unused uint32_t loffset)
{
    unsigned char buffer[512];

    file_seek(file, loffset);
    if (fs_read(file, buffer, 512) < 0) {
        ERROR("Cannot load first bloc of file...\n");
        return -2;
    }
    if (buffer[0x1FE] != 0x55 || buffer[0x1FF] != 0xAA) {
        DPRINTF("Not a PREP file\n");
        return -2;
    }

    return -2;
}
