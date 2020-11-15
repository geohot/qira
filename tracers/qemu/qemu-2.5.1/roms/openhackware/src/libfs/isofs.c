/*
 * <isofs.c>
 *
 * Open Hack'Ware BIOS ISO file system management
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
#include "libfs.h"

/* ISOFS filesystem */
int fs_isofs_probe (unused part_t *part, unused uint32_t *size,
                    unused fs_ops_t **fs_ops, unused unsigned char **name,
                    unused void **private)
{
    return -1;
}
