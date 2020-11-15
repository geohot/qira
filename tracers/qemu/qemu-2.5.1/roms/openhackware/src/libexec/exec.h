/*
 * <exec.h>
 *
 * Open Hack'Ware BIOS: executable files loader definitions
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

#if !defined(__OHW_EXEC_H__)
#define __OHW_EXEC_H__

int _bootfile_load (inode_t *file, void **dest, void **entry, void **end,
                    uint32_t loffset, int type);
int exec_load_elf (inode_t *file, void **dest, void **entry, void **end,
                   uint32_t loffset);
int exec_load_xcoff (inode_t *file, void **dest, void **entry, void **end,
                     uint32_t loffset);
int exec_load_macho (inode_t *file, void **dest, void **entry, void **end,
                     uint32_t loffset);
int exec_load_pef (inode_t *file, void **dest, void **entry, void **end,
                   uint32_t loffset);
int exec_load_prep (inode_t *file, void **dest, void **entry, void **end,
                    uint32_t loffset);
int exec_load_chrp (inode_t *file, void **dest, void **entry, void **end,
                    uint32_t loffset);

#endif /* !defined(__OHW_EXEC_H__) */
