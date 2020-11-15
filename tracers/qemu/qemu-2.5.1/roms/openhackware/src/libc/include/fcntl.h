/*
 * <fcntl.h>
 *
 * Open Hack'Ware BIOS: subset of POSIX fcntl definitions
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

#if !defined (__OHW_FCNTL_H__)
#define __OHW_FCNTL_H__

enum {
    O_RDONLY = 0x0001,
    O_WRONLY = 0x0002,
    O_RDWR   = 0x0003,
    O_CREAT  = 0x0010,
    O_EXCL   = 0x0020,
};

#endif /* !defined (__OHW_FCNTL_H__) */
