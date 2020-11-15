/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 * Copyright (C) 1996-1998 Robert Leslie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * $Id: medium.h,v 1.3 1998/04/11 08:27:13 rob Exp $
 */

/*
 * Partition Types:
 *
 * "Apple_partition_map"	partition map
 * "Apple_Driver"		device driver
 * "Apple_Driver43"		SCSI Manager 4.3 device driver
 * "Apple_MFS"			Macintosh 64K ROM filesystem
 * "Apple_HFS"			Macintosh hierarchical filesystem
 * "Apple_Unix_SVR2"		Unix filesystem
 * "Apple_PRODOS"		ProDOS filesystem
 * "Apple_Free"			unused
 * "Apple_Scratch"		empty
 */

int m_zeroddr(hfsvol *);

int m_zeropm(hfsvol *, unsigned int);
int m_findpmentry(hfsvol *, const char *, Partition *, unsigned long *);
int m_mkpart(hfsvol *, const char *, const char *, unsigned long);

int m_zerobb(hfsvol *);
