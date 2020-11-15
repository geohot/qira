/*
 *                     OpenBIOS - free your system! 
 *              ( firmware/flash device driver for Linux )
 *                          
 *  flashchips.h - flash device structures.
 *  
 *  This program is part of a free implementation of the IEEE 1275-1994 
 *  Standard for Boot (Initialization Configuration) Firmware.
 *
 *  Copyright (C) 1998-2004  Stefan Reinauer, <stepan@openbios.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA, 02110-1301 USA
 *
 */

/*
 *   flags structure
 *   bit 0 = needs erase before write (f_needs_erase)
 *   bit 1-3 flash manu type
 *   bit 4-6 probably needed for more manu
 *   bit 7 = sector erase happens one sector at a time
 *           (f_slow_sector_erase)
 */

#define f_needs_erase   0x01

/* 3 bit for flashtype */
#define f_manuf_compl   0x0e /* Mask out bits 1-3 */
#define f_intel_compl   0x02 /* 001 */
#define f_atmel_compl   0x04 /* 010 */
#define f_fwh_compl     0x08 /* 100 */

#define f_slow_sector_erase 0x80

#define FLASH_UNKNOWN	0
#define FLASH_CFI	1
#define FLASH_JEDEC	2

typedef struct flashdevice {
	unsigned long	mapped;
	unsigned long   physical;
	unsigned long   offset;
	unsigned int	flashnum, manufnum;
	unsigned short	id;
	unsigned int	size, sectors;
	unsigned int	idx;
	void		*data;
	int		open_mode, open_cnt;
} flashdevice_t;

typedef struct flashchip {
	char		*name;
	unsigned short	id;
	unsigned int	voltage;
	unsigned int	size;		/* KBytes */
	unsigned int	supported;
	unsigned int	pagesize;	/* Bytes */
	unsigned int	flags;
	unsigned int	*sectors;	/* Kbytes[] including end of last sector */
} flashchip_t;

typedef struct manufacturer {
	char		*name;
	unsigned short	id;
} manufacturer_t;

extern unsigned int currflash;
extern flashdevice_t  flashdevices[BIOS_MAXDEV];
extern const flashchip_t flashchips[];
extern const manufacturer_t manufacturers[];
