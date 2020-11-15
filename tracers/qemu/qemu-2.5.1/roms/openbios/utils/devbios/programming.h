/*
 *                     OpenBIOS - free your system! 
 *              ( firmware/flash device driver for Linux )
 *                          
 *  programming.h - prototypes for flash device programming  
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

/* Addresses */
#define ADDR_MANUFACTURER	0x0000
#define ADDR_DEVICE_ID		0x0001
#define ADDR_SECTOR_LOCK	0x0002
#define ADDR_HANDSHAKE		0x0003

#define ADDR_UNLOCK_1		0x5555
#define ADDR_UNLOCK_2		0x2AAA
#define ADDR_COMMAND		0x5555

/* Commands */
#define CMD_UNLOCK_DATA_1		0xAA
#define CMD_UNLOCK_DATA_2		0x55
#define CMD_MANUFACTURER_UNLOCK_DATA	0x90
#define CMD_UNLOCK_BYPASS_MODE		0x20
#define CMD_PROGRAM_UNLOCK_DATA		0xA0
#define CMD_RESET_DATA			0xF0
#define CMD_SECTOR_ERASE_UNLOCK_DATA	0x80
#define CMD_SECTOR_ERASE_UNLOCK_DATA_2	0x30
#define CMD_ERASE_DATA			0x10
#define CMD_UNLOCK_SECTOR		0x60

extern int flashcount;

void flash_command(unsigned char *addr, unsigned char command);

void flash_program (unsigned char *addr);
void flash_program_atmel (unsigned char *addr);

int  flash_ready_toggle (unsigned char *addr, unsigned int offset);
int  flash_ready_poll (unsigned char *addr, unsigned int offset, unsigned char data);

int  flash_erase (unsigned char *addr, unsigned int flashnum);
int  flash_erase_sectors (unsigned char *addr, unsigned int flashnum, 
			unsigned int startsec, unsigned int endsec);

void iflash_program_byte  (unsigned char *addr, unsigned int offset, unsigned char data);
int  iflash_erase_sectors (unsigned char *addr, unsigned int flashnum, unsigned int startsec, unsigned int endsec);

unsigned char flash_readb(unsigned char *addr, unsigned int offset);
void flash_writeb(unsigned char *addr, unsigned int offset, unsigned char data);


int flash_probe_address(void *address);
void flash_probe_area(unsigned long romaddr, unsigned long romsize, 
		int map_always);

