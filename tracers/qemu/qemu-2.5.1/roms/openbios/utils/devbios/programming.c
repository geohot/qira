/*
 *                     OpenBIOS - free your system! 
 *              ( firmware/flash device driver for Linux )
 *                          
 *  programming.c - flash device programming and probing algorithms.  
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

// <-- C++ style comments are for experimental comments only.
// They will disappear as soon as I fixed all the stuff.

/* #define DEBUG_PROBING */

#include <linux/config.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && defined(MODVERSIONS)
#include <linux/modversions.h>
#endif

#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <asm/io.h>
#include <asm/delay.h>
#include <asm/uaccess.h>

#include "bios.h"
#include "pcisets.h"
#include "flashchips.h"
#include "programming.h"

struct flashdevice flashdevices[BIOS_MAXDEV];
int flashcount;

/*
 * ******************************************
 *
 *	flashchip handling
 *
 * ****************************************** 
 */


void flash_command (unsigned char *addr, unsigned char command)
#if 1
{
	flash_writeb(addr, 0x5555, 0xaa);
	flash_writeb(addr, 0x2AAA, 0x55);
	flash_writeb(addr, 0x5555, command);
}
void fwh_flash_command(unsigned char *addr, unsigned char command)
#endif
{
	flash_writeb(addr, 0x75555, 0xaa);
	flash_writeb(addr, 0x72aaa, 0x55);
	flash_writeb(addr, 0x75555, command);
}

#define CFLASH flashdevices[flashcount]
int flash_probe_address(void *address)
{
	int flashnum=0, manufnum=0, sectors=0;
	unsigned short flash_id, testflash;
	unsigned long flags;
#ifdef DEBUG_PROBING
	printk( KERN_DEBUG "BIOS: Probing for flash chip @0x%08lx\n", (unsigned long) address);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	save_flags(flags);
#endif
	spin_lock_irqsave(&bios_lock, flags);

	testflash= (flash_readb(address, 0))+(flash_readb(address, 1)<<8);

	/* 1st method: Intel, Atmel listen to this.. */

	flash_command(address, 0x90);
	udelay(20);

	flash_id = (flash_readb(address, 0))+(flash_readb(address, 1)<<8);

#ifdef DEBUG_PROBING
	printk (KERN_DEBUG "BIOS: testflash[%04x] flash_id[%04x]\n",
		testflash, flash_id); 
#endif
	
	/* 2nd method: Winbond (I think this is Jedec standard) */

	if (flash_id==testflash) {
#ifdef DEBUG_PROBING
		printk (KERN_DEBUG "BIOS: Trying 2nd ID method.\n"); 
#endif
		flash_command(address, 0xf0); /* Reset */
		udelay(20);

		flash_command(address, 0x80);
		flash_command(address, 0x60);
		udelay(20);

		flash_id = (flash_readb(address, 0))+(flash_readb(address, 1)<<8);
#ifdef DEBUG_PROBING
	printk (KERN_DEBUG "BIOS: testflash[%04x] flash_id[%04x]\n",
		testflash, flash_id); 
#endif
	}

	/* 3rd Method: Some Winbonds seem to want this */

	if (flash_id==testflash) {
#ifdef DEBUG_PROBING
		printk (KERN_DEBUG "BIOS: Trying 3rd ID method.\n"); 
#endif
		flash_command(address, 0xf0); /* Reset again */
		udelay(20);

		flash_command(address, 0x80);
		flash_command(address, 0x20);
		udelay(20);

		flash_id = (flash_readb(address, 0))+(flash_readb(address, 1)<<8);
#ifdef DEBUG_PROBING
	printk (KERN_DEBUG "BIOS: testflash[%04x] flash_id[%04x]\n",
		testflash, flash_id); 
#endif
	}

	if (flash_id==0x7f7f && flash_readb(address, 0x100)==0x1c) {
		/* We have an Eon flashchip. They keep their
		 * device id at 0x101 instead of 0x1
		 */
		printk(KERN_INFO "BIOS: Eon flash device detected\n");
		flash_id=(flash_readb(address, 0x1))+(flash_readb(address, 0x101)<<8);
	}

	flash_command(address, 0xf0);
	udelay(20);

	spin_unlock_irqrestore(&bios_lock, flags);

	if (flash_id==testflash) return 0; /* Nothing found :-( */

	while (flashchips[flashnum].id!=0) {
		if (flash_id==flashchips[flashnum].id) 
			break;
		flashnum++;
	}

	while (manufacturers[manufnum].id!=0) {
		if ((flash_id&0xff)==manufacturers[manufnum].id) 
			break;
		manufnum++;
	}
	
	if (flashchips[flashnum].id) {
		while (flashchips[flashnum].sectors[sectors]<flashchips[flashnum].size)
			sectors++;
	}

	if (flashcount >= BIOS_MAXDEV) {
		printk(KERN_DEBUG "BIOS: Too many flash devices found.\n");
		return -1;
	}

	CFLASH.flashnum	= flashnum;
	CFLASH.manufnum	= manufnum;
	CFLASH.id	= flash_id;
	CFLASH.size	= (flashchips[flashnum].size<<10);
	CFLASH.sectors	= sectors;
	CFLASH.open_mode= 0;
	CFLASH.open_cnt	= 0;

	return 1;
}

void flash_probe_area(unsigned long romaddr, unsigned long romsize, 
		int map_always)
{
	unsigned long probeaddr;
	unsigned char *mapped;

	mapped=ioremap(romaddr, romsize);
	
	devices[flashdevices[currflash].idx].activate();
	
	probeaddr=(unsigned long)mapped;
	
	while ( probeaddr < (unsigned long)mapped + romsize - 0x5555 ) {
		if ( flash_probe_address ((void *)probeaddr) != 1) {
			probeaddr += 4*1024;
			continue;
		}
		
		CFLASH.offset	= probeaddr-(unsigned long)mapped;
		CFLASH.mapped	= (unsigned long)mapped;
		CFLASH.physical	= romaddr+CFLASH.offset;
		
		printk( KERN_INFO "BIOS: flash device with size "
				"%dk (ID 0x%04x) found.\n", 
				CFLASH.size >> 10, CFLASH.id);
		
		printk( KERN_INFO "BIOS:   physical address "
				"0x%08lx (va=0x%08lx+0x%lx).\n",
				CFLASH.physical, (unsigned long)CFLASH.mapped,
				CFLASH.offset);

		if (flashchips[CFLASH.flashnum].flags&f_fwh_compl) {
			unsigned long t_lk;
			unsigned int i=7;
			printk(KERN_INFO "BIOS:   FWH compliant "
							"chip detected.\n");
			for (t_lk=0xffb80002; t_lk<=0xffbf0002; t_lk+=0x10000) 
			{
				printk(KERN_INFO "Lock register %d "
						 "(0x%08lx): 0x%x\n",
						i, t_lk, (unsigned int)
						(readb(phys_to_virt(t_lk))));
				i--;
			}
		}
		flashcount++;
		currflash++;
#ifdef MULTIPLE_FLASH
		probeaddr += flashdevices[flashcount-1].size;
		flashdevices[flashcount].mapped=flashdevices[flashcount-1].mapped;
		flashdevices[flashcount].data=flashdevices[flashcount-1].data;
		continue;
#else
		break;
#endif
	}

	/* We might want to always map the memory
	 * region in certain cases
	 */

	if (map_always) {
		CFLASH.flashnum = 0;
		CFLASH.manufnum = 0;
		CFLASH.id       = 0;
		CFLASH.size     = romsize;
		CFLASH.sectors  = 0;
		CFLASH.open_mode= 0;
		CFLASH.open_cnt = 0;
		CFLASH.offset   = 0;
		CFLASH.mapped   = (unsigned long)mapped;
		CFLASH.physical = romaddr;
		printk( KERN_INFO "BIOS: rom device with size "
				"%dk registered.\n", CFLASH.size >> 10);
		flashcount++; currflash++;
		return;
	}
	
	/* We found nothing in this area, so let's unmap it again */
	
	if (flashcount && flashdevices[flashcount-1].mapped != (unsigned long)mapped)
		iounmap(mapped);

	devices[flashdevices[currflash].idx].deactivate();
}

#undef CFLASH

void flash_program (unsigned char *addr)
{
	flash_command(addr, 0xa0);
}

void flash_program_atmel (unsigned char *addr)
{
	flash_command(addr, 0x80);
	flash_command(addr, 0x20);
}

int flash_erase (unsigned char *addr, unsigned int flashnum) 
{
	flash_command(addr, 0x80);
	flash_command(addr, 0x10);
	udelay(80);
	return flash_ready_toggle(addr, 0);
}

int flash_erase_sectors (unsigned char *addr, unsigned int flashnum, unsigned int startsec, unsigned int endsec) 
{
	unsigned int sector;
  
	if (!(flashchips[flashnum].flags & f_slow_sector_erase)) {
		flash_command(addr, 0x80);

		if (flashchips[flashnum].flags&f_fwh_compl) {
			flash_writeb(addr, 0x75555,0xaa);
			flash_writeb(addr, 0x72aaa,0x55);
		} else {
			flash_writeb(addr, 0x5555,0xaa);
			flash_writeb(addr, 0x2aaa,0x55);
		}
    
		for (sector=startsec; sector <= endsec; sector++) {
			flash_writeb (addr, flashchips[flashnum].sectors[sector]*1024, 0x30);
		}
    
		udelay(150); // 80 max normally, wait 150usec to be sure
#if 0
  		if (flashchips[flashnum].flags&f_fwh_compl)
#endif
			return flash_ready_toggle(addr, flashchips[flashnum].sectors[sector-1]*1024);
#if 0
		else
			return flash_ready_poll(addr, flashchips[flashnum].sectors[sector-1]*1024, 0xff);
#endif
	}
  
	/* sectors must be sent the sector erase command for every sector */
	for (sector=startsec; sector <= endsec; sector++) {
		flash_command(addr, 0x80);
		if (flashchips[flashnum].flags&f_fwh_compl) {
			flash_writeb(addr, 0x75555,0xaa);
			flash_writeb(addr, 0x72aaa,0x55);
		} else {
			flash_writeb(addr, 0x5555,0xaa);
			flash_writeb(addr, 0x2aaa,0x55);
		}
    
		flash_writeb(addr, flashchips[flashnum].sectors[sector]*1024, 0x30);
		udelay(150);
#if 0
		if (flashchips[flashnum].flags&f_fwh_compl)
#endif
			flash_ready_toggle(addr, flashchips[flashnum].sectors[sector] *1024);
#if 0
		else
			flash_ready_poll(addr, flashchips[flashnum].sectors[sector]*1024, 0xff);
#endif
	}

	return 0;

}

/* waiting for the end of programming/erasure by using the toggle method.
 * As long as there is a programming procedure going on, bit 6 of the last
 * written byte is toggling it's state with each consecutive read. 
 * The toggling stops as soon as the procedure is completed.
 * This function returns 0 if everything is ok, 1 if an error occured
 * while programming was in progress.
 */ 

int flash_ready_toggle (unsigned char *addr, unsigned int offset)
{
	unsigned long int timeout=0;
	unsigned char oldflag, flag;
	int loop=1;

	oldflag=flash_readb(addr, offset) & 0x40;

	while (loop && (timeout<0x7fffffff)) {
		flag=flash_readb(addr, offset) & 0x40;

		if (flag == oldflag)
			loop=0;
		
		oldflag=flag;
		timeout++;
	}

	if (loop) {
		printk(KERN_DEBUG "BIOS: operation timed out (Toggle)\n");
		return 1;
	}
	
	return 0;
}

/* This functions is similar to the above one. While a programming
 * procedure is going on, bit 7 of the last written data byte is
 * inverted. When the procedure is completed, bit 7 contains the
 * correct data value
 */

int flash_ready_poll (unsigned char *addr, unsigned int offset, unsigned char data)
{
	unsigned long int timeout=0;
	unsigned char flag;

	flag=flash_readb(addr, offset);

	while ( ( flag & 0x80) != ( data & 0x80)) {
		if ( ( flag & 0x80 ) == ( data & 0x80 ) ) {
#ifdef DBGTIMEOUT
			printk(KERN_DEBUG "BIOS: Timeout value (EOT Polling) %ld\n",timeout);
#endif
			return 0;
		}			
		flag=flash_readb(addr, offset);
		if (timeout++>12800) {	// 10 times more than usual.
			printk(KERN_ERR "BIOS: EOT Polling timed out at 0x%08x."
				" Try again or increase max. timeout.\n",offset);
			return 1;
		}
		if ((flag & 0x80) == ( data & 0x80)) {
		  flag=flash_readb(addr, offset);
		}
	}
#ifdef DBGTIMEOUT
	printk(KERN_DEBUG "BIOS: Timeout value (EOT Polling) %ld\n",timeout);
#endif

	flag=flash_readb(addr, offset);
	if ( ( flag & 0x80 ) == ( data & 0x80 ) ) return 0; else return 1;
}



void iflash_program_byte (unsigned char *addr, unsigned int offset, unsigned char data)
{
	unsigned long int timeout=0;
	unsigned char flag;

	flash_writeb (addr, offset, 0x40);
	flash_writeb (addr, offset, data);

	flash_writeb (addr, offset, 0x70);	/* Read Status */
	do {
		flag=flash_readb (addr, offset);
		if (timeout++>100) { // usually 2 or 3 :-)
			printk(KERN_ERR "BIOS: Intel programming timed out at"
				"0x%08x. Try again or increase max. timeout.\n",offset);
			return;
		}
	} while ((flag&0x80) != 0x80);

#ifdef DBGTIMEOUT
	printk (KERN_DEBUG"BIOS: Timeout value (Intel byte program) %ld\n",timeout);
#endif

	if (flag&0x18) {
		flash_writeb (addr, offset, 0x50);	/* Reset Status Register */
		printk (KERN_ERR "BIOS: Error occured, please repeat write operation. (intel)\n");
	}

	flash_writeb (addr, offset, 0xff);
}



int  iflash_erase_sectors (unsigned char *addr, unsigned int flashnum, unsigned int startsec, unsigned int endsec)
{
	unsigned long int timeout;
	unsigned int sector, offset=0;
	unsigned char flag;

	for (sector=startsec; sector<=endsec; sector++) {
		offset=(flashchips[flashnum].sectors[sector]*1024);
		flash_writeb (addr, offset, 0x20);
		flash_writeb (addr, offset, 0xd0);

		flash_writeb (addr, offset, 0x70);	/* Read Status */
		timeout=0;
		do {
			flag=flash_readb (addr, offset);
			if (timeout++>1440000) { // usually 144000
				printk(KERN_ERR "BIOS: Intel sector erase timed out at 0x%08x. Try again or increase max. timeout.\n",offset);
				return 1;
			}
		} while ((flag&0x80) != 0x80);

#ifdef DBGTIMEOUT
		printk (KERN_DEBUG "BIOS: Timeout value (Intel sector erase) %ld\n",timeout);
#endif

		if (flag&0x28) {
			flash_writeb (addr, offset, 0x50);
			flash_writeb (addr, offset, 0xff);
			return 1; /* Error! */
		}
	}

	flash_writeb (addr, offset, 0xff);
	return 0;	
}



unsigned char flash_readb(unsigned char *addr, unsigned int offset)
{
#if defined(__alpha__)
	if (flashdevices[currflash].data==(void *)0xfff80000) {
		if (offset<0x80000)
			outb(0x00,0x800);
		else {
			outb(0x01, 0x800);
			offset-=0x80000;
		}
	}
#endif	
	return readb(addr+offset);
}



void flash_writeb(unsigned char *addr, unsigned int offset, unsigned char data) 
{
#if defined(__alpha__)
	if (flashdevices[currflash].data==(void *)0xfff80000) {
		if (offset<0x80000)
			outb(0x00,0x800);
		else {
			outb(0x01, 0x800);
			offset-=0x80000;
		}
	}
#endif	
/* 
	printk(KERN_DEBUG "BIOS: writing 0x%02x to 0x%lx+0x%x\n",
							data,bios,offset);
 */
	writeb(data,addr+offset);
}
