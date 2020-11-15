/*
 *                     OpenBIOS - free your system! 
 *              ( firmware/flash device driver for Linux )
 *                          
 *  filesystem.c - vfs character device interface
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

#include <linux/config.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && defined(MODVERSIONS)
#include <linux/modversions.h>
#endif
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/fcntl.h>
#include <linux/delay.h>

#include <asm/uaccess.h>

#include "bios.h"
#include "flashchips.h"
#include "pcisets.h"
#include "programming.h"

#ifdef MODULE
void inc_mod(void);
void dec_mod(void);
#endif

/*
 * ******************************************
 *
 *	/dev/bios filesystem operations
 *
 * ****************************************** 
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#define FDEV		(MINOR(file->f_dentry->d_inode->i_rdev))
#else
#define FDEV		(iminor(file->f_dentry->d_inode))
#endif
#define CFLASH		flashdevices[FDEV]
// #define BIOS_SIZE	((flashchips[CFLASH.flashnum].size)*1024)
#define BIOS_SIZE	(CFLASH.size)

static loff_t bios_llseek(struct file *file, loff_t offset, int origin )
{
	currflash=FDEV;
	switch(origin) {
	  case 0:
		break;
	  case 1:
		offset += file->f_pos;
		break;
	  case 2:
		offset += BIOS_SIZE;
		break;
	}
	return((offset >= 0)?(file->f_pos = offset):-EINVAL);
}

static ssize_t bios_read(struct file *file, char *buffer, size_t count, loff_t *ppos)
{
	signed int size=((BIOS_SIZE-*ppos>count) ? count : BIOS_SIZE-*ppos);
	unsigned char *addr = (unsigned char*)CFLASH.mapped + CFLASH.offset;
	int i;

	currflash = FDEV;

	devices[flashdevices[currflash].idx].activate();

	for (i=0;i<size;i++) 
		buffer[i]=flash_readb(addr,*ppos+i);

	devices[flashdevices[currflash].idx].deactivate();

	*ppos+=size;
	return size;
}

static ssize_t bios_write(struct file *file, const char *buffer, size_t count, loff_t *ppos)
{
        unsigned long flags;
	unsigned int offset=0, startsec=0, endsec=0;
	unsigned int secnum=0, size=0, writeoffs=0;
	unsigned int i, fn;
	unsigned char *clipboard;
	unsigned char *addr = (unsigned char*)CFLASH.mapped + CFLASH.offset;

	currflash=FDEV;
	fn=CFLASH.flashnum;

	/* Some security checks. */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	if (!suser())
		return -EACCES;
#endif

	if (!write) {
		printk (KERN_WARNING "Writing is disabled for security reasons.  RTFM.\n");
		return -EACCES;
	}

	if (!flashchips[fn].supported) {
		printk (KERN_ERR "BIOS: Flash device not supported.\n");
		return -EMEDIUMTYPE;
	}

	if ( count > BIOS_SIZE-*ppos )
		return -EFBIG;

	/* FIXME: Autoselect(AMD) BC-90 
	 * -> 00/MID; 
	 *    01/PID; 
	 *    02/Protected (1=yes/0=no)
	 */

	/* Determine size of data to be written */

	if (!(flashchips[fn].flags & f_needs_erase) ) {
		offset=(unsigned int)*ppos&~(flashchips[fn].pagesize-1);
		size=(((unsigned int)*ppos+count+(flashchips[fn].pagesize-1))&
				~(flashchips[CFLASH.flashnum].pagesize-1))-offset;
	} else {
		while (flashchips[fn].sectors[secnum] <= flashchips[fn].size ) {
			if ((unsigned int)*ppos >= flashchips[fn].sectors[secnum]*1024) {
				offset=flashchips[fn].sectors[secnum]*1024;
				startsec=secnum;
			}
			if ((unsigned int)*ppos+count-1 <= flashchips[fn].sectors[secnum]*1024) {
				size=(flashchips[fn].sectors[secnum]*1024)-offset;
				endsec=secnum-1;
				break;
			}
			secnum++;
		}
	}

#ifdef DEBUG
	printk (KERN_DEBUG "BIOS: Write [0x%06x..0x%06x] [0x%06x..0x%06x]\n",
			(unsigned int)(*ppos),(unsigned int)(*ppos+count-1),offset,offset+size-1);
#endif

	/* prepare data for writing */

	clipboard=vmalloc(size);

	spin_lock_irqsave(&bios_lock, flags);

	devices[flashdevices[currflash].idx].activate();

	for (i=0; i < size; i++) 
		clipboard[i] = flash_readb(addr,offset+i);

	copy_from_user(clipboard+(*ppos-offset), buffer, count);

	/* start write access */

	if (flashchips[fn].flags & f_intel_compl) {
		iflash_erase_sectors(addr,fn,startsec,endsec);

		for (i=0;i<size;i++)
			iflash_program_byte(addr, offset+i, clipboard[i]);

		flash_command(addr, 0xff);

	} else {

	  if (flashchips[fn].flags & f_needs_erase) {
	    if (size == flashchips[fn].size*1024) { /* whole chip erase */
	      printk (KERN_DEBUG "BIOS: Erasing via whole chip method\n");
	      flash_erase(addr, fn);
	    } else {
	      printk (KERN_DEBUG "BIOS: Erasing via sector method\n");
	      flash_erase_sectors(addr, fn,startsec,endsec);
	    }
	  } 

	  while (size>0) {
	    if ((flashchips[fn].flags & f_manuf_compl) != f_atmel_compl) {
	      flash_program(addr);
	    } else {
	      flash_program_atmel(addr);
	    }
	    for (i=0;i<flashchips[fn].pagesize;i++) {
	      flash_writeb(addr,offset+writeoffs+i,clipboard[writeoffs+i]);
	    }
	    if ((flashchips[fn].flags & f_manuf_compl) == f_atmel_compl) {
	      udelay(750);
	    } else {
		    if (flashchips[fn].pagesize==1)
			    udelay(30);
	 	    else
	      		    udelay(300);
	    }

	    if (flash_ready_poll(addr,offset+writeoffs+flashchips[fn].pagesize-1,
				 clipboard[writeoffs+flashchips[fn].pagesize-1])) {
	      printk (KERN_ERR "BIOS: Error occured, please repeat write operation.\n");
	    }
	    flash_command(addr, 0xf0);
	    
	    writeoffs += flashchips[fn].pagesize;
	    size	  -= flashchips[fn].pagesize;
	  }
	}

	devices[flashdevices[currflash].idx].deactivate();

	spin_unlock_irqrestore(&bios_lock, flags);

	vfree(clipboard);

	*ppos+=count;
	return count;
}

static int bios_open(struct inode *inode, struct file *file)
{
	currflash=FDEV;
	
	if (flashcount<=FDEV) {
		printk (KERN_ERR "BIOS: There is no device (%d).\n",FDEV);
		return -ENODEV;
	}

#ifdef DEBUG
	printk(KERN_DEBUG "BIOS: Opening device %d\n",FDEV);
#endif
	/* Only one shall open for writing */

	if ((CFLASH.open_cnt && (file->f_flags & O_EXCL)) ||
		(CFLASH.open_mode & O_EXCL) ||
		((file->f_mode & 2) && (CFLASH.open_mode & O_RDWR)))
		return -EBUSY;

	if (file->f_flags & O_EXCL)
		CFLASH.open_mode |= O_EXCL;

	if (file->f_mode & 2)
		CFLASH.open_mode |= O_RDWR;

	CFLASH.open_cnt++;

	
#ifdef MODULE
	inc_mod();
#endif
	return 0;
}

static int bios_release(struct inode *inode, struct file *file)
{
	currflash=FDEV;
	if (file->f_flags & O_EXCL)
		CFLASH.open_mode &= ~O_EXCL;

	if (file->f_mode & 2)
		CFLASH.open_mode &= ~O_RDWR;

	CFLASH.open_cnt--;
	
#ifdef MODULE
	dec_mod();
#endif
	return 0;
}

struct file_operations bios_fops = {
        .owner		= THIS_MODULE,
	.llseek		= bios_llseek,
	.read		= bios_read,
	.write		= bios_write,
	.open		= bios_open,
	.release	= bios_release,
};

