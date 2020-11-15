/*
 *                     OpenBIOS - free your system! 
 *              ( firmware/flash device driver for Linux )
 *                          
 *  procfs.c - proc filesystem handling for flash device listing.  
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
#include <linux/proc_fs.h>

#ifdef CONFIG_PROC_FS
#include "bios.h"
#include "pcisets.h"
#include "flashchips.h"
#include "programming.h"

struct proc_dir_entry *proc_bios;

#define PRINT_PROC(fmt,args...) 				\
	do {							\
		if (!run) 					\
			break;					\
		len += sprintf( buffer+len, fmt, ##args );	\
		if (begin + len > offset + size) 		\
			run=0;					\
		else if (begin + len < offset) {		\
			begin += len;				\
			len = 0;				\
		}						\
	} while (0)

/*
 * ******************************************
 *
 *	/proc/bios handling
 *
 * ****************************************** 
 */

#define CFLASH flashdevices[i]
#define FLASH  flashchips[CFLASH.flashnum]
#define MANUF  manufacturers[CFLASH.manufnum]

int bios_read_proc(char *buffer, char **start, off_t offset, int size, int *eof, void *data)
{
	int len=0, run=1, i;
	off_t begin = 0;

	for (i=0;i<flashcount;i++) {
#ifdef DEBUG_PROC
		printk(KERN_DEBUG "BIOS: processing proc info for "
				"flashchip %d\n",i+1);
#endif
		if (i) /* empty line is seperator between flash chips */
			PRINT_PROC("\n");
		
		PRINT_PROC("Memory Address  : 0x%08lx\n", 
				(unsigned long)CFLASH.physical);
		PRINT_PROC("Memory Size     : %d kByte\n", CFLASH.size>>10);
		PRINT_PROC("Flash Type      : ");
		
		if (CFLASH.id == 0) {
			PRINT_PROC("ROM\n");
			continue;
		}
		
		/* Flash chip completely unknown -> output ID and proceed */
		if (FLASH.id == 0) {
			PRINT_PROC("unknown %s device (id 0x%04x)\n",
						MANUF.name, CFLASH.id);
			PRINT_PROC("Supported       : no\n");
			continue;
		}
		
		PRINT_PROC("%s %s (%dV)\n", MANUF.name, 
				FLASH.name, FLASH.voltage);

		PRINT_PROC("Supported       : %s\n",
				FLASH.supported ? "yes": "no");
#ifdef DEBUG
		PRINT_PROC("Pagetable       : %d Byte\n", FLASH.pagesize );

		PRINT_PROC("Erase first     : %s\n",
				FLASH.flags & f_needs_erase ? "yes": "no");
			
		PRINT_PROC("Intel compliant : %s\n",
				FLASH.flags & f_intel_compl ? "yes": "no");

		PRINT_PROC("FWH compliant   : %s\n",
				FLASH.flags & f_fwh_compl ? "yes": "no");
				
		if (CFLASH.sectors > 1)
			PRINT_PROC("Sectors         : %d\n", CFLASH.sectors);
#endif
	}
#ifdef DEBUG_PROC
	printk(KERN_DEBUG "BIOS: read_proc done.\n");
#endif
	/* set to 1 if we're done */
	*eof=run;

	if (offset >= begin + len)
		return 0;

	*start = buffer + (begin - offset);

	return (size < begin + len - offset ? size : begin + len - offset);	
}
#undef FLASH
#undef MANUF
#undef CFLASH

#ifdef PROC_WRITEABLE
int bios_write_proc(struct file *file, const char *buffer, unsigned long count, void *data)
{
  printk (KERN_INFO "%s\n",buffer);
  return count;
}
#endif

int bios_proc_register(void)
{
	if ((proc_bios = create_proc_entry("bios", 0, 0))) {
		proc_bios->read_proc = bios_read_proc;
#ifdef PROC_WRITABLE
		proc_bios->write_proc = bios_write_proc;
#endif
		return 0;
	}
	return 1;
}

int bios_proc_unregister(void)
{
        if (proc_bios)
                remove_proc_entry("bios", 0);
	return 0;
}
#endif
