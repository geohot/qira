/*
 *                     OpenBIOS - free your system! 
 *              ( firmware/flash device driver for Linux )
 *                          
 *  bios_core.c - core skeleton 
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#ifdef MODULE
#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#endif
#include <linux/module.h>
#endif
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/init.h>

#include <asm/io.h>

#include "bios.h"
#include "pcisets.h"
#include "flashchips.h"
#include "programming.h"

extern struct file_operations bios_fops;
int bios_proc_register(void);
int bios_proc_unregister(void);

int write = 0;

spinlock_t bios_lock = SPIN_LOCK_UNLOCKED;

/*
 * ******************************************
 *
 *      Cleanup
 *
 * ******************************************
 */

static void free_iomaps(void)
{
	unsigned long lastmapped=0;
	unsigned int i;

	/* We remember the last mapped area to be sure that we only iounmap 
	 * every mapped area once. If two flash devices are in the same 
	 * area but do not occur sequentially during probing you have a
	 * seriously strange hardware
	 */
	for (i=0; i<flashcount; i++) {
		if (lastmapped==flashdevices[i].mapped)
			continue;
		iounmap((void *)flashdevices[i].mapped);
		lastmapped=flashdevices[i].mapped;
	}
}

/*
 * ******************************************
 *
 *	Initialization
 *
 * ****************************************** 
 */

void probe_system(void)
{
#ifdef __alpha__
	probe_alphafw();
#endif
	/* This function checks all flash media attached to
	 * PCI devices in the system. This means NON-PCI systems
	 * don't work. This causes machine checks on my LX164 test 
	 * machine, so leave it away until it's fixed. This is
	 * needed for Ruffians, so we check the machine type
	 * in probe_alphafw() and call probe_pcibus from there.
	 * This could use some cleanup
	 */
#ifndef __alpha__
	probe_pcibus();
#endif
}

static __init int bios_init(void)
{
	printk(KERN_INFO "BIOS driver v" BIOS_VERSION " (writing %s) for "
			UTS_RELEASE "\n", write?"enabled":"disabled");

#if !defined(UTC_BIOS) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	if (!pci_present()) {
		printk(KERN_WARNING "BIOS: No PCI system.");
		return -EBUSY;
	}
#endif

	/* Probe for flash devices */
	probe_system();

	if (flashcount==0) {
		printk(KERN_WARNING "BIOS: No flash devices found.\n");
		return -EBUSY;
	}
	
	if (register_chrdev(BIOS_MAJOR, "bios",  &bios_fops) == -EBUSY) {
		printk(KERN_WARNING "BIOS: Could not register bios device.\n");
		free_iomaps();
		return -EBUSY;
	}

#ifdef CONFIG_PROC_FS
	bios_proc_register();
#endif
	return 0;
}

/*
 * ******************************************
 *
 *	module handling
 *
 * ****************************************** 
 */

#ifdef MODULE
MODULE_PARM(write,"i");
MODULE_AUTHOR("Stefan Reinauer <stepan@openbios.org>");
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,10)
MODULE_LICENSE("GPL");
#endif

static __exit void cleanup_bios_module (void)
{
#ifdef CONFIG_PROC_FS
	bios_proc_unregister();
#endif
	free_iomaps();
	
	unregister_chrdev(BIOS_MAJOR, "bios");
	printk(KERN_INFO "BIOS driver removed.\n");
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
int init_module(void)
{
	return bios_init();
}

void cleanup_module(void)
{
	cleanup_bios_module();
}
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,74)
module_init(bios_init);
module_exit(cleanup_bios_module);
#endif

void inc_mod(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_INC_USE_COUNT; 
#endif
}

void dec_mod(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_DEC_USE_COUNT; 
#endif
}

#endif
