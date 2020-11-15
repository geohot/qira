/*
 *                     OpenBIOS - free your system! 
 *              ( firmware/flash device driver for Linux )
 *                          
 *  pcisets.c - support functions to map flash devices to kernel space  
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
#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#endif
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/ioport.h>
#include <asm/io.h>
#ifdef __alpha__
#include <asm/hwrpb.h>
#endif

#include "bios.h"
#include "flashchips.h"
#include "pcisets.h"
#include "programming.h"

#ifdef CONFIG_PCI
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
#define pci_find_class pci_get_class
#endif

#define pci_id(dev)	((dev->vendor<<16) | (dev->device))
struct pci_dev *hostbridge=NULL;
static unsigned char pci_dummy[4];

/*
 * ******************************************
 *
 *   own pci/shadow handling; We can't use 
 *   the PCI bios here as it would sweep
 *   itself out!
 *
 * ****************************************** 
 */

static int pci_read(struct pci_dev *dev, unsigned char where)
{
	if (!dev) return 0;
	
	outl((0x80000000 | (dev->bus->number << 16) | (dev->devfn << 8) | 
	      						(where & ~3)), 0xCF8);
	mb();
	return inb(0xCFC + (where&3));
}

static void pci_write(struct pci_dev *dev, unsigned char where, unsigned char value)
{
	if (!dev) return;
	outl((0x80000000 | (dev->bus->number << 16) | (dev->devfn << 8) |
	      						(where & ~3)), 0xCF8);
	mb();
	outb(value, 0xCFC + (where&3));
}

/* 
 * standard system firmware adress emitter 
 */

static int system_memarea(unsigned long *address, unsigned long *size, 
							struct pci_dev *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
	const struct pci_driver *drv;
	drv = pci_dev_driver(dev);
#endif
#ifndef __alpha__
	*address=0xffe00000;
	*size=2048*1024;
#else
	*address=0xfffffffffc000000;
	*size=512*1024;
#endif
	printk(KERN_INFO "BIOS: Probing system firmware with "
			 "%ldk rom area @0x%lx (%04x:%04x)\n",
			 (*size>>10), *address, dev->vendor, dev->device );
#ifdef CONFIG_PCI_NAMES
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
	if (drv) printk(KERN_INFO "BIOS: System device is %s\n", drv->name);
#else
	printk(KERN_INFO "BIOS: System device is %s\n", dev->name);
#endif
#endif
	return 0;
}

static int memarea_256k(unsigned long *address, unsigned long *size,
							struct pci_dev *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
	const struct pci_driver *drv;
	drv = pci_dev_driver(dev);
#endif
	*address=0xfffc0000;
	*size=256*1024;
	printk(KERN_INFO "BIOS: Probing system firmware with "
			 "%ldk rom area @0x%lx (%04x:%04x)\n",
			 (*size>>10), *address, dev->vendor, dev->device );
#ifdef CONFIG_PCI_NAMES
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
	if (drv) printk(KERN_INFO "BIOS: System device is %s\n", drv->name);
#else
	printk(KERN_INFO "BIOS: System device is %s\n", dev->name);
#endif
#endif
	return 0;
}

/*
 * standard address emitter for normal pci devices
 */

static int default_memarea(unsigned long *address, unsigned long *size,
							 struct pci_dev *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	*address=dev->resource[PCI_ROM_RESOURCE].start;
	*size=dev->resource[PCI_ROM_RESOURCE].end - *address + 1;
#else
	*address=0xdeadbeef;
	*size=0x00000000;
#endif
	if (*address && (signed long)*address!=-1 ) {
		printk (KERN_DEBUG "BIOS: Probing PCI device %02x:%02x.%01x "
				"with %ldk rom area @ 0x%lx\n",
				dev->bus->number, PCI_SLOT(dev->devfn),
				PCI_FUNC(dev->devfn),
				(*size>>10), *address);
		return 1;
	}
	*address=0xdeadbeef;
	*size=0x00000000;
	return 0;
}

#ifdef __alpha__
void probe_alphafw(void)
{
	switch(hwrpb->sys_type) {
	case ST_DEC_EB164:
		/* Fall through */
		break;
	case ST_DTI_RUFFIAN:
	/* case ST_DEC_TSUNAMI: // This crashes for whatever reason */
		probe_pcibus();
		return;
	default:
		printk(KERN_INFO "BIOS: unsupported alpha motherboard.\n");
		return;
	}
	
	/* LX164 has system variation 0x2000 */
	if (hwrpb->sys_variation == 0x2000)
		printk(KERN_INFO "BIOS: LX164 detected\n");
	else
		printk(KERN_INFO "BIOS: EB164 board detected. Sys_var=0x%lx\n",
						hwrpb->sys_variation);

	flashdevices[flashcount].data=(void *)0xfff80000;
	flash_probe_area(0xfff80000, 512*1024, 0);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0) 
#define pci_for_each_dev(dev) \
        for(dev = pci_devices->next; dev != pci_devices; dev = dev->next)
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,74)
#define pci_for_each_dev(dev) \
        while ((dev = pci_find_device(PCI_ANY_ID, PCI_ANY_ID, dev)))
#endif

#define DEVICE(x) devices[g].pcidevs[x]
void probe_pcibus(void)
{
	struct pci_dev *dev=NULL;
	unsigned int g=0, d, map_always=0;
	unsigned long addr, size;
	
	/* Look whether we find something supported */
	pci_for_each_dev(dev) {
		/* Search all device groups */
        	for (g=0; DEVICE(0); g++ ) {
			/* Search all devices in group */
			for (d=0; DEVICE(d) && DEVICE(d) != pci_id(dev); d++);
			if(DEVICE(d) == pci_id(dev))
				break;
		}

		flashdevices[flashcount].idx=g;
		flashdevices[flashcount].data=dev;
		
		map_always=devices[g].memarea(&addr, &size, dev);
#ifdef DEBUG_PCI
		printk(KERN_INFO "BIOS: device=%x, cs=%d addr=%lx, size=%ld\n",
				pci_id(dev),g, addr,size);
#endif
		if(!size)
			continue;
		
		flash_probe_area(addr, size, map_always);
	}
}
#undef DEVICE

/* Intel 430, 440, 450 PCI Chipsets */

#define CURRENT ((struct pci_dev *)flashdevices[currflash].data)
static int gporeg_save;
static void intel4x0_activate(void)
{
#ifdef __ABIT_BE6II_v11__
#define GPONUM 26
#define GPOREG_OFFSET 0x34
	register unsigned int gporeg;
	/* Read Bus 0, Dev 7, Func 3, Reg 40-44 (Power Managment Base Address) */
	outl (0x80003B40, 0x0CF8);
	/* calc General Purpose Output Register I/O port address */
	gporeg = (0xFFFFFFFE & inl (0x0CFC)) + GPOREG_OFFSET;

	/* Set GPO26 to 0 */
	gporeg_save=inl(gporeg);
	printk(KERN_DEBUG "BIOS: GPOREG=0x%08x, mask=0x%x, new=0x%x\n",gporeg_save, (~(1<<GPONUM)), gporeg_save&(~(1<<GPONUM)));
	outl (gporeg_save&(~(1<<GPONUM)), gporeg);
#undef GPOREG_OFFSET
#endif

	pci_dummy[0]=pci_read(CURRENT, 0x4e);
	pci_dummy[1]=pci_read(CURRENT, 0x4f);
	
	/* Write and 128k enable */
	pci_dummy[2]=0x44; //0xC4

	if (CURRENT->device < 0x7000) {
		/* enable 512k */
		pci_dummy[2]|=0x80;
	} else {
		/* enable 1M */
		pci_write(CURRENT, 0x4f, pci_dummy[1] | 0x02);
	}
	
	pci_write(CURRENT, 0x4e, pci_dummy[0] | pci_dummy[2]);

	// printk(KERN_DEBUG "BIOS: isa bridge cfg is 0x%02x\n", pci_dummy[0]);
}

static void intel4x0_deactivate(void)
{
#ifdef __ABIT_BE6II_v11__
#define GPOREG_OFFSET 0x34
	register unsigned long gporeg;
               
	/* Read Bus 0, Dev 7, Func 3, Reg 40-44 (Power Managment Base Address) */
	outl (0x80003B40, 0x0CF8);
	/* calc General Purpose Output Register I/O port address */
	gporeg = (0xFFFFFFFE & inl (0x0CFC)) + GPOREG_OFFSET;

	/* Reset GBO26 */
	outl (gporeg_save, gporeg);
#undef GPOREG_OFFSET
#endif
	pci_write(CURRENT, 0x4e, pci_dummy[0]);
	pci_write(CURRENT, 0x4f, pci_dummy[1]);
}

/* preliminary support for Intel 830 mobile chipset. untested!! */

static void intel8x0_activate(void)
{
	pci_dummy[0]=pci_read(CURRENT, 0x4e);
	pci_dummy[1]=pci_read(CURRENT, 0xe3);
	pci_write(CURRENT, 0x4e, pci_dummy[0] | 0x01);
	pci_write(CURRENT, 0xe3, pci_dummy[1] | 0xC0);

	// We don't have to change FWH_DEC_EN1, as it decodes
	// all memory areas to the FWH per default. 
	// We try it anyways.

	// FWH_DEC_EN1: isabridge, 0xe3,  8bit, default 0xff.
	// FWH_SEL1:    isabridge, 0xe8, 32bit, default 0x00112233 (??)

	//printk(KERN_DEBUG "BIOS: BIOS_CNTL is 0x%02x\n", pci_dummy[0]);
	//printk(KERN_DEBUG "BIOS: FWH_DEC_EN1 is 0x%02x\n", pci_dummy[1]);
}

static void intel8x0_deactivate(void)
{
	pci_write(CURRENT, 0x4e, pci_dummy[0]);
	pci_write(CURRENT, 0xe3, pci_dummy[1]);
}

/* AMD 760/756/751 & VIA (M)VP3  */

static void amd7xx_activate(void)
{
	pci_dummy[0]=pci_read(CURRENT, 0x40); /* IO Control 1 */
	pci_dummy[1]=pci_read(CURRENT, 0x43); /* SEGEN */
	
	pci_write(CURRENT, 0x40, pci_dummy[0] | 0x01);
	pci_write(CURRENT, 0x43, pci_dummy[1] | 0x80);
}

static void amd7xx_deactivate(void)
{
	pci_write(CURRENT, 0x43, pci_dummy[1]);
	pci_write(CURRENT, 0x40, pci_dummy[0]);
}

static void viamvp3_activate(void)
{
	hostbridge = pci_find_class(PCI_CLASS_BRIDGE_HOST<<8,NULL);
	if (!hostbridge)
		return;
	pci_dummy[0]=pci_read(hostbridge,0x52);
	pci_write(hostbridge, 0x52, pci_dummy[0] & 0xcf);
	pci_dummy[1]=pci_read(hostbridge, 0x63);
	pci_write(hostbridge, 0x63, pci_dummy[1] & 0x0f);
	pci_dummy[2]=pci_read(CURRENT,0x43);
	pci_write(CURRENT, 0x43, pci_dummy[2] |0xF8);

	pci_write(CURRENT, 0x40, pci_read(CURRENT,0x40) | 0x01);
}

static void viamvp3_deactivate(void)
{
	if (!hostbridge)
		return;
	pci_write(CURRENT, 0x40, pci_read(CURRENT,0x40) & 0xfe);
	pci_write(hostbridge, 0x63, pci_dummy[1]);
	pci_write(hostbridge, 0x52, pci_dummy[0]);
	pci_write(CURRENT, 0x43, pci_dummy[2]);
}

/* SiS works with 530/5595 chipsets */

static void sis_activate(void) 
{
	char b;
	hostbridge = pci_find_class(PCI_CLASS_BRIDGE_HOST<<8,NULL);
	if (!hostbridge)
		return;
	
	pci_dummy[0]=pci_read(hostbridge, 0x76);
	pci_dummy[1]=readb(0x51);
	pci_dummy[2]=pci_read(CURRENT, 0x40);
	pci_dummy[3]=pci_read(CURRENT, 0x45);
	
	/* disable shadow */
	pci_write(hostbridge, 0x76, 0x00);
	/* disable cache */
	writeb(pci_dummy[1] & 0x7f, 0x51);
	
	/* Enable 0xFFF8000~0xFFFF0000 decoding on SiS 540/630 */
	pci_write(CURRENT, 0x40, pci_dummy[2]|0x0b);
	/* Flash write enable on SiS 540/630 */
	pci_write(CURRENT, 0x45, pci_dummy[3]|0x40);

	/* The same thing on SiS 950 SuperIO side */
	outb(0x87, 0x2e);
	outb(0x01, 0x2e);
	outb(0x55, 0x2e);
	outb(0x55, 0x2e);
	if (inb(0x2f) != 0x87) {
		/* printf("Can not access SiS 950\n"); */
		return;
	}
	
	outb(0x24, 0x2e);
	b = inb(0x2f) | 0xfc;
	outb(0x24, 0x2e);
	outb(b, 0x2f);
	outb(0x02, 0x2e);
	outb(0x02, 0x2f);
}

static void sis_deactivate(void) 
{
	if (!hostbridge)
		return;

	/* Restore PCI Registers */
	pci_write(hostbridge, 0x76, pci_dummy[0]);
	pci_write(CURRENT, 0x45, pci_dummy[2]);
	pci_write(CURRENT, 0x45, pci_dummy[3]);
	/* restore cache to original status */
	writeb(pci_dummy[1], 0x51);
}

/* UMC 486 Chipset 8881/886a */

static void umc_activate(void)
{
	hostbridge = pci_find_class(PCI_CLASS_BRIDGE_HOST<<8,NULL);
	if (!hostbridge)
		return;
	
        pci_dummy[0]=pci_read(hostbridge, 0x54);
	pci_dummy[1]=pci_read(hostbridge, 0x55);

        pci_write(hostbridge, 0x54, 0x00);
        pci_write(hostbridge, 0x55, 0x40);

	pci_write(CURRENT,0x47, pci_read(CURRENT,0x47) & ~0x40);
}

static void umc_deactivate(void)
{
	if (!hostbridge)
		return;
	
	pci_write(CURRENT, 0x47, pci_read(CURRENT,0x47) | 0x40);

        pci_write(hostbridge, 0x54, pci_dummy[0]);
        pci_write(hostbridge, 0x55, pci_dummy[1]);
}

/* CS5530 functions */

static void cs5530_activate(void)
{
	/* Save modified registers for later reset */
	pci_dummy[0]=pci_read(CURRENT,0x52);
	pci_dummy[1]=pci_read(CURRENT,0x5b);

	/* enable rom write access */
	pci_write(CURRENT, 0x52, pci_dummy[0]|0x06);

	/* enable rom positive decode */
	// pci_write(CURRENT,0x5b, pci_dummy[1]|0x20);
	// pci_write(CURRENT,0x52, pci_read(CURRENT,0x52)|0x01);
}

static void cs5530_deactivate(void)
{
        pci_write(CURRENT, 0x52, pci_dummy[0]);
        // pci_write(CURRENT, 0x5b, pci_dummy[1]);
}

/* Reliance / ServerWorks */

static void reliance_activate(void)
{
	pci_dummy[0]=pci_read(CURRENT,0x41);
	pci_dummy[1]=pci_read(CURRENT,0x70);
	pci_dummy[2]=inb(0xc6f);
	
	/* Enable 512k */
	pci_write(CURRENT, 0x41, pci_dummy[0] | 0x02);
	/* Enable 4MB */
	pci_write(CURRENT, 0x70, pci_dummy[1] | 0x80);
	/* Enable flash write */
	outb(pci_dummy[2] | 0x40, 0xc6f);
}
 
static void reliance_deactivate(void)
{
	pci_write(CURRENT, 0x41, pci_dummy[0]);
	pci_write(CURRENT, 0x70, pci_dummy[1]);
	outb(pci_dummy[2], 0xc6f);
}

/* ALi Methods - untested */
static void ali_activate(void)
{
	pci_dummy[0]=pci_read(CURRENT, 0x47);
	pci_dummy[1]=pci_read(CURRENT, 0x79);
	pci_dummy[2]=pci_read(CURRENT, 0x7f);

	/* write enable, 256k enable */
#ifdef OLD_ALi
	pci_write(CURRENT, 0x47, pci_dummy[0]|0x47);
#else
	pci_write(CURRENT, 0x47, pci_dummy[0]|0x43);
#endif

	/* M1543C rev B1 supports 512k. Register reserved before */
#ifdef OLD_ALi
	pci_write(CURRENT, 0x79, pci_dummy[1]|0x10);
	pci_write(CURRENT, 0x7f, pci_dummy[2]|0x01);
#else
	pci_write(CURRENT, 0x7b, pci_dummy[1]|0x10);
#endif
}

static void ali_deactivate(void)
{
	pci_write(CURRENT, 0x47, pci_dummy[0]);
	pci_write(CURRENT, 0x79, pci_dummy[1]);
	pci_write(CURRENT, 0x7f, pci_dummy[2]);
}

/* Default routines. Use these if nothing else works */
#if 0
static unsigned int def_addr;
#endif
static void default_activate(void)
{
#if 0 && LINUX_VERSION_CODE > KERNEL_VERSION(2,4,0)
	struct resource *r;
	
	r=&CURRENT->resource[PCI_ROM_RESOURCE];

	r->flags |= PCI_ROM_ADDRESS_ENABLE;
	r->flags &= ~(IORESOURCE_READONLY|IORESOURCE_CACHEABLE);
	pci_read_config_dword(CURRENT, CURRENT->rom_base_reg, &def_addr);
	if (def_addr)
		pci_write_config_dword (CURRENT, CURRENT->rom_base_reg,
				def_addr|PCI_ROM_ADDRESS_ENABLE);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	long ret;

	if (pci_enable_device(CURRENT))
		return;

	pci_write_config_dword (CURRENT, CURRENT->rom_base_reg,
			pci_resource_start(CURRENT, PCI_ROM_RESOURCE)|
			PCI_ROM_ADDRESS_ENABLE);

	ret=(long)request_mem_region( pci_resource_start(CURRENT, 
				PCI_ROM_RESOURCE), pci_resource_len(CURRENT,
					PCI_ROM_RESOURCE), "Firmware memory");
	if (!ret)
		printk (KERN_ERR "BIOS:   cannot reserve MMROM region " 
				"0x%lx+0x%lx\n",
				pci_resource_start(CURRENT, PCI_ROM_RESOURCE),
				pci_resource_len(CURRENT, PCI_ROM_RESOURCE));
	else
		printk (KERN_INFO "BIOS:   mapped rom region to 0x%lx\n", ret);
#endif
}

static void default_deactivate(void)
{
#if 0 && LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	struct resource *r;
	r=&CURRENT->resource[PCI_ROM_RESOURCE];
	r->flags &= ~PCI_ROM_ADDRESS_ENABLE;
	r->flags |= (IORESOURCE_READONLY|IORESOURCE_CACHEABLE);
	pci_write_config_dword (CURRENT, CURRENT->rom_base_reg, def_addr);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	release_mem_region(pci_resource_start(CURRENT, PCI_ROM_RESOURCE),
			pci_resource_len(CURRENT, PCI_ROM_RESOURCE));
#endif
}

const struct flashdev devices[] = {
	/* Intel 4x0 chipsets */
	{ (int[]) { 0x8086122e, 0x80861234, 0x80867000, 0x80867110, 
		    0x80867198, 0 },
	  intel4x0_activate, intel4x0_deactivate, system_memarea },

	/* Intel 8x0 chipsets */	
	{ (int[]) { 0x80862410, 0x80862420, 0x80862440, 0x8086244c,
	            0x80862480, 0x8086248c, 0x80867600, 0 },
	  intel8x0_activate, intel8x0_deactivate, system_memarea },

	/* Irongate 75x, AMD-76xMP(X), VT8231/3 */
	{ (int[]) { 0x10227400, 0x10227408, 0x10227410, 0x10227440,
		    0x11068231, 0x11063074, 0 },
	  amd7xx_activate, amd7xx_deactivate, system_memarea },

	/* AMD Hammer (thor chipset) */
	{ (int[]) { 0x10227468, 0 },
	  amd7xx_activate, amd7xx_deactivate, system_memarea },

	/* VIA (M)VP3, VT82C686 [Apollo Super South] */
	{ (int[]) { 0x11060586, 0x11060596, 0x11060686, 0 },
	  viamvp3_activate, viamvp3_deactivate, memarea_256k },
	  
	/* UMC */  
	{ (int[]) { 0x1060886a, 0x10600886, 0x1060e886, 0x10608886, 0 },
	   umc_activate, umc_deactivate, system_memarea },

	/* SiS */
	{ (int[]) { 0x10390008, 0x10390018, 0 },
	   sis_activate, sis_deactivate, system_memarea },

	/* OPTi */
	{ (int[]) { 0x1045c558, 0 },
	  default_activate, default_deactivate, system_memarea },

	/* NSC CS5530(A) */
	{ (int[]) { 0x10780100, 0 },
	  cs5530_activate, cs5530_deactivate, memarea_256k },

	/* Reliance/ServerWorks NB6xxx */
	{ (int[]) { 0x11660200, 0 },
	  reliance_activate, reliance_deactivate, system_memarea },

	/* ALi */
	{ (int[]) { 0x10b91523, 0x10b91533, 0x10b91543, 0 },
	  ali_activate, ali_deactivate, system_memarea },

	{ (int[]) { 0x00000000 },
	  default_activate, default_deactivate, default_memarea }
};

#endif /* CONFIG_PCI */

