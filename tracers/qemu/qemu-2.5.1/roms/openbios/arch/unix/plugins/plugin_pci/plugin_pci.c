/* tag: openbios pci plugin
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include <stdio.h>
#include <stdlib.h>
#include "unix/plugins.h"
#include "unix/plugin_pci.h"

#define DEBUG

u32 pci_conf_addr = 0;
pci_dev_t *pci_devices = NULL;

static pci_dev_t *find_device(u32 conf_addr)
{
	pci_dev_t *devs = pci_devices;
	unsigned bus = (conf_addr >> 16) & 0xff;
	unsigned dev = (conf_addr >> 11) & 0x1f;
	unsigned fn = (conf_addr >> 8) & 0x7;

	// printf("Looking for device %x\n",conf_addr);

	while (devs) {
		if (devs->bus == bus && devs->dev == dev && devs->fn == fn)
			return devs;
		devs = devs->next;
	}
	return NULL;
}

/*
 * IO functions. These manage all the magic of providing a PCI
 * compatible interface to OpenBIOS' unix version of the kernel.
 */

static u8 pci_inb(u32 reg)
{
	u32 basereg = (reg & 0xfffc);
	u32 basepos = (reg & 0x03);
	pci_dev_t *dev;

	if (basereg == 0xcf8) {
		return (pci_conf_addr >> (basepos << 3));
	}

	/* still here? so we're 0xCFC */
	dev = find_device(pci_conf_addr);
	if (!dev || !dev->config)
		return 0xff;

	return dev->config[(pci_conf_addr + basepos) & 0xff];
}

static u16 pci_inw(u32 reg)
{
	u32 basereg = (reg & 0xfffc);
	u32 basepos = (reg & 0x02);
	pci_dev_t *dev;

	if (basereg == 0xcf8) {
		return (pci_conf_addr >> (basepos << 3));
	}

	/* still here? so we're 0xCFC */
	dev = find_device(pci_conf_addr);
	if (!dev || !dev->config)
		return 0xffff;

	return *(u16 *) (dev->config + ((pci_conf_addr + basepos) & 0xff));
}

static u32 pci_inl(u32 reg)
{
	u32 basereg = (reg & 0xfffc);
	pci_dev_t *dev;

	if (basereg == 0xcf8) {
		return pci_conf_addr;
	}

	/* still here? so we're 0xCFC */
	dev = find_device(pci_conf_addr);
	if (!dev || !dev->config)
		return 0xffffffff;

	return *(u32 *) (dev->config + (pci_conf_addr & 0xff));
}

static void pci_outb(u32 reg, u8 val)
{
	u32 basereg = (reg & 0xfffc);
	u32 basepos = (reg & 0x03);
	pci_dev_t *dev;

	if (basereg == 0xcf8) {
		pci_conf_addr &= (~(0xff << (basepos << 3)));
		pci_conf_addr |= (val << (basepos << 3));
		return;
	}

	/* still here? so we're 0xCFC */
	dev = find_device(pci_conf_addr);
	if (!dev || !dev->config)
		return;

	dev->config[pci_conf_addr & 0xff] = val;
}

static void pci_outw(u32 reg, u16 val)
{
	u32 basereg = (reg & 0xfffc);
	u32 basepos = (reg & 0x02);
	pci_dev_t *dev;

	if (basereg == 0xcf8) {
		pci_conf_addr &= (~(0xffff << (basepos << 3)));
		pci_conf_addr |= (val << (basepos << 3));
		return;
	}

	/* still here? so we're 0xCFC */
	dev = find_device(pci_conf_addr);
	if (!dev || !dev->config)
		return;

	*(u16 *) (dev->config + (pci_conf_addr & 0xff)) = val;
}

static void pci_outl(u32 reg, u32 val)
{
	u32 basereg = (reg & 0xfffc);
	pci_dev_t *dev;

	if (basereg == 0xcf8) {
		pci_conf_addr = val;
		return;
	}

	/* still here? so we're 0xCFC */
	dev = find_device(pci_conf_addr);
	if (!dev || !dev->config)
		return;

	*(u32 *) (dev->config + (pci_conf_addr & 0xff)) = val;
}

static io_ops_t pci_io_ops = {
      inb:pci_inb,
      inw:pci_inw,
      inl:pci_inl,
      outb:pci_outb,
      outw:pci_outw,
      outl:pci_outl
};

/*
 * Functions visible to modules depending on this module.
 */

int pci_register_device(unsigned bus, unsigned dev, unsigned fn,
			u8 * config)
{
	pci_dev_t *newdev;
	u32 caddr = (1 << 31) | (bus << 16) | (dev << 11) | (fn << 8);

	if (find_device(caddr)) {
		printf("Error: pci device %02x:%02x.%01x already exists\n",
		       bus, dev, fn);
		return -1;
	}

	newdev = malloc(sizeof(pci_dev_t));

	if (!newdev) {
		printf("Out of memory\n");
		return -1;
	}

	newdev->bus = bus;
	newdev->dev = dev;
	newdev->fn = fn;
	newdev->config = config;
	newdev->next = pci_devices;

	pci_devices = newdev;

	return 0;
}

/*
 * Initialization is really simple. We just grab the
 * PCI conf1 io range for our emulation functions.
 */
extern int plugin_pci_init( void );

int plugin_pci_init(void)
{
#ifdef DEBUG
	printf("Plugin \"pci\" initializing... ");
#endif
	register_iorange("pci", &pci_io_ops, 0xcf8, 0xcff);
#ifdef DEBUG
	printf("done.\n");
#endif
	return 0;
}

/* plugin meta information available for the plugin loader */
PLUGIN_AUTHOR       ("Stefan Reinauer <stepan@openbios.org>")
PLUGIN_DESCRIPTION  ("Generic PCI Device Emulation")
PLUGIN_LICENSE      ("GPL v2")

/* This plugin has no dependencies. Otherwise the following
 * macro would be uncommented:
 * PLUGIN_DEPENDENCIES ("this", "that")
 */
