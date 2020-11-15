/* tag: openbios pci plugin headers
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#ifndef __PLUGINS_PCI_H
#define __PLUGINS_PCI_H

typedef struct pci_dev pci_dev_t;

struct pci_dev {
	unsigned bus;
	unsigned dev;
	unsigned fn;

	u8 *config;
	pci_dev_t *next;
};

int pci_register_device(unsigned bus, unsigned dev, unsigned fn, u8 *config);

#endif
