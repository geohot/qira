/*
 *                     OpenBIOS - free your system! 
 *              ( firmware/flash device driver for Linux )
 *                          
 *  pcisets.h - structures for device bindings  
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

#include <linux/pci.h>

#ifdef CONFIG_PCI

struct flashdev {
	unsigned int *pcidevs;
	void (*activate)(void);
	void (*deactivate) (void);
	int (*memarea)(unsigned long *address, unsigned long *size,
				struct pci_dev *dev);
};

extern const struct flashdev devices[];

void probe_pcibus(void);
#ifdef __alpha__
void probe_alphafw(void);
#endif
#endif
