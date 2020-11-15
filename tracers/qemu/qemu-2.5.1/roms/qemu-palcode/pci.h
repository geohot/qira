/* Simplistic PCI support.

   Copyright (C) 2011 Richard Henderson

   This file is part of QEMU PALcode.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the text
   of the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not see
   <http://www.gnu.org/licenses/>.  */

/* This header is intended to be compatible with the pci.h from SeaBIOS.
   Their header, however, is too PC specific to be of use.  */

#ifndef PCI_H
#define PCI_H 1

extern void *pci_conf_base;

static inline void pci_config_writel(int bdf, uint8_t addr, uint32_t val)
{
  *(volatile uint32_t *)(pci_conf_base + bdf * 256 + addr) = val;
}

static inline void pci_config_writew(int bdf, uint8_t addr, uint16_t val)
{
  *(volatile uint16_t *)(pci_conf_base + bdf * 256 + addr) = val;
}

static inline void pci_config_writeb(int bdf, uint8_t addr, uint8_t val)
{
  *(volatile uint8_t *)(pci_conf_base + bdf * 256 + addr) = val;
}

static inline uint32_t pci_config_readl(int bdf, uint8_t addr)
{
  return *(volatile uint32_t *)(pci_conf_base + bdf * 256 + addr);
}

static inline uint16_t pci_config_readw(int bdf, uint8_t addr)
{
  return *(volatile uint16_t *)(pci_conf_base + bdf * 256 + addr);
}

static inline uint8_t pci_config_readb(int bdf, uint8_t addr)
{
  return *(volatile uint8_t *)(pci_conf_base + bdf * 256 + addr);
}

extern void pci_config_maskw(int bdf, int addr, uint16_t off, uint16_t on);

extern int pci_next(int bdf, int *pmax);

#define foreachpci(BDF, MAX)				\
	for (MAX = 0x0100, BDF = pci_next(0, &MAX);	\
	     BDF >= 0;					\
	     BDF = pci_next(BDF+1, &MAX))

#endif /* PCI_H */
