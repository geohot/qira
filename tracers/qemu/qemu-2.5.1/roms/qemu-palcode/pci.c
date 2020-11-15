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

/* We don't bother supporting PCI bridges, because the device model we're
   currently using for QEMU doesn't build any.

   We don't bother to build real datastructures in memory, because it's
   fairly quick under emulation simply to access configuration space again.
   This helps when running kernels under the emulator that might have
   re-organized the BARs out from under us.  */

#include "protos.h"
#include "pci.h"
#include "pci_regs.h"


#define PCI_DEVFN(slot, func)	((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_BUS(devfn)		((devfn) >> 8)
#define PCI_SLOT(devfn)		(((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn)		((devfn) & 0x07)
#define PCI_SLOT_MAX		32
#define PCI_FUNC_MAX		8
#define PCI_REGION_ROM		6
#define PCI_REGIONS_MAX		7


void
pci_config_maskw(int bdf, int addr, uint16_t off, uint16_t on)
{
  uint16_t val = pci_config_readw(bdf, addr);
  val = (val & ~off) | on;
  pci_config_writew(bdf, addr, val);
}

int
pci_next(int bdf, int *pmax)
{
  int max;

  if (PCI_FUNC(bdf) == 1)
    {
      /* If the last device was not a multi-function device, skip to next.  */
      if ((pci_config_readb(bdf-1, PCI_HEADER_TYPE) & 0x80) == 0)
        bdf += 7;
    }

  max = *pmax;
  while (1)
    {
      uint16_t vendor;

      /* ??? Support multiple PCI busses here at some point.  */
      if (bdf >= max)
	return -1;

      /* Check if there is a device present at the location.  */
      vendor = pci_config_readw(bdf, PCI_VENDOR_ID);
      if (vendor != 0x0000 && vendor != 0xffff)
	return bdf;

      bdf += (PCI_FUNC(bdf) == 0 ? 8 : 1);
    }
}

static void
pci_setup_device(int bdf, uint32_t *p_io_base, uint32_t *p_mem_base)
{
  int vendor_id, device_id, class_id, region;

  vendor_id = pci_config_readw(bdf, PCI_VENDOR_ID);
  device_id = pci_config_readw(bdf, PCI_DEVICE_ID);
  class_id = pci_config_readw(bdf, PCI_CLASS_DEVICE);

  printf("PCI: %02x:%02x:%x class %04x id %04x:%04x\r\n",
	 PCI_BUS(bdf), PCI_SLOT(bdf), PCI_FUNC(bdf),
         class_id, vendor_id, device_id);

  for (region = 0; region < PCI_REGION_ROM; region++)
    {
      int ofs = PCI_BASE_ADDRESS_0 + region * 4;
      uint32_t old, mask, val, size, align;
      uint32_t *p_base;

      old = pci_config_readl(bdf, ofs);
      if (old & PCI_BASE_ADDRESS_SPACE_IO)
	{
	  mask = PCI_BASE_ADDRESS_IO_MASK;
	  p_base = p_io_base;
	}
      else
	{
	  mask = PCI_BASE_ADDRESS_MEM_MASK;
	  p_base = p_mem_base;
	}

      pci_config_writel(bdf, ofs, -1);
      val = pci_config_readl(bdf, ofs);
      pci_config_writel(bdf, ofs, old);

      align = size = ~(val & mask) + 1;
      if (val != 0)
	{
	  uint32_t addr = *p_base;
	  addr = (addr + align - 1) & ~(align - 1);
	  *p_base = addr + size;
	  pci_config_writel(bdf, ofs, addr);

	  printf("PCI:   region %d: %08x\r\n", region, addr);

	  if ((val & PCI_BASE_ADDRESS_MEM_TYPE_MASK)
	      == PCI_BASE_ADDRESS_MEM_TYPE_64)
	    {
	      pci_config_writel(bdf, ofs + 4, 0);
	      region++;
	    }
	}
    }

  pci_config_maskw(bdf, PCI_COMMAND, 0, PCI_COMMAND_IO | PCI_COMMAND_MEMORY);

  /* Map the interrupt.  */
}

void
pci_setup(void)
{
  uint32_t io_base = 0xc000;
  uint32_t mem_base = 256 * 1024 * 1024;
  int bdf, max;

  foreachpci (bdf, max)
    pci_setup_device(bdf, &io_base, &mem_base);
}
