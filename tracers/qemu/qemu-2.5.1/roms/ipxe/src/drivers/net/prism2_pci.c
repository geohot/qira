/**************************************************************************
Etherboot -  BOOTP/TFTP Bootstrap Program
Prism2 NIC driver for Etherboot
Wrapper for prism2_pci

Written by Michael Brown of Fen Systems Ltd
$Id$
***************************************************************************/

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/pci.h>
#include <nic.h>

#define WLAN_HOSTIF WLAN_PCI
#include "prism2.c"

static int prism2_pci_probe ( struct nic *nic, struct pci_device *pci ) {
  hfa384x_t *hw = &hw_global;

  printf ( "Prism2.5 has registers at %#lx\n", pci->membase );
  hw->membase = ioremap ( pci->membase, 0x100 );

  nic->ioaddr = pci->membase;
  nic->irqno = 0;

  return prism2_probe ( nic, hw );
}

static void prism2_pci_disable ( struct nic *nic ) {
  prism2_disable ( nic );
}

static struct pci_device_id prism2_pci_nics[] = {
PCI_ROM(0x1260, 0x3873, "prism2_pci",	"Harris Semiconductor Prism2.5 clone", 0),
};

PCI_DRIVER ( prism2_pci_driver, prism2_pci_nics, PCI_NO_CLASS );

DRIVER ( "Prism2/PCI", nic_driver, pci_driver, prism2_pci_driver,
	 prism2_pci_probe, prism2_pci_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
