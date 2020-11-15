/**************************************************************************
Etherboot -  BOOTP/TFTP Bootstrap Program
Prism2 NIC driver for Etherboot
Wrapper for prism2_plx

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

#define WLAN_HOSTIF WLAN_PLX
#include "prism2.c"

/*
 * Find PLX card.  Prints out information strings from PCMCIA CIS as visual
 * confirmation of presence of card.
 *
 * Arguments:
 *	hw		device structure to be filled in
 *      p               PCI device structure
 *
 * Returns:
 *      1               Success
 */
static int prism2_find_plx ( hfa384x_t *hw, struct pci_device *p )
{
  int found = 0;
  uint32_t plx_lcr  = 0; /* PLX9052 Local Configuration Register Base (I/O) */
  uint32_t attr_mem = 0; /* Prism2 Attribute Memory Base */
  uint32_t iobase   = 0; /* Prism2 I/O Base */
  unsigned char *cis_tpl  = NULL;
  unsigned char *cis_string;
  
  /* Obtain all memory and IO base addresses */
  pci_read_config_dword( p, PLX_LOCAL_CONFIG_REGISTER_BASE, &plx_lcr);
  plx_lcr &= ~PCI_BASE_ADDRESS_IO_MASK;
  pci_read_config_dword( p, PRISM2_PLX_ATTR_MEM_BASE, &attr_mem);
  pci_read_config_dword( p, PRISM2_PLX_IO_BASE, &iobase);
  iobase &= ~PCI_BASE_ADDRESS_IO_MASK;

  /* Fill out hw structure */
  hw->iobase = iobase;
  printf ( "PLX9052 has local config registers at %#x\n", plx_lcr );
  printf ( "Prism2 has attribute memory at %#x and I/O base at %#x\n", attr_mem, iobase );

  /* Search for CIS strings */
  printf ( "Searching for PCMCIA card...\n" );
  cis_tpl = bus_to_virt(attr_mem);
  while ( *cis_tpl != CISTPL_END ) {
    if ( *cis_tpl == CISTPL_VERS_1 ) {
      /* CISTPL_VERS_1 contains some nice text strings */
      printf ( "...found " );
      found = 1;
      cis_string = cis_tpl + CISTPL_VERS_1_STR_OFF;
      while ( ! ( ( *cis_string == 0 ) && ( *(cis_string+CIS_STEP) == 0 ) ) ) {
	printf ( "%c", *cis_string == 0 ? ' ' : *cis_string );
	cis_string += CIS_STEP;
      }
      printf ( "\n" );
    }
    /* printf ( "CIS tuple type %#hhx, length %#hhx\n", *cis_tpl, *(cis_tpl+CISTPL_LEN_OFF) ); */
    cis_tpl += CISTPL_HEADER_LEN + CIS_STEP * ( *(cis_tpl+CISTPL_LEN_OFF) );
  }
  if ( found == 0 ) {
    printf ( "...nothing found\n" );
  }
  ((unsigned char *)bus_to_virt(attr_mem))[COR_OFFSET] = COR_VALUE; /* Write COR to enable PC card */
  return found;
}

static int prism2_plx_probe ( struct nic *nic, struct pci_device *pci ) {
  hfa384x_t *hw = &hw_global;
  
  /* Find and intialise PLX Prism2 card */
  if ( ! prism2_find_plx ( hw, pci ) ) return 0;
  nic->ioaddr = hw->iobase;
  nic->irqno  = 0;
  return prism2_probe ( nic, hw );
}

static void prism2_plx_disable ( struct nic *nic ) {
  prism2_disable ( nic );
}

static struct pci_device_id prism2_plx_nics[] = {
PCI_ROM(0x1385, 0x4100, "ma301",         "Netgear MA301", 0),
PCI_ROM(0x10b7, 0x7770, "3c-airconnect", "3Com AirConnect", 0),
PCI_ROM(0x111a, 0x1023, "ss1023",        "Siemens SpeedStream SS1023", 0),
PCI_ROM(0x15e8, 0x0130, "correga",       "Correga", 0),
PCI_ROM(0x1638, 0x1100, "smc2602w",      "SMC EZConnect SMC2602W", 0),	/* or Eumitcom PCI WL11000, Addtron AWA-100 */
PCI_ROM(0x16ab, 0x1100, "gl24110p",      "Global Sun Tech GL24110P", 0),
PCI_ROM(0x16ab, 0x1101, "16ab-1101",     "Unknown", 0),
PCI_ROM(0x16ab, 0x1102, "wdt11",         "Linksys WDT11", 0),
PCI_ROM(0x16ec, 0x3685, "usr2415",       "USR 2415", 0),
PCI_ROM(0xec80, 0xec00, "f5d6000",       "Belkin F5D6000", 0),
PCI_ROM(0x126c, 0x8030, "emobility",     "Nortel emobility", 0),
};

PCI_DRIVER ( prism2_plx_driver, prism2_plx_nics, PCI_NO_CLASS );


DRIVER ( "Prism2/PLX", nic_driver, pci_driver, prism2_plx_driver,
	 prism2_plx_probe, prism2_plx_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
