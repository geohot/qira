/** @file Stub file for vxge driver
 *
 * This file drags in the rest of the driver for Neterion Inc's X3100 Series
 * 10GbE PCIe I/O Virtualized Server Adapter, allowing the driver to be built
 * as "vxge" even though the code is in vxge_* named files.
 */

FILE_LICENCE(GPL2_OR_LATER_OR_UBDL);

#include <ipxe/pci.h>

PROVIDE_REQUIRING_SYMBOL();
REQUIRE_OBJECT(vxge_main);

/** vxge PCI IDs for util/parserom.pl which are put into bin/NIC */
static struct pci_device_id vxge_nics[] __unused = {
	/* If you change this, also adjust vxge_main_nics[] in vxge_main.c */
	PCI_ROM(0x17d5, 0x5833, "vxge-x3100", "Neterion X3100 Series", 0),
};
