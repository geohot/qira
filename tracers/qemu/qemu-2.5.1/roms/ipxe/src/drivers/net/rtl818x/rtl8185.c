/* Realtek 8185 card: rtl818x driver + rtl8185_rtl8225 RF module */

FILE_LICENCE(GPL2_OR_LATER);

#include <ipxe/pci.h>
#include "rtl818x.h"

static struct pci_device_id rtl8185_nics[] __unused = {
	PCI_ROM(0x10ec, 0x8185, "rtl8185", "Realtek 8185", 0),
	PCI_ROM(0x1799, 0x700f, "f5d7000", "Belkin F5D7000", 0),
	PCI_ROM(0x1799, 0x701f, "f5d7010", "Belkin F5D7010", 0),
};

struct pci_driver rtl8185_driver __pci_driver = {
	.ids            = rtl8185_nics,
	.id_count       = sizeof(rtl8185_nics) / sizeof(rtl8185_nics[0]),
	.probe		= rtl818x_probe,
	.remove		= rtl818x_remove,
};

REQUIRING_SYMBOL(rtl8185_driver);
REQUIRE_OBJECT(rtl8185_rtl8225);
