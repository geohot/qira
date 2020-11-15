#ifndef PPC_PCI_H
#define PPC_PCI_H

#include "asm/io.h"

#if !(defined(PCI_CONFIG_1) || defined(PCI_CONFIG_2))
#define PCI_CONFIG_1 1 /* default */
#endif

#ifdef PCI_CONFIG_1

/* PCI Configuration Mechanism #1 */

#define PCI_ADDR(bus, dev, fn) \
    ((pci_addr) (0x80000000u \
		| (uint32_t) (bus) << 16 \
		| (uint32_t) (dev) << 11 \
		| (uint32_t) (fn) << 8))

#define PCI_BUS(pcidev) ((uint8_t) ((pcidev) >> 16))
#define PCI_DEV(pcidev) ((uint8_t) ((pcidev) >> 11) & 0x1f)
#define PCI_FN(pcidev) ((uint8_t) ((pcidev) >> 8) & 7)

static inline uint8_t pci_config_read8(pci_addr dev, uint8_t reg)
{
	uint8_t res;
	out_le32((unsigned *)arch->cfg_addr, dev | (reg & ~3));
	res = in_8((unsigned char*)(arch->cfg_data + (reg & 3)));
	return res;
}

static inline uint16_t pci_config_read16(pci_addr dev, uint8_t reg)
{
	uint16_t res;
	out_le32((unsigned *)arch->cfg_addr, dev | (reg & ~3));
	res = in_le16((unsigned short*)(arch->cfg_data + (reg & 2)));
	return res;
}

static inline uint32_t pci_config_read32(pci_addr dev, uint8_t reg)
{
	uint32_t res;
	out_le32((unsigned *)arch->cfg_addr, dev | reg);
	res = in_le32((unsigned *)(arch->cfg_data));
	return res;
}

static inline void pci_config_write8(pci_addr dev, uint8_t reg, uint8_t val)
{
	out_le32((unsigned *)arch->cfg_addr, dev | (reg & ~3));
	out_8((unsigned char*)(arch->cfg_data + (reg & 3)), val);
}

static inline void pci_config_write16(pci_addr dev, uint8_t reg, uint16_t val)
{
	out_le32((unsigned *)arch->cfg_addr, dev | (reg & ~3));
	out_le16((unsigned short *)(arch->cfg_data + (reg & 2)), val);
}

static inline void pci_config_write32(pci_addr dev, uint8_t reg, uint32_t val)
{
	out_le32((unsigned *)arch->cfg_addr, dev | reg);
	out_le32((unsigned *)(arch->cfg_data), val);
}
#else /* !PCI_CONFIG_1 */
#error PCI Configuration Mechanism is not specified or implemented
#endif

#endif /* PPC_PCI_H */
