#ifndef SPARC64_PCI_H
#define SPARC64_PCI_H

#include "asm/io.h"

#if !(defined(PCI_CONFIG_1) || defined(PCI_CONFIG_2))
#define PCI_CONFIG_1 1 /* default */
#endif

#ifdef PCI_CONFIG_1

/* PCI Configuration Mechanism #1 */

#define PCI_ADDR(bus, dev, fn) \
    (((pci_addr) (uint32_t) (bus) << 16  \
		| (uint32_t) (dev) << 11 \
		| (uint32_t) (fn) << 8))

#define PCI_BUS(pcidev) ((uint8_t) ((pcidev) >> 16) & 0xff)
#define PCI_DEV(pcidev) ((uint8_t) ((pcidev) >> 11) & 0x1f)
#define PCI_FN(pcidev) ((uint8_t) ((pcidev) >> 8) & 7)

#define PCI_CONFIG(dev) (arch->cfg_addr                                 \
                         + (unsigned long)PCI_ADDR(PCI_BUS(dev),        \
                                                   PCI_DEV(dev),        \
                                                   PCI_FN(dev)))

static inline uint8_t pci_config_read8(pci_addr dev, uint8_t reg)
{
	uint8_t res;
        res = in_8((unsigned char*)(PCI_CONFIG(dev) + reg));
	return res;
}

static inline uint16_t pci_config_read16(pci_addr dev, uint8_t reg)
{
	uint16_t res;
        res = in_be16((uint16_t *)(PCI_CONFIG(dev) + reg));
	return res;
}

static inline uint32_t pci_config_read32(pci_addr dev, uint8_t reg)
{
	uint32_t res;
        res = in_be32((uint32_t *)(PCI_CONFIG(dev) + reg));
	return res;
}

static inline void pci_config_write8(pci_addr dev, uint8_t reg, uint8_t val)
{
        out_8((unsigned char*)(PCI_CONFIG(dev) + reg), val);
}

static inline void pci_config_write16(pci_addr dev, uint8_t reg, uint16_t val)
{
        out_be16((uint16_t *)(PCI_CONFIG(dev) + reg), val);
}

static inline void pci_config_write32(pci_addr dev, uint8_t reg, uint32_t val)
{
        out_be32((uint32_t *)(PCI_CONFIG(dev) + reg), val);
}
#else /* !PCI_CONFIG_1 */
#error PCI Configuration Mechanism is not specified or implemented
#endif

#endif /* SPARC64_PCI_H */
