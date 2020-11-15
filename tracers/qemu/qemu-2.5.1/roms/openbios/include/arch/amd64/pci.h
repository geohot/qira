#ifndef AMD64_PCI_H
#define AMD64_PCI_H

#include "asm/io.h"

#if !(defined(PCI_CONFIG_1) || defined(PCI_CONFIG_2))
#define PCI_CONFIG_1 1 /* default */
#endif

#ifdef PCI_CONFIG_1

/* PCI Configuration Mechanism #1 */

/* Have pci_addr in the same format as the values written to 0xcf8
 * so register accesses can be made easy. */
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
    outl(dev | (reg & ~3), 0xcf8);
    return inb(0xcfc | (reg & 3));
}

static inline uint16_t pci_config_read16(pci_addr dev, uint8_t reg)
{
    outl(dev | (reg & ~3), 0xcf8);
    return inw(0xcfc | (reg & 2));
}

static inline uint32_t pci_config_read32(pci_addr dev, uint8_t reg)
{
    outl(dev | reg, 0xcf8);
    return inl(0xcfc | reg);
}

static inline void pci_config_write8(pci_addr dev, uint8_t reg, uint8_t val)
{
    outl(dev | (reg & ~3), 0xcf8);
    outb(val, 0xcfc | (reg & 3));
}

static inline void pci_config_write16(pci_addr dev, uint8_t reg, uint16_t val)
{
    outl(dev | (reg & ~3), 0xcf8);
    outw(val, 0xcfc | (reg & 2));
}

static inline void pci_config_write32(pci_addr dev, uint8_t reg, uint32_t val)
{
    outl(dev | reg, 0xcf8);
    outl(val, 0xcfc);
}

#else /* !PCI_CONFIG_1 */
#error PCI Configuration Mechanism is not specified or implemented
#endif

#endif /* AMD64_PCI_H */
