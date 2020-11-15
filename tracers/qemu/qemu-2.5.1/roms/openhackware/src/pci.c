/* PCI BIOS.
 *
 *  Copyright (c) 2004-2005 Jocelyn Mayer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include "bios.h"

//#define DEBUG_PCI 1

#if defined (DEBUG_PCI)
#define PCI_DPRINTF(fmt, args...) \
do { dprintf("PCI %s: " fmt, __func__ , ##args); } while (0)
#else
#define PCI_DPRINTF(fmt, args...) \
do { } while (0)
#endif

/* On PMAC, there are four kind of PCI bridges:
 * - uninorth, for all recent machines (all Core99 and more).
 * - chaos : buggy bandit like
 * - grackle, for powerbook 1998 & some powermac G3
 * - bandit : some early PCI powermacs.
 * For now, only uninorth will be supported, as other ones are deprecated.
 */

enum {
    /* Fake devices */
    PCI_FAKE_HOST   = 0x00000001,
    PCI_FAKE_BRIDGE = 0x00000002,
    /* Device found during PCI probe */
    PCI_HOST_BRIDGE = 0x00000003,
    PCI_DEV_BRIDGE  = 0x00000004,
    PCI_DEVICE      = 0x00000005,
};

enum {
    BRIDGE_TYPE_UNINORTH = 0x0001,
};

/* PCI devices database */
typedef struct pci_class_t pci_class_t;
typedef struct pci_subclass_t pci_subclass_t;
typedef struct pci_iface_t pci_iface_t;

struct pci_iface_t {
    uint8_t iface;
    const unsigned char *name;
    const unsigned char *type;
    const pci_dev_t *devices;
    int (*config_cb)(pci_device_t *device);
    const void *private;
};

struct pci_subclass_t {
    uint8_t subclass;
    const unsigned char *name;
    const unsigned char *type;
    const pci_dev_t *devices;
    const pci_iface_t *iface;
    int (*config_cb)(pci_device_t *device);
    const void *private;
};

struct pci_class_t {
    const unsigned char *name;
    const unsigned char *type;
    const pci_subclass_t *subc;
};

/* PCI devices tree */
struct pci_common_t {
    int type;
    const pci_dev_t *device;
    const pci_u_t *parent;
    void *OF_private;
};

struct pci_device_t {
    pci_common_t common;
    uint8_t bus;
    uint8_t devfn;
    uint16_t rev;
    uint32_t class_code;
    uint16_t min_grant;
    uint16_t max_latency;
    uint8_t  irq_line;
    uint32_t regions[7]; /* the region 6 is the PCI ROM */
    uint32_t sizes[7];
    pci_device_t *next;
};

struct pci_host_t {
    pci_device_t dev;
    pci_bridge_t *bridge;
    pci_host_t *next;
};

struct pci_bridge_t {
    pci_device_t dev;
    uint32_t cfg_base;
    uint32_t cfg_len;
    uint32_t io_base;
    uint32_t io_len;
    uint32_t io_cur;
    uint32_t mem_base;
    uint32_t mem_len;
    uint32_t mem_cur;
    uint32_t rbase;
    uint32_t rlen;
    uint32_t cfg_addr;
    uint32_t cfg_data;
    uint32_t flags;
    const pci_ops_t *ops;
    pci_device_t *devices;
    pci_bridge_t *next;
};

union pci_u_t {
    pci_common_t common;
    pci_host_t host;
    pci_device_t device;
    pci_bridge_t bridge;
};

/* Low level access helpers */
struct pci_ops_t {
    uint8_t (*config_readb)(pci_bridge_t *bridge,
                            uint8_t bus, uint8_t devfn, uint8_t offset);
    void (*config_writeb)(pci_bridge_t *bridge,
                          uint8_t bus, uint8_t devfn,
                          uint8_t offset, uint8_t val);
    uint16_t (*config_readw)(pci_bridge_t *bridge,
                             uint8_t bus, uint8_t devfn, uint8_t offset);
    void (*config_writew)(pci_bridge_t *bridge,
                          uint8_t bus, uint8_t devfn,
                          uint8_t offset, uint16_t val);
    uint32_t (*config_readl)(pci_bridge_t *bridge,
                             uint8_t bus, uint8_t devfn, uint8_t offset);
    void (*config_writel)(pci_bridge_t *bridge,
                          uint8_t bus, uint8_t devfn,
                          uint8_t offset, uint32_t val);
};

/* IRQ numbers assigned to PCI IRQs */
static uint8_t prep_pci_irqs[4] = { 9, 11, 9, 11 };
static uint8_t heathrow_pci_irqs[4] = { 0x15, 0x16, 0x17, 0x18 };
static uint8_t pmac_pci_irqs[4] = { 8, 9, 10, 11 };

/* PREP PCI host */
static inline uint32_t PREP_cfg_addr (pci_bridge_t *bridge, unused uint8_t bus,
                                      uint8_t devfn, uint8_t offset)
{
#if 0
    printf("Translate %0x %0x %d %x %x => %0x",
           bridge->cfg_addr, bridge->cfg_data, bus, devfn, offset,
           bridge->cfg_addr |
           (1 << (devfn >> 3)) | ((devfn & 7) << 8) | offset);
#endif
    return bridge->cfg_addr |
        (1 << (devfn >> 3)) | ((devfn & 7) << 8) | offset;
}

static uint8_t PREP_config_readb (pci_bridge_t *bridge,
                                  uint8_t bus, uint8_t devfn,
                                  uint8_t offset)
{
    uint32_t addr;

    if (bus != 0 || (devfn >> 3) < 11 || (devfn >> 3) > 21)
        return 0xFF;
    addr = PREP_cfg_addr(bridge, bus, devfn, offset);
    
    return *((uint8_t *)addr);
}

static void PREP_config_writeb (pci_bridge_t *bridge,
                                uint8_t bus, uint8_t devfn,
                                uint8_t offset, uint8_t val)
{
    uint32_t addr;

    if (bus != 0 || (devfn >> 3) < 11 || (devfn >> 3) > 21)
        return;
    addr = PREP_cfg_addr(bridge, bus, devfn, offset);
    *((uint8_t *)addr) = val;
}

static uint16_t PREP_config_readw (pci_bridge_t *bridge,
                                   uint8_t bus, uint8_t devfn,
                                   uint8_t offset)
{
    uint32_t addr;

    if (bus != 0 || (devfn >> 3) < 11 || (devfn >> 3) > 21)
        return 0xFFFF;
    addr = PREP_cfg_addr(bridge, bus, devfn, offset);
    
    return ldswap16((uint16_t *)addr);
}

static void PREP_config_writew (pci_bridge_t *bridge,
                                uint8_t bus, uint8_t devfn,
                                uint8_t offset, uint16_t val)
{
    uint32_t addr;

    if (bus != 0 || (devfn >> 3) < 11 || (devfn >> 3) > 21)
        return;
    addr = PREP_cfg_addr(bridge, bus, devfn, offset);
    stswap16((uint16_t *)addr, val);
}

static uint32_t PREP_config_readl (pci_bridge_t *bridge,
                                   uint8_t bus, uint8_t devfn,
                                   uint8_t offset)
{
    uint32_t addr;

    if (bus != 0 || (devfn >> 3) < 11 || (devfn >> 3) > 21)
        return 0xFFFFFFFF;
    addr = PREP_cfg_addr(bridge, bus, devfn, offset);
    
    return ldswap32((uint32_t *)addr);
}

static void PREP_config_writel (pci_bridge_t *bridge,
                                uint8_t bus, uint8_t devfn,
                                uint8_t offset, uint32_t val)
{
    uint32_t addr;

    if (bus != 0 || (devfn >> 3) < 11 || (devfn >> 3) > 21)
        return;
    addr = PREP_cfg_addr(bridge, bus, devfn, offset);
    stswap32((uint32_t *)addr, val);
}

static pci_ops_t PREP_pci_ops = {
    &PREP_config_readb, &PREP_config_writeb,
    &PREP_config_readw, &PREP_config_writew,
    &PREP_config_readl, &PREP_config_writel,
};

/* Uninorth PCI host */
static uint32_t macrisc_cfg_address (pci_bridge_t *bridge,
                                     uint8_t bus, uint8_t devfn,
                                     uint8_t offset)
{
    uint32_t addr;
    int i;

    /* Kind of magic... */
    if (bridge->cfg_base == 0xF2000000) {
        if (bus != 0) {
#if 0
            printf("Skip bus: %d dev: %x offset: %x\n", bus, devfn, offset);
#endif
            return -1;
        }
        addr = (1 << (devfn >> 3));
    } else {
        addr = (bus << 16) | ((devfn & 0xF8) << 8) | 0x01;
    }
    addr |= ((devfn & 0x07) << 8) | (offset & 0xFC);
    /* Avoid looping forever */
#if 0
    printf("Translate %0x %0x %d %x %x => %0x",
           bridge->cfg_addr, bridge->cfg_data, bus, devfn, offset, addr);
#endif
    for (i = 0; i < 100; i++) {
        stswap32((uint32_t *)bridge->cfg_addr, addr);
        eieio();
        if (ldswap32((uint32_t *)bridge->cfg_addr) == addr)
            break;
    }
    if (i == 100) {
#if 1
    printf("Translate %0x %0x %d %x %x => %0x",
           bridge->cfg_addr, bridge->cfg_data, bus, devfn, offset, addr);
        printf("\nTimeout accessing PCI bridge cfg address\n");
#endif
        return -1;
    }
    if (bridge->flags & BRIDGE_TYPE_UNINORTH)
        offset &= 0x07;
    else
        offset &= 0x03;
#if 0
    printf(" %0x\n", bridge->cfg_data + offset);
#endif

    return bridge->cfg_data + offset;
}

static uint8_t uninorth_config_readb (pci_bridge_t *bridge,
                                      uint8_t bus, uint8_t devfn,
                                      uint8_t offset)
{
    uint32_t addr;

    if (bridge->cfg_base == 0xF2000000 && (devfn >> 3) < 11)
        return 0xFF;
    addr = macrisc_cfg_address(bridge, bus, devfn, offset);
    if (addr == (uint32_t)(-1))
        return 0xFF;
    
    return *((uint8_t *)addr);
}

static void uninorth_config_writeb (pci_bridge_t *bridge,
                                    uint8_t bus, uint8_t devfn,
                                    uint8_t offset, uint8_t val)
{
    uint32_t addr;

    if (bridge->cfg_base == 0xF2000000 && (devfn >> 3) < 11)
        return;
    addr = macrisc_cfg_address(bridge, bus, devfn, offset);
    if (addr != (uint32_t)(-1))
        *((uint8_t *)addr) = val;
}

static uint16_t uninorth_config_readw (pci_bridge_t *bridge,
                                       uint8_t bus, uint8_t devfn,
                                       uint8_t offset)
{
    uint32_t addr;

    if (bridge->cfg_base == 0xF2000000 && (devfn >> 3) < 11)
        return 0xFFFF;
    addr = macrisc_cfg_address(bridge, bus, devfn, offset);
    if (addr == (uint32_t)(-1))
        return 0xFFFF;
    
    return ldswap16((uint16_t *)addr);
}

static void uninorth_config_writew (pci_bridge_t *bridge,
                                    uint8_t bus, uint8_t devfn,
                                    uint8_t offset, uint16_t val)
{
    uint32_t addr;

    if (bridge->cfg_base == 0xF2000000 && (devfn >> 3) < 11)
        return;
    addr = macrisc_cfg_address(bridge, bus, devfn, offset);
    if (addr != (uint32_t)(-1))
        stswap16((uint16_t *)addr, val);
}

static uint32_t uninorth_config_readl (pci_bridge_t *bridge,
                                       uint8_t bus, uint8_t devfn,
                                       uint8_t offset)
{
    uint32_t addr;

    if (bridge->cfg_base == 0xF2000000 && (devfn >> 3) < 11)
        return 0xFFFFFFFF;
    addr = macrisc_cfg_address(bridge, bus, devfn, offset);
    if (addr == (uint32_t)(-1)) {
        //        printf("bad address -1\n");
        return 0xFFFFFFFF;
    }
    //    printf("%s: addr=%0x\n", __func__, addr);
    
    return ldswap32((uint32_t *)addr);
}

static void uninorth_config_writel (pci_bridge_t *bridge,
                                    uint8_t bus, uint8_t devfn,
                                    uint8_t offset, uint32_t val)
{
    uint32_t addr;

    if (bridge->cfg_base == 0xF2000000 && (devfn >> 3) < 11)
        return;
    addr = macrisc_cfg_address(bridge, bus, devfn, offset);
    if (addr != (uint32_t)(-1))
        stswap32((uint32_t *)addr, val);
}

static pci_ops_t uninorth_pci_ops = {
    &uninorth_config_readb, &uninorth_config_writeb,
    &uninorth_config_readw, &uninorth_config_writew,
    &uninorth_config_readl, &uninorth_config_writel,
};

/* Grackle PCI host */

static uint32_t grackle_cfg_address (pci_bridge_t *bridge,
                                     uint8_t bus, uint8_t devfn,
                                     uint8_t offset)
{
    uint32_t addr;
    addr = 0x80000000 | (bus << 16) | (devfn << 8) | (offset & 0xfc);
    stswap32((uint32_t *)bridge->cfg_addr, addr);
    return bridge->cfg_data + (offset & 3);
}

static uint8_t grackle_config_readb (pci_bridge_t *bridge,
                                      uint8_t bus, uint8_t devfn,
                                      uint8_t offset)
{
    uint32_t addr;
    addr = grackle_cfg_address(bridge, bus, devfn, offset);
    return *((uint8_t *)addr);
}

static void grackle_config_writeb (pci_bridge_t *bridge,
                                    uint8_t bus, uint8_t devfn,
                                    uint8_t offset, uint8_t val)
{
    uint32_t addr;
    addr = grackle_cfg_address(bridge, bus, devfn, offset);
    *((uint8_t *)addr) = val;
}

static uint16_t grackle_config_readw (pci_bridge_t *bridge,
                                       uint8_t bus, uint8_t devfn,
                                       uint8_t offset)
{
    uint32_t addr;
    addr = grackle_cfg_address(bridge, bus, devfn, offset);
    return ldswap16((uint16_t *)addr);
}

static void grackle_config_writew (pci_bridge_t *bridge,
                                    uint8_t bus, uint8_t devfn,
                                    uint8_t offset, uint16_t val)
{
    uint32_t addr;
    addr = grackle_cfg_address(bridge, bus, devfn, offset);
    stswap16((uint16_t *)addr, val);
}

static uint32_t grackle_config_readl (pci_bridge_t *bridge,
                                       uint8_t bus, uint8_t devfn,
                                       uint8_t offset)
{
    uint32_t addr;
    addr = grackle_cfg_address(bridge, bus, devfn, offset);
    return ldswap32((uint32_t *)addr);
}

static void grackle_config_writel (pci_bridge_t *bridge,
                                    uint8_t bus, uint8_t devfn,
                                    uint8_t offset, uint32_t val)
{
    uint32_t addr;

    addr = grackle_cfg_address(bridge, bus, devfn, offset);
    stswap32((uint32_t *)addr, val);
}

static pci_ops_t grackle_pci_ops = {
    &grackle_config_readb, &grackle_config_writeb,
    &grackle_config_readw, &grackle_config_writew,
    &grackle_config_readl, &grackle_config_writel,
};

static inline uint8_t pci_config_readb (pci_bridge_t *bridge,
                                        uint8_t bus, uint8_t devfn,
                                        uint8_t offset)
{
    return (*bridge->ops->config_readb)(bridge, bus, devfn, offset);
}

static inline void pci_config_writeb (pci_bridge_t *bridge,
                                      uint8_t bus, uint8_t devfn,
                                      uint8_t offset, uint8_t val)
{
    (*bridge->ops->config_writeb)(bridge, bus, devfn, offset, val);
}

static inline uint16_t pci_config_readw (pci_bridge_t *bridge,
                                         uint8_t bus, uint8_t devfn,
                                         uint8_t offset)
{
    return (*bridge->ops->config_readw)(bridge, bus, devfn, offset);
}

static inline void pci_config_writew (pci_bridge_t *bridge,
                                      uint8_t bus, uint8_t devfn,
                                      uint8_t offset, uint16_t val)
{
    (*bridge->ops->config_writew)(bridge, bus, devfn, offset, val);
}

static inline uint32_t pci_config_readl (pci_bridge_t *bridge,
                                         uint8_t bus, uint8_t devfn,
                                         uint8_t offset)
{
    return (*bridge->ops->config_readl)(bridge, bus, devfn, offset);
}


static inline void pci_config_writel (pci_bridge_t *bridge,
                                      uint8_t bus, uint8_t devfn,
                                      uint8_t offset, uint32_t val)
{
    (*bridge->ops->config_writel)(bridge, bus, devfn, offset, val);
}

unused static void *get_parent_OF_private (pci_device_t *device)
{
    const pci_u_t *u;

    for (u = (pci_u_t *)device; u != NULL; u = u->common.parent) {
        if (u->common.OF_private != NULL)
            return u->common.OF_private;
    }
    
    return NULL;
}

/* PCI devices database */
static pci_subclass_t undef_subclass[] = {
    {
        0x00, "misc undefined", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL, NULL, NULL, NULL,
        NULL, NULL,
    },
};

static int ide_config_cb2 (pci_device_t *device)
{
    OF_finalize_pci_ide(device->common.OF_private,
                        device->regions[0] & ~0x0000000F,
                        device->regions[1] & ~0x0000000F,
                        device->regions[2] & ~0x0000000F,
                        device->regions[3] & ~0x0000000F);
    return 0;
}

static pci_dev_t ide_devices[] = {
    {
        0x1095, 0x0646, /* CMD646 IDE controller */
        "pci-ide", "pci-ata", NULL, NULL,
        0, 0, 0,
        ide_config_cb2, NULL,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

#if 0
/* should base it on PCI ID, not on arch */
static int ide_config_cb (unused pci_device_t *device)
{
    printf("Register IDE controller\n");
    switch (arch) {
    case ARCH_MAC99:
        ide_pci_pmac_register(device->regions[0] & ~0x0000000F,
                              device->regions[1] & ~0x0000000F,
                              device->common.OF_private);
        break;
    default:
        break;
    }
    return 0;
}

static int ata_config_cb (pci_device_t *device)
{
    printf("Register ATA  controller\n");
    switch (arch) {
    case ARCH_MAC99:
        ide_pci_pmac_register(device->regions[0] & ~0x0000000F,
                              device->regions[1] & ~0x0000000F,
                              device->common.OF_private);
        break;
    default:
        break;
    }

    return 0;
}
#endif

static pci_subclass_t mass_subclass[] = {
    {
        0x00, "SCSI bus controller",        NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x01, "IDE controller",             "ide", ide_devices, NULL,
        NULL, NULL,
    },
    {
        0x02, "Floppy disk controller",     NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x03, "IPI bus controller",         NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x04, "RAID controller",            NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x05, "ATA controller",             "ata", NULL, NULL,
        NULL, NULL,
    },
    {
        0x80, "misc mass-storage controller", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_dev_t eth_devices[] = {
    { 0x10EC, 0x8029,
      NULL, "NE2000",   "NE2000 PCI",  NULL,
      0, 0, 0,
      NULL, "ethernet",
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

static pci_subclass_t net_subclass[] = {
    {
        0x00, "ethernet controller",       NULL, eth_devices, NULL,
        NULL, "ethernet",
    },
    {
        0x01, "token ring controller",      NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x02, "FDDI controller",            NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x03, "ATM controller",             NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x04, "ISDN controller",            NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x05, "WordFip controller",         NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x06, "PICMG 2.14 controller",      NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x80, "misc network controller",    NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_dev_t vga_devices[] = {
    {
        0x1002, 0x5046,
        NULL, "ATY",      "ATY Rage128", "VGA",
        0, 0, 0,
        NULL, NULL,
    },
    {
        0x1234, 0x1111,
        NULL, "Qemu VGA", "Qemu VGA",    "VGA",
        0, 0, 0,
        NULL, NULL,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

/* VGA configuration */
/* HACK... */
extern int vga_width, vga_height, vga_depth;
int vga_console_register (void);
static int vga_config_cb (pci_device_t *device)
{
    /* Found a VGA device. Let's configure it ! */
    printf("Set VGA to %0x\n", device->regions[0] & ~0x0000000F);
    if (device->regions[0] != 0x00000000) {
        vga_set_mode(vga_width, vga_height, vga_depth);
        vga_set_address(device->regions[0] & ~0x0000000F);
        /* VGA 640x480x16 */
        OF_vga_register(device->common.device->name,
                        device->regions[0] & ~0x0000000F,
                        vga_width, vga_height, vga_depth,
                        device->regions[6] & ~0x0000000F,
                        device->sizes[6]);
    }
    vga_console_register();

    return 0;
}

static struct pci_iface_t vga_iface[] = {
    { 
        0x00, "VGA controller", NULL,
        vga_devices, &vga_config_cb, NULL,
    },
    {
        0x01, "8514 compatible controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFF, NULL, NULL,
        NULL, NULL, NULL,
    },
};

static pci_subclass_t displ_subclass[] = {
    {
        0x00, "display controller",         NULL,  NULL, vga_iface,
        NULL, NULL,
    },
    {
        0x01, "XGA display controller",     NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x02, "3D display controller",      NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x80, "misc display controller",    NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_subclass_t media_subclass[] = {
    {
        0x00, "video device",              NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x01, "audio device",              NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x02, "computer telephony device", NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x80, "misc multimedia device",    NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_subclass_t mem_subclass[] = {
    {
        0x00, "RAM controller",             NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x01, "flash controller",           NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_dev_t uninorth_agp_fake_bridge = {
    0xFFFF, 0xFFFF,
    "uni-north-agp", "uni-north-agp", NULL, "uni-north-agp",
    -1, -1, -1,
    NULL, &uninorth_pci_ops,
};

static pci_dev_t uninorth_fake_bridge = {
    0xFFFF, 0xFFFF,
    "uni-north", "uni-north", NULL, "uni-north",
    -1, -1, -1,
    NULL, &uninorth_pci_ops,
};

static pci_dev_t PREP_fake_bridge = {
    0xFFFF, 0xFFFF,
    "pci", "pci", NULL, "pci",
    -1, -1, -1,
    NULL, &PREP_pci_ops,
};

pci_dev_t grackle_fake_bridge = {
    0xFFFF, 0xFFFF,
    "pci", "pci-bridge", "DEC,21154", "DEC,21154.pci-bridge",
    -1, -1, -1,
    NULL, &grackle_pci_ops,
};

static pci_dev_t hbrg_devices[] = {
    {
        0x106B, 0x0020, NULL,
        "pci", "AAPL,UniNorth", "uni-north",
        3, 2, 1,
        NULL, &uninorth_agp_fake_bridge,
    },
    {
        0x106B, 0x001F, NULL, 
        "pci", "AAPL,UniNorth", "uni-north",
        3, 2, 1,
        NULL, &uninorth_fake_bridge,
    },
    {
        0x106B, 0x001E, NULL,
        "pci", "AAPL,UniNorth", "uni-north",
        3, 2, 1,
        NULL, &uninorth_fake_bridge,
    },
    {
        0x1057, 0x0002, "pci",
        "pci", "MOT,MPC106", "grackle",
        3, 2, 1,
        NULL, &grackle_fake_bridge,
    },
    {
        0x1057, 0x4801, NULL,
        "pci-bridge", "PREP Host PCI Bridge - Motorola Raven", NULL,
        3, 2, 1,
        NULL, &PREP_pci_ops,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

static pci_dev_t PCIbrg_devices[] = {
    {
        0x1011, 0x0026, NULL,
        "pci-bridge", NULL, NULL,
        3, 2, 1,
        NULL, &PREP_pci_ops,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

static pci_subclass_t bridg_subclass[] = {
    {
        0x00, "PCI host bridge",           NULL,  hbrg_devices, NULL,
        NULL, NULL,
    },
    {
        0x01, "ISA bridge",                NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x02, "EISA bridge",               NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x03, "MCA bridge",                NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x04, "PCI-to-PCI bridge",         NULL,  PCIbrg_devices, NULL,
        NULL, NULL,
    },
    {
        0x05, "PCMCIA bridge",             NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x06, "NUBUS bridge",              NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x07, "cardbus bridge",            NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x08, "raceway bridge",            NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x09, "semi-transparent PCI-to-PCI bridge", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x0A, "infiniband-to-PCI bridge",  NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0x80, "misc PCI bridge",           NULL,  NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_iface_t serial_iface[] = {
    {
        0x00, "XT serial controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x01, "16450 serial controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x02, "16550 serial controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x03, "16650 serial controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x04, "16750 serial controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x05, "16850 serial controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x06, "16950 serial controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFF, NULL, NULL,
        NULL, NULL, NULL,
    },
};

static pci_iface_t par_iface[] = {
    {
        0x00, "parallel port", NULL,
        NULL, NULL, NULL,
    },
    {
        0x01, "bi-directional parallel port", NULL,
        NULL, NULL, NULL,
    },
    {
        0x02, "ECP 1.x parallel port", NULL,
        NULL, NULL, NULL,
    },
    {
        0x03, "IEEE 1284 controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFE, "IEEE 1284 device", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFF, NULL, NULL,
        NULL, NULL, NULL,
    },
};

static pci_iface_t modem_iface[] = {
    {
        0x00, "generic modem", NULL,
        NULL, NULL, NULL,
    },
    {
        0x01, "Hayes 16450 modem", NULL,
        NULL, NULL, NULL,
    },
    {
        0x02, "Hayes 16550 modem", NULL,
        NULL, NULL, NULL,
    },
    {
        0x03, "Hayes 16650 modem", NULL,
        NULL, NULL, NULL,
    },
    {
        0x04, "Hayes 16750 modem", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFF, NULL, NULL,
        NULL, NULL, NULL,
    },
};

static pci_subclass_t comm_subclass[] = {
    {
        0x00, "serial controller",          NULL, NULL, serial_iface,
        NULL, NULL,
    },
    {
        0x01, "parallel port",             NULL, NULL, par_iface,
        NULL, NULL,
    },
    {
        0x02, "multiport serial controller", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x03, "modem",                     NULL, NULL, modem_iface,
        NULL, NULL,
    },
    {
        0x04, "GPIB controller",           NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x05, "smart card",                NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x80, "misc communication device", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static pci_iface_t pic_iface[] = {
    {
        0x00, "8259 PIC", NULL,
        NULL, NULL, NULL,
    },
    {
        0x01, "ISA PIC", NULL,
        NULL, NULL, NULL,
    },
    {
        0x02, "EISA PIC", NULL,
        NULL, NULL, NULL,
    },
    {
        0x10, "I/O APIC", NULL,
        NULL, NULL, NULL,
    },
    {
        0x20, "I/O APIC", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFF, NULL, NULL,
        NULL, NULL, NULL,
    },
};

static pci_iface_t dma_iface[] = {
    {
        0x00, "8237 DMA controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x01, "ISA DMA controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x02, "EISA DMA controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFF, NULL, NULL,
        NULL, NULL, NULL,
    },
};

static pci_iface_t tmr_iface[] = {
    {
        0x00, "8254 system timer", NULL,
        NULL, NULL, NULL,
    },
    {
        0x01, "ISA system timer", NULL,
        NULL, NULL, NULL,
    },
    {
        0x02, "EISA system timer", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFF, NULL, NULL,
        NULL, NULL, NULL,
    },
};

static pci_iface_t rtc_iface[] = {
    {
        0x00, "generic RTC controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x01, "ISA RTC controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFF, NULL, NULL,
        NULL, NULL, NULL,
    },
};

static const pci_dev_t sys_devices[] = {
    /* IBM MPIC controller */
    { 
        0x1014, 0x0002,
        "open-pic", "MPIC", NULL, "chrp,open-pic",
        0, 0, 2,
        NULL, NULL,
    },
    /* IBM MPIC2 controller */
    { 
        0x1014, 0xFFFF,
        "open-pic", "MPIC2", NULL, "chrp,open-pic",
        0, 0, 2,
        NULL, NULL,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

static pci_subclass_t sys_subclass[] = {
    {
        0x00, "PIC",                       NULL, NULL, pic_iface,
        NULL, NULL,
    },
    {
        0x01, "DMA controller",             NULL, NULL, dma_iface,
        NULL, NULL,
    },
    {
        0x02, "system timer",              NULL, NULL, tmr_iface,
        NULL, NULL,
    },
    {
        0x03, "RTC controller",             NULL, NULL, rtc_iface,
        NULL, NULL,
    },
    {
        0x04, "PCI hotplug controller",     NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x80, "misc system peripheral",    NULL, sys_devices, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_subclass_t inp_subclass[] = {
    {
        0x00, "keyboard controller",        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x01, "digitizer",                 NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x02, "mouse controller",           NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x03, "scanner controller",         NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x04, "gameport controller",        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x80, "misc input device",         NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_subclass_t dock_subclass[] = {
    {
        0x00, "generic docking station",   NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x80, "misc docking station",      NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_subclass_t cpu_subclass[] = {
    {
        0x00, "i386 processor",            NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x01, "i486 processor",            NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x02, "pentium processor",         NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x10, "alpha processor",           NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x20, "PowerPC processor",         NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x30, "MIPS processor",            NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x40, "co-processor",              NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_iface_t usb_iface[] = {
    {
        0x00, "UHCI USB controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x10, "OHCI USB controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x20, "EHCI USB controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x80, "misc USB controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFE, "USB device", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFF, NULL, NULL,
        NULL, NULL, NULL,
    },
};

static pci_iface_t ipmi_iface[] = {
    {
        0x00, "IPMI SMIC interface", NULL,
        NULL, NULL, NULL,
    },
    {
        0x01, "IPMI keyboard interface", NULL,
        NULL, NULL, NULL,
    },
    {
        0x02, "IPMI block transfer interface", NULL,
        NULL, NULL, NULL,
    },
    {
        0xFF, NULL, NULL,
        NULL, NULL, NULL,
    },
};

static pci_subclass_t ser_subclass[] = {
    {
        0x00, "Firewire bus controller",    "ieee1394", NULL, NULL,
        NULL, NULL,
    },
    {
        0x01, "ACCESS bus controller",      NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x02, "SSA controller",             NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x03, "USB controller",             "usb", NULL, usb_iface,
        NULL, NULL,
    },
    {
        0x04, "fibre channel controller",   NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x05, "SMBus controller",           NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x06, "InfiniBand controller",      NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x07, "IPMI interface",            NULL, NULL,  ipmi_iface,
        NULL, NULL,
    },
    {
        0x08, "SERCOS controller",          NULL, NULL,  ipmi_iface,
        NULL, NULL,
    },
    {
        0x09, "CANbus controller",          NULL, NULL,  ipmi_iface,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_subclass_t wrl_subclass[] = {
    {
        0x00, "IRDA controller",           NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x01, "consumer IR controller",    NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x10, "RF controller",             NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x11, "bluetooth controller",      NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x12, "broadband controller",      NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x80, "misc wireless controller",  NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_subclass_t sat_subclass[] = {
    {
        0x01, "satellite TV controller",   NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x02, "satellite audio controller", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x03, "satellite voice controller", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x04, "satellite data controller", NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_subclass_t crypt_subclass[] = {
    {
        0x00, "cryptographic network controller", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x10, "cryptographic entertainment controller", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x80, "misc cryptographic controller",    NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static pci_subclass_t spc_subclass[] = {
    {
        0x00, "DPIO module",               NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x01, "performances counters",     NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x10, "communication synchronisation", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0x20, "management card",           NULL, NULL,  NULL,
        NULL, NULL,
    },
    {
        0x80, "misc signal processing controller", NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,                        NULL,  NULL,  NULL,
        NULL, NULL,
    },
};

static const pci_class_t pci_classes[] = {
    /* 0x00 */
    { "undefined",                         NULL,             undef_subclass, },
    /* 0x01 */
    { "mass-storage controller",           NULL,              mass_subclass, },
    /* 0x02 */
    { "network controller",                "network",          net_subclass, },
    /* 0x03 */
    { "display controller",                "display",        displ_subclass, },
    /* 0x04 */
    { "multimedia device",                 NULL,             media_subclass, },
    /* 0x05 */ 
    { "memory controller",                 "memory-controller", mem_subclass, },
    /* 0x06 */
    { "PCI bridge",                        "pci",            bridg_subclass, },
    /* 0x07 */
    { "communication device",              NULL,               comm_subclass,},
    /* 0x08 */
    { "system peripheral",                 NULL,               sys_subclass, },
    /* 0x09 */
    { "input device",                      NULL,               inp_subclass, },
    /* 0x0A */
    { "docking station",                   NULL,              dock_subclass, },
    /* 0x0B */
    { "processor",                         NULL,               cpu_subclass, },
    /* 0x0C */
    { "serial bus controller",             NULL,               ser_subclass, },
    /* 0x0D */
    { "wireless controller",               NULL,               wrl_subclass, },
    /* 0x0E */
    { "intelligent I/O controller",        NULL,               NULL,         },
    /* 0x0F */
    { "satellite communication controller", NULL,               sat_subclass, },
    /* 0x10 */
    { "cryptographic controller",           NULL,             crypt_subclass, },
    /* 0x11 */
    { "signal processing controller",       NULL,               spc_subclass, },
};

static int macio_config_cb (pci_device_t *device)
{
    void *private_data;

    private_data = cuda_init(device->regions[0] + 0x16000);
    OF_finalize_pci_macio(device->common.OF_private,
                          device->regions[0] & ~0x0000000F, device->sizes[0],
                          private_data);

    return 0;
}

static const pci_dev_t misc_pci[] = {
    /* Paddington Mac I/O */
    { 
        0x106B, 0x0017,
        "mac-io", "mac-io", "AAPL,343S1211", "paddington\1heathrow",
        1, 1, 1,
        &macio_config_cb, NULL,
    },
    /* KeyLargo Mac I/O */
    { 
        0x106B, 0x0022,
        "mac-io", "mac-io", "AAPL,Keylargo", "Keylargo",
        1, 1, 2,
        &macio_config_cb, NULL,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

static pci_dev_t *pci_find_device (uint8_t class, uint8_t subclass,
                                   uint8_t iface, uint16_t vendor,
                                   uint16_t product)
{
    int (*config_cb)(pci_device_t *device);
    const pci_class_t *pclass;
    const pci_subclass_t *psubclass;
    const pci_iface_t *piface;
    const pci_dev_t *dev;
    const void *private;
    pci_dev_t *new;
    const unsigned char *name, *type;

    name = "unknown";
    type = "unknown";
    config_cb = NULL;
    private = NULL;
#if 0
    printf("check PCI device : %x %x (%x %x %x)\n",
           vendor, product, class, subclass, iface);
#endif
    if (class == 0x00 && subclass == 0x01) {
        /* Special hack for old style VGA devices */
        class = 0x03;
        subclass = 0x00;
    } else if (class == 0xFF) {
        /* Special case for misc devices */
        dev = misc_pci;
        goto find_device;
    }
    if (class > (sizeof(pci_classes) / sizeof(pci_class_t))) {
        name = "invalid PCI device";
        type = "invalid";
        goto bad_device;
    }
    pclass = &pci_classes[class];
    name = pclass->name;
    type = pclass->type;
    for (psubclass = pclass->subc; ; psubclass++) {
        if (psubclass->subclass == 0xFF)
            goto bad_device;
        if (psubclass->subclass == subclass) {
            if (psubclass->name != NULL)
                name = psubclass->name;
            if (psubclass->type != NULL)
                type = psubclass->type;
            if (psubclass->config_cb != NULL) {
                config_cb = psubclass->config_cb;
            }
            if (psubclass->private != NULL)
                private = psubclass->private;
            if (psubclass->iface != NULL)
                break;
            dev = psubclass->devices;
            goto find_device;
        }
    }
    for (piface = psubclass->iface; ; piface++) {
        if (piface->iface == 0xFF) {
            dev = psubclass->devices;
            break;
        }
        if (piface->iface == iface) {
            if (piface->name != NULL)
                name = piface->name;
            if (piface->type != NULL)
                type = piface->type;
            if (piface->config_cb != NULL) {
                config_cb = piface->config_cb;
            }
            if (piface->private != NULL)
                private = piface->private;
            dev = piface->devices;
            break;
        }
    }
    find_device:
    for (;; dev++) {
        if (dev->vendor == 0xFFFF && dev->product == 0xFFFF) {
            goto bad_device;
        }
        if (dev->vendor == vendor && dev->product == product) {
            if (dev->name != NULL)
                name = dev->name;
            if (dev->type != NULL)
                type = dev->type;
            if (dev->config_cb != NULL) {
                config_cb = dev->config_cb;
            }
            if (dev->private != NULL)
                private = dev->private;
            new = malloc(sizeof(pci_dev_t));
            if (new == NULL)
                return NULL;
            new->vendor = vendor;
            new->product = product;
            new->type = type;
            new->name = name;
            new->model = dev->model;
            new->compat = dev->compat;
            new->acells = dev->acells;
            new->scells = dev->scells;
            new->icells = dev->icells;
            new->config_cb = config_cb;
            new->private = private;

            return new;
        }
    }
 bad_device:
    printf("Cannot manage '%s' PCI device type '%s':\n %x %x (%x %x %x)\n",
           name, type, vendor, product, class, subclass, iface);

    return NULL;
}

/* PCI devices discovery helpers */
static inline void pci_fill_common (pci_common_t *comm, pci_u_t *parent,
                                    int type, pci_dev_t *device)
{
    comm->type = type;
    comm->device = device;
    comm->parent = parent;
}

static inline void pci_fill_device (pci_device_t *device, pci_u_t *parent,
                                    int type, uint8_t bus, uint8_t devfn,
                                    pci_dev_t *dev, uint32_t class_code)
{
    pci_fill_common(&device->common, parent, type, dev);
    device->bus = bus;
    device->devfn = devfn;
    device->class_code = class_code;
    device->rev = class_code;
}

static inline void pci_update_device (pci_bridge_t *bridge,
                                      pci_device_t *device,
                                      uint8_t min_grant, uint8_t max_latency,
                                      int irq_line)
{
    uint32_t cmd, addr;
    int i;

    device->min_grant = min_grant;
    device->max_latency = max_latency;
    device->irq_line = irq_line;
    if (irq_line != -1) {
        pci_config_writeb(bridge, device->bus, device->devfn,
                          0x3c, device->irq_line);
        printf("MAP PCI device %d:%d to IRQ %d\n",
               device->bus, device->devfn, irq_line);
    }
    for (i = 0; i < 7; i++) {
        if ((device->regions[i] & ~0xF) != 0x00000000 &&
            (device->regions[i] & ~0xF) != 0xFFFFFFF0) {
            printf("Map PCI device %d:%d %d to %0x %0x (%s)\n",
                   device->bus, device->devfn, i,
                   device->regions[i], device->sizes[i],
                   (device->regions[i] & 0x00000001) && i != 6 ? "I/O" : 
                    "memory");
            if (i != 6) {
            cmd = pci_config_readl(bridge, device->bus, device->devfn, 0x04);
            if (device->regions[i] & 0x00000001)
                cmd |= 0x00000001;
            else
                cmd |= 0x00000002;
            pci_config_writel(bridge, device->bus, device->devfn, 0x04, cmd);
            }
            if (i == 6)
                addr = 0x30; /* PCI ROM */
            else
                addr = 0x10 + (i * sizeof(uint32_t));
            if (device->regions[i] & 0x00000001) {
            pci_config_writel(bridge, device->bus, device->devfn,
                              addr, device->regions[i] - 0x80000000);
            } else {
            pci_config_writel(bridge, device->bus, device->devfn,
                              addr, device->regions[i] - 0xc0000000);
            }
        }
    }
}

static pci_host_t *pci_add_host (pci_host_t **hostp, pci_dev_t *device,
                                 uint32_t class_code)
{
    pci_host_t *new, **lnk;

    new = malloc(sizeof(pci_host_t));
    if (new == NULL)
        return NULL;
    pci_fill_common(&new->dev.common, NULL, PCI_HOST_BRIDGE, device);
    new->dev.class_code = class_code;
    new->dev.rev = class_code;
    for (lnk = hostp; *lnk != NULL; lnk = &((*lnk)->next))
        continue;
    *lnk = new;
    
    return new;
}

static pci_bridge_t *pci_add_bridge (pci_host_t *host,
                                     uint8_t bus, uint8_t devfn,
                                     pci_dev_t *dev, uint32_t class_code,
                                     uint32_t cfg_base, uint32_t cfg_len,
                                     uint32_t cfg_addr, uint32_t cfg_data,
                                     uint32_t mem_base, uint32_t mem_len,
                                     uint32_t io_base, uint32_t io_len,
                                     uint32_t rbase, uint32_t rlen,
                                     uint32_t flags, const pci_ops_t *ops)
{
    pci_u_t *u;
    pci_bridge_t *new, **lnk;

    new = malloc(sizeof(pci_bridge_t));
    if (new == NULL)
        return NULL;
    u = (pci_u_t *)host;
    pci_fill_device(&new->dev, u, PCI_DEV_BRIDGE, bus, devfn, dev, class_code);
    new->cfg_base = cfg_base;
    new->cfg_len = cfg_len;
    new->mem_base = mem_base;
    new->mem_len = mem_len;
    new->io_base = io_base;
    new->io_len = io_len;
    new->mem_cur = mem_base;
    if (io_base != 0x00000000)
        new->io_cur = io_base + 0x1000;
    else
        new->io_cur = 0x00000000;
    new->cfg_addr = cfg_addr;
    new->cfg_data = cfg_data;
    new->rbase = rbase;
    new->rlen = rlen;
    new->flags = flags;
    new->ops = ops;
    for (lnk = &host->bridge; *lnk != NULL; lnk = &((*lnk)->next))
        continue;
    *lnk = new;
    
    return new;
}

static pci_device_t *pci_add_device (pci_bridge_t *bridge,
                                     uint8_t bus, uint8_t devfn,
                                     pci_dev_t *dev, uint32_t class_code)
{
    pci_u_t *u;
    pci_device_t *new, **lnk;

    new = malloc(sizeof(pci_device_t));
    if (new == NULL)
        return NULL;
    u = (pci_u_t *)bridge;
    pci_fill_device(new, u, PCI_DEV_BRIDGE, bus, devfn, dev, class_code);
    for (lnk = &bridge->devices; *lnk != NULL; lnk = &((*lnk)->next))
        continue;
    *lnk = new;

    return new;
}

static pci_u_t *pci_check_device (pci_host_t **hostp, pci_host_t **phost,
                                  uint8_t bus, uint8_t devfn,
                                  uint16_t checkv, uint16_t checkp,
                                  uint8_t cclass, uint8_t csubclass,
                                  uint8_t ciface, int check_bridges)
{
    pci_u_t *ret;
    pci_host_t *host, *newh;
    pci_bridge_t *bridge, *newb;
    pci_device_t *newd;
    pci_dev_t *dev;
    uint32_t *io_base, *mem_base, *base;
    uint32_t ccode, addr, omask, amask, size, smask, reloc, min_align;
    uint16_t vendor, product;
    uint8_t class, subclass, iface, rev, min_grant, max_latency;
    int i, max_areas, irq_line, irq_pin;
    
    ret = NULL;
    newd = NULL;
    host = *hostp;
    irq_line = -1;
    bridge = host->bridge;
    vendor = pci_config_readw(bridge, bus, devfn, 0x00);
    product = pci_config_readw(bridge, bus, devfn, 0x02);
    if (vendor == 0xFFFF && product == 0xFFFF) {
        /* No device: do nothing */
        goto out;
    }
    ccode = pci_config_readl(bridge, bus, devfn, 0x08);
    class = ccode >> 24;
    subclass = ccode >> 16;
    iface = ccode >> 8;
    rev = ccode;
    if (checkv != 0xFFFF && vendor != checkv) {
#if 0
        printf("Mismatching vendor for dev %x %x: %x %x\n",
               bus, devfn, checkv, vendor);
#endif
        goto out;
    }
    if (checkp != 0xFFFF && product != checkp) {
#if 0
        printf("Mismatching product for dev %x %x: %x %x\n",
               bus, devfn, checkp, product);
#endif
        goto out;
    }
    if (cclass != 0xFF && class != cclass) {
#if 0
        printf("Mismatching class for dev %x %x: %x %x\n",
               bus, devfn, cclass, class);
#endif
        goto out;
    }
    if (csubclass != 0xFF && subclass != csubclass) {
#if 0
        printf("Mismatching subclass for dev %x %x: %x %x\n",
               bus, devfn, csubclass, subclass);
#endif
        goto out;
    }
    if (ciface != 0xFF && iface != ciface) {
#if 0
        printf("Mismatching iface for dev %x %x: %x %x\n",
               bus, devfn, ciface, iface);
#endif
        goto out;
    }
    dev = pci_find_device(class, subclass, iface, vendor, product);
    if (dev == NULL) {
        goto out;
    }
    min_grant = pci_config_readb(bridge, bus, devfn, 0x3C);
    max_latency = pci_config_readb(bridge, bus, devfn, 0x3D);
    /* Special cases for bridges */
    if (class == 0x06) {
        if (check_bridges < 1)
            goto out;
        if (subclass == 0x00) {            
            if (check_bridges < 2)
                goto out;
            /* host bridge case */
            printf("Found new host bridge '%s' '%s' '%s'...\n",
                   dev->type, dev->model, dev->compat);
            newh = pci_add_host(phost, dev, ccode);
            if (newh == NULL) {
                printf("Can't allocate new host bridge...\n");
                goto out;
            }
            ret = (pci_u_t *)newh;
#if 0
            if ((*hostp)->bridge->dev.common.type != PCI_FAKE_BRIDGE) {
                printf("Keep PCI bridge\n");
                /* If we already found a PCI bridge, keep it */
                newh->bridge = (*phost)->bridge;
                goto out;
            }
            printf("Add fake PCI bridge\n");
            /* Add fake PCI bridge */
            newh->bridge = NULL;
            dev = dev->private;
            newb = pci_add_bridge(host, bus, devfn, dev, ccode,
                                  bridge->cfg_base, bridge->cfg_len,
                                  bridge->cfg_addr, bridge->cfg_data,
                                  bridge->mem_base, bridge->mem_len,
                                  bridge->io_base, bridge->io_len,
                                  bridge->rbase, bridge->rlen,
                                  bridge->flags, dev->private);
            if (newb == NULL) {
                printf("Can't allocate new PCI bridge\n");
                goto out;
            }
            newb->dev.common.type = PCI_FAKE_BRIDGE;
            newb->devices = bridge->devices;
#else
            newh->bridge = (*hostp)->bridge;
            newb = newh->bridge;
#endif
            newd = &bridge->dev;
            host = newh;
            host->dev.common.OF_private =
                OF_register_pci_host(dev, rev, ccode,
                                     bridge->cfg_base, bridge->cfg_len,
                                     bridge->mem_base, bridge->mem_len,
                                     bridge->io_base, bridge->io_len,
                                     bridge->rbase, bridge->rlen,
                                     min_grant, max_latency);
            goto update_device;
        } else if (subclass == 0x04) {
            /* PCI-to-PCI bridge case */
            printf("Found new PCI bridge '%s' '%s' '%s' '%s' %p...\n",
                   dev->name, dev->type, dev->model, dev->compat,
                   dev->private);
            newb = pci_add_bridge(host, bus + 1, devfn, dev, ccode,
                                  bridge->cfg_base, bridge->cfg_len,
                                  bridge->cfg_addr, bridge->cfg_data,
                                  bridge->mem_base, bridge->mem_len,
                                  bridge->io_base, bridge->io_len,
                                  bridge->rbase, bridge->rlen,
                                  0, dev->private);
            if (newb == NULL) {
                printf("Can't allocate new PCI bridge...\n");
                goto out;
            }
            ret = (pci_u_t *)newb;
#if 0
            printf("Config addr: 0x%0x data: 0x%0x cfg_base: 0x%08x "
                   "base: 0x%0x\n",
                   newb->cfg_addr, newb->cfg_data, newb->cfg_base, newb->base);
            printf("newb: %p hb: %p b: %p next: %p\n", newb,
                   host->bridge, bridge, host->bridge->next);
#endif
            if (bridge->dev.common.type == PCI_FAKE_BRIDGE) {
                /* Free fake bridge if it's still present
                 * Note: it should always be first...
                 */
                printf("Free fake bridge\n");
                newb->devices = host->bridge->devices;
                host->bridge = bridge->next;
            }
            bridge = host->bridge;
            newd = &bridge->dev;
#if 0
            printf("newb: %p hb: %p b: %p next: %p dev: %p\n", newb,
                   host->bridge, bridge, host->bridge->next, newd);
#endif
            max_areas = 2;
            bridge->dev.common.OF_private =
                OF_register_pci_bridge(host->dev.common.OF_private,
                                       dev, devfn, rev, ccode,
                                       bridge->cfg_base, bridge->cfg_len,
                                       min_grant, max_latency);
            goto configure_device;
        }
        printf("Bridges type %x aren't managed for now\n", subclass);
        free(dev);
        goto out;
    }
    /* Main case */
    printf("Found PCI device %x:%x %d-%d %d %d\n",
           vendor, product, bus, devfn, class, subclass);
    printf("=> '%s' '%s' '%s' '%s' (%p)\n",
           dev->name, dev->type, dev->model, dev->compat, dev->config_cb);
    newd = pci_add_device(bridge, bus, devfn, dev, ccode);
    if (newd == NULL) {
        printf("Cannot allocate new PCI device: %x %x (%x %x %x) '%s' '%s'\n",
               vendor, product, class, subclass, iface, dev->type, dev->name);
        goto out;
    }
    ret = (pci_u_t *)newd;
    max_areas = 7;
    /* register PCI device in OF tree */
    if (bridge->dev.common.type == PCI_FAKE_BRIDGE) {
        newd->common.OF_private =
            OF_register_pci_device(host->dev.common.OF_private, dev, devfn,
                                   rev, ccode, min_grant, max_latency);
    } else {
        newd->common.OF_private =
            OF_register_pci_device(bridge->dev.common.OF_private, dev, devfn,
                                   rev, ccode, min_grant, max_latency);
    }
 configure_device:
#if 0
    printf("Config addr: 0x%08x data: 0x%08x cfg_base: 0x%08x base: 0x%08x\n",
           bridge->cfg_addr, bridge->cfg_data, bridge->cfg_base, bridge->base);
    printf("ops: %p uni-ops: %p\n", bridge->ops, &uninorth_pci_ops);
#endif
    io_base = &bridge->io_cur;
    mem_base = &bridge->mem_cur;
    omask = 0x00000000;
    for (i = 0; i < max_areas; i++) {
        newd->regions[i] = 0x00000000;
        newd->sizes[i] = 0x00000000;
        if ((omask & 0x0000000F) == 0x4) {
            /* Handle 64 bits memory mapping */
            continue;
        }
        if (i == 6)
            addr = 0x30; /* PCI ROM */
        else
        addr = 0x10 + (i * sizeof(uint32_t));
        /* Get region size
         * Note: we assume it's always a power of 2
         */
        pci_config_writel(bridge, bus, devfn, addr, 0xFFFFFFFF);
        smask = pci_config_readl(bridge, bus, devfn, addr);
        if (smask == 0x00000000 || smask == 0xFFFFFFFF)
            continue;
        if ((smask & 0x00000001) != 0 && i != 6) {
            /* I/O space */
            base = io_base;
            /* Align to a minimum of 256 bytes (arbitrary) */
            min_align = 1 << 8;
            amask = 0x00000001;
        } else {
            /* Memory space */
            base = mem_base;
            /* Align to a minimum of 64 kB (arbitrary) */
            min_align = 1 << 16;
            amask = 0x0000000F;
            if (i == 6)
                smask |= 1; /* PCI ROM enable */
        }
        omask = smask & amask;
        smask &= ~amask;
        size = (~smask) + 1;
        reloc = *base;
#if 0
        printf("Relocate %s area %d of size %0x to 0x%0x (0x%0x 0x%0x %0x)\n",
               omask & 0x00000001 ? "I/O" : "memory", i,
               size, reloc, reloc + size, smask);
#endif
        if (size < min_align) {
            size = min_align;
        }
        /* Align reloc to size */
        reloc = (reloc + size - 1) & ~(size - 1);
        (*base) = reloc + size;
        if (omask & 0x00000001) {
            /* I/O resources are offsets */
            reloc -= bridge->io_base;
        }
        /* Set region address */
        newd->regions[i] = reloc | omask;
        newd->sizes[i] = size;
    }
    /* Realign io-base to 4 kB */
    bridge->io_base = (bridge->io_base + (1 << 12) - 1) & ~((1 << 12) - 1);
    /* Realign mem-base to 1 MB */
    bridge->mem_base = (bridge->mem_base + (1 << 20) - 1) & ~((1 << 20) - 1);

    irq_pin = pci_config_readb(bridge, bus, devfn, 0x3d);
    if (irq_pin > 0) {
        /* assign the IRQ */
        irq_pin = ((devfn >> 3) + irq_pin - 1) & 3;
        /* XXX: should base it on the PCI bridge type, not the arch */
        switch(arch) {
        case ARCH_PREP:
            {
            int elcr_port, val;
            irq_line = prep_pci_irqs[irq_pin];
            /* set the IRQ to level-sensitive */
            elcr_port = 0x4d0 + (irq_line >> 8);
            val = inb(elcr_port);
            val |= 1 << (irq_line & 7);
            outb(elcr_port, val);
            }
            break;
        case ARCH_MAC99:
            irq_line = pmac_pci_irqs[irq_pin];
            break;
        case ARCH_HEATHROW:
            irq_line = heathrow_pci_irqs[irq_pin];
            break;
        default:
            break;
        }
    }
 update_device:
    pci_update_device(bridge, newd, min_grant, max_latency, irq_line);
    OF_finalize_pci_device(newd->common.OF_private, bus, devfn,
                           newd->regions, newd->sizes, irq_line);
    /* Call special inits if needed */
    if (dev->config_cb != NULL)
        (*dev->config_cb)(newd);

 out:
    return ret;
}

static int pci_check_host (pci_host_t **hostp,
                           uint32_t cfg_base, uint32_t cfg_len,
                           uint32_t mem_base, uint32_t mem_len,
                           uint32_t io_base, uint32_t io_len,
                           uint32_t rbase, uint32_t rlen,
                           uint16_t checkv, uint16_t checkp)
{
    pci_host_t *fake_host, *host, **phost;
    pci_bridge_t *fake_bridge;
    pci_dev_t *dev;
    int bus, devfn;
    int ret;

    fake_host = NULL;
    ret = -1;
    switch (arch) {
    case ARCH_PREP:
        dev = pci_find_device(0x06, 0x00, 0xFF, checkv, checkp);
        if (dev == NULL)
            return -1;
        fake_host = pci_add_host(hostp, dev,
                                 (0x06 << 24) | (0x00 << 16) | (0xFF << 8));
        if (fake_host == NULL)
            return -1;
        fake_host->dev.common.type = PCI_FAKE_HOST;
        dev = &PREP_fake_bridge;
        if (dev == NULL)
            goto free_fake_host;
        fake_bridge = pci_add_bridge(fake_host, 0, 11, dev,
                                     (0x06 << 24) | (0x00 << 16) | (0xFF << 8),
                                     cfg_base, cfg_len,
                                     cfg_base + 0x00800000,
                                     cfg_base + 0x00C00000,
                                     mem_base, mem_len,
                                     io_base, io_len,
                                     rbase, rlen,
                                     0,
                                     &PREP_pci_ops);
        if (fake_bridge == NULL)
            goto free_fake_host;
        fake_bridge->dev.common.type = PCI_FAKE_BRIDGE;
        break;
    case ARCH_CHRP:
        /* TODO */
        break;
    case ARCH_HEATHROW:
        dev = pci_find_device(0x06, 0x00, 0xFF, checkv, checkp);
        if (dev == NULL)
            return -1;
        fake_host = pci_add_host(hostp, dev,
                                 (0x06 << 24) | (0x00 << 16) | (0xFF << 8));
        if (fake_host == NULL)
            return -1;
        fake_host->dev.common.type = PCI_FAKE_HOST;
        dev = &grackle_fake_bridge;
        if (dev == NULL)
            goto free_fake_host;
        fake_bridge = pci_add_bridge(fake_host, 0, 0, dev,
                                     (0x06 << 24) | (0x04 << 16) | (0xFF << 8),
                                     cfg_base, cfg_len,
                                     cfg_base + 0x7ec00000,
                                     cfg_base + 0x7ee00000,
                                     mem_base, mem_len,
                                     io_base, io_len,
                                     rbase, rlen,
                                     0,
                                     &grackle_pci_ops);
        if (fake_bridge == NULL)
            goto free_fake_host;
        fake_bridge->dev.common.type = PCI_FAKE_BRIDGE;
        break;
    case ARCH_MAC99:
        dev = pci_find_device(0x06, 0x00, 0xFF, checkv, checkp);
        if (dev == NULL)
            return -1;
        fake_host = pci_add_host(hostp, dev,
                                 (0x06 << 24) | (0x00 << 16) | (0xFF << 8));
        if (fake_host == NULL)
            return -1;
        fake_host->dev.common.type = PCI_FAKE_HOST;
        dev = &uninorth_fake_bridge;
        if (dev == NULL)
            goto free_fake_host;
        fake_bridge = pci_add_bridge(fake_host, 0, 11, dev,
                                     (0x06 << 24) | (0x00 << 16) | (0xFF << 8),
                                     cfg_base, cfg_len,
                                     cfg_base + 0x00800000,
                                     cfg_base + 0x00C00000,
                                     mem_base, mem_len,
                                     io_base, io_len,
                                     rbase, rlen,
                                     BRIDGE_TYPE_UNINORTH,
                                     &uninorth_pci_ops);
        if (fake_bridge == NULL)
            goto free_fake_host;
        fake_bridge->dev.common.type = PCI_FAKE_BRIDGE;
        fake_bridge->flags |= BRIDGE_TYPE_UNINORTH;
        break;
    case ARCH_POP:
        /* TODO */
        break;
    }
    host = NULL;
    phost = &host;
    for (bus = 0; bus < 256; bus++) {
        for (devfn = 0; devfn < 256; devfn++) {
            /* Find host bridge */
            pci_check_device(hostp, phost, bus, devfn,
                             checkv, checkp, 0x06, 0x00, 0xFF, 2);
            if (host != NULL) {
                *hostp = host;
                OF_finalize_pci_host(host->dev.common.OF_private, bus, 1);
                ret = 0;
                goto done;
            }
        }
    }
 done:
    free(fake_host->bridge);
 free_fake_host:
    free(fake_host);

    return ret;
}

static int pci_check_devices (pci_host_t *host)
{
    int bus, devfn;

    /* Find all PCI bridges */
    printf("Check PCI bridges\n");
    for (bus = 0; bus < 256; bus++) {
        for (devfn = 0; devfn < 256; devfn++) {
            pci_check_device(&host, &host, bus, devfn, 0xFFFF, 0xFFFF,
                             0x06, 0xFF, 0xFF, 1);
        }
    }
    /* Now, find all other devices */
    /* XXX: should recurse thru all host and bridges ! */
    printf("Check PCI devices\n");
    for (bus = 0; bus < 256; bus++) {
        for (devfn = 0; devfn < 256; devfn++) {
            pci_check_device(&host, &host, bus, devfn, 0xFFFF, 0xFFFF,
                             0xFF, 0xFF, 0xFF, 0);
        }
    }

    return 0;
}

pci_host_t *pci_init (void)
{
    pci_host_t *pci_main = NULL, *curh;
    uint32_t rbase, rlen, cfg_base, cfg_len;
    uint32_t mem_base, mem_len, io_base, io_len;
    uint8_t busnum;

    printf("Probing PCI devices\n");
    /* We need to discover PCI bridges and devices */
    switch (arch) {
    case ARCH_PREP:
        /* supposed to have 1 host bridge:
         * - the Motorola Raven PCI bridge
         */
        cfg_base = 0x80000000;
        cfg_len  = 0x00100000;
        mem_base = 0xF0000000;
        mem_len  = 0x10000000;
        io_base  = 0x80000000;
        io_len   = 0x00010000;
#if 0
        rbase    = 0x80C00000; /* ? */
#else
        rbase    = 0x00000000;
#endif
        rlen     = 0x00400000; /* ? */
        if (pci_check_host(&pci_main, cfg_base, cfg_len,
                           mem_base, mem_len, io_base, io_len, rbase, rlen,
                           0x1057, 0x4801) == 0) {
            isa_io_base = io_base;
            busnum++;
        }
        for (curh = pci_main; curh->next != NULL; curh = curh->next)
            continue;
        pci_check_devices(curh);
        break;
    case ARCH_CHRP:
        /* TODO */
        break;
    case ARCH_HEATHROW:
        cfg_base = 0x80000000;
        cfg_len  = 0x7f000000;
        mem_base = 0x80000000;
        mem_len  = 0x01000000;
        io_base  = 0xfe000000;
        io_len   = 0x00800000;
#if 1
        rbase    = 0xfd000000;
        rlen     = 0x01000000;
#else
        rbase    = 0x00000000;
        rlen     = 0x01000000;
#endif
        if (pci_check_host(&pci_main, cfg_base, cfg_len,
                           mem_base, mem_len, io_base, io_len, rbase, rlen,
                           0x1057, 0x0002) == 0) {
            isa_io_base = io_base;
            busnum++;
        }
        for (curh = pci_main; curh->next != NULL; curh = curh->next)
            continue;
        pci_check_devices(curh);
        break;
    case ARCH_MAC99:
        /* We are supposed to have 3 host bridges:
         * - the uninorth AGP bridge at 0xF0000000
         * - the uninorth PCI expansion bridge at 0xF2000000
         * - the uninorth PCI internal bridge at 0xF4000000
         */
        cfg_base = 0xF0000000;
        cfg_len  = 0x02000000;
        mem_base = 0x90000000;
        mem_len  = 0x10000000;
        io_base  = 0xF0000000;
        io_len   = 0x00800000;
        rbase    = 0xF1000000;
        rlen     = 0x01000000;
#if 0
        if (pci_check_host(&pci_main, cfg_base, cfg_len,
                           mem_base, mem_len, io_base, io_len, rbase, rlen,
                           0x106b, 0x0020) == 0) {
            busnum++;
        }
        for (curh = pci_main; curh->next != NULL; curh = curh->next)
            continue;
        pci_check_devices(curh);
#endif

        cfg_base = 0xF2000000;
        cfg_len  = 0x02000000;
        mem_base = 0x80000000;
        mem_len  = 0x10000000;
        io_base  = 0xF2000000;
        io_len   = 0x00800000;
#if 0 // Hack
        rbase    = 0xF3000000;
        rlen     = 0x01000000;
#else
        rbase    = 0x00000000;
        rlen     = 0x01000000;
#endif
        if (pci_check_host(&pci_main, cfg_base, cfg_len,
                           mem_base, mem_len, io_base, io_len, rbase, rlen,
                           0x106b, 0x001F) == 0) {
            isa_io_base = io_base;
            busnum++;
        }
        for (curh = pci_main; curh->next != NULL; curh = curh->next)
            continue;
        pci_check_devices(curh);

#if 0
        cfg_base = 0xF4000000;
        cfg_len  = 0x02000000;
        mem_base = 0xA0000000;
        mem_len  = 0x10000000;
        io_base  = 0xF4000000;
        io_len   = 0x00800000;
        rbase    = 0xF5000000;
        rlen     = 0x01000000;
        if (pci_check_host(&pci_main, cfg_base, cfg_len,
                           mem_base, mem_len, io_base, io_len, rbase, rlen,
                           0x106b, 0x001F) == 0) {
            busnum++;
        }
        for (curh = pci_main; curh->next != NULL; curh = curh->next)
            continue;
        pci_check_devices(curh);
#endif
        break;
    case ARCH_POP:
        /* TODO */
        break;
    }
    printf("PCI probe done (%p)\n", pci_main);

    return pci_main;
}

void pci_get_mem_range (pci_host_t *host, uint32_t *start, uint32_t *len)
{
    *start = host->bridge->mem_base;
    *len = host->bridge->mem_len;
}
