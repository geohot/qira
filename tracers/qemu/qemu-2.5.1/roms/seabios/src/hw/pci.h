#ifndef __PCI_H
#define __PCI_H

#include "types.h" // u32
#include "list.h" // hlist_node

#define PORT_PCI_CMD           0x0cf8
#define PORT_PCI_REBOOT        0x0cf9
#define PORT_PCI_DATA          0x0cfc

#define PCI_ROM_SLOT 6
#define PCI_NUM_REGIONS 7
#define PCI_BRIDGE_NUM_REGIONS 2

enum pci_region_type {
    PCI_REGION_TYPE_IO,
    PCI_REGION_TYPE_MEM,
    PCI_REGION_TYPE_PREFMEM,
    PCI_REGION_TYPE_COUNT,
};

static inline u8 pci_bdf_to_bus(u16 bdf) {
    return bdf >> 8;
}
static inline u8 pci_bdf_to_devfn(u16 bdf) {
    return bdf & 0xff;
}
static inline u16 pci_bdf_to_busdev(u16 bdf) {
    return bdf & ~0x07;
}
static inline u8 pci_bdf_to_dev(u16 bdf) {
    return (bdf >> 3) & 0x1f;
}
static inline u8 pci_bdf_to_fn(u16 bdf) {
    return bdf & 0x07;
}
static inline u16 pci_to_bdf(int bus, int dev, int fn) {
    return (bus<<8) | (dev<<3) | fn;
}
static inline u16 pci_bus_devfn_to_bdf(int bus, u16 devfn) {
    return (bus << 8) | devfn;
}

void pci_config_writel(u16 bdf, u32 addr, u32 val);
void pci_config_writew(u16 bdf, u32 addr, u16 val);
void pci_config_writeb(u16 bdf, u32 addr, u8 val);
u32 pci_config_readl(u16 bdf, u32 addr);
u16 pci_config_readw(u16 bdf, u32 addr);
u8 pci_config_readb(u16 bdf, u32 addr);
void pci_config_maskw(u16 bdf, u32 addr, u16 off, u16 on);

struct pci_device *pci_find_device(u16 vendid, u16 devid);
struct pci_device *pci_find_class(u16 classid);

struct pci_device {
    u16 bdf;
    u8 rootbus;
    struct hlist_node node;
    struct pci_device *parent;

    // Configuration space device information
    u16 vendor, device;
    u16 class;
    u8 prog_if, revision;
    u8 header_type;
    u8 secondary_bus;

    // Local information on device.
    int have_driver;
};
extern u64 pcimem_start, pcimem_end;
extern u64 pcimem64_start, pcimem64_end;
extern struct hlist_head PCIDevices;
extern int MaxPCIBus;
int pci_probe_host(void);
void pci_probe_devices(void);
static inline u32 pci_classprog(struct pci_device *pci) {
    return (pci->class << 8) | pci->prog_if;
}

#define foreachpci(PCI)                                 \
    hlist_for_each_entry(PCI, &PCIDevices, node)

int pci_next(int bdf, int bus);
#define foreachbdf(BDF, BUS)                                    \
    for (BDF=pci_next(pci_bus_devfn_to_bdf((BUS), 0)-1, (BUS))  \
         ; BDF >= 0                                             \
         ; BDF=pci_next(BDF, (BUS)))

#define PCI_ANY_ID      (~0)
struct pci_device_id {
    u32 vendid;
    u32 devid;
    u32 class;
    u32 class_mask;
    void (*func)(struct pci_device *pci, void *arg);
};

#define PCI_DEVICE(vendor_id, device_id, init_func)     \
    {                                                   \
        .vendid = (vendor_id),                          \
        .devid = (device_id),                           \
        .class = PCI_ANY_ID,                            \
        .class_mask = 0,                                \
        .func = (init_func)                             \
    }

#define PCI_DEVICE_CLASS(vendor_id, device_id, class_code, init_func)   \
    {                                                                   \
        .vendid = (vendor_id),                                          \
        .devid = (device_id),                                           \
        .class = (class_code),                                          \
        .class_mask = ~0,                                               \
        .func = (init_func)                                             \
    }

#define PCI_DEVICE_END                          \
    {                                           \
        .vendid = 0,                            \
    }

int pci_init_device(const struct pci_device_id *ids
                    , struct pci_device *pci, void *arg);
struct pci_device *pci_find_init_device(const struct pci_device_id *ids
                                        , void *arg);
u8 pci_find_capability(struct pci_device *pci, u8 cap_id);
int pci_bridge_has_region(struct pci_device *pci,
                          enum pci_region_type region_type);
void pci_reboot(void);

#endif
