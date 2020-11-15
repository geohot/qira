#include "config.h"
#include "libopenbios/bindings.h"
#include "drivers/pci.h"
#include "libc/vsprintf.h"

#include "pci_database.h"

/* PCI devices database */

typedef struct pci_class_t pci_class_t;
typedef struct pci_subclass_t pci_subclass_t;
typedef struct pci_iface_t pci_iface_t;

struct pci_iface_t {
    uint8_t iface;
    const char *name;
    const char *type;
    const pci_dev_t *devices;
    int (*config_cb)(const pci_config_t *config);
    const void *private;
};

struct pci_subclass_t {
    uint8_t subclass;
    const char *name;
    const char *type;
    const pci_dev_t *devices;
    const pci_iface_t *iface;
    int (*config_cb)(const pci_config_t *config);
    const void *private;
};

struct pci_class_t {
    const char *name;
    const char *type;
    const pci_subclass_t *subc;
};

/* Current machine description */

static const pci_subclass_t undef_subclass[] = {
    {
        0xFF, NULL, NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_dev_t scsi_devices[] = {
    {
        /* Virtio-block controller */
        PCI_VENDOR_ID_REDHAT_QUMRANET, PCI_DEVICE_ID_VIRTIO_BLOCK,
        NULL, "virtio-blk", NULL,
        "pci1af4,1001\0pci1af4,1001\0pciclass,01018f\0",
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

static const pci_dev_t ide_devices[] = {
    {
        PCI_VENDOR_ID_CMD, PCI_DEVICE_ID_CMD_646, /* CMD646 IDE controller */
        "pci-ide", "pci-ata", NULL,
	"pci1095,646\0pci1095,646\0pciclass,01018f\0",
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

static const pci_subclass_t mass_subclass[] = {
    {
        PCI_SUBCLASS_STORAGE_SCSI, "SCSI bus controller",
        "scsi", scsi_devices, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_STORAGE_IDE, "IDE controller",
        "ide", ide_devices, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_STORAGE_FLOPPY, "Floppy disk controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_STORAGE_IPI, "IPI bus controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_STORAGE_RAID, "RAID controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_STORAGE_ATA, "ATA controller",
        "ata", NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_STORAGE_OTHER, "misc mass-storage controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_dev_t eth_devices[] = {
    {
        PCI_VENDOR_ID_REALTEK, PCI_DEVICE_ID_REALTEK_RTL8029,
        NULL, "NE2000",   "NE2000 PCI",  NULL,
        0, 0, 0,
        NULL, "ethernet",
    },
    {
        /* Virtio-network controller */
        PCI_VENDOR_ID_REDHAT_QUMRANET, PCI_DEVICE_ID_VIRTIO_NET,
        NULL, "virtio-net", NULL,
        "pci1af4,1000\0pci1af4,1000\0pciclass,020000\0",
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

static const pci_subclass_t net_subclass[] = {
    {
        PCI_SUBCLASS_NETWORK_ETHERNET, "ethernet controller",
        NULL, eth_devices, NULL,
        eth_config_cb, "ethernet",
    },
    {
        PCI_SUBCLASS_NETWORK_TOKEN_RING, "token ring controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_NETWORK_FDDI, "FDDI controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_NETWORK_ATM, "ATM controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_NETWORK_ISDN, "ISDN controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_NETWORK_WORDFIP, "WordFip controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_NETWORK_PICMG214, "PICMG 2.14 controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_NETWORK_OTHER, "misc network controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_dev_t vga_devices[] = {
    {
        PCI_VENDOR_ID_ATI, PCI_DEVICE_ID_ATI_RAGE128_PF,
        NULL, "ATY",      "ATY Rage128", "VGA\0",
        0, 0, 0,
        NULL, NULL,
    },
    {
        PCI_VENDOR_ID_QEMU, PCI_DEVICE_ID_QEMU_VGA,
        NULL, "QEMU,VGA", "Qemu VGA",    "VGA\0",
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

static const struct pci_iface_t vga_iface[] = {
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

static const pci_subclass_t displ_subclass[] = {
    {
        PCI_SUBCLASS_DISPLAY_VGA, "display controller",
        NULL, NULL, vga_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_DISPLAY_XGA, "XGA display controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_DISPLAY_3D, "3D display controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_DISPLAY_OTHER, "misc display controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_subclass_t media_subclass[] = {
    {
        PCI_SUBCLASS_MULTIMEDIA_VIDEO, "video device",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_MULTIMEDIA_AUDIO, "audio device",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_MULTIMEDIA_PHONE, "computer telephony device",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_MULTIMEDIA_OTHER, "misc multimedia device",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_subclass_t mem_subclass[] = {
    {
        PCI_SUBCLASS_MEMORY_RAM, "RAM controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_MEMORY_FLASH, "flash controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};


static const pci_dev_t hbrg_devices[] = {
    {
        PCI_VENDOR_ID_APPLE, PCI_DEVICE_ID_APPLE_U3_AGP, NULL,
        "pci", "AAPL,UniNorth", "u3-agp\0",
        3, 2, 1,
        host_config_cb, NULL,
    },
    {
        PCI_VENDOR_ID_APPLE, PCI_DEVICE_ID_APPLE_UNI_N_AGP, NULL,
        "pci", "AAPL,UniNorth", "uni-north\0",
        3, 2, 1,
        host_config_cb, NULL,
    },
    {
        PCI_VENDOR_ID_APPLE, PCI_DEVICE_ID_APPLE_UNI_N_PCI, NULL,
        "pci", "AAPL,UniNorth", "uni-north\0",
        3, 2, 1,
        host_config_cb, NULL,
    },
    {
        PCI_VENDOR_ID_APPLE, PCI_DEVICE_ID_APPLE_UNI_N_I_PCI, NULL,
        "pci", "AAPL,UniNorth", "uni-north\0",
        3, 2, 1,
        NULL, NULL
    },
    {
        PCI_VENDOR_ID_MOTOROLA, PCI_DEVICE_ID_MOTOROLA_MPC106, "pci",
        "pci", "MOT,MPC106", "grackle\0",
        3, 2, 1,
        host_config_cb, NULL
    },
    {
        PCI_VENDOR_ID_MOTOROLA, PCI_DEVICE_ID_MOTOROLA_RAVEN, NULL,
        "pci", "PREP Host PCI Bridge - Motorola Raven", NULL,
        3, 2, 1,
        host_config_cb, NULL,
    },
    {
        PCI_VENDOR_ID_SUN, PCI_DEVICE_ID_SUN_SABRE, NULL,
        "pci", "SUNW,sabre", "pci108e,a000\0pciclass,0\0",
        3, 2, 1,
        sabre_config_cb, NULL,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

static const pci_dev_t PCIbrg_devices[] = {
    {
        PCI_VENDOR_ID_DEC, PCI_DEVICE_ID_DEC_21154, NULL,
        "pci-bridge", "DEV,21154", "DEV,21154\0pci-bridge\0",
        3, 2, 1,
        bridge_config_cb, NULL,
    },
    {
        PCI_VENDOR_ID_SUN, PCI_DEVICE_ID_SUN_SIMBA, NULL,
        "pci", "SUNW,simba", "pci108e,5000\0pciclass,060400\0",
        3, 2, 1,
        bridge_config_cb, NULL,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

static const pci_dev_t miscbrg_devices[] = {
    {
        PCI_VENDOR_ID_SUN, PCI_DEVICE_ID_SUN_EBUS, NULL,
        "ebus", "ebus", "pci108e,1000\0pciclass,068000\0",
        2, 1, 1,
        ebus_config_cb, NULL,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

static const pci_dev_t isabrg_devices[] = {
    {
        PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82378, NULL,
        "isa", "isa", "pci8086,484\0",
        1, 1, 1,
        i82378_config_cb, NULL,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

static const pci_subclass_t bridg_subclass[] = {
    {
        PCI_SUBCLASS_BRIDGE_HOST, "PCI host bridge",
        "pci", hbrg_devices, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_ISA, "ISA bridge",
        "isa", isabrg_devices, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_EISA, "EISA bridge",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_MC, "MCA bridge",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_PCI, "PCI-to-PCI bridge",
        "pci", PCIbrg_devices, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_PCMCIA, "PCMCIA bridge",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_NUBUS, "NUBUS bridge",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_CARDBUS, "cardbus bridge",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_RACEWAY, "raceway bridge",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_PCI_SEMITP, "semi-transparent PCI-to-PCI bridge",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_IB_PCI, "infiniband-to-PCI bridge",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_BRIDGE_OTHER, "misc PCI bridge",
        NULL, miscbrg_devices, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_iface_t serial_iface[] = {
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

static const pci_iface_t par_iface[] = {
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

static const pci_iface_t modem_iface[] = {
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

static const pci_subclass_t comm_subclass[] = {
    {
        PCI_SUBCLASS_COMMUNICATION_SERIAL, "serial controller",
        NULL, NULL, serial_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_COMMUNICATION_PARALLEL, "parallel port",
        NULL, NULL, par_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_COMMUNICATION_MULTISERIAL, "multiport serial controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_COMMUNICATION_MODEM, "modem",
        NULL, NULL, modem_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_COMMUNICATION_GPIB, "GPIB controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_COMMUNICATION_SC, "smart card",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_COMMUNICATION_OTHER, "misc communication device",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_iface_t pic_iface[] = {
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

static const pci_iface_t dma_iface[] = {
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

static const pci_iface_t tmr_iface[] = {
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

static const pci_iface_t rtc_iface[] = {
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
        PCI_VENDOR_ID_IBM, PCI_DEVICE_ID_IBM_OPENPIC,
        "open-pic", "MPIC", NULL, "chrp,open-pic\0",
        0, 0, 2,
        NULL, NULL,
    },
    /* IBM MPIC2 controller */
    {
        PCI_VENDOR_ID_IBM, PCI_DEVICE_ID_IBM_OPENPIC2,
        "open-pic", "MPIC2", NULL, "chrp,open-pic\0",
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

static const pci_subclass_t sys_subclass[] = {
    {
        PCI_SUBCLASS_SYSTEM_PIC, "PIC",
        NULL, NULL, pic_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SYSTEM_DMA, "DMA controller",
        NULL, NULL, dma_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SYSTEM_TIMER, "system timer",
        NULL, NULL, tmr_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SYSTEM_RTC, "RTC controller",
        NULL, NULL, rtc_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SYSTEM_PCI_HOTPLUG, "PCI hotplug controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SYSTEM_OTHER, "misc system peripheral",
        NULL, sys_devices, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_subclass_t inp_subclass[] = {
    {
        PCI_SUBCLASS_INPUT_KEYBOARD, "keyboard controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_INPUT_PEN, "digitizer",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_INPUT_MOUSE, "mouse controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_INPUT_SCANNER, "scanner controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_INPUT_GAMEPORT, "gameport controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_INPUT_OTHER, "misc input device",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_subclass_t dock_subclass[] = {
    {
        PCI_SUBCLASS_DOCKING_GENERIC, "generic docking station",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_DOCKING_OTHER, "misc docking station",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_subclass_t cpu_subclass[] = {
    {
        PCI_SUBCLASS_PROCESSOR_386, "i386 processor",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_PROCESSOR_486, "i486 processor",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_PROCESSOR_PENTIUM, "pentium processor",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_PROCESSOR_ALPHA, "alpha processor",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_PROCESSOR_POWERPC, "PowerPC processor",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_PROCESSOR_MIPS, "MIPS processor",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_PROCESSOR_CO, "co-processor",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_dev_t usb_devices[] = {
#if defined(CONFIG_QEMU)
    {
        PCI_VENDOR_ID_APPLE, PCI_DEVICE_ID_APPLE_KEYL_USB,
        "usb", "usb", NULL,
	"pci106b,3f\0pciclass,0c0310\0",
        1, 0, 0,
        NULL, NULL,
    },
#endif
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

static const pci_iface_t usb_iface[] = {
    {
        0x00, "UHCI USB controller", NULL,
        NULL, NULL, NULL,
    },
    {
        0x10, "OHCI USB controller", NULL,
        usb_devices, &usb_ohci_config_cb, NULL,
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

static const pci_iface_t ipmi_iface[] = {
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

static const pci_subclass_t ser_subclass[] = {
    {
        PCI_SUBCLASS_SERIAL_FIREWIRE, "Firewire bus controller",
        "ieee1394", NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SERIAL_ACCESS, "ACCESS bus controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SERIAL_SSA, "SSA controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SERIAL_USB, "USB controller",
        "usb", NULL, usb_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SERIAL_FIBER, "fibre channel controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SERIAL_SMBUS, "SMBus controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SERIAL_IB, "InfiniBand controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SERIAL_IPMI, "IPMI interface",
        NULL, NULL, ipmi_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SERIAL_SERCOS, "SERCOS controller",
        NULL, NULL, ipmi_iface,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SERIAL_CANBUS, "CANbus controller",
        NULL, NULL, ipmi_iface,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_subclass_t wrl_subclass[] = {
    {
        PCI_SUBCLASS_WIRELESS_IRDA, "IRDA controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_WIRELESS_CIR, "consumer IR controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_WIRELESS_RF_CONTROLLER, "RF controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_WIRELESS_BLUETOOTH, "bluetooth controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_WIRELESS_BROADBAND, "broadband controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_WIRELESS_OTHER, "misc wireless controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_subclass_t sat_subclass[] = {
    {
        PCI_SUBCLASS_SATELLITE_TV, "satellite TV controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SATELLITE_AUDIO, "satellite audio controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SATELLITE_VOICE, "satellite voice controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SATELLITE_DATA, "satellite data controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_subclass_t crypt_subclass[] = {
    {
        PCI_SUBCLASS_CRYPT_NETWORK, "cryptographic network controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_CRYPT_ENTERTAINMENT,
        "cryptographic entertainment controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_CRYPT_OTHER, "misc cryptographic controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
        NULL, NULL,
    },
};

static const pci_subclass_t spc_subclass[] = {
    {
        PCI_SUBCLASS_SP_DPIO, "DPIO module",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SP_PERF, "performances counters",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SP_SYNCH, "communication synchronisation",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SP_MANAGEMENT, "management card",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        PCI_SUBCLASS_SP_OTHER, "misc signal processing controller",
        NULL, NULL, NULL,
        NULL, NULL,
    },
    {
        0xFF, NULL,
        NULL, NULL, NULL,
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
    { "PCI bridge",                        NULL,             bridg_subclass, },
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

static const pci_dev_t misc_pci[] = {
    /* Heathrow Mac I/O */
    {
        PCI_VENDOR_ID_APPLE, PCI_DEVICE_ID_APPLE_343S1201,
        "mac-io", "mac-io", "AAPL,343S1201", "heathrow\0",
        1, 1, 1,
        &macio_heathrow_config_cb, NULL,
    },
    /* Paddington Mac I/O */
    {
        PCI_VENDOR_ID_APPLE, PCI_DEVICE_ID_APPLE_343S1211,
        "mac-io", "mac-io", "AAPL,343S1211", "paddington\0heathrow\0",
        1, 1, 1,
        &macio_heathrow_config_cb, NULL,
    },
    /* KeyLargo Mac I/O */
    {
        PCI_VENDOR_ID_APPLE, PCI_DEVICE_ID_APPLE_UNI_N_KEYL,
        "mac-io", "mac-io", "AAPL,Keylargo", "Keylargo\0",
        1, 1, 1,
        &macio_keylargo_config_cb, NULL,
    },
    {
        0xFFFF, 0xFFFF,
        NULL, NULL, NULL, NULL,
        -1, -1, -1,
        NULL, NULL,
    },
};

const pci_dev_t *pci_find_device (uint8_t class, uint8_t subclass,
                                  uint8_t iface, uint16_t vendor,
                                  uint16_t product)
{
    int (*config_cb)(const pci_config_t *config);
    const pci_class_t *pclass;
    const pci_subclass_t *psubclass;
    const pci_iface_t *piface;
    const pci_dev_t *dev;
    const void *private;
    pci_dev_t *new;
    const char *name, *type;

    name = "unknown";
    type = "unknown";
    config_cb = NULL;
    private = NULL;

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
    if (dev == NULL)
	goto bad_device;
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
    printk("Cannot manage '%s' PCI device type '%s':\n %x %x (%x %x %x)\n",
           name, type, vendor, product, class, subclass, iface);

    return NULL;
}
