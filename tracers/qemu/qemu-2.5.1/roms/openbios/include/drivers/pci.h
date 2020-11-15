#ifndef _H_PCI
#define _H_PCI

typedef uint32_t pci_addr;

typedef struct pci_arch_t pci_arch_t;

struct pci_arch_t {
	const char * name;
	uint16_t vendor_id;
	uint16_t device_id;
	unsigned long cfg_addr;
	unsigned long cfg_data;
	unsigned long cfg_base;
	unsigned long cfg_len;
	unsigned long host_pci_base; /* offset of PCI memory space within host memory space */
	unsigned long pci_mem_base; /* in PCI memory space */
	unsigned long mem_len;
	unsigned long io_base;
	unsigned long io_len;
	unsigned long rbase;
	unsigned long rlen;
	uint8_t irqs[4];
};

extern const pci_arch_t *arch;

/* Device tree offsets */

#define PCI_INT_MAP_PCI0         0
#define PCI_INT_MAP_PCI1         1
#define PCI_INT_MAP_PCI2         2
#define PCI_INT_MAP_PCI_INT      3
#define PCI_INT_MAP_PIC_HANDLE   4
#define PCI_INT_MAP_PIC_INT      5
#define PCI_INT_MAP_PIC_POL      6

/* Device classes and subclasses */

#define PCI_BASE_CLASS_STORAGE           0x01
#define PCI_SUBCLASS_STORAGE_SCSI        0x00
#define PCI_SUBCLASS_STORAGE_IDE         0x01
#define PCI_SUBCLASS_STORAGE_FLOPPY      0x02
#define PCI_SUBCLASS_STORAGE_IPI         0x03
#define PCI_SUBCLASS_STORAGE_RAID        0x04
#define PCI_SUBCLASS_STORAGE_ATA         0x05
#define PCI_SUBCLASS_STORAGE_SAS         0x07
#define PCI_SUBCLASS_STORAGE_OTHER       0x80

#define PCI_BASE_CLASS_NETWORK           0x02
#define PCI_SUBCLASS_NETWORK_ETHERNET    0x00
#define PCI_SUBCLASS_NETWORK_TOKEN_RING  0x01
#define PCI_SUBCLASS_NETWORK_FDDI        0x02
#define PCI_SUBCLASS_NETWORK_ATM         0x03
#define PCI_SUBCLASS_NETWORK_ISDN        0x04
#define PCI_SUBCLASS_NETWORK_WORDFIP     0x05
#define PCI_SUBCLASS_NETWORK_PICMG214    0x06
#define PCI_SUBCLASS_NETWORK_OTHER       0x80

#define PCI_BASE_CLASS_DISPLAY           0x03
#define PCI_SUBCLASS_DISPLAY_VGA         0x00
#define PCI_SUBCLASS_DISPLAY_XGA         0x01
#define PCI_SUBCLASS_DISPLAY_3D          0x02
#define PCI_SUBCLASS_DISPLAY_OTHER       0x80

#define PCI_BASE_CLASS_MULTIMEDIA        0x04
#define PCI_SUBCLASS_MULTIMEDIA_VIDEO    0x00
#define PCI_SUBCLASS_MULTIMEDIA_AUDIO    0x01
#define PCI_SUBCLASS_MULTIMEDIA_PHONE    0x02
#define PCI_SUBCLASS_MULTIMEDIA_OTHER    0x80

#define PCI_BASE_CLASS_MEMORY            0x05
#define PCI_SUBCLASS_MEMORY_RAM          0x00
#define PCI_SUBCLASS_MEMORY_FLASH        0x01

#define PCI_BASE_CLASS_BRIDGE            0x06
#define PCI_SUBCLASS_BRIDGE_HOST         0x00
#define PCI_SUBCLASS_BRIDGE_ISA          0x01
#define PCI_SUBCLASS_BRIDGE_EISA         0x02
#define PCI_SUBCLASS_BRIDGE_MC           0x03
#define PCI_SUBCLASS_BRIDGE_PCI          0x04
#define PCI_SUBCLASS_BRIDGE_PCMCIA       0x05
#define PCI_SUBCLASS_BRIDGE_NUBUS        0x06
#define PCI_SUBCLASS_BRIDGE_CARDBUS      0x07
#define PCI_SUBCLASS_BRIDGE_RACEWAY      0x08
#define PCI_SUBCLASS_BRIDGE_PCI_SEMITP   0x09
#define PCI_SUBCLASS_BRIDGE_IB_PCI       0x0a
#define PCI_SUBCLASS_BRIDGE_OTHER        0x80

#define PCI_BASE_CLASS_COMMUNICATION     0x07
#define PCI_SUBCLASS_COMMUNICATION_SERIAL 0x00
#define PCI_SUBCLASS_COMMUNICATION_PARALLEL 0x01
#define PCI_SUBCLASS_COMMUNICATION_MULTISERIAL 0x02
#define PCI_SUBCLASS_COMMUNICATION_MODEM 0x03
#define PCI_SUBCLASS_COMMUNICATION_GPIB  0x04
#define PCI_SUBCLASS_COMMUNICATION_SC    0x05
#define PCI_SUBCLASS_COMMUNICATION_OTHER 0x80

#define PCI_BASE_CLASS_SYSTEM            0x08
#define PCI_SUBCLASS_SYSTEM_PIC          0x00
#define PCI_SUBCLASS_SYSTEM_DMA          0x01
#define PCI_SUBCLASS_SYSTEM_TIMER        0x02
#define PCI_SUBCLASS_SYSTEM_RTC          0x03
#define PCI_SUBCLASS_SYSTEM_PCI_HOTPLUG  0x04
#define PCI_SUBCLASS_SYSTEM_OTHER        0x80

#define PCI_BASE_CLASS_INPUT             0x09
#define PCI_SUBCLASS_INPUT_KEYBOARD      0x00
#define PCI_SUBCLASS_INPUT_PEN           0x01
#define PCI_SUBCLASS_INPUT_MOUSE         0x02
#define PCI_SUBCLASS_INPUT_SCANNER       0x03
#define PCI_SUBCLASS_INPUT_GAMEPORT      0x04
#define PCI_SUBCLASS_INPUT_OTHER         0x80

#define PCI_BASE_CLASS_DOCKING           0x0a
#define PCI_SUBCLASS_DOCKING_GENERIC     0x00
#define PCI_SUBCLASS_DOCKING_OTHER       0x80

#define PCI_BASE_CLASS_PROCESSOR         0x0b
#define PCI_SUBCLASS_PROCESSOR_386       0x00
#define PCI_SUBCLASS_PROCESSOR_486       0x01
#define PCI_SUBCLASS_PROCESSOR_PENTIUM   0x02
#define PCI_SUBCLASS_PROCESSOR_ALPHA     0x10
#define PCI_SUBCLASS_PROCESSOR_POWERPC   0x20
#define PCI_SUBCLASS_PROCESSOR_MIPS      0x30
#define PCI_SUBCLASS_PROCESSOR_CO        0x40

#define PCI_BASE_CLASS_SERIAL            0x0c
#define PCI_SUBCLASS_SERIAL_FIREWIRE     0x00
#define PCI_SUBCLASS_SERIAL_ACCESS       0x01
#define PCI_SUBCLASS_SERIAL_SSA          0x02
#define PCI_SUBCLASS_SERIAL_USB          0x03
#define PCI_SUBCLASS_SERIAL_FIBER        0x04
#define PCI_SUBCLASS_SERIAL_SMBUS        0x05
#define PCI_SUBCLASS_SERIAL_IB           0x06
#define PCI_SUBCLASS_SERIAL_IPMI         0x07
#define PCI_SUBCLASS_SERIAL_SERCOS       0x08
#define PCI_SUBCLASS_SERIAL_CANBUS       0x09

#define PCI_BASE_CLASS_WIRELESS          0x0d
#define PCI_SUBCLASS_WIRELESS_IRDA       0x00
#define PCI_SUBCLASS_WIRELESS_CIR        0x01
#define PCI_SUBCLASS_WIRELESS_RF_CONTROLLER 0x10
#define PCI_SUBCLASS_WIRELESS_BLUETOOTH  0x11
#define PCI_SUBCLASS_WIRELESS_BROADBAND  0x12
#define PCI_SUBCLASS_WIRELESS_OTHER      0x80

#define PCI_BASE_CLASS_SATELLITE         0x0f
#define PCI_SUBCLASS_SATELLITE_TV        0x00
#define PCI_SUBCLASS_SATELLITE_AUDIO     0x01
#define PCI_SUBCLASS_SATELLITE_VOICE     0x03
#define PCI_SUBCLASS_SATELLITE_DATA      0x04

#define PCI_BASE_CLASS_CRYPT             0x10
#define PCI_SUBCLASS_CRYPT_NETWORK       0x00
#define PCI_SUBCLASS_CRYPT_ENTERTAINMENT 0x01
#define PCI_SUBCLASS_CRYPT_OTHER         0x80

#define PCI_BASE_CLASS_SIGNAL_PROCESSING 0x11
#define PCI_SUBCLASS_SP_DPIO             0x00
#define PCI_SUBCLASS_SP_PERF             0x01
#define PCI_SUBCLASS_SP_SYNCH            0x10
#define PCI_SUBCLASS_SP_MANAGEMENT       0x20
#define PCI_SUBCLASS_SP_OTHER            0x80

#define PCI_CLASS_OTHERS                 0xff

/* Vendors and devices. */

#define PCI_VENDOR_ID_ATI                0x1002
#define PCI_DEVICE_ID_ATI_RAGE128_PF     0x5046

#define PCI_VENDOR_ID_DEC                0x1011
#define PCI_DEVICE_ID_DEC_21154          0x0026

#define PCI_VENDOR_ID_IBM                0x1014
#define PCI_DEVICE_ID_IBM_OPENPIC        0x0002
#define PCI_DEVICE_ID_IBM_OPENPIC2       0xffff

#define PCI_VENDOR_ID_MOTOROLA           0x1057
#define PCI_DEVICE_ID_MOTOROLA_MPC106    0x0002
#define PCI_DEVICE_ID_MOTOROLA_RAVEN     0x4801

#define PCI_VENDOR_ID_APPLE              0x106b
#define PCI_DEVICE_ID_APPLE_343S1201     0x0010
#define PCI_DEVICE_ID_APPLE_343S1211     0x0017
#define PCI_DEVICE_ID_APPLE_UNI_N_I_PCI  0x001e
#define PCI_DEVICE_ID_APPLE_UNI_N_PCI    0x001f
#define PCI_DEVICE_ID_APPLE_UNI_N_AGP    0x0020
#define PCI_DEVICE_ID_APPLE_UNI_N_KEYL   0x0022
#define PCI_DEVICE_ID_APPLE_KEYL_USB     0x003f
#define PCI_DEVICE_ID_APPLE_U3_AGP       0x004b

#define PCI_VENDOR_ID_SUN                0x108e
#define PCI_DEVICE_ID_SUN_EBUS           0x1000
#define PCI_DEVICE_ID_SUN_SIMBA          0x5000
#define PCI_DEVICE_ID_SUN_PBM            0x8000
#define PCI_DEVICE_ID_SUN_SABRE          0xa000

#define PCI_VENDOR_ID_CMD                0x1095
#define PCI_DEVICE_ID_CMD_646            0x0646

#define PCI_VENDOR_ID_REALTEK            0x10ec
#define PCI_DEVICE_ID_REALTEK_RTL8029    0x8029

#define PCI_VENDOR_ID_QEMU               0x1234
#define PCI_DEVICE_ID_QEMU_VGA           0x1111

#define PCI_VENDOR_ID_REDHAT_QUMRANET    0x1af4
#define PCI_DEVICE_ID_VIRTIO_NET         0x1000
#define PCI_DEVICE_ID_VIRTIO_BLOCK       0x1001

#define PCI_VENDOR_ID_INTEL              0x8086
#define PCI_DEVICE_ID_INTEL_82378        0x0484
#define PCI_DEVICE_ID_INTEL_82441        0x1237

#endif	/* _H_PCI */
