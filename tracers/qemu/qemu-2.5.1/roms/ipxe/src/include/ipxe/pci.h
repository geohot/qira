#ifndef	_IPXE_PCI_H
#define _IPXE_PCI_H

/** @file
 *
 * PCI bus
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/device.h>
#include <ipxe/tables.h>
#include <ipxe/pci_io.h>

/** PCI vendor ID */
#define PCI_VENDOR_ID		0x00

/** PCI device ID */
#define PCI_DEVICE_ID		0x02

/** PCI command */
#define PCI_COMMAND		0x04
#define PCI_COMMAND_IO			0x0001	/**< I/O space */
#define PCI_COMMAND_MEM			0x0002	/**< Memory space */
#define PCI_COMMAND_MASTER		0x0004	/**< Bus master */
#define PCI_COMMAND_INVALIDATE		0x0010	/**< Mem. write & invalidate */
#define PCI_COMMAND_PARITY		0x0040	/**< Parity error response */
#define PCI_COMMAND_SERR		0x0100	/**< SERR# enable */
#define PCI_COMMAND_INTX_DISABLE	0x0400	/**< Interrupt disable */

/** PCI status */
#define PCI_STATUS		0x06
#define PCI_STATUS_CAP_LIST		0x0010	/**< Capabilities list */
#define PCI_STATUS_PARITY		0x0100	/**< Master data parity error */
#define PCI_STATUS_REC_TARGET_ABORT	0x1000	/**< Received target abort */
#define PCI_STATUS_REC_MASTER_ABORT	0x2000	/**< Received master abort */
#define PCI_STATUS_SIG_SYSTEM_ERROR	0x4000	/**< Signalled system error */
#define PCI_STATUS_DETECTED_PARITY	0x8000	/**< Detected parity error */

/** PCI revision */
#define PCI_REVISION		0x08

/** PCI cache line size */
#define PCI_CACHE_LINE_SIZE	0x0c

/** PCI latency timer */
#define PCI_LATENCY_TIMER	0x0d

/** PCI header type */
#define PCI_HEADER_TYPE         0x0e
#define PCI_HEADER_TYPE_NORMAL		0x00	/**< Normal header */
#define PCI_HEADER_TYPE_BRIDGE		0x01	/**< PCI-to-PCI bridge header */
#define PCI_HEADER_TYPE_CARDBUS		0x02	/**< CardBus header */
#define PCI_HEADER_TYPE_MASK		0x7f	/**< Header type mask */
#define PCI_HEADER_TYPE_MULTI		0x80	/**< Multi-function device */

/** PCI base address registers */
#define PCI_BASE_ADDRESS(n)	( 0x10 + ( 4 * (n) ) )
#define PCI_BASE_ADDRESS_0	PCI_BASE_ADDRESS ( 0 )
#define PCI_BASE_ADDRESS_1	PCI_BASE_ADDRESS ( 1 )
#define PCI_BASE_ADDRESS_2	PCI_BASE_ADDRESS ( 2 )
#define PCI_BASE_ADDRESS_3	PCI_BASE_ADDRESS ( 3 )
#define PCI_BASE_ADDRESS_4	PCI_BASE_ADDRESS ( 4 )
#define PCI_BASE_ADDRESS_5	PCI_BASE_ADDRESS ( 5 )
#define PCI_BASE_ADDRESS_SPACE_IO	0x00000001UL	/**< I/O BAR */
#define	PCI_BASE_ADDRESS_IO_MASK	0x00000003UL	/**< I/O BAR mask */
#define PCI_BASE_ADDRESS_MEM_TYPE_64	0x00000004UL	/**< 64-bit memory */
#define PCI_BASE_ADDRESS_MEM_TYPE_MASK	0x00000006UL	/**< Memory type mask */
#define	PCI_BASE_ADDRESS_MEM_MASK	0x0000000fUL	/**< Memory BAR mask */

/** PCI subsystem vendor ID */
#define PCI_SUBSYSTEM_VENDOR_ID	0x2c

/** PCI subsystem ID */
#define PCI_SUBSYSTEM_ID	0x2e  

/** PCI expansion ROM base address */
#define	PCI_ROM_ADDRESS		0x30

/** PCI capabilities pointer */
#define PCI_CAPABILITY_LIST	0x34

/** CardBus capabilities pointer */
#define PCI_CB_CAPABILITY_LIST	0x14

/** PCI interrupt line */
#define PCI_INTERRUPT_LINE	0x3c

/** Capability ID */
#define PCI_CAP_ID		0x00
#define PCI_CAP_ID_PM			0x01	/**< Power management */
#define PCI_CAP_ID_VPD			0x03	/**< Vital product data */
#define PCI_CAP_ID_VNDR			0x09	/**< Vendor-specific */
#define PCI_CAP_ID_EXP			0x10	/**< PCI Express */

/** Next capability */
#define PCI_CAP_NEXT		0x01

/** Power management control and status */
#define PCI_PM_CTRL		0x04
#define PCI_PM_CTRL_STATE_MASK		0x0003	/**< Current power state */
#define PCI_PM_CTRL_PME_ENABLE		0x0100	/**< PME pin enable */
#define PCI_PM_CTRL_PME_STATUS		0x8000	/**< PME pin status */

/** Uncorrectable error status */
#define PCI_ERR_UNCOR_STATUS	0x04

/** Network controller */
#define PCI_CLASS_NETWORK	0x02

/** Serial bus controller */
#define PCI_CLASS_SERIAL	0x0c
#define PCI_CLASS_SERIAL_USB		0x03	/**< USB controller */
#define PCI_CLASS_SERIAL_USB_UHCI	 0x00	/**< UHCI USB controller */
#define PCI_CLASS_SERIAL_USB_OHCI	 0x10	/**< OHCI USB controller */
#define PCI_CLASS_SERIAL_USB_EHCI	 0x20	/**< ECHI USB controller */
#define PCI_CLASS_SERIAL_USB_XHCI	 0x30	/**< xHCI USB controller */

/** Construct PCI class
 *
 * @v base		Base class (or PCI_ANY_ID)
 * @v sub		Subclass (or PCI_ANY_ID)
 * @v progif		Programming interface (or PCI_ANY_ID)
 */
#define PCI_CLASS( base, sub, progif )					\
	( ( ( (base) & 0xff ) << 16 ) |	( ( (sub) & 0xff ) << 8 ) |	\
	  ( ( (progif) & 0xff) << 0 ) )

/** A PCI device ID list entry */
struct pci_device_id {
	/** Name */
	const char *name;
	/** PCI vendor ID */
	uint16_t vendor;
	/** PCI device ID */
	uint16_t device;
	/** Arbitrary driver data */
	unsigned long driver_data;
};

/** Match-anything ID */
#define PCI_ANY_ID 0xffff

/** A PCI class ID */
struct pci_class_id {
	/** Class */
	uint32_t class;
	/** Class mask */
	uint32_t mask;
};

/** Construct PCI class ID
 *
 * @v base		Base class (or PCI_ANY_ID)
 * @v sub		Subclass (or PCI_ANY_ID)
 * @v progif		Programming interface (or PCI_ANY_ID)
 */
#define PCI_CLASS_ID( base, sub, progif ) {				   \
	.class = PCI_CLASS ( base, sub, progif ),			   \
	.mask = ( ( ( ( (base) == PCI_ANY_ID ) ? 0x00 : 0xff ) << 16 ) |   \
		  ( ( ( (sub) == PCI_ANY_ID ) ? 0x00 : 0xff ) << 8 ) |	   \
		  ( ( ( (progif) == PCI_ANY_ID ) ? 0x00 : 0xff ) << 0 ) ), \
	}

/** A PCI device */
struct pci_device {
	/** Generic device */
	struct device dev;
	/** Memory base
	 *
	 * This is the physical address of the first valid memory BAR.
	 */
	unsigned long membase;
	/**
	 * I/O address
	 *
	 * This is the physical address of the first valid I/O BAR.
	 */
	unsigned long ioaddr;
	/** Vendor ID */
	uint16_t vendor;
	/** Device ID */
	uint16_t device;
	/** Device class */
	uint32_t class;
	/** Interrupt number */
	uint8_t irq;
	/** Bus, device, and function (bus:dev.fn) number */
	uint16_t busdevfn;
	/** Driver for this device */
	struct pci_driver *driver;
	/** Driver-private data
	 *
	 * Use pci_set_drvdata() and pci_get_drvdata() to access this
	 * field.
	 */
	void *priv;
	/** Driver device ID */
	struct pci_device_id *id;
};

/** A PCI driver */
struct pci_driver {
	/** PCI ID table */
	struct pci_device_id *ids;
	/** Number of entries in PCI ID table */
	unsigned int id_count;
	/** PCI class ID */
	struct pci_class_id class;
	/**
	 * Probe device
	 *
	 * @v pci	PCI device
	 * @ret rc	Return status code
	 */
	int ( * probe ) ( struct pci_device *pci );
	/**
	 * Remove device
	 *
	 * @v pci	PCI device
	 */
	void ( * remove ) ( struct pci_device *pci );
};

/** PCI driver table */
#define PCI_DRIVERS __table ( struct pci_driver, "pci_drivers" )

/** Declare a PCI driver */
#define __pci_driver __table_entry ( PCI_DRIVERS, 01 )

/** Declare a fallback PCI driver */
#define __pci_driver_fallback __table_entry ( PCI_DRIVERS, 02 )

#define PCI_BUS( busdevfn )		( ( (busdevfn) >> 8 ) & 0xff )
#define PCI_SLOT( busdevfn )		( ( (busdevfn) >> 3 ) & 0x1f )
#define PCI_FUNC( busdevfn )		( ( (busdevfn) >> 0 ) & 0x07 )
#define PCI_BUSDEVFN( bus, slot, func )	\
	( ( (bus) << 8 ) | ( (slot) << 3 ) | ( (func) << 0 ) )
#define PCI_FIRST_FUNC( busdevfn )	( (busdevfn) & ~0x07 )
#define PCI_LAST_FUNC( busdevfn )	( (busdevfn) | 0x07 )

#define PCI_BASE_CLASS( class )		( (class) >> 16 )
#define PCI_SUB_CLASS( class )		( ( (class) >> 8 ) & 0xff )
#define PCI_PROG_INTF( class )		( (class) & 0xff )

/*
 * PCI_ROM is used to build up entries in a struct pci_id array.  It
 * is also parsed by parserom.pl to generate Makefile rules and files
 * for rom-o-matic.
 *
 * PCI_ID can be used to generate entries without creating a
 * corresponding ROM in the build process.
 */
#define PCI_ID( _vendor, _device, _name, _description, _data ) {	\
	.vendor = _vendor,						\
	.device = _device,						\
	.name = _name,							\
	.driver_data = _data						\
}
#define PCI_ROM( _vendor, _device, _name, _description, _data ) \
	PCI_ID( _vendor, _device, _name, _description, _data )

/** PCI device debug message format */
#define PCI_FMT "PCI %02x:%02x.%x"

/** PCI device debug message arguments */
#define PCI_ARGS( pci )							\
	PCI_BUS ( (pci)->busdevfn ), PCI_SLOT ( (pci)->busdevfn ),	\
	PCI_FUNC ( (pci)->busdevfn )

extern void adjust_pci_device ( struct pci_device *pci );
extern unsigned long pci_bar_start ( struct pci_device *pci,
				     unsigned int reg );
extern int pci_read_config ( struct pci_device *pci );
extern int pci_find_next ( struct pci_device *pci, unsigned int busdevfn );
extern int pci_find_driver ( struct pci_device *pci );
extern int pci_probe ( struct pci_device *pci );
extern void pci_remove ( struct pci_device *pci );
extern int pci_find_capability ( struct pci_device *pci, int capability );
extern unsigned long pci_bar_size ( struct pci_device *pci, unsigned int reg );

/**
 * Initialise PCI device
 *
 * @v pci		PCI device
 * @v busdevfn		PCI bus:dev.fn address
 */
static inline void pci_init ( struct pci_device *pci, unsigned int busdevfn ) {
	pci->busdevfn = busdevfn;
}

/**
 * Set PCI driver
 *
 * @v pci		PCI device
 * @v driver		PCI driver
 * @v id		PCI device ID
 */
static inline void pci_set_driver ( struct pci_device *pci,
				    struct pci_driver *driver,
				    struct pci_device_id *id ) {
	pci->driver = driver;
	pci->id = id;
	pci->dev.driver_name = id->name;
}

/**
 * Set PCI driver-private data
 *
 * @v pci		PCI device
 * @v priv		Private data
 */
static inline void pci_set_drvdata ( struct pci_device *pci, void *priv ) {
	pci->priv = priv;
}

/**
 * Get PCI driver-private data
 *
 * @v pci		PCI device
 * @ret priv		Private data
 */
static inline void * pci_get_drvdata ( struct pci_device *pci ) {
	return pci->priv;
}

#endif	/* _IPXE_PCI_H */
