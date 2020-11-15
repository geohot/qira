#ifndef _IPXE_BOFM_H
#define _IPXE_BOFM_H

/**
 * @file
 *
 * IBM BladeCenter Open Fabric Manager (BOFM)
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/list.h>
#include <ipxe/pci.h>
#include <config/sideband.h>

/** 'IBM ' signature
 *
 * Present in %edi when the BIOS initialisation entry point is called,
 * with the BOFM table pointer in %esi.
 *
 * Defined in section 4.1.2 of the POST/BIOS BOFM I/O Address
 * Re-Assignment Architecture document.
 */
#define IBMs_SIGNATURE ( ( 'I' << 24 ) + ( 'B' << 16 ) + ( 'M' << 8 ) + ' ' )

/** ' IBM' signature
 *
 * Returned in %edi from the BIOS initialisation entry point, with the
 * return code in %dl.
 *
 * Defined in section 4.1.2 of the POST/BIOS BOFM I/O Address
 * Re-Assignment Architecture document.
 */
#define sIBM_SIGNATURE ( ( ' ' << 24 ) + ( 'I' << 16 ) + ( 'B' << 8 ) + 'M' )

/** @defgroup bofmrc BOFM return codes
 *
 * Defined in section 4.1.3 of the POST/BIOS BOFM I/O Address
 * Re-Assignment Architecture document.
 *
 * @{
 */

/** Successful */
#define BOFM_SUCCESS 0x00

/** Invalid action string */
#define BOFM_ERR_INVALID_ACTION 0x01

/** Unsupported parameter structure version */
#define BOFM_ERR_UNSUPPORTED 0x02

/** Device error prohibited MAC/WWN update */
#define BOFM_ERR_DEVICE_ERROR 0x03

/** PCI reset required (may be combined with another return code) */
#define BOFM_PCI_RESET 0x80

/** @} */

/** Skip option ROM initialisation
 *
 * A BOFM BIOS may call the initialisation entry point multiple times;
 * only the last call should result in actual initialisation.
 *
 * This flag is internal to iPXE.
 */
#define BOFM_SKIP_INIT 0x80000000UL

/** BOFM table header
 *
 * Defined in section 4.1 of the Open Fabric Manager Parameter
 * Specification document.
 */
struct bofm_global_header {
	/** Signature */
	uint32_t magic;
	/** Subsignature (action string) */
	uint32_t action;
	/** Data structure version */
	uint8_t version;
	/** Data structure level */
	uint8_t level;
	/** Data structure length */
	uint16_t length;
	/** Data structure checksum */
	uint8_t checksum;
	/** Data structure profile */
	char profile[32];
	/** Data structure global options */
	uint32_t options;
	/** Data structure sequence stamp */
	uint32_t sequence;
} __attribute__ (( packed ));

/** BOFM table header signature
 *
 * Defined in section 4.1.2 of the POST/BIOS BOFM I/O Address
 * Re-Assignment Architecture document.
 */
#define BOFM_IOAA_MAGIC	 ( 'I' + ( 'O' << 8 ) + ( 'A' << 16 ) + ( 'A' << 24 ) )

/** @defgroup bofmaction BOFM header subsignatures (action strings)
 *
 * Defined in section 4.1.2 of the POST/BIOS BOFM I/O Address
 * Re-Assignment Architecture document.
 *
 * @{
 */

/** Update MAC/WWN */
#define BOFM_ACTION_UPDT ( 'U' + ( 'P' << 8 ) + ( 'D' << 16 ) + ( 'T' << 24 ) )

/** Restore MAC/WWN to factory default */
#define BOFM_ACTION_DFLT ( 'D' + ( 'F' << 8 ) + ( 'L' << 16 ) + ( 'T' << 24 ) )

/** Harvest MAC/WWN */
#define BOFM_ACTION_HVST ( 'H' + ( 'V' << 8 ) + ( 'S' << 16 ) + ( 'T' << 24 ) )

/** Update MAC/WWN and initialise device */
#define BOFM_ACTION_PARM ( 'P' + ( 'A' << 8 ) + ( 'R' << 16 ) + ( 'M' << 24 ) )

/** Just initialise the device */
#define BOFM_ACTION_NONE ( 'N' + ( 'O' << 8 ) + ( 'N' << 16 ) + ( 'E' << 24 ) )

/** @} */

/** BOFM section header
 *
 * Defined in section 4.2 of the Open Fabric Manager Parameter
 * Specification document.
 */
struct bofm_section_header {
	/** Signature */
	uint32_t magic;
	/** Length */
	uint16_t length;
} __attribute__ (( packed ));

/** @defgroup bofmsections BOFM section header signatures
 *
 * Defined in section 4.2 of the Open Fabric Manager Parameter
 * Specification document.
 *
 * @{
 */

/** EN start marker */
#define BOFM_EN_MAGIC    ( ' ' + ( ' ' << 8 ) + ( 'E' << 16 ) + ( 'N' << 24 ) )

/** End marker */
#define BOFM_DONE_MAGIC	 ( 'D' + ( 'O' << 8 ) + ( 'N' << 16 ) + ( 'E' << 24 ) )

/** @} */

/** BOFM Ethernet parameter entry
 *
 * Defined in section 5.1 of the Open Fabric Manager Parameter
 * Specification document.
 */
struct bofm_en {
	/** Options */
	uint16_t options;
	/** PCI bus:dev.fn
	 *
	 * Valid only if @c options indicates @c BOFM_EN_MAP_PFA
	 */
	uint16_t busdevfn;
	/** Slot or mezzanine number
	 *
	 * Valid only if @c options indicates @c BOFM_EN_MAP_SLOT_PORT
	 */
	uint8_t slot;
	/** Port number
	 *
	 * Valid only if @c options indicates @c BOFM_EN_MAP_SLOT_PORT
	 */
	uint8_t port;
	/** Multi-port index */
	uint8_t mport;
	/** VLAN tag for MAC address A */
	uint16_t vlan_a;
	/** MAC address A
	 *
	 * MAC address A is the sole MAC address, or the lower
	 * (inclusive) bound of a range of MAC addresses.
	 */
	uint8_t mac_a[6];
	/** VLAN tag for MAC address B */
	uint16_t vlan_b;
	/** MAC address B
	 *
	 * MAC address B is unset, or the upper (inclusive) bound of a
	 * range of MAC addresses
	 */
	uint8_t mac_b[6];
} __attribute__ (( packed ));

/** @defgroup bofmenopts BOFM Ethernet parameter entry options
 *
 * Defined in section 5.1 of the Open Fabric Manager Parameter
 * Specification document.
 *
 * @{
 */

/** Port mapping mask */
#define BOFM_EN_MAP_MASK	0x0001

/** Port mapping is by PCI bus:dev.fn */
#define BOFM_EN_MAP_PFA			0x0000

/** Port mapping is by slot/port */
#define BOFM_EN_MAP_SLOT_PORT		0x0001

/** MAC address B is present */
#define BOFM_EN_EN_B		0x0002

/** VLAN tag for MAC address B is present */
#define BOFM_EN_VLAN_B		0x0004

/** MAC address A is present */
#define BOFM_EN_EN_A		0x0008

/** VLAN tag for MAC address A is present */
#define BOFM_EN_VLAN_A		0x0010

/** Entry consumption indicator mask */
#define BOFM_EN_CSM_MASK	0x00c0

/** Entry has not been used */
#define BOFM_EN_CSM_UNUSED		0x0000

/** Entry has been used successfully */
#define BOFM_EN_CSM_SUCCESS		0x0040

/** Entry has been used but failed */
#define BOFM_EN_CSM_FAILED		0x0080

/** Consumed entry change mask */
#define BOFM_EN_CHG_MASK	0x0100

/** Consumed entry is same as previous active entry */
#define BOFM_EN_CHG_UNCHANGED		0x0000

/** Consumed entry is different than previous active entry */
#define BOFM_EN_CHG_CHANGED		0x0100

/** Ignore values - it's harvest time */
#define BOFM_EN_USAGE_HARVEST	0x1000

/** Use entry values for assignment */
#define BOFM_EN_USAGE_ENTRY	0x0800

/** Use factory default values */
#define BOFM_EN_USAGE_DEFAULT	0x0400

/** Harvest complete */
#define BOFM_EN_HVST		0x2000

/** Harvest request mask */
#define BOFM_EN_RQ_HVST_MASK	0xc000

/** Do not harvest */
#define BOFM_EN_RQ_HVST_NONE		0x0000

/** Harvest factory default values */
#define BOFM_EN_RQ_HVST_DEFAULT		0x4000

/** Harvest active values */
#define BOFM_EN_RQ_HVST_ACTIVE		0xc000

/** @} */

/** BOFM magic value debug message format */
#define BOFM_MAGIC_FMT "'%c%c%c%c'"

/** BOFM magic value debug message arguments */
#define BOFM_MAGIC_ARGS( magic )					\
	( ( (magic) >> 0 ) & 0xff ), ( ( (magic) >> 8 ) & 0xff ),	\
	( ( (magic) >> 16 ) & 0xff ), ( ( (magic) >> 24 ) & 0xff )

/** A BOFM device */
struct bofm_device {
	/** Underlying PCI device */
	struct pci_device *pci;
	/** BOFM device operations */
	struct bofm_operations *op;
	/** List of BOFM devices */
	struct list_head list;
};

/** BOFM device operations */
struct bofm_operations {
	/** Harvest Ethernet MAC
	 *
	 * @v bofm		BOFM device
	 * @v mport		Multi-port index
	 * @v mac		MAC to fill in
	 * @ret rc		Return status code
	 */
	int ( * harvest ) ( struct bofm_device *bofm, unsigned int mport,
			    uint8_t *mac );
	/** Update Ethernet MAC
	 *
	 * @v bofm		BOFM device
	 * @v mport		Multi-port index
	 * @v mac		New MAC
	 * @ret rc		Return status code
	 */
	int ( * update ) ( struct bofm_device *bofm, unsigned int mport,
			   const uint8_t *mac );
};

/** BOFM driver table */
#define BOFM_DRIVERS __table ( struct pci_driver, "bofm_drivers" )

/** Declare a BOFM driver
 *
 * In the common case of non-BOFM-enabled builds, allow any BOFM code
 * to be garbage-collected at link time to save space.
 */
#ifdef CONFIG_BOFM
#define __bofm_driver __table_entry ( BOFM_DRIVERS, 01 )
#else
#define __bofm_driver
#endif

/**
 * Initialise BOFM device
 *
 * @v bofm		BOFM device
 * @v pci		PCI device
 * @v op		BOFM device operations
 */
static inline __attribute__ (( always_inline )) void
bofm_init ( struct bofm_device *bofm, struct pci_device *pci,
	    struct bofm_operations *op ) {
	bofm->pci = pci;
	bofm->op = op;
}

extern int bofm_register ( struct bofm_device *bofm );
extern void bofm_unregister ( struct bofm_device *bofm );
extern int bofm_find_driver ( struct pci_device *pci );
extern int bofm ( userptr_t bofmtab, struct pci_device *pci );
extern void bofm_test ( struct pci_device *pci );

#endif /* _IPXE_BOFM_H */
