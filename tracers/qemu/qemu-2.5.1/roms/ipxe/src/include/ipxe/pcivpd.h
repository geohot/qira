#ifndef _IPXE_PCIVPD_H
#define _IPXE_PCIVPD_H

/**
 * @file
 *
 * PCI Vital Product Data
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <byteswap.h>
#include <ipxe/isapnp.h>
#include <ipxe/pci.h>

/** PCI VPD address register */
#define PCI_VPD_ADDRESS 0x02

/** PCI VPD write flag */
#define PCI_VPD_FLAG 0x8000

/** PCI VPD data register */
#define PCI_VPD_DATA 0x04

/** A PCI VPD field */
struct pci_vpd_field {
	/** Keyword */
	uint16_t keyword;
	/** Length */
	uint8_t len;
} __attribute__ (( packed ));

/** Maximum PCI VPD field length */
#define PCI_VPD_MAX_LEN 0xff

/** Construct PCI VPD field descriptor
 *
 * @v tag		ISAPnP tag
 * @v keyword1		First character of keyword
 * @v keyword2		Second character of keyword
 * @ret field		VPD field descriptor
 */
#define PCI_VPD_FIELD( tag, keyword1, keyword2 ) \
	( ( (tag) << 16 ) | ( (keyword2) << 8 ) | ( (keyword1) << 0 ) )

/** Construct PCI VPD whole-tag field descriptor
 *
 * @v tag		ISAPnP tag
 * @ret field		VPD field descriptor
 */
#define PCI_VPD_WHOLE_TAG_FIELD( tag ) PCI_VPD_FIELD ( (tag), '\0', '\0' )

/** Extract PCI VPD ISAPnP tag
 *
 * @v field		VPD field descriptor
 * @ret tag		ISAPnP tag
 */
#define PCI_VPD_TAG( field ) ( (field) >> 16 )

/** Extract PCI VPD keyword
 *
 * @v field		VPD field descriptor
 * @ret keyword		Keyword
 */
#define PCI_VPD_KEYWORD( field ) ( cpu_to_le16 ( (field) & 0xffff ) )

/** PCI VPD field debug message format */
#define PCI_VPD_FIELD_FMT "%c%c"

/** PCI VPD field debug message arguments */
#define PCI_VPD_FIELD_ARGS( field ) \
	( (field) >> 0 ), ( (field) >> 8 )

/** PCI VPD Read-Only field tag */
#define PCI_VPD_TAG_RO 0x90

/** PCI VPD Read-Write field tag */
#define PCI_VPD_TAG_RW 0x91

/** PCI VPD Card Name field descriptor */
#define PCI_VPD_FIELD_NAME PCI_VPD_WHOLE_TAG_FIELD ( ISAPNP_TAG_ANSISTR )

/** PCI VPD Part Number field descriptor */
#define PCI_VPD_FIELD_PN PCI_VPD_FIELD ( PCI_VPD_TAG_RO, 'P', 'N' )

/** PCI VPD Engineering Change Level field descriptor */
#define PCI_VPD_FIELD_EC PCI_VPD_FIELD ( PCI_VPD_TAG_RO, 'E', 'C' )

/** PCI VPD Fabric Geography field descriptor */
#define PCI_VPD_FIELD_FG PCI_VPD_FIELD ( PCI_VPD_TAG_RO, 'F', 'G' )

/** PCI VPD Location field descriptor */
#define PCI_VPD_FIELD_LC PCI_VPD_FIELD ( PCI_VPD_TAG_RO, 'L', 'C' )

/** PCI VPD Manufacturer ID field descriptor */
#define PCI_VPD_FIELD_MN PCI_VPD_FIELD ( PCI_VPD_TAG_RO, 'M', 'N' )

/** PCI VPD PCI Geography field descriptor */
#define PCI_VPD_FIELD_PG PCI_VPD_FIELD ( PCI_VPD_TAG_RO, 'P', 'G' )

/** PCI VPD Serial Number field descriptor */
#define PCI_VPD_FIELD_SN PCI_VPD_FIELD ( PCI_VPD_TAG_RO, 'S', 'N' )

/** PCI VPD Extended Capability field descriptor */
#define PCI_VPD_FIELD_CP PCI_VPD_FIELD ( PCI_VPD_TAG_RO, 'C', 'P' )

/** PCI VPD Checksum and Reserved field descriptor */
#define PCI_VPD_FIELD_RV PCI_VPD_FIELD ( PCI_VPD_TAG_RO, 'R', 'V' )

/** PCI VPD Asset Tag field descriptor */
#define PCI_VPD_FIELD_YA PCI_VPD_FIELD ( PCI_VPD_TAG_RW, 'Y', 'A' )

/** PCI VPD Remaining Read/Write Area field descriptor */
#define PCI_VPD_FIELD_RW PCI_VPD_FIELD ( PCI_VPD_TAG_RW, 'R', 'W' )

/** Maximum wait for PCI VPD (in ms) */
#define PCI_VPD_MAX_WAIT_MS 100

/** PCI VPD cache */
struct pci_vpd_cache {
	/** Address */
	int address;
	/** Data */
	uint32_t data;
};

/** PCI VPD */
struct pci_vpd {
	/** PCI device */
	struct pci_device *pci;
	/** VPD capability offset */
	int cap;
	/** Read cache */
	struct pci_vpd_cache cache;
};

/**
 * Check for presence of PCI VPD
 *
 * @v vpd		PCI VPD
 * @ret is_present	VPD is present
 */
static inline __attribute__ (( always_inline )) int
pci_vpd_is_present ( struct pci_vpd *vpd ) {
	return ( vpd->cap != 0 );
}

/**
 * Check if PCI VPD read cache is valid
 *
 * @v vpd		PCI VPD
 * @ret is_valid	Read cache is valid
 */
static inline __attribute__ (( always_inline )) int
pci_vpd_cache_is_valid ( struct pci_vpd *vpd ) {
	return ( vpd->cache.address >= 0 );
}

/**
 * Invalidate PCI VPD read cache
 *
 * @v vpd		PCI VPD
 */
static inline __attribute__ (( always_inline )) void
pci_vpd_invalidate_cache ( struct pci_vpd *vpd ) {
	vpd->cache.address = -1;
}

extern int pci_vpd_init ( struct pci_vpd *vpd, struct pci_device *pci );
extern int pci_vpd_read ( struct pci_vpd *vpd, unsigned int address,
			  void *buf, size_t len );
extern int pci_vpd_write ( struct pci_vpd *vpd, unsigned int address,
			   const void *buf, size_t len );
extern int pci_vpd_find ( struct pci_vpd *vpd, unsigned int field,
			  unsigned int *address, size_t *len );
extern int pci_vpd_resize ( struct pci_vpd *vpd, unsigned int field,
			    size_t len, unsigned int *address );

#endif /* _IPXE_PCIVPD_H */
