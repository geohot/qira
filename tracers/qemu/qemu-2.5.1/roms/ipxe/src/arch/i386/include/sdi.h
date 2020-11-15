#ifndef _SDI_H
#define _SDI_H

/** @file
 *
 * System Deployment Image (SDI)
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** SDI image header */
struct sdi_header {
	/** Signature */
	uint32_t magic;
	/** Version (as an ASCII string) */
	uint32_t version;
	/** Reserved */
	uint8_t reserved[8];
	/** Boot code offset */
	uint64_t boot_offset;
	/** Boot code size */
	uint64_t boot_size;
} __attribute__ (( packed ));

/** SDI image signature */
#define SDI_MAGIC \
	( ( '$' << 0 ) | ( 'S' << 8 ) | ( 'D' << 16 ) | ( 'I' << 24 ) )

/** SDI boot segment */
#define SDI_BOOT_SEG 0x0000

/** SDI boot offset */
#define SDI_BOOT_OFF 0x7c00

/** Constant to binary-OR with physical address of SDI image */
#define SDI_WTF 0x41

#endif /* _SDI_H */
