#ifndef _IPXE_VESAFB_H
#define _IPXE_VESAFB_H

/** @file
 *
 * VESA frame buffer console
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <realmode.h>

/** INT 10,4f00: return controller information */
#define VBE_CONTROLLER_INFO 0x4f00

/** VBE controller information */
struct vbe_controller_info {
	/** VBE signature */
	uint32_t vbe_signature;
	/** VBE minor version */
	uint8_t vbe_minor_version;
	/** VBE major version */
	uint8_t vbe_major_version;
	/** Pointer to OEM string */
	struct segoff oem_string_ptr;
	/** Capabilities of graphics controller */
	uint32_t capabilities;
	/** Pointer to video mode list */
	struct segoff video_mode_ptr;
	/** Number of 64kB memory blocks */
	uint16_t total_memory;
	/** VBE implementation software revision */
	uint16_t oem_software_rev;
	/** Pointer to vendor name string */
	struct segoff oem_vendor_name_ptr;
	/** Pointer to product name string */
	struct segoff oem_product_name_ptr;
	/** Pointer to product revision string */
	struct segoff oem_product_rev_ptr;
	/** Reserved for VBE implementation scratch area */
	uint8_t reserved[222];
	/* VBE2.0 defines an additional 256-byte data area for
	 * including the OEM strings inline within the VBE information
	 * block; we omit this to reduce the amount of base memory
	 * required for VBE calls.
	 */
} __attribute__ (( packed ));

/** VBE controller information signature */
#define VBE_CONTROLLER_SIGNATURE \
	( ( 'V' << 0 ) | ( 'E' << 8 ) | ( 'S' << 16 ) | ( 'A' << 24 ) )

/** VBE mode list end marker */
#define VBE_MODE_END 0xffff

/** INT 10,4f01: return VBE mode information */
#define VBE_MODE_INFO 0x4f01

/** VBE mode information */
struct vbe_mode_info {
	/** Mode attributes */
	uint16_t mode_attributes;
	/** Window A attributes */
	uint8_t win_a_attributes;
	/** Window B attributes */
	uint8_t win_b_attributes;
	/** Window granularity */
	uint16_t win_granularity;
	/** Window size */
	uint16_t win_size;
	/** Window A start segment */
	uint16_t win_a_segment;
	/** Window B start segment */
	uint16_t win_b_segment;
	/** Pointer to window function */
	struct segoff win_func_ptr;
	/** Bytes per scan line */
	uint16_t bytes_per_scan_line;
	/** Horizontal resolution in pixels or characters */
	uint16_t x_resolution;
	/** Vertical resolution in pixels or characters */
	uint16_t y_resolution;
	/** Character cell width in pixels */
	uint8_t x_char_size;
	/** Character cell height in pixels */
	uint8_t y_char_size;
	/** Number of memory planes */
	uint8_t number_of_planes;
	/** Bits per pixel */
	uint8_t bits_per_pixel;
	/** Number of banks */
	uint8_t number_of_banks;
	/** Memory model type */
	uint8_t memory_model;
	/** Bank size in kB */
	uint8_t bank_size;
	/** Number of images */
	uint8_t number_of_image_pages;
	/** Reserved for page function */
	uint8_t reserved_1;
	/** Size of direct colour red mask in bits */
	uint8_t red_mask_size;
	/** Bit position of LSB of red mask */
	uint8_t red_field_position;
	/** Size of direct colour green mask in bits */
	uint8_t green_mask_size;
	/** Bit position of LSB of green mask */
	uint8_t green_field_position;
	/** Size of direct colour blue mask in bits */
	uint8_t blue_mask_size;
	/** Bit position of LSB of blue mask */
	uint8_t blue_field_position;
	/** Size of direct colour reserved mask in bits */
	uint8_t rsvd_mask_size;
	/** Bit position of LSB of reserved mask */
	uint8_t rsvd_field_position;
	/** Direct colour mode attributes */
	uint8_t direct_colour_mode_info;
	/** Physical address for flat memory frame buffer */
	uint32_t phys_base_ptr;
	/** Pointer to start of off-screen memory */
	uint32_t off_screen_mem_offset;
	/** Amount of off-screen memory in 1kB units */
	uint16_t off_screen_mem_size;
	/** Reserved */
	uint8_t reserved_2[206];
} __attribute__ (( packed ));

/** VBE mode attributes */
enum vbe_mode_attributes {
	/** Mode supported in hardware */
	VBE_MODE_ATTR_SUPPORTED = 0x0001,
	/** TTY output functions supported by BIOS */
	VBE_MODE_ATTR_TTY = 0x0004,
	/** Colour mode */
	VBE_MODE_ATTR_COLOUR = 0x0008,
	/** Graphics mode */
	VBE_MODE_ATTR_GRAPHICS = 0x0010,
	/** Not a VGA compatible mode */
	VBE_MODE_ATTR_NOT_VGA = 0x0020,
	/** VGA compatible windowed memory mode is not available */
	VBE_MODE_ATTR_NOT_WINDOWED = 0x0040,
	/** Linear frame buffer mode is available */
	VBE_MODE_ATTR_LINEAR = 0x0080,
	/** Double scan mode is available */
	VBE_MODE_ATTR_DOUBLE = 0x0100,
	/** Interlaced mode is available */
	VBE_MODE_ATTR_INTERLACED = 0x0200,
	/** Hardware triple buffering support */
	VBE_MODE_ATTR_TRIPLE_BUF = 0x0400,
	/** Hardware stereoscopic display support */
	VBE_MODE_ATTR_STEREO = 0x0800,
	/** Dual display start address support */
	VBE_MODE_ATTR_DUAL = 0x1000,
};

/** VBE mode memory models */
enum vbe_mode_memory_model {
	/** Text mode */
	VBE_MODE_MODEL_TEXT = 0x00,
	/** CGA graphics mode */
	VBE_MODE_MODEL_CGA = 0x01,
	/** Hercules graphics mode */
	VBE_MODE_MODEL_HERCULES = 0x02,
	/** Planar mode */
	VBE_MODE_MODEL_PLANAR = 0x03,
	/** Packed pixel mode */
	VBE_MODE_MODEL_PACKED_PIXEL = 0x04,
	/** Non-chain 4, 256 colour mode */
	VBE_MODE_MODEL_NON_CHAIN_4 = 0x05,
	/** Direct colour mode */
	VBE_MODE_MODEL_DIRECT_COLOUR = 0x06,
	/** YUV mode */
	VBE_MODE_MODEL_YUV = 0x07,
};

/** INT 10,4f02: set VBE mode */
#define VBE_SET_MODE 0x4f02

/** VBE linear frame buffer mode bit */
#define VBE_MODE_LINEAR 0x4000

/** INT 10,1130: get font information */
#define VBE_GET_FONT 0x1130

/** Font sets */
enum vbe_font_set {
	/** 8x14 character font */
	VBE_FONT_8x14 = 0x0200,
	/** 8x8 double dot font */
	VBE_FONT_8x8_DOUBLE = 0x0300,
	/** 8x8 double dot font (high 128 characters) */
	VBE_FONT_8x8_DOUBLE_HIGH = 0x0400,
	/** 9x14 alpha alternate font */
	VBE_FONT_9x14_ALPHA_ALT = 0x0500,
	/** 8x16 font */
	VBE_FONT_8x16 = 0x0600,
	/** 9x16 alternate font */
	VBE_FONT_9x16_ALT = 0x0700,
};

/** INT 10,00: set VGA mode */
#define VBE_SET_VGA_MODE 0x0000

/** INT 10,0f: get VGA mode */
#define VBE_GET_VGA_MODE 0x0f00

#endif /* _IPXE_VESAFB_H */
