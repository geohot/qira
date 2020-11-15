#ifndef _BZIMAGE_H
#define _BZIMAGE_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/**
 * A bzImage header
 *
 * As documented in Documentation/i386/boot.txt
 */
struct bzimage_header {
	/** The size of the setup in sectors
	 *
	 * If this field contains 0, assume it contains 4.
	 */
	uint8_t setup_sects;
	/** If set, the root is mounted readonly */
	uint16_t root_flags;
	/** DO NOT USE - for bootsect.S use only */
	uint16_t syssize;
	/** DO NOT USE - obsolete */
	uint16_t swap_dev;
	/** DO NOT USE - for bootsect.S use only */
	uint16_t ram_size;
	/** Video mode control */
	uint16_t vid_mode;
	/** Default root device number */
	uint16_t root_dev;
	/** 0xAA55 magic number */
	uint16_t boot_flag;
	/** Jump instruction */
	uint16_t jump;
	/** Magic signature "HdrS" */
	uint32_t header;
	/** Boot protocol version supported */
	uint16_t version;
	/** Boot loader hook (see below) */
	uint32_t realmode_swtch;
	/** The load-low segment (0x1000) (obsolete) */
	uint16_t start_sys;
	/** Pointer to kernel version string */
	uint16_t kernel_version;
	/** Boot loader identifier */
	uint8_t type_of_loader;
	/** Boot protocol option flags */
	uint8_t loadflags;
	/** Move to high memory size (used with hooks) */
	uint16_t setup_move_size;
	/** Boot loader hook (see below) */
	uint32_t code32_start;
	/** initrd load address (set by boot loader) */
	uint32_t ramdisk_image;
	/** initrd size (set by boot loader) */
	uint32_t ramdisk_size;
	/** DO NOT USE - for bootsect.S use only */
	uint32_t bootsect_kludge;
	/** Free memory after setup end */
	uint16_t heap_end_ptr;
	/** Unused */
	uint16_t pad1;
	/** 32-bit pointer to the kernel command line */
	uint32_t cmd_line_ptr;
	/** Highest legal initrd address */
	uint32_t initrd_addr_max;
	/** Physical addr alignment required for kernel	*/
	uint32_t kernel_alignment;
	/** Whether kernel is relocatable or not */
	uint8_t relocatable_kernel;
	/** Unused */
	uint8_t pad2[3];
	/** Maximum size of the kernel command line */
	uint32_t cmdline_size;
} __attribute__ (( packed ));

/** Offset of bzImage header within kernel image */
#define BZI_HDR_OFFSET 0x1f1

/** bzImage boot flag value */
#define BZI_BOOT_FLAG 0xaa55

/** bzImage magic signature value */
#define BZI_SIGNATURE 0x53726448

/** bzImage boot loader identifier for Etherboot */
#define BZI_LOADER_TYPE_ETHERBOOT 0x40

/** bzImage boot loader identifier for iPXE
 *
 * We advertise ourselves as Etherboot version 6.
 */
#define BZI_LOADER_TYPE_IPXE ( BZI_LOADER_TYPE_ETHERBOOT | 0x06 )

/** bzImage "load high" flag */
#define BZI_LOAD_HIGH 0x01

/** Load address for high-loaded kernels */
#define BZI_LOAD_HIGH_ADDR 0x100000

/** Load address for low-loaded kernels */
#define BZI_LOAD_LOW_ADDR 0x10000

/** bzImage "kernel can use heap" flag */
#define BZI_CAN_USE_HEAP 0x80

/** bzImage special video mode "normal" */
#define BZI_VID_MODE_NORMAL 0xffff

/** bzImage special video mode "ext" */
#define BZI_VID_MODE_EXT 0xfffe

/** bzImage special video mode "ask" */
#define BZI_VID_MODE_ASK 0xfffd

/** bzImage maximum initrd address for versions < 2.03 */
#define BZI_INITRD_MAX 0x37ffffff

/** bzImage command-line structure used by older kernels */
struct bzimage_cmdline {
	/** Magic signature */
	uint16_t magic;
	/** Offset to command line */
	uint16_t offset;
} __attribute__ (( packed ));

/** Offset of bzImage command-line structure within kernel image */
#define BZI_CMDLINE_OFFSET 0x20

/** bzImage command line present magic marker value */
#define BZI_CMDLINE_MAGIC 0xa33f

/** Assumed size of real-mode portion (including .bss) */
#define BZI_ASSUMED_RM_SIZE 0x8000

/** Amount of stack space to provide */
#define BZI_STACK_SIZE 0x1000

/** Maximum size of command line */
#define BZI_CMDLINE_SIZE 0x7ff

#endif /* _BZIMAGE_H */
