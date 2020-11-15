FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

	.text
	.arch i386
	.section ".prefix", "awx", @progbits
	.code16
	.org 0

#include "mbr.S"

/* Partition table: 64 heads, 32 sectors/track (ZIP-drive compatible) */
	.org 446
	.space 16
	.space 16
	/* Partition 3: log partition (for CONSOLE_INT13) */
	.byte 0x00, 0x01, 0x01, 0x00
	.byte 0xe0, 0x3f, 0x20, 0x00
	.long 0x00000020
	.long 0x000007e0
	/* Partition 4: boot partition */
	.byte 0x80, 0x00, 0x01, 0x01
	.byte 0xeb, 0x3f, 0x20, 0x02
	.long 0x00000800
	.long 0x00001000

	.org 510
	.byte 0x55, 0xaa

/* Skip to start of log partition */
	.org 32 * 512
	.ascii "iPXE LOG\n\n"

/* Skip to start of boot partition */
	.org 2048 * 512
