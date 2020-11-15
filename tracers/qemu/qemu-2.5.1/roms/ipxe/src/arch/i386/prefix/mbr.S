FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

	.text
	.arch i386
	.section ".prefix", "awx", @progbits
	.code16
	.org 0

mbr:
	movw	$exec_sector, %bp
	jmp	find_active_partition
exec_sector:
	ljmp	$0x0000, $0x7c00

#include "bootpart.S"
