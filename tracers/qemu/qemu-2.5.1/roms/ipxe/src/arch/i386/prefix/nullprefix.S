FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

	.org	0
	.text
	.arch i386

	.section ".prefix", "ax", @progbits
	.code16
_prefix:

	.section ".text16", "ax", @progbits
prefix_exit:

prefix_exit_end:
	.previous
