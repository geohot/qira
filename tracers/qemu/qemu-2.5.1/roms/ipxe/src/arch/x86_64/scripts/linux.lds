/* -*- sh -*- */

/*
 * Linker script for x86_64 Linux images
 *
 */

OUTPUT_FORMAT ( "elf64-x86-64", "elf64-x86-64", "elf64-x86-64" )
OUTPUT_ARCH ( i386:x86-64 )

SECTIONS {
	_max_align = 32;

	. = 0x400000;

	/*
	 * The text section
	 *
	 */

	. = ALIGN ( _max_align );
	.text : {
		_text = .;
		*(.text)
		*(.text.*)
		_etext = .;
	}

	/*
	 * The rodata section
	 *
	 */

	. = ALIGN ( _max_align );
	.rodata : {
		_rodata = .;
		*(.rodata)
		*(.rodata.*)
		_erodata = .;
	}

	/*
	 * The data section
	 *
	 * Adjust the address for the data segment.  We want to adjust up to
	 * the same address within the page on the next page up.
	 */

	. = ALIGN (CONSTANT (MAXPAGESIZE)) - ((CONSTANT (MAXPAGESIZE) - .) & (CONSTANT (MAXPAGESIZE) - 1));
	. = DATA_SEGMENT_ALIGN (CONSTANT (MAXPAGESIZE), CONSTANT (COMMONPAGESIZE));
	.data : {
		_data = .;
		*(.data)
		*(.data.*)
		KEEP(*(SORT(.tbl.*)))
		KEEP(*(.provided))
		KEEP(*(.provided.*))
		_edata = .;
	}

	/*
	 * The bss section
	 *
	 */

	. = ALIGN ( _max_align );
	.bss : {
		_bss = .;
		*(.bss)
		*(.bss.*)
		*(COMMON)
		_ebss = .;
	}

	/*
	 * Weak symbols that need zero values if not otherwise defined
	 *
	 */

	.weak 0x0 : {
		_weak = .;
		*(.weak)
		*(.weak.*)
		_eweak = .;
	}
	_assert = ASSERT ( ( _weak == _eweak ), ".weak is non-zero length" );

	/*
	 * Dispose of the comment and note sections to make the link map
	 * easier to read
	 *
	 */

	/DISCARD/ : {
		*(.comment)
		*(.comment.*)
		*(.note)
		*(.note.*)
		*(.rel)
		*(.rel.*)
		*(.discard)
		*(.discard.*)
	}
}
