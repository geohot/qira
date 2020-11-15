/* -*- sh -*- */

/*
 * Linker script for EFI images
 *
 */

SECTIONS {

    /* The file starts at a virtual address of zero, and sections are
     * contiguous.  Each section is aligned to at least _max_align,
     * which defaults to 32.  Load addresses are equal to virtual
     * addresses.
     */

    _max_align = 32;

    /* Allow plenty of space for file headers */
    . = 0x1000;

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
     */

    . = ALIGN ( _max_align );
    .data : {
	_data = .;
	*(.data)
	*(.data.*)
	KEEP(*(SORT(.tbl.*)))	/* Various tables.  See include/tables.h */
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
	*(.eh_frame)
	*(.eh_frame.*)
	*(.rel)
	*(.rel.*)
	*(.einfo)
	*(.einfo.*)
	*(.discard)
	*(.discard.*)
    }
}
