/* -*- sh -*- */

/*
 * Linker script for i386 images
 *
 */

OUTPUT_FORMAT ( "elf32-i386", "elf32-i386", "elf32-i386" )
OUTPUT_ARCH ( i386 )

SECTIONS {

    /* All sections in the resulting file have consecutive load
     * addresses, but may have individual link addresses depending on
     * the memory model being used.
     *
     * The linker symbols _prefix_link_addr, load_addr, and
     * _max_align may be specified explicitly.  If not specified, they
     * will default to:
     *
     *   _prefix_link_addr	= 0
     *   _load_addr		= 0
     *   _max_align		= 16
     * 
     * We guarantee alignment of virtual addresses to any alignment
     * specified by the constituent object files (e.g. via
     * __attribute__((aligned(x)))).  Load addresses are guaranteed
     * only up to _max_align.  Provided that all loader and relocation
     * code honours _max_align, this means that physical addresses are
     * also guaranteed up to _max_align.
     *
     * Note that when using -DKEEP_IT_REAL, the UNDI segments are only
     * guaranteed to be loaded on a paragraph boundary (i.e. 16-byte
     * alignment).  Using _max_align>16 will therefore not guarantee
     * >16-byte alignment of physical addresses when -DKEEP_IT_REAL is
     * used (though virtual addresses will still be fully aligned).
     *
     */

    /*
     * The prefix
     */

    _prefix_link_addr = DEFINED ( _prefix_link_addr ) ? _prefix_link_addr : 0;
    . = _prefix_link_addr;
    _prefix = .;

    .prefix : AT ( _prefix_load_offset + __prefix ) {
	__prefix = .;
	_entry = .;
	*(.prefix)
	*(.prefix.*)
	_eprefix_progbits = .;
    }
    
    _eprefix = .;

    /*
     * The 16-bit sections
     */

    _text16_link_addr = 0;
    . = _text16_link_addr;
    _text16 = .;

    . += 1;			/* Prevent NULL being valid */

    .text16 : AT ( _text16_load_offset + __text16 ) {
	__text16 = .;
	KEEP(*(.text.null_trap))
	KEEP(*(.text.null_trap.*))
	*(.text16)
	*(.text16.*)
	*(.text)
	*(.text.*)
	_etext16_progbits = .;
    } = 0x9090

    _etext16 = .;

    _data16_link_addr = 0;
    . = _data16_link_addr;
    _data16 = .;

    . += 1;			/* Prevent NULL being valid */

    .rodata16 : AT ( _data16_load_offset + __rodata16 ) {
	__rodata16 = .;
	*(.rodata16)
	*(.rodata16.*)
	*(.rodata)
	*(.rodata.*)
    }
    .data16 : AT ( _data16_load_offset + __data16 ) {
	__data16 = .;
	*(.data16)
	*(.data16.*)
	*(.data)
	*(.data.*)
	KEEP(*(SORT(.tbl.*)))	/* Various tables.  See include/tables.h */
	KEEP(*(.provided))
	KEEP(*(.provided.*))
	_edata16_progbits = .;
    }
    .bss16 : AT ( _data16_load_offset + __bss16 ) {
	__bss16 = .;
	_bss16 = .;
	*(.bss16)
	*(.bss16.*)
	*(.bss)
	*(.bss.*)
	*(COMMON)
	_ebss16 = .;
    }
    .stack16 : AT ( _data16_load_offset + __stack16 ) {
	__stack16 = .;
	*(.stack16)
	*(.stack16.*)
	*(.stack)
	*(.stack.*)
    }

    _edata16 = .;

    _end = .;

    /*
     * Dispose of the comment and note sections to make the link map
     * easier to read
     */

    /DISCARD/ : {
	*(.comment)
	*(.comment.*)
	*(.note)
	*(.note.*)
	*(.discard)
	*(.discard.*)
    }

    /*
     * Load address calculations.  The slightly obscure nature of the
     * calculations is because ALIGN(x) can only operate on the
     * location counter.
     */

    _max_align		    = DEFINED ( _max_align ) ? _max_align : 16;
    _load_addr		    = DEFINED ( _load_addr ) ? _load_addr : 0;

    .			    = _load_addr;

    .			   -= _prefix_link_addr;
    _prefix_load_offset	    = ALIGN ( _max_align );
    _prefix_load_addr	    = _prefix_link_addr + _prefix_load_offset;
    _prefix_size	    = _eprefix - _prefix;
    _prefix_progbits_size   = _eprefix_progbits - _prefix;
    .			    = _prefix_load_addr + _prefix_progbits_size;

    .			   -= _text16_link_addr;
    _text16_load_offset	    = ALIGN ( _max_align );
    _text16_load_addr	    = _text16_link_addr + _text16_load_offset;
    _text16_size	    = _etext16 - _text16;
    _text16_progbits_size   = _etext16_progbits - _text16;
    .			    = _text16_load_addr + _text16_progbits_size;

    .			   -= _data16_link_addr;
    _data16_load_offset	    = ALIGN ( _max_align );
    _data16_load_addr	    = _data16_link_addr + _data16_load_offset;
    _data16_size	    = _edata16 - _data16;
    _data16_progbits_size   = _edata16_progbits - _data16;
    .			    = _data16_load_addr + _data16_progbits_size;

    .			    = ALIGN ( _max_align );

    _load_size		    = . - _load_addr;

    /*
     * Alignment checks.  ALIGN() can only operate on the location
     * counter, so we set the location counter to each value we want
     * to check.
     */

    . = _prefix_load_addr - _prefix_link_addr;
    _assert = ASSERT ( ( . == ALIGN ( _max_align ) ),
		       "_prefix is badly aligned" );

    . = _text16_load_addr - _text16_link_addr;
    _assert = ASSERT ( ( . == ALIGN ( _max_align ) ),
		       "_text16 is badly aligned" );

    . = _data16_load_addr - _data16_link_addr;
    _assert = ASSERT ( ( . == ALIGN ( _max_align ) ),
		       "_data16 is badly aligned" );

    /*
     * Values calculated to save code from doing it
     */
    _text16_size_pgh	= ( ( _text16_size + 15 ) / 16 );
    _data16_size_pgh	= ( ( _data16_size + 15 ) / 16 );
    _load_size_pgh	= ( ( _load_size + 15 ) / 16 );
    _load_size_sect	= ( ( _load_size + 511 ) / 512 );
}
