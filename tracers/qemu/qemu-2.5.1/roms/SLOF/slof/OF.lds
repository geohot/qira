/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

OUTPUT_FORMAT("elf64-powerpc", "elf64-powerpc", "elf64-powerpc")
OUTPUT_ARCH(powerpc:common64)
ENTRY(_start_OF)


SECTIONS
{
	. = 0x0E100100;
	_start_OF = .;
	.slof.loader : { *(.slof.loader) }
	. = ALIGN(0x100);
	_slof_text = .;
	.text : { *(.entry_text) *(.text) } = 0x60000000
	_slof_text_end = .;
	. = ALIGN(8);
	_slof_text_size = (_slof_text_end - _slof_text);

	. = ALIGN(0x100);
	.opd : 
	{ 
		_slof_data = .;
		*(.opd)
	}
	. = ALIGN(8);
	.got :
	{
		*(.got .toc)
	}

	.data : { 
		*(.rodata .rodata.*)
		*(.data .data.*)
		*(.note.gnu.build-id)
	}

	.comment : { *(.comment) }
	.branch_lt : { *(.branch_lt) }

	. = ALIGN(8);
	_slof_data_end = .;
	_slof_data_size = (_slof_data_end - _slof_data);

	.bss :
	{
	  _slof_bss = .;
	  *(*COM* .bss .sbss .gnu.linkonce.b.*)
	  _slof_bss_end = .;
	}
	_slof_bss_size = (_slof_bss_end - _slof_bss);
	
	. = ALIGN(0x1000);
	the_mem = .;
}
