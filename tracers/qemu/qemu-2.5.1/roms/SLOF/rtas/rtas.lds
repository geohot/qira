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

SECTIONS {
	.text 0:
	{
	  *(.rtasstart)
	  *(.text .stub .text.* .gnu.linkonce.t.*)
	  *(.sfpr .glink)
	  *(.rodata .rodata.* .gnu.linkonce.r.*)
	  *(.opd)
	} =0x60000000
	.data :
	{
	  *(.data .data.* .gnu.linkonce.d.*)
	}
	.got :
	{
	  . = ALIGN(256);
	  _got = DEFINED (.TOC.) ? .TOC. : ADDR (.got) + 0x8000;
	  *(.got .toc)
	}  	
	.reloc :
	{
	  . = ALIGN(4);
	  _reloc_table_start = .;
	  *(.reloc)
	  _reloc_table_end = .;
	}
	.bss :
	{
	  __bss_start = .;
	  *(*COM* .bss .sbss .gnu.linkonce.b.*)
	  __bss_end = .;
	}
	__bss_size = (__bss_end - __bss_start);
	_rtas_end = .;
}
