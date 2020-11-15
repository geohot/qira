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
ENTRY(_entry)

SECTIONS {
	. = 0xF000100;
	.text :
        {
	  __client_start = .;
	  *(.text* .stub .gnu.linkonce.t.*)
	  *(.sfpr .glink)
	}

	. = ALIGN(0x100);
	.rodata :
	{
          *(.rodata* .gnu.linkonce.r.*)
	}

	. = ALIGN(0x10);
	.data :
        {
	  *(.data* .gnu.linkonce.d.*)
	  *(.force.data)
	  *(.toc1)
	  *(.branch_lt)
        }

	. = ALIGN(0x10);
	.opd :
	{
	  *(.opd)
	}

	. = ALIGN(256);
	.got :
	{
	  _got = DEFINED (.TOC.) ? .TOC. : ADDR (.got) + 0x8000;
          *(.got)
	  *(.toc)
	  _got_end = .;
	}

	. = ALIGN(0x1000);
	.bss :
	{
          *(*COM* .bss* .gnu.linkonce.b.*)
	}
	__client_end = .;

	.dynsym : { *(.dynsym) }
	.dynstr : { *(.dynstr) }
	. = ALIGN(0x10);
	.dynamic : {
	  *(.dynamic)
	}
	. = ALIGN(0x10);
	.rela.dyn : {
	  *(.rela*)
	}
	.hash : { *(.hash) }

	.comment : {
	  /*
	   * Discarding this section caused errors on binutils 2.23,
	   * this is fixed in 2.24.
	   */
	  *(.comment)
	}
	/DISCARD/ : {
	  *(.interp)
	}
}
