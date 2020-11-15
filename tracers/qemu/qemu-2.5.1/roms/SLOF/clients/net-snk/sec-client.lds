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
	.client 0x200000:
	{
	__client_start = .;
	  *(.text .stub .text.* .gnu.linkonce.t.*)
	  *(.sfpr .glink)
          *(.rodata .rodata.* .gnu.linkonce.r.*)
          KEEP (*(.opd))
	  . = ALIGN(256); 
	  *(.data .data.* .gnu.linkonce.d.*)
	  . = ALIGN(256);
/*          *(*COM* .bss .gnu.linkonce.b.*) */
	} =0x60000000

	.got : 
	{
	  . = ALIGN(8);
	  _got = .;
          *(.got .toc)
	  _got_end = .;
	}  	
	.bss :
	{
          *(*COM* .bss .gnu.linkonce.b.*)
	__client_end = .;
	}
}
