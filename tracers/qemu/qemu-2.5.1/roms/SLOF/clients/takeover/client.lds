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
	.client 0x400100:
	{
	__client_start = .;
	  *(.start)
	  *(.text .stub .text.* .gnu.linkonce.t.*)
	  *(.sfpr .glink)
          *(.rodata .rodata.* .gnu.linkonce.r.*)
          KEEP (*(.opd))
	  . = ALIGN(256); 
	  *(.data .data.* .gnu.linkonce.d.*)
	  . = ALIGN(256);
	} =0x60000000

	.diag_table :
	{
	  _diag_init_start = .;
	  *(.diag_init)
	  _diag_init_end = .;
        }
	.lowmem :
	{
	  _lowmem_start = .;
	  *(.lowmem)
	  _lowmem_end = .;
	}

	.got :
	{
	  . = ALIGN(256);
	  _got = DEFINED (.TOC.) ? .TOC. : ADDR (.got) + 0x8000;
          *(.got .toc)
	  _got_end = .;
	}  	
	.comment : { *(.comment) }
	.branch_lt : { *(.branch_lt) }
	.bss :
	{
	__bssStart = .;
          *(*COM* .bss .gnu.linkonce.b.*)
	__client_end = .;
	__bssSize = . - __bssStart;
	}
}
