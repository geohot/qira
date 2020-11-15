// Linker definitions for an option rom
//
// Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH("i386")
ENTRY(_optionrom_entry)
SECTIONS
{
        .text 0 : {
                KEEP(*(.rom.header))
                *(.text.*)
                _rodata = . ;
                *(.rodata*)
                *(.data16.*)
                }

        // Discard regular data sections to force a link error if
        // 16bit code attempts to access data not marked with VAR16.
        /DISCARD/ : { *(.text*) *(.rodata*) *(.data*) *(.bss*) *(COMMON) }
}
