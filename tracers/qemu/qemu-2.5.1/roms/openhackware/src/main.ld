/*
 * Open Hack'Ware BIOS main.
 * 
 *   Copyright (C) 2004-2005 Jocelyn Mayer (l_indien@magic.fr)
 *   
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

OUTPUT_ARCH(powerpc:common)

MEMORY
{
        start (rwx) : ORIGIN = 0x05800000, LENGTH = 0x00000400
        bios (rwx)  : ORIGIN = 0x05800400, LENGTH = 0x0007FC00
        ram  (rw)   : ORIGIN = 0x06000000, LENGTH = 0x00200000
}

SECTIONS
{
        .start    : { *(.start)   } > start
        . = ALIGN(4) ;
        .text     : { *(.text*)   } > bios
        . = ALIGN(4) ;
        .OpenFirmware : { *(.OpenFirmware) } > bios
        . = ALIGN(4) ;
        _data_start = . ;
        .data     : { *(.data)    } > bios
        _data_end = . ;
        . = ALIGN(4) ;
        _OF_vars_start = . ;
        .OpenFirmware_vars : { *(.OpenFirmware_vars) } > bios
        _OF_vars_end = . ;
        . = ALIGN(4) ;
        _sdata_start = . ;
        .sdata    : { *(.sdata)   } > bios
        . = ALIGN(4) ;
        .sdata2   : { *(.sdata2)  } > bios
        _sdata_end = . ;
        . = ALIGN(4) ;
        _ro_start = . ;
        .rodata    : { *(.rodata*) } > bios
        _ro_end = . ;
        . = ALIGN(4) ;
        _RTAS_start = .;
        .RTAS     : { *(.RTAS)    } > bios
        _RTAS_end = .;
        . = ALIGN(4) ;
        _RTAS_data_start = .;
        .RTAS_vars : { *(.RTAS_vars) } > bios
        . = ALIGN(4) ;
        _RTAS_data_end = .;
        _bss_start = . ;
        .sbss     : {
          *(.sbss) *(.scommon)
        } > bios
        . = ALIGN(4) ;
        .bss      : { *(.bss) *(COMMON) } > bios
        _bss_end = . ;
        . = ALIGN(4) ;
        _ram_start = . ;
        .ram      : {
          *(.ram)
        } > ram
        /DISCARD/ : { *(.stab)    }
        /DISCARD/ : { *(.stabstr) }
        /DISCARD/ : { *(.comment) }
        /DISCARD/ : { *(.note)    }
}
