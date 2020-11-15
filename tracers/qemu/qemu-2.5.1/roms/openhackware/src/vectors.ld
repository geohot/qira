/* 
 *   <vectors.ld>
 *      
 *   Second stage boot-loader and exception vectors for Open Hack'Ware
 *   linker script
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
        text   (rx)   : ORIGIN = 0x00000000, LENGTH = 0x3000
        rodata (r)    : ORIGIN = 0x00003000, LENGTH = 0x0C00
        data   (rw)   : ORIGIN = 0x00003C00, LENGTH = 0x0200
}

SECTIONS
{
        .text     : { *(.text)    } > text
        .rodata   : { *(.rodata)  } > rodata
        .data     : { *(.data)    } > data
        /DISCARD/ : { *(.bss)     }
        /DISCARD/ : { *(.sbss)    }
        /DISCARD/ : { *(.sdata)   }
        /DISCARD/ : { *(.sdata2)  }
        /DISCARD/ : { *(.stab)    }
        /DISCARD/ : { *(.stabstr) }
        /DISCARD/ : { *(.comment) }
        /DISCARD/ : { *(.note)    }
}
