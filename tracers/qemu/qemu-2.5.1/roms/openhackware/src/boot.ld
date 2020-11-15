/* 
 *   <boot.ld>
 *      
 *   First stage BIOS loader for Open Hack'Ware linker script.
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
        /* NOTE: some old ld do not support wrapping to zero, 
           so we set a dummy address different from 0xFFFFFE00 */
        rom (rx) : ORIGIN = 0xEFFFFE00, LENGTH = 512
}

SECTIONS
{
        .rom      : { *(.rom)     } > rom
        /DISCARD/ : { *(.text)    }
        /DISCARD/ : { *(.rodata)  }
        /DISCARD/ : { *(.data)    }
        /DISCARD/ : { *(.bss)     }
        /DISCARD/ : { *(.sbss)    }
        /DISCARD/ : { *(.sdata)   }
        /DISCARD/ : { *(.sdata2)  }
        /DISCARD/ : { *(.stab)    }
        /DISCARD/ : { *(.stabstr) }
        /DISCARD/ : { *(.comment) }
        /DISCARD/ : { *(.note)    }
}
