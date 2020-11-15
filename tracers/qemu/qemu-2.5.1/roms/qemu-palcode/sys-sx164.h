/* Declarations for the SX164 system emulation.

   Copyright (C) 2011 Richard Henderson

   This file is part of QEMU PALcode.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the text
   of the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not see
   <http://www.gnu.org/licenses/>.  */

#ifndef SYS_SX164_H
#define SYS_SX164_H 1

#include "core_cia.h"

#ifdef __ASSEMBLER__

.macro	SYS_ACK_CLK	t0, t1, t2
	LOAD_KSEG_PCI_IO \t0		// Set RTCADD (0x70) to index reg 0xC
	mov	0xc, \t1
	stb	\t1, 0x70(\t0)
	ldbu	\t1, 0x71(\t0)		// Read RTCDAT to clear interrupt
.endm

.macro	SYS_DEV_VECTOR	ret
	FIXME
.endm

#endif /* ASSEMBLER */

#define SYS_TYPE	ST_DEC_EB164
#define SYS_VARIATION	(15 << 10)
#define SYS_REVISION	0

#endif /* SYS_SX164_H */
