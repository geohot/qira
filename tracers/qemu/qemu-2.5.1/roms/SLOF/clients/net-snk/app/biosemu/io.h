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

#ifndef _BIOSEMU_IO_H_
#define _BIOSEMU_IO_H_
#include <x86emu/x86emu.h>
#include <stdint.h>

uint8_t my_inb(X86EMU_pioAddr addr);

uint16_t my_inw(X86EMU_pioAddr addr);

uint32_t my_inl(X86EMU_pioAddr addr);

void my_outb(X86EMU_pioAddr addr, uint8_t val);

void my_outw(X86EMU_pioAddr addr, uint16_t val);

void my_outl(X86EMU_pioAddr addr, uint32_t val);

#endif
