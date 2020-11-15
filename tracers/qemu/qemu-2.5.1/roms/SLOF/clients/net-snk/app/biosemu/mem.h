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

#ifndef _BIOSEMU_MEM_H_
#define _BIOSEMU_MEM_H_
#include <x86emu/x86emu.h>
#include <stdint.h>

// read byte from memory
uint8_t my_rdb(uint32_t addr);

//read word from memory
uint16_t my_rdw(uint32_t addr);

//read long from memory
uint32_t my_rdl(uint32_t addr);

//write byte to memory
void my_wrb(uint32_t addr, uint8_t val);

//write word to memory
void my_wrw(uint32_t addr, uint16_t val);

//write long to memory
void my_wrl(uint32_t addr, uint32_t val);

#endif
