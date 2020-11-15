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

#include <cpu.h>
#include <stdint.h>
#include <hw.h>

uint16_t
bswap16_load(uint64_t addr)
{
	unsigned int val;
	set_ci();
	asm volatile ("lhbrx %0, 0, %1":"=r" (val):"r"(addr));
	clr_ci();
	return val;
}

uint32_t
bswap32_load(uint64_t addr)
{
	unsigned int val;
	set_ci();
	asm volatile ("lwbrx %0, 0, %1":"=r" (val):"r"(addr));
	clr_ci();
	return val;
}

void
bswap16_store(uint64_t addr, uint16_t val)
{
	set_ci();
	asm volatile ("sthbrx %0, 0, %1"::"r" (val), "r"(addr));
	clr_ci();
}

void
bswap32_store(uint64_t addr, uint32_t val)
{
	set_ci();
	asm volatile ("stwbrx %0, 0, %1"::"r" (val), "r"(addr));
	clr_ci();
}

uint8_t
load8_ci(uint64_t addr)
{
	uint8_t val;
	set_ci();
	val = *(uint8_t *) addr;
	clr_ci();
	return val;
}

uint16_t
load16_ci(uint64_t addr)
{
	uint16_t val;
	set_ci();
	val = *(uint16_t *) addr;
	clr_ci();
	return val;
}

uint32_t
load32_ci(uint64_t addr)
{
	uint32_t val;
	set_ci();
	val = *(uint32_t *) addr;
	clr_ci();
	return val;
}

uint64_t
load64_ci(uint64_t addr)
{
	uint64_t val;
	set_ci();
	val = *(uint64_t *) addr;
	clr_ci();
	return val;
}


void
store8_ci(uint64_t addr, uint8_t val)
{
	set_ci();
	*(uint8_t *) addr = val;
	clr_ci();
}

void
store16_ci(uint64_t addr, uint16_t val)
{
	set_ci();
	*(uint16_t *) addr = val;
	clr_ci();
}

void
store32_ci(uint64_t addr, uint32_t val)
{
	set_ci();
	*(uint32_t *) addr = val;
	clr_ci();
}

void
store64_ci(uint64_t addr, uint64_t val)
{
	set_ci();
	*(uint64_t *) addr = val;
	clr_ci();
}
