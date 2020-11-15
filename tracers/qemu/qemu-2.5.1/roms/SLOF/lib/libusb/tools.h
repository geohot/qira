/*****************************************************************************
 * Copyright (c) 2013 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef __TOOLS_H
#define __TOOLS_H

#include <stdint.h>
#include <byteorder.h>
#include <cache.h>

#define PTR_U32(x)  ((uint32_t) (uint64_t) (x))

static inline uint32_t read_reg32(uint32_t *reg)
{
	return bswap_32(ci_read_32(reg));
}

static inline void write_reg32(uint32_t *reg, uint32_t value)
{
	mb();
	ci_write_32(reg, bswap_32(value));
}

static inline uint8_t read_reg8(uint8_t *reg)
{
	return ci_read_8(reg);
}

static inline void write_reg8(uint8_t *reg, uint8_t value)
{
	mb();
	ci_write_8(reg, value);
}

static inline uint16_t read_reg16(uint16_t *reg)
{
	return bswap_16(ci_read_16(reg));
}

static inline void write_reg16(uint16_t *reg, uint16_t value)
{
	mb();
	ci_write_16(reg, bswap_16(value));
}

static inline uint64_t read_reg64(uint64_t *reg)
{
	return bswap_64(ci_read_64(reg));
}

static inline void write_reg64(uint64_t *reg, uint64_t value)
{
	mb();
	ci_write_64(reg, bswap_64(value));
}

static inline uint32_t ci_read_reg(uint32_t *reg)
{
	return bswap_32(ci_read_32(reg));
}

static inline void ci_write_reg(uint32_t *reg, uint32_t value)
{
	mb();
	ci_write_32(reg, bswap_32(value));
}

#endif
