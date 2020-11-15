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

uint16_t bswap16_load(uint64_t addr) ;
uint32_t bswap32_load(uint64_t addr) ;

void bswap16_store(uint64_t addr, uint16_t val) ;
void bswap32_store(uint64_t addr, uint32_t val) ;

uint8_t load8_ci(uint64_t addr) ;
uint16_t load16_ci(uint64_t addr) ;
uint32_t load32_ci(uint64_t addr) ;
uint64_t load64_ci(uint64_t addr) ;

void store8_ci(uint64_t  addr, uint8_t val) ;
void store16_ci(uint64_t  addr, uint16_t val) ;
void store32_ci(uint64_t  addr, uint32_t val) ;
void store64_ci(uint64_t  addr, uint64_t val) ;
