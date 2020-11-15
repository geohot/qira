/*
 *	<ofmem_sparc32.h>
 *
 *	OF Memory manager
 *
 *   Copyright (C) 1999, 2002 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_OFMEM_SPARC32
#define _H_OFMEM_SPARC32

#include "libopenbios/ofmem.h"

#define OF_CODE_START 0xffd00000
#define OFMEM_VIRT_TOP 0xfe000000

struct mem;
extern struct mem cdvmem;

extern unsigned long *l1;
extern unsigned long find_pte(unsigned long va, int alloc);

void mem_init(struct mem *t, char *begin, char *limit);
void *mem_alloc(struct mem *t, int size, int align);

#endif   /* _H_OFMEM_SPARC32 */