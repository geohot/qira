/*
 *	<ofmem_sparc64.h>
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

#ifndef _H_OFMEM_SPARC64
#define _H_OFMEM_SPARC64

#include "libopenbios/ofmem.h"

#define PAGE_SIZE_4M   (4 * 1024 * 1024)
#define PAGE_SIZE_512K (512 * 1024)
#define PAGE_SIZE_64K  (64 * 1024)
#define PAGE_SIZE_8K   (8 * 1024)
#define PAGE_MASK_4M   (4 * 1024 * 1024 - 1)
#define PAGE_MASK_512K (512 * 1024 - 1)
#define PAGE_MASK_64K  (64 * 1024 - 1)
#define PAGE_MASK_8K   (8 * 1024 - 1)

extern ucell *va2ttedata;
extern unsigned long find_tte(unsigned long va);

void itlb_load2(unsigned long vaddr, unsigned long tte_data);
void itlb_load3(unsigned long vaddr, unsigned long tte_data, unsigned long tte_index);
unsigned long itlb_faultva(void);
void itlb_demap(unsigned long vaddr);
void dtlb_load2(unsigned long vaddr, unsigned long tte_data);
void dtlb_load3(unsigned long vaddr, unsigned long tte_data, unsigned long tte_index);
unsigned long dtlb_faultva(void);
void dtlb_demap(unsigned long vaddr);

typedef int (*translation_entry_cb)(ucell phys,	ucell virt, ucell size, ucell mode);

extern void ofmem_walk_boot_map(translation_entry_cb cb);

extern translation_t **g_ofmem_translations;

extern void dtlb_miss_handler(void);
extern void itlb_miss_handler(void);
extern void bug(void);

#endif   /* _H_OFMEM_SPARC64 */
