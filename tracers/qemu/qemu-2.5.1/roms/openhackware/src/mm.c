/*
 * Open Hack'Ware BIOS memory management.
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
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

#include <stdlib.h>
#include "bios.h"

#if 0
static uint8_t *page_bitmap;
static uint32_t memory_size;

static void mark_page_in_use (uint32_t page_nb)
{
    uint32_t offset, bit;

    offset = page_nb >> 3;
    bit = page_nb & 7;
    page_bitmap[offset] |= 1 << bit;
}

static void mark_page_free (uint32_t page_nb)
{
    uint32_t offset, bit;

    offset = page_nb >> 3;
    bit = page_nb & 7;
    page_bitmap[offset] &= ~(1 << bit);
}

static int is_page_in_use (uint32_t page_nb)
{
    uint32_t offset, bit;

    offset = page_nb >> 3;
    bit = page_nb & 7;
    
    return (page_bitmap[offset] & (~(1 << bit))) != 0;
}

void mm_init (uint32_t memsize)
{
    uint32_t page_start, page_ram_start, page, ram_start;
    uint32_t nb_pages, bitmap_size;
    
    /* Init bitmap */
    ram_start = (uint32_t)(&_ram_start);
    ram_start = (ram_start + (1 << 12) - 1) & ~((1 << 12) - 1);
    page_bitmap = (void *)ram_start;
    nb_pages = (memsize + (1 << 12) - 1) >> 12;
    bitmap_size = (nb_pages + 7) >> 3;
    /* First mark all pages as free */
    memset(page_bitmap, 0, bitmap_size);
    /* Mark all pages used by the BIOS as used (code + data + bitmap) */
    page_start = (uint32_t)(0x05800000) >> 12; /* TO FIX */
    ram_start += bitmap_size;
    ram_start = (ram_start + (1 << 12) - 1) & ~((1 << 12) - 1);
    page_ram_start = ram_start >> 12;
    for (page = page_start; page < page_ram_start; page++)
        mark_page_in_use(page);
    memory_size = memsize;
}

void *page_get (int nb_pages)
{
    uint32_t page_start, page_end, page;
    int nb;

    page_start = (uint32_t)(0x05800000) >> 12; /* TO FIX */
    page_end = memory_size >> 12;
    for (page = page_start; page < page_end; ) {
        /* Skip all full "blocs" */
        for (; page < page_end; page += 8) {
            if (page_bitmap[page >> 3] != 0xFF)
                break;
        }
        for (nb = 0; page < page_end; page++) {
            if (!is_page_in_use(page)) {
                nb++;
                if (nb == nb_pages) {
                    /* Found ! */
                    for (; nb >= 0; nb--, page--)
                        mark_page_in_use(page);

                    return (void *)(page << 12);
                }
            }
        }
    }

    return NULL;
}

void page_put (void *addr, int nb_pages)
{
    uint32_t page_start, page_end, page;

    page_start = (uint32_t)addr >> 12;
    page_end = page_start + nb_pages;
    for (page = page_start; page < page_end; page++) {
        if (!is_page_in_use(page))
            printf("ERROR: page %u has already been freed !\n", page);
        mark_page_free(page);
    }
}
#else
static uint8_t *page_alloc;

void mm_init (unused uint32_t memsize)
{
    uint32_t ram_start;
    ram_start = (uint32_t)(&_ram_start);
    ram_start = (ram_start + (1 << 12) - 1) & ~((1 << 12) - 1);
    page_alloc = (void *)ram_start;
}

void *page_get (unused int nb_pages)
{
    void *ret;

    ret = page_alloc;
    page_alloc += nb_pages << 12;
    memset(ret, 0, nb_pages << 12);

    return ret;
}

void page_put (unused void *addr, unused int nb_pages)
{
}
#endif
