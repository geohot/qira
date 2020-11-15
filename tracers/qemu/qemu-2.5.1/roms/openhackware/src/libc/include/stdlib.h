/*
 * <stdlib.h>
 *
 * Open Hack'Ware BIOS: subset of POSIX stdlib definitions
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

#if !defined (__OHW_STDLIB_H__)
#define __OHW_STDLIB_H__

#define NULL ((void *)0)

/* size_t is declared here */
#include <stddef.h>

void *malloc (size_t size);
void free (void *ptr);
void *realloc (void *ptr, size_t size);

/* memset is declared here */
#include <string.h>

static inline void *calloc (size_t nmemb, size_t size)
{
    void *ret;

    ret = malloc(nmemb * size);
    if (ret != NULL)
        memset(ret, 0, nmemb * size);

    return ret;
}

int mkstemp (char *template);

#endif /* !defined (__OHW_STDLIB_H__) */
