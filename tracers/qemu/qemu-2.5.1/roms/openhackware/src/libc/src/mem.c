/*
 * <mem.c>
 *
 * Open Hack'Ware BIOS: mem<xxx> functions
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

/* functions prototypes are here */
#include <string.h>
/* NULL is declared here */
#include <stdlib.h>

/* mem___ functions */
#if defined (__USE_memcpy__)
void *memcpy (void *dest, const void *src, size_t n)
{
    const char *p;
    char *q;

    p = src;
    q = dest;
    for (; n != 0; n--)
        *q++ = *p++;

    return dest;
}
#endif

#if defined (__USE_memccpy__)
void *memccpy (void *dest, const void *src, int c, size_t n)
{
    const char *p;
    char *q, *r;

    p = src;
    q = dest;
    r = NULL;
    for (; n != 0; n--, q++) {
        *q = *p++;
        if (*q == c) {
            r = q;
            break;
        }
    }

    return r;
}
#endif

#if defined (__USE_mempcpy__)
/* GNU extension */
void *mempcpy (void *dest, const void *src, size_t n)
{
    const char *p;
    char *q;

    p = src;
    q = dest;
    for (; n != 0; n--)
        *q++ = *p++;

    return q;
}
#endif

#if defined (__USE_memmove__)
void *memmove (void *dest, const void *src, size_t n)
{
    const char *p;
    char *q;

    p = src;
    q = dest;
    if (dest <= src) {
        for (; n != 0; n--)
            *q++ = *p++;
    } else {
        p += n;
        q += n;
        for (; n != 0; n--)
            *--q = *--p;
    }

    return dest;
}
#endif

#if defined (__USE_memcmove__)
/* OHW extension */
void *memcmove (void *dest, const void *src, int c, size_t n)
{
    const char *p;
    char *q, *r;

    p = src;
    q = dest;
    r = NULL;
    if (dest <= src) {
        for (; n != 0; n--, q++) {
            *q++ = *p++;
            if (*q == c) {
                r = q;
                break;
            }
        }
    } else {
        p += n;
        q += n;
        for (; n != 0; n--, q--) {
            *--q = *--p;
            if (*q == c) {
                r = q;
                break;
            }
        }
    }

    return dest;
}
#endif

#if defined (__USE_mempmove__)
/* OHW extension */
void *mempmove (void *dest, const void *src, size_t n)
{
    const char *p;
    char *q, *r;

    p = src;
    q = dest;
    r = q + n;
    if (dest <= src) {
        for (; n != 0; n--)
            *q++ = *p++;
    } else {
        p += n;
        q = r;
        for (; n != 0; n--)
            *--q = *--p;
    }

    return r;
}
#endif

#if defined (__USE_memset__)
void *memset (void *s, int c, size_t n)
{
    char *p;

    for (p = s; n != 0; n--)
        *p++ = c;

    return s;
}
#endif

#if defined (__USE_memcmp__)
int memcmp (const void *s1, const void *s2, size_t n)
{
    const char *p, *q;
    int ret;

    p = s1;
    q = s2;
    for (ret = 0; n != 0 && ret == 0; n--)
        ret = *p++ - *q++;

    return ret;
}
#endif

#if defined (__USE_memchr__)
void *memchr (const void *s, int c, size_t n)
{
    const char *p, *r;

    r = NULL;
    for (p = s; n != 0; n--, p++) {
        if (*p == c) {
            r = p;
            break;
        }
    }

    return (void *)r;
}
#endif

#if defined (__USE_rawmemchr__)
/* GNU extension */
void *rawmemchr (const void *s, int c)
{
    const char *p;

    for (p = s; *p != c; p++)
        continue;

    return (void *)p;
}
#endif

#if defined (__USE_memrchr__)
void *memrchr (const void *s, int c, size_t n)
{
    const char *p, *r;

    r = NULL;
    for (p = s + n; n != 0; n--, p--) {
        if (*p == c) {
            r = p;
            break;
        }
    }

    return (void *)r;
}
#endif

#if defined (__USE_memmem__)
/* GNU extension */
void *memmem (const void *haystack, size_t haystacklen,
              const void *needle, size_t neddlelen)
{
    const char *p, *r;

    r = NULL;
    for (p = haystack; haystacklen > neddlelen; haystacklen--, p++) {
        if (memcmp(p, needle, neddlelen) == 0) {
            r = p;
            break;
        }
    }

    return (void *)r;
}
#endif
