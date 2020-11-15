/*
 * <string.h>
 *
 * Open Hack'Ware BIOS: subset of POSIX string definitions
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

#if !defined (__OHW_STRING_H__)
#define __OHW_STRING_H__

/* size_t is declared here */
#include <stddef.h>

void *memcpy (void *dest, const void *src, size_t n);
void *memccpy (void *dest, const void *src, int c, size_t n);
void *mempcpy (void *dest, const void *src, size_t n);
void *memmove (void *dest, const void *src, size_t n);
void *memcmove (void *dest, const void *src, int c, size_t n);
void *mempmove (void *dest, const void *src, size_t n);
void *memset (void *s, int c, size_t n);
int memcmp (const void *s1, const void *s2, size_t n);
void *memchr (const void *s, int c, size_t n);
void *rawmemchr (const void *s, int c);
void *memrchr (const void *s, int c, size_t n);
void *memmem (const void *haystack, size_t haystacklen,
              const void *needle, size_t neddlelen);
void *strcpy (char *dest, const char *src);
void *strncpy (char *dest, const char *src, size_t n);
char *strdup (const char *s);
char *strndup (const char *s, size_t n);
void *stpcpy (char *dest, const char *src);
void *stpncpy (char *dest, const char *src, size_t n);
char *strcat (char *dest, const char *src);
char *strncat (char *dest, const char *src, size_t n);
int strcmp (const char *s1, const char *s2);
int strcasecmp (const char *s1, const char *s2);
int strncmp (const char *s1, const char *s2, size_t n);
int strncasecmp (const char *s1, const char *s2, size_t n);
char *strchr (const char *s, int c);
char *strchrnul (const char *s, int c);
char *strrchr (const char *s, int c);
char *strstr (const char *haystack, const char *needle);
char *strcasestr (const char *haystack, const char *needle);
#if 0 // TODO
size_t strspn (const char *s, const char *accept);
size_t strcspn (const char *s, const char *reject);
char *strpbrk (const char *s, const char *accept);
char *strtok (char *s, const char *delim);
char *strtok_r (char *s, const char *delim, char **ptrptr);
char *strsep (char **stringp, const char *delim);
#endif // TODO
char *basename (char *path);
char *dirname (char *path);
size_t strlen (const char *s);
size_t strnlen (const char *s, size_t maxlen);

#if 0
static inline int ffs (int value)
{
    int tmp;
    
    __asm__ __volatile__ ("cntlzw %0, %1" : "=r" (tmp) : "r" (value));
    
    return 32 - tmp;
}
#endif

static inline int ffs (int value)
{
    return __builtin_ffs(value);
}

int ffsl (long i);
int ffsll (long long i);

#endif /* !defined (__OHW_STRING_H__) */
