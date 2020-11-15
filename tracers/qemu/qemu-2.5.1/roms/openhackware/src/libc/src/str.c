/*
 * <str.c>
 *
 * Open Hack'Ware BIOS: str<xxx> functions
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
/* NULL is defined here */
/* malloc is defined here */
#include <stdlib.h>
/* toupper is defined here */
#include <ctype.h>

/* str___ functions */
#if defined (__USE_strcpy__)
void *strcpy (char *dest, const char *src)
{
    char *q;

    q = dest;
    for (; ; q++) {
        *q = *src++;
        if (*q == '\0')
            break;
    }

    return dest;
}
#endif

#if defined (__USE_strncpy__)
void *strncpy (char *dest, const char *src, size_t n)
{
    char *q;

    q = dest;
    for (; n != 0; n--, q++) {
        *q = *src++;
        if (*q == '\0')
            break;
    }

    return dest;
}
#endif

#if defined (__USE_strdup__)
char *strdup (const char *s)
{
    char *dest;
    size_t len;

    len = strlen(s) + 1;
    dest = malloc(len);
    if (dest != NULL)
        memcpy(dest, s, len);

    return dest;
}
#endif

#if defined (__USE_strndup__)
/* GNU extension */
char *strndup (const char *s, size_t n)
{
    char *dest;
    size_t len;

    len = strlen(s) + 1;
    if (len > n)
        len = n;
    dest = malloc(len);
    if (dest != NULL) {
        memcpy(dest, s, len - 1);
        dest[len - 1] = '\0';
    }

    return dest;
}
#endif

#if defined (__USE_stpcpy__)
void *stpcpy (char *dest, const char *src)
{
    char *q;

    q = dest;
    for (; ; q++) {
        *q = *src++;
        if (*q == '\0')
            break;
    }

    return q;
}
#endif

#if defined (__USE_stpncpy__)
void *stpncpy (char *dest, const char *src, size_t n)
{
    char *q;

    q = dest;
    for (; n != 0; n--, q++) {
        *q = *src++;
        if (*q == '\0')
            break;
    }

    return q;
}
#endif

#if defined (__USE_strcat__)
char *strcat (char *dest, const char *src)
{
    char *q;
    
    for (q = dest + strlen(dest); ; q++) {
        *q = *src++;
        if (*q == '\0')
            break;
    }

    return dest;
}
#endif

#if defined (__USE_strncat__)
char *strncat (char *dest, const char *src, size_t n)
{
    char *q;
    
    for (q = dest + strlen(dest); n != 0; n--, q++) {
        *q = *src++;
        if (*q == '\0')
            break;
    }

    return dest;
}
#endif

#if defined (__USE_strcmp__)
int strcmp (const char *s1, const char *s2)
{
    int ret;
    
    for (ret = 0; ret == 0; s1++) {
        ret = *s1 - *s2++;
        if (*s1 == '\0')
            break;
    }

    return ret;
}
#endif

#if defined (__USE_strcasecmp__)
int strcasecmp (const char *s1, const char *s2)
{
    int ret;
    
    for (ret = 0; ret == 0; s1++) {
        ret = toupper(*s1) - toupper(*s2++);
        if (*s1 == '\0')
            break;
    }

    return ret;
}
#endif

#if defined (__USE_strncmp__)
int strncmp (const char *s1, const char *s2, size_t n)
{
    int ret;
    
    for (ret = 0; ret == 0 && n != 0; n--, s1++) {
        ret = *s1 - *s2++;
        if (*s1 == '\0')
            break;
    }

    return ret;
}
#endif

#if defined (__USE_strncasecmp__)
int strncasecmp (const char *s1, const char *s2, size_t n)
{
    int ret;
    
    for (ret = 0; ret == 0 && n != 0; n--, s1++) {
        ret = toupper(*s1) - toupper(*s2++);
        if (*s1 == '\0')
            break;
    }

    return ret;
}
#endif

#if defined (__USE_strchr__)
char *strchr (const char *s, int c)
{
    const char *r;

    for (r = NULL; *s != '\0'; s++) {
        if (*s == c) {
            r = s;
            break;
        }
    }

    return (char *)r;
}
#endif

#if defined (__USE_strchrnul__)
/* GNU extension */
char *strchrnul (const char *s, int c)
{
    for (; *s != '\0' && *s != c; s++)
        continue;

    return (char *)s;
}
#endif

#if defined (__USE_strrchr__)
char *strrchr (const char *s, int c)
{
    const char *p, *r;

    r = NULL;
    for (p = s + strlen(s); p != s; p--) {
        if (*p == c) {
            r = p;
            break;
        }
    }

    return (char *)r;
}
#endif

#if defined (__USE_strstr__)
char *strstr (const char *haystack, const char *needle)
{
    const char *r;
    size_t hlen, nlen;

    if (*needle == '\0')
        return (char *)haystack;
    r = NULL;
    hlen = strlen(haystack);
    nlen = strlen(needle);
    for (; hlen > nlen; hlen--, haystack++) {
        if (memcmp(haystack, needle, nlen) == 0) {
            r = haystack;
            break;
        }
    }

    return (char *)r;
}
#endif

#if defined (__USE_strcasestr__)
char *strcasestr (const char *haystack, const char *needle)
{
    const char *p, *q, *r;
    size_t hlen, nlen, n;

    if (*needle == '\0')
        return (char *)haystack;
    r = NULL;
    hlen = strlen(haystack);
    nlen = strlen(needle);
    for (; hlen > nlen; hlen--, haystack++) {
        p = haystack;
        q = needle;
        for (n = nlen; n != 0; n--) {
            if (toupper(*p++) != toupper(*q++))
                break;
        }
        if (n == 0) {
            r = haystack;
            break;
        }
    }

    return (char *)r;
}
#endif

#if defined (__USE_strspn__)
#error "TODO"
size_t strspn (const char *s, const char *accept)
{
}
#endif

#if defined (__USE_strcspn__)
#error "TODO"
size_t strcspn (const char *s, const char *reject)
{
}
#endif

#if defined (__USE_strpbrk__)
#error "TODO"
char *strpbrk (const char *s, const char *accept)
{
}
#endif

#if defined (__USE_strtok__)
#error "TODO"
char *strtok (char *s, const char *delim)
{
}
#endif

#if defined (__USE_strtok_r__)
#error "TODO"
char *strtok_r (char *s, const char *delim, char **ptrptr)
{
}
#endif

#if defined (__USE_strsep__)
#error "TODO"
char *strsep (char **stringp, const char *delim)
{
}
#endif

#if defined (__USE_basename__)
char *basename (char *path)
{
    char *sl;
    size_t len;

    if (path == NULL || (len = strlen(path)) == 0)
        return strdup(".");
    sl = path + len - 1;
    if (*sl == '/')
        sl--;
    for (; sl != path; sl--) {
        if (*sl == '/')
            break;
    }
    
    return strdup(sl + 1);
}
#endif

#if defined (__USE_dirname__)
char *dirname (char *path)
{
    char *sl, *ret;
    size_t len;

    if (path == NULL || (len = strlen(path)) == 0) {
        ret = strdup(".");
    } else {
        sl = path + len - 1;
        if (*sl == '/')
            sl--;
        for (; sl != path; sl--) {
            if (*sl == '/')
                break;
        }
        len = sl - path;
        if (len == 0) {
            ret = strdup(".");
        } else {
            ret = malloc(len + 1);
            if (ret != NULL) {
                memcpy(path, ret, len);
                path[len] = '\0';
            }
        }
    }
    
    return ret;
}
#endif

#if defined (__USE_strlen__)
size_t strlen (const char *s)
{
    size_t len;

    for (len = 0; *s != '\0'; len++)
        s++;

    return len;
}
#endif

#if defined (__USE_strnlen__)
size_t strnlen (const char *s, size_t maxlen)
{
    size_t len;

    for (len = 0; maxlen != 0 && *s != '\0'; maxlen--, len++)
        s++;

    return len;
}
#endif
