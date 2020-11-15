/*
 * <ctype.h>
 *
 * Open Hack'Ware BIOS POSIX like ctype definitions
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

#if !defined (__OHW_CTYPE_H__)
#define __OHW_CTYPE_H__

/* Beware that those routines only support ASCII */
static inline int islower (int c)
{
    return c >= 'a' && c <= 'z';
}

static inline int isupper (int c)
{
    return c >= 'A' && c <= 'Z';
}

static inline int isalpha (int c)
{
    return islower(c) || isupper(c);
}

static inline int isdigit (int c)
{
    return c >= '0' && c <= '9';
}

static inline int isalnum (int c)
{
    return isalpha(c) || isdigit(c);
}

static inline int isxdigit (int c)
{
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static inline int isspace (int c)
{
    return c == ' ' || c == '\f' || c == '\n' || c == '\r' ||
        c == '\t' || c == '\v';
}

static inline int isgraph (int c)
{
    return (c >= 0x21 && c <= 0x7E) || (c >= 0xA1 && c <= 0xFF);
}

static inline int isprint (int c)
{
    return isgraph(c) && c != ' ';
}

static inline int ispunct (int c)
{
    return isprint(c) && !isalpha(c) && !isspace(c);
}

static inline int isblank (int c)
{
    return c == ' ' || c == '\t';
}

static inline int iscntrl (int c)
{
    return !isprint(c);
}

static inline int isascii (int c)
{
    return (c & 0x80) == 0;
}

static inline int tolower (int c)
{
    if (isupper(c))
        c |= 0x20;

    return c;
}

static inline int toupper (int c)
{
    if (islower(c))
        c &= ~0x20;

    return c;
}

static inline int toascii (int c)
{
    return c & ~0x80;
}

#endif /* !defined (__OHW_CTYPE_H__) */
