/*
 * <format.c>
 *
 * Open Hack'Ware BIOS: formated output functions
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
#include <stdio.h>
/* va_list is defined here */
#include <stdarg.h>
/* size_t is defined here */
#include <stddef.h>
/* NULL is defined here */
#include <stdlib.h>
/* write is defined here */
#include <unistd.h>
/* memcpy is defined here */
/* memset is defined here */
/* strlen is defined here */
#include <string.h>

#define unused __attribute__ (( unused ))
int console_write (const void *buffer, int len);
/* XXX: this is a hack to be fixed */
int serial_write (const void *buffer, int len);
#define debug_write serial_write

/* Low level output fonctions */
typedef size_t (*outf_t)(void *private, const unsigned char *buf, size_t len);

/* output to fd */
#if defined (__USE__vprintf__)
size_t outfd (void *private, const unsigned char *buf, size_t len)
{
    int *fd = private;

    if (*fd == 1 || *fd == 2)
        return console_write(buf, len);

    return write(*fd, buf, len);
}

size_t outf_dbg (void *private, const unsigned char *buf, size_t len)
{
    int *fd = private;

    if (*fd == 1 || *fd == 2)
        return debug_write(buf, len);

    return write(*fd, buf, len);
}

/* output to buffer */
size_t outbuf (void *private, const unsigned char *buf, size_t len)
{
    unsigned char **dst = private;

    memcpy(*dst, buf, len);
    (*dst) += len;
    (*dst)[0] = '\0';

    return len;
}

/* misc formatted output functions */
/* out one character */
static size_t outc (outf_t outf, void *private,
                    unsigned int value, size_t maxlen)
{
    unsigned char buffer;
    
    if (maxlen < 1)
        return 0;
    buffer = value;
    if ((*outf)(private, &buffer, 1) == (size_t)-1)
        return -1;

    return 1;
}

/* out one int in decimal */
static size_t outdecs (outf_t outf, void *private,
                       int value, size_t fill, size_t maxlen)
{
    unsigned char buffer[12];
    size_t pos, len;
    int sign;
    
    buffer[11] = '\0';
    pos = 10;
    if (value == 0) {
        sign = 0;
        buffer[pos--] = '0';
    } else {
        if (value < 0) {
            sign = -1;
            value = -value;
        } else {
            sign = 1;
        }
        for (; value != 0; pos--) {
            buffer[pos] = (value % 10) + '0';
            value = value / 10;
        }
    }
    if (fill != 0)
        fill -= pos - 10;
    for (; fill != 0 && pos != 0; fill--) {
        buffer[pos--] = '0';
    }
    if (sign == -1)
        buffer[pos--] = '-';
    len = 10 - pos;
    if (len > maxlen)
        len = maxlen;
    if ((*outf)(private, buffer + pos + 1, len) == (size_t)-1)
        return -1;

    return len;
}

/* out one unsigned int as decimal */
static size_t outdecu (outf_t outf, void *private,
                       unsigned int value, size_t fill, size_t maxlen)
{
    unsigned char buffer[11];
    size_t pos, len;
    
    buffer[10] = '\0';
    pos = 9;
    if (value == 0) {
        buffer[pos--] = '0';
    } else {
        for (; value != 0; pos--) {
            buffer[pos] = (value % 10) + '0';
            value = value / 10;
        }
    }
    if (fill != 0)
        fill -= pos - 9;
    for (; fill != 0 && pos != (size_t)-1; fill--) {
        buffer[pos--] = '0';
    }
    len = 9 - pos;
    if (len > maxlen)
        len = maxlen;
    if ((*outf)(private, buffer + pos + 1, len) == (size_t)-1)
        return -1;

    return len;
}

/* out one unsigned int as hexadecimal */
static size_t outhex (outf_t outf, void *private,
                      unsigned int value, size_t fill, size_t maxlen)
{
    unsigned char buffer[9];
    size_t pos, len;
    int d;

    buffer[8] = '\0';
    pos = 7;
    if (value == 0) {
        buffer[pos--] = '0';
    } else {
        for (; value != 0; pos--) {
            d = value & 0xF;
            if (d > 9)
            d += 'a' - '0' - 10;
            buffer[pos] = d + '0';
            value = value >> 4;
        }
    }
    if (fill > 0)
        fill -= pos - 7;
    for (; fill != 0 && pos != (size_t)-1; fill--) {
        buffer[pos--] = '0';
    }
    len = 7 - pos;
    if (len > maxlen)
        len = maxlen;
    if ((*outf)(private, buffer + pos + 1, len) == (size_t)-1)
        return -1;

    return len;
}

static size_t outstr (outf_t outf, void *private,
                      const unsigned char *str, unused size_t fill,
                      size_t maxlen)
{
#define TMPBUF_LEN 256
#if 0
    unsigned char tmpbuf[TMPBUF_LEN];
    size_t len, totlen, tmp;
#else
    size_t len, totlen;
#endif

    if (str == NULL) {
        /* Avoid crash if given a NULL string */
        str = "<null>";
    }
    len = strlen(str);
    totlen = 0;
#if 0
    if (len < fill) {
        memset(tmpbuf, ' ', TMPBUF_LEN);
        fill -= len;
        for (; fill > 0; fill -= tmp) {
            tmp = fill;
            if (tmp > TMPBUF_LEN)
                tmp = TMPBUF_LEN;
            totlen += tmp;
            if (totlen > maxlen) {
                tmp = maxlen - totlen;
                totlen = maxlen;
            }
            (*outf)(private, tmpbuf, tmp);
        }
    }
#endif
    totlen += len;
    if (totlen > maxlen) {
        len = maxlen - totlen;
        totlen = maxlen;
    }
    if ((*outf)(private, str, len) == (size_t)-1)
        return -1;

    return totlen;
}

int _vprintf(outf_t outf, void *private, size_t maxlen,
             const unsigned char *format, va_list ap)
{
    const unsigned char *p, *str;
    size_t maxfill, totlen, len, tmp;
    int cur;

    cur = 0;
    str = format;
    for (totlen = 0; totlen != maxlen;) {
        for (p = str; (*p != '%' || cur > 6) && *p != '\0'; p++)
            continue;
        len = p - str;
        if (len + totlen > maxlen)
            len = maxlen - totlen;
        tmp = (*outf)(private, str, p - str);
        if (tmp == (size_t)-1)
            return -1;
        totlen += tmp;
        if (*p == '\0')
            break;
        maxfill = -2;
        str = p;
    next:
        p++;
        switch (*p) {
        case '\0':
            /* Invalid format */
            goto invalid;
        case '0':
            if (maxfill >= (size_t)-2) {
                maxfill = -1;
                goto next;
            }
            /* No break here */
        case '1' ... '9':
            switch (maxfill) {
            case -2:
                /* Invalid format */
                goto invalid;
            case -1:
                maxfill = *p - '0';
                break;
            default:
                maxfill = (maxfill * 10) + *p - '0';
                break;
            }
            goto next;
        case 'l':
            /* Ignore it */
            goto next;
        case 'h':
            /* Ignore it */
            goto next;
        case 'd':
            if (maxfill == (size_t)-2 || maxfill == (size_t)(-1))
                maxfill = 0;
            tmp = outdecs(outf, private,
                          va_arg(ap, int), maxfill, maxlen - totlen);
            break;
        case 'u':
            if (maxfill == (size_t)-2 || maxfill == (size_t)(-1))
                maxfill = 0;
            tmp = outdecu(outf, private,
                          va_arg(ap, unsigned int), maxfill, maxlen - totlen);
            break;
        case 'x':
            if (maxfill == (size_t)-2 || maxfill == (size_t)(-1))
                maxfill = 0;
            tmp = outhex(outf, private,
                         va_arg(ap, unsigned int), maxfill, maxlen - totlen);
            break;
        case 'p':
            if (p != str + 1) {
                /* Invalid format */
                goto invalid;
            } else {
                if (maxfill == (size_t)-2 || maxfill == (size_t)(-1))
                    maxfill = 0;
                tmp = outhex(outf, private, va_arg(ap, unsigned int),
                             maxfill, maxlen - totlen);
            }
            break;
        case 'c':
            if (p != str + 1) {
                /* Invalid format */
                goto invalid;
            } else {
                tmp = outc(outf, private,
                           va_arg(ap, int), maxlen - totlen);
            }
            break;
        case 's':
            if (maxfill == (size_t)-2 || maxfill == (size_t)(-1))
                maxfill = 0;
            str = va_arg(ap, const unsigned char *);
            tmp = outstr(outf, private, str, maxfill, maxlen - totlen);
            break;
        case '%':
            if (p != str + 1) {
                /* Invalid format */
                goto invalid;
            } else {
                tmp = outc(outf, private, '%', maxlen - totlen);
            }
        default:
        invalid:
            /* Invalid format : display the raw string */
            len = p - str + 1;
            if (len + totlen > maxlen)
                len = maxlen - totlen;
            tmp = (*outf)(private, str, len);
            break;
        }
        if (tmp == (size_t)-1)
            return -1;
        totlen += tmp;
        str = p + 1;
    }

    return 0;
}
#else /* defined (__USE__vprintf__) */
size_t outfd (void *private, const unsigned char *buf, size_t len);
size_t outf_dbg (void *private, const unsigned char *buf, size_t len);
size_t outbuf (void *private, const unsigned char *buf, size_t len);
int _vprintf(outf_t outf, void *private, size_t maxlen,
             const unsigned char *format, va_list ap);
#endif /* defined (__USE__vprintf__) */

#if defined (__USE_printf__)
int printf (const char *format, ...)
{
    va_list ap;
    int fd = 1;
    int ret;

    va_start(ap, format);
    ret = _vprintf(&outfd, &fd, -1, format, ap);
    va_end(ap);

    return ret;
}
#endif /* defined (__USE_printf__) */

#if defined (__USE_dprintf__)
int dprintf (const char *format, ...)
{
    va_list ap;
    int fd = 1;
    int ret;

    va_start(ap, format);
    ret = _vprintf(&outf_dbg, &fd, -1, format, ap);
    va_end(ap);

    return ret;
}
#endif /* defined (__USE_dprintf__) */

#if defined (__USE_sprintf__)
int sprintf (char *str, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = _vprintf(&outbuf, &str, -1, format, ap);
    va_end(ap);

    return ret;
}
#endif /* defined (__USE_sprintf__) */

#if defined (__USE_snprintf__)
int snprintf (char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = _vprintf(&outbuf, &str, size, format, ap);
    va_end(ap);

    return ret;
}
#endif /* defined (__USE_snprintf__) */

#if defined (__USE_vprintf__)
int vprintf (const char *format, va_list ap)
{
    int fd = 1;

    return _vprintf(&outfd, &fd, -1, format, ap);
}
#endif /* defined (__USE_vprintf__) */

#if defined (__USE_vdprintf__)
int vdprintf (const char *format, va_list ap)
{
    int fd = 1;

    return _vprintf(&outf_dbg, &fd, -1, format, ap);
}
#endif /* defined (__USE_vdprintf__) */

#if defined (__USE_vsprintf__)
int vsprintf (char *str, const char *format, va_list ap)
{
    return _vprintf(&outbuf, &str, -1, format, ap);
}
#endif /* defined (__USE_vsprintf__) */

#if defined (__USE_vsnprintf__)
int vsnprintf (char *str, size_t size, const char *format, va_list ap)
{
    return _vprintf(&outbuf, &str, size, format, ap);
}
#endif /* defined (__USE_vsnprintf__) */
