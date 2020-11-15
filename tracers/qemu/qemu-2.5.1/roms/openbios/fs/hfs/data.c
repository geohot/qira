/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 * Copyright (C) 1996-1998 Robert Leslie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * $Id: data.c,v 1.7 1998/11/02 22:08:57 rob Exp $
 */

#include "config.h"
#include "data.h"

#define TIMEDIFF  2082844800UL

static
time_t tzdiff = -1;

static const
unsigned char hfs_charorder[256] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,

  0x20, 0x22, 0x23, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
  0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
  0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
  0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,

  0x47, 0x48, 0x58, 0x5a, 0x5e, 0x60, 0x67, 0x69,
  0x6b, 0x6d, 0x73, 0x75, 0x77, 0x79, 0x7b, 0x7f,
  0x8d, 0x8f, 0x91, 0x93, 0x96, 0x98, 0x9f, 0xa1,
  0xa3, 0xa5, 0xa8, 0xaa, 0xab, 0xac, 0xad, 0xae,

  0x54, 0x48, 0x58, 0x5a, 0x5e, 0x60, 0x67, 0x69,
  0x6b, 0x6d, 0x73, 0x75, 0x77, 0x79, 0x7b, 0x7f,
  0x8d, 0x8f, 0x91, 0x93, 0x96, 0x98, 0x9f, 0xa1,
  0xa3, 0xa5, 0xa8, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,

  0x4c, 0x50, 0x5c, 0x62, 0x7d, 0x81, 0x9a, 0x55,
  0x4a, 0x56, 0x4c, 0x4e, 0x50, 0x5c, 0x62, 0x64,
  0x65, 0x66, 0x6f, 0x70, 0x71, 0x72, 0x7d, 0x89,
  0x8a, 0x8b, 0x81, 0x83, 0x9c, 0x9d, 0x9e, 0x9a,

  0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0x95,
  0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0x52, 0x85,
  0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
  0xc9, 0xca, 0xcb, 0x57, 0x8c, 0xcc, 0x52, 0x85,

  0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0x26,
  0x27, 0xd4, 0x20, 0x4a, 0x4e, 0x83, 0x87, 0x87,
  0xd5, 0xd6, 0x24, 0x25, 0x2d, 0x2e, 0xd7, 0xd8,
  0xa7, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,

  0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
  0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/*
 * NAME:	data->getsb()
 * DESCRIPTION:	marshal 1 signed byte into local host format
 */
signed char d_getsb(register const unsigned char *ptr)
{
  return ptr[0];
}

/*
 * NAME:	data->getub()
 * DESCRIPTION:	marshal 1 unsigned byte into local host format
 */
unsigned char d_getub(register const unsigned char *ptr)
{
  return ptr[0];
}

/*
 * NAME:	data->getsw()
 * DESCRIPTION:	marshal 2 signed bytes into local host format
 */
signed short d_getsw(register const unsigned char *ptr)
{
  return
    (((  signed short) ptr[0] << 8) |
     ((unsigned short) ptr[1] << 0));
}

/*
 * NAME:	data->getuw()
 * DESCRIPTION:	marshal 2 unsigned bytes into local host format
 */
unsigned short d_getuw(register const unsigned char *ptr)
{
  return
    (((unsigned short) ptr[0] << 8) |
     ((unsigned short) ptr[1] << 0));
}

/*
 * NAME:	data->getsl()
 * DESCRIPTION:	marshal 4 signed bytes into local host format
 */
signed long d_getsl(register const unsigned char *ptr)
{
  return
    (((  signed long) ptr[0] << 24) |
     ((unsigned long) ptr[1] << 16) |
     ((unsigned long) ptr[2] <<  8) |
     ((unsigned long) ptr[3] <<  0));
}

/*
 * NAME:	data->getul()
 * DESCRIPTION:	marshal 4 unsigned bytes into local host format
 */
unsigned long d_getul(register const unsigned char *ptr)
{
  return
    (((unsigned long) ptr[0] << 24) |
     ((unsigned long) ptr[1] << 16) |
     ((unsigned long) ptr[2] <<  8) |
     ((unsigned long) ptr[3] <<  0));
}

/*
 * NAME:	data->putsb()
 * DESCRIPTION:	marshal 1 signed byte out in big-endian format
 */
void d_putsb(register unsigned char *ptr,
	     register signed char data)
{
  *ptr = data;
}

/*
 * NAME:	data->putub()
 * DESCRIPTION:	marshal 1 unsigned byte out in big-endian format
 */
void d_putub(register unsigned char *ptr,
	     register unsigned char data)
{
  *ptr = data;
}

/*
 * NAME:	data->putsw()
 * DESCRIPTION:	marshal 2 signed bytes out in big-endian format
 */
void d_putsw(register unsigned char *ptr,
	     register signed short data)
{
  *ptr++ = ((unsigned short) data & 0xff00) >> 8;
  *ptr   = ((unsigned short) data & 0x00ff) >> 0;
}

/*
 * NAME:	data->putuw()
 * DESCRIPTION:	marshal 2 unsigned bytes out in big-endian format
 */
void d_putuw(register unsigned char *ptr,
	     register unsigned short data)
{
  *ptr++ = (data & 0xff00) >> 8;
  *ptr   = (data & 0x00ff) >> 0;
}

/*
 * NAME:	data->putsl()
 * DESCRIPTION:	marshal 4 signed bytes out in big-endian format
 */
void d_putsl(register unsigned char *ptr,
	     register signed long data)
{
  *ptr++ = ((unsigned long) data & 0xff000000UL) >> 24;
  *ptr++ = ((unsigned long) data & 0x00ff0000UL) >> 16;
  *ptr++ = ((unsigned long) data & 0x0000ff00UL) >>  8;
  *ptr   = ((unsigned long) data & 0x000000ffUL) >>  0;
}

/*
 * NAME:	data->putul()
 * DESCRIPTION:	marshal 4 unsigned bytes out in big-endian format
 */
void d_putul(register unsigned char *ptr,
	     register unsigned long data)
{
  *ptr++ = (data & 0xff000000UL) >> 24;
  *ptr++ = (data & 0x00ff0000UL) >> 16;
  *ptr++ = (data & 0x0000ff00UL) >>  8;
  *ptr   = (data & 0x000000ffUL) >>  0;
}

/*
 * NAME:	data->fetchsb()
 * DESCRIPTION:	incrementally retrieve a signed byte of data
 */
void d_fetchsb(register const unsigned char **ptr,
	       register signed char *dest)
{
  *dest = *(*ptr)++;
}

/*
 * NAME:	data->fetchub()
 * DESCRIPTION:	incrementally retrieve an unsigned byte of data
 */
void d_fetchub(register const unsigned char **ptr,
	       register unsigned char *dest)
{
  *dest = *(*ptr)++;
}

/*
 * NAME:	data->fetchsw()
 * DESCRIPTION:	incrementally retrieve a signed word of data
 */
void d_fetchsw(register const unsigned char **ptr,
	       register signed short *dest)
{
  *dest =
    (((  signed short) (*ptr)[0] << 8) |
     ((unsigned short) (*ptr)[1] << 0));
  *ptr += 2;
}

/*
 * NAME:	data->fetchuw()
 * DESCRIPTION:	incrementally retrieve an unsigned word of data
 */
void d_fetchuw(register const unsigned char **ptr,
	       register unsigned short *dest)
{
  *dest =
    (((unsigned short) (*ptr)[0] << 8) |
     ((unsigned short) (*ptr)[1] << 0));
  *ptr += 2;
}

/*
 * NAME:	data->fetchsl()
 * DESCRIPTION:	incrementally retrieve a signed long word of data
 */
void d_fetchsl(register const unsigned char **ptr,
	       register signed long *dest)
{
  *dest =
    (((  signed long) (*ptr)[0] << 24) |
     ((unsigned long) (*ptr)[1] << 16) |
     ((unsigned long) (*ptr)[2] <<  8) |
     ((unsigned long) (*ptr)[3] <<  0));
  *ptr += 4;
}

/*
 * NAME:	data->fetchul()
 * DESCRIPTION:	incrementally retrieve an unsigned long word of data
 */
void d_fetchul(register const unsigned char **ptr,
	       register unsigned long *dest)
{
  *dest =
    (((unsigned long) (*ptr)[0] << 24) |
     ((unsigned long) (*ptr)[1] << 16) |
     ((unsigned long) (*ptr)[2] <<  8) |
     ((unsigned long) (*ptr)[3] <<  0));
  *ptr += 4;
}

/*
 * NAME:	data->storesb()
 * DESCRIPTION:	incrementally store a signed byte of data
 */
void d_storesb(register unsigned char **ptr,
	       register signed char data)
{
  *(*ptr)++ = data;
}

/*
 * NAME:	data->storeub()
 * DESCRIPTION:	incrementally store an unsigned byte of data
 */
void d_storeub(register unsigned char **ptr,
	       register unsigned char data)
{
  *(*ptr)++ = data;
}

/*
 * NAME:	data->storesw()
 * DESCRIPTION:	incrementally store a signed word of data
 */
void d_storesw(register unsigned char **ptr,
	       register signed short data)
{
  *(*ptr)++ = ((unsigned short) data & 0xff00) >> 8;
  *(*ptr)++ = ((unsigned short) data & 0x00ff) >> 0;
}

/*
 * NAME:	data->storeuw()
 * DESCRIPTION:	incrementally store an unsigned word of data
 */
void d_storeuw(register unsigned char **ptr,
	       register unsigned short data)
{
  *(*ptr)++ = (data & 0xff00) >> 8;
  *(*ptr)++ = (data & 0x00ff) >> 0;
}

/*
 * NAME:	data->storesl()
 * DESCRIPTION:	incrementally store a signed long word of data
 */
void d_storesl(register unsigned char **ptr,
	       register signed long data)
{
  *(*ptr)++ = ((unsigned long) data & 0xff000000UL) >> 24;
  *(*ptr)++ = ((unsigned long) data & 0x00ff0000UL) >> 16;
  *(*ptr)++ = ((unsigned long) data & 0x0000ff00UL) >>  8;
  *(*ptr)++ = ((unsigned long) data & 0x000000ffUL) >>  0;
}

/*
 * NAME:	data->storeul()
 * DESCRIPTION:	incrementally store an unsigned long word of data
 */
void d_storeul(register unsigned char **ptr,
	       register unsigned long data)
{
  *(*ptr)++ = (data & 0xff000000UL) >> 24;
  *(*ptr)++ = (data & 0x00ff0000UL) >> 16;
  *(*ptr)++ = (data & 0x0000ff00UL) >>  8;
  *(*ptr)++ = (data & 0x000000ffUL) >>  0;
}

/*
 * NAME:	data->fetchstr()
 * DESCRIPTION:	incrementally retrieve a string
 */
void d_fetchstr(const unsigned char **ptr, char *dest, unsigned size)
{
  unsigned len;

  len = d_getub(*ptr);

  if (len > 0 && len < size)
    memcpy(dest, *ptr + 1, len);
  else
    len = 0;

  dest[len] = 0;

  *ptr += size;
}

/*
 * NAME:	data->storestr()
 * DESCRIPTION:	incrementally store a string
 */
void d_storestr(unsigned char **ptr, const char *src, unsigned size)
{
  unsigned len;

  len = strlen(src);
  if (len > --size)
    len = 0;

  d_storeub(ptr, len);

  memcpy(*ptr, src, len);
  memset(*ptr + len, 0, size - len);

  *ptr += size;
}

/*
 * NAME:	data->relstring()
 * DESCRIPTION:	compare two strings as per MacOS for HFS
 */
int d_relstring(const char *str1, const char *str2)
{
  register int diff;

  while (*str1 && *str2)
    {
      diff = hfs_charorder[(unsigned char) *str1] -
	     hfs_charorder[(unsigned char) *str2];

      if (diff)
	return diff;

      ++str1, ++str2;
    }

  if (! *str1 && *str2)
    return -1;
  else if (*str1 && ! *str2)
    return 1;

  return 0;
}

/*
 * NAME:	calctzdiff()
 * DESCRIPTION:	calculate the timezone difference between local time and UTC
 */
static
void calctzdiff(void)
{
# ifdef HAVE_MKTIME

  time_t t;
  int isdst;
  struct tm tm;
  const struct tm *tmp;

  time(&t);
  isdst = localtime(&t)->tm_isdst;

  tmp = gmtime(&t);
  if (tmp)
    {
      tm = *tmp;
      tm.tm_isdst = isdst;

      tzdiff = t - mktime(&tm);
    }
  else
    tzdiff = 0;

# else

  tzdiff = 0;

# endif
}

/*
 * NAME:	data->ltime()
 * DESCRIPTION:	convert MacOS time to local time
 */
time_t d_ltime(unsigned long mtime)
{
  if (tzdiff == -1)
    calctzdiff();

  return (time_t) (mtime - TIMEDIFF) - tzdiff;
}

/*
 * NAME:	data->mtime()
 * DESCRIPTION:	convert local time to MacOS time
 */
unsigned long d_mtime(time_t ltime)
{
  if (tzdiff == -1)
    calctzdiff();

  return (unsigned long) (ltime + tzdiff) + TIMEDIFF;
}
