/* A reduced version of the printf function.

   Copyright (C) 2011 Richard Henderson

   This file is part of QEMU PALcode.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the text
   of the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include "console.h"

static int print_buf_pad(char *buf, int buflen, char *p, int width, int pad)
{
  int len = buf + buflen - p;
  int r = 0;

  if (width > len)
    {
      *--p = pad;
      len++;

      while (width > buflen)
	{
	  crb_puts(0, p, 1);
	  width--;
	  r++;
	}
      while (width > len)
	*--p = pad, len++;
    }

  crb_puts(0, p, len);
  return r + len;
}

static int print_decimal(unsigned long val, int width, int pad)
{
  char buf[32];
  char *p = buf + sizeof(buf);

  if (val == 0)
    *--p = '0';
  else
    {
      do
	{
	  unsigned long d, r;

	  /* Compiling with -Os results in a call to the division routine.
	     Do what the compiler ought to have done.  */
	  d = __builtin_alpha_umulh(val, 0xcccccccccccccccd);
	  d >>= 3;
	  r = val - (d * 10);

	  *--p = r + '0';
	  val = d;
	}
      while (val);
    }

  return print_buf_pad(buf, sizeof(buf), p, width, pad);
}

static int print_hex(unsigned long val, int width, char pad)
{
  char buf[32];
  char *p = buf + sizeof(buf);

  if (val == 0)
    *--p = '0';
  else
    {
      do
	{
	  int d = val % 16;
	  *--p = (d < 10 ? '0' : 'a' - 10) + d;
	  val /= 16;
	}
      while (val);
    }

  return print_buf_pad(buf, sizeof(buf), p, width, pad);
}

int printf(const char *fmt, ...)
{
  va_list args;
  unsigned long val;
  int r = 0;

  va_start(args, fmt);

  for (; *fmt ; fmt++)
    if (*fmt != '%')
      {
        crb_puts(0, fmt, 1);
	r++;
      }
    else
      {
        const char *percent = fmt;
	bool is_long = false;
        char pad = ' ';
        int width = 0;

      restart:
        switch (*++fmt)
	  {
	  case '%':
	    crb_puts(0, "%", 1);
	    r++;
	    break;

	  case 'l':
	    is_long = true;
	    goto restart;

	  case 'd':
	    if (is_long)
	      {
		long d = va_arg (args, long);
		if (d < 0)
		  {
		    crb_puts(0, "-", 1);
		    d = -d;
		  }
		val = d;
	      }
	    else
	      {
		int d = va_arg (args, int);
		if (d < 0)
		  {
		    crb_puts(0, "-", 1);
		    d = -d;
		    r++;
		  }
		val = d;
	      }
	    goto do_unsigned;

	  case 'u':
	    if (is_long)
	      val = va_arg (args, unsigned long);
	    else
	      val = va_arg (args, unsigned int);

	  do_unsigned:
	    r += print_decimal (val, width, pad);
	    break;

	  case 'x':
	    if (is_long)
	      val = va_arg (args, unsigned long);
	    else
	      val = va_arg (args, unsigned int);
	    r += print_hex (val, width, pad);
	    break;

	  case 's':
	    {
	      const char *s = va_arg (args, const char *);
	      int len = strlen(s);
	      crb_puts(0, s, len);
	      r += len;
	    }
	    break;

	  case '0':
	    pad = '0';
          case '1' ... '9':
	    width = *fmt - '0';
	    while (fmt[1] >= '0' && fmt[1] <= '9')
	      width = width * 10 + *++fmt - '0';
	    goto restart;

	  default:
	    {
	      int len = fmt - percent;
	      crb_puts(0, percent, len);
	      r += len;
	    }
	    break;
	  }
      }

  va_end(args);
  return r;
}
