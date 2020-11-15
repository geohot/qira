/* The SRM console prompt.

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

#include "protos.h"
#include "console.h"
#include "vgatables.h"


static void
output_crnl(void)
{
  crb_puts(0, "\r\n", 2);
}

static void
output_bell(void)
{
  crb_puts(0, "\a", 1);
}

static void
backspace_and_erase(void)
{
  crb_puts(0, "\b \b", 3);
}

static unsigned long
getline(char *buf, unsigned long bufsize)
{
  unsigned long len = 0;
  long c;

  while (1)
    {
      c = crb_getc(0);
      if (c < 0)
	continue;
      switch ((int)c)
	{
	case '\r':
	case '\n':
	  output_crnl();
	  buf[len] = 0;
	  return len;

        case '\b':
	case 0x7f: /* Delete */
          if (len > 0)
	    {
	      backspace_and_erase();
              len--;
            }
	  else
	    output_bell();
          break;

        default:
	  if (len + 1 < bufsize)
	    {
	      buf[len] = c;
              crb_puts(0, buf+len, 1);
	      len++;
	    }
	  else
	    output_bell();
	  break;
        }
    }
}

static inline void set_console_alarm(void)
{
  /* Just set a new timeout for 10ms = 10M ns.  */
  set_alarm_rel(10 * 1000 * 1000);
}

void
do_entInt(unsigned long type, unsigned long vector)
{
  switch (type)
    {
    case 0:
      /* ??? SMP interrupt.  We're going to need this for starting up
         secondary cpus.  */
      break;
    case 1:
      /* Timer interrupt.  */
      set_console_alarm();
      break;
    case 2:
      /* ??? Device interrupt.  We're going to need this for virtio disk
         operations at minimum.  */
      break;
    }
}

void
do_console(void)
{
  char line[256];
  unsigned long len;

  wrkgp();
  wrent(entInt, 0);
  set_console_alarm();
  swpipl(0);

  if (have_vga)
  {
    unsigned short *vga, attr;
    vga = pci_mem_base + SEG_CTEXT *16;
    attr = 0x2000;
    vga[0] = 'H' + attr;
    vga[1] = 'e' + attr;
    vga[2] = 'l' + attr;
    vga[3] = 'l' + attr;
    vga[4] = 'o' + attr;
  }

  while (1)
    {
      crb_puts(0, ">>> ", 4);
      len = getline(line, sizeof(line));
      crb_puts(0, "got: ", 5);
      crb_puts(0, line, len);
      output_crnl();
    }
}
