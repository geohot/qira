/* Console Callback Routines.

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

#include "hwrpb.h"
#include "protos.h"
#include "console.h"
#include "uart.h"


/* All routines use the high bit to signal error.  */
#define ERR	0x8000000000000000ul


unsigned long
crb_getc(long unit)
{
  /* Multiple consoles not yet supported.  */
  if (unit != 0)
    return ERR;

  return uart_getchar(COM1);
}

unsigned long
crb_process_keycode(long unit, long keycode, long again)
{
  /* This routine might be needed for real keyboards, and mostly for
     internationalization stuff.  */
  /* Return Failure: routine not supported.  */
  return 0xc000000000000000ul;
}

unsigned long
crb_puts(long unit, const char *buf, unsigned long length)
{
  unsigned int orig_length = length;

  /* Multiple consoles not yet supported.  */
  if (unit != 0)
    return ERR;

  for (; length != 0; --length, ++buf)
    uart_putchar_raw(COM1, (unsigned char)*buf);

  /* Bits <31:0> of the return value are the number of bytes written.
     To me that implies that the input value must be 32-bit, but v2
     of the ARM doesn't explicitly say.  */
  return orig_length;
}

unsigned long
crb_reset_term(long unit)
{
  /* Multiple consoles not yet supported.  */
  if (unit != 0)
    return ERR;

  uart_init_line(COM1, 9600);
  return 0;
}

static unsigned long
crb_set_term_ctl(long unit, long ctb)
{
  /* ??? The contents of the CTB do not seem to be defined anywhere.
     How, therefore, can the user set new contents?  */
  return ERR;
}

static unsigned long
crb_set_term_int(long unit, long mask)
{
  /* We do no buffering, therefore we don't need to support interrupts.  */
  if (unit != 0 || (mask & 0x22) != 0)
    return ERR;
  return 0;
}

unsigned long
crb_open(const char *devstr,  unsigned long length)
{
  /* FIXME */
  return ERR;
}

unsigned long
crb_close(long channel)
{
  /* FIXME */
  return 0;
}

static unsigned long
crb_ioctl(long channel)
{
  /* We do not, nor will not, support virtual tapes.  */
  return ERR;
}

unsigned long
crb_read(long channel, unsigned long length, char *buf, unsigned long block)
{
  /* FIXME */
  return ERR;
}

unsigned long
crb_write(long channel, unsigned long length, const char *buf,
          unsigned long block)
{
  /* FIXME */
  return ERR;
}

unsigned long
crb_get_env(unsigned long id, char *buf, unsigned long length)
{
  /* FIXME */
  return 0xc000000000000000ul;
}

unsigned long
crb_set_env(unsigned long id, const char *buf, unsigned long length)
{
  /* FIXME */
  return 0xc000000000000000ul;
}

static unsigned long
crb_reset_env(unsigned long id, char *buf, unsigned long length)
{
  /* FIXME */
  return 0xc000000000000000ul;
}

static unsigned long
crb_save_env(void)
{
  /* FIXME */
  return 0xc000000000000000ul;
}

static unsigned long
crb_pswitch(long action, long cpu_id)
{
  /* Why would we ever need to support switching primary processor?  */
  return ERR;
}

static unsigned long __attribute__((used))
int_crb_dispatch(long select, long a1, long a2, long a3, long a4)
{
  switch (select)
    {
    case CRB_GETC:
      return crb_getc(a1);
    case CRB_PUTS:
      return crb_puts(a1, (const char *)a2, a3);
    case CRB_RESET_TERM:
      return crb_reset_term(a1);
    case CRB_SET_TERM_INT:
      return crb_set_term_int(a1, a2);
    case CRB_SET_TERM_CTL:
      return crb_set_term_ctl(a1, a2);
    case CRB_PROCESS_KEYCODE:
      return crb_process_keycode(a1, a2, a3);

    case CRB_OPEN:
      return crb_open((const char*)a1, a2);
    case CRB_CLOSE:
      return crb_close(a1);
    case CRB_IOCTL:
      return crb_ioctl(a1);
    case CRB_READ:
      return crb_read(a1, a2, (char *)a3, a4);
    case CRB_WRITE:
      return crb_write(a1, a2, (const char *)a3, a4);

    case CRB_SET_ENV:
      return crb_set_env(a1, (const char *)a2, a3);
    case CRB_RESET_ENV:
      return crb_reset_env(a1, (char *)a2, a3);
    case CRB_GET_ENV:
      return crb_get_env(a1, (char *)a2, a3);
    case CRB_SAVE_ENV:
      return crb_save_env();

    case CRB_PSWITCH:
      return crb_pswitch(a1, a2);
    }
  return ERR;
}

static unsigned long __attribute__((used))
int_crb_fixup(unsigned long vptptr, unsigned long hwrpb)
{
  /* Given that this console is written to use the KSEG, and not be
     mapped into any page-table address space, it doesn't seem like
     we need to do anything at all here.  */
  return 0;
}

/* The CRB DISPATCH and FIXUP functions are defined to use the VMS
   calling convention.  This has several effects: 
     (1) The set of call-saved registers is different.
     (2) $27 contains the procdesc_struct, not the called function.
   Map between the two calling conventions here.  */

asm(".macro	VMStoUNIX name\n"
"	.globl	\\name\n"
"	.ent	\\name\n"
"\\name:\n"
"	.frame	$sp, 64, $26, 0\n"
"	subq	$sp, 64, $sp\n"
"	stq	$26, 0($sp)\n"
"	stq	$2, 8($sp)\n"
"	stq	$3, 16($sp)\n"
"	stq	$4, 24($sp)\n"
"	stq	$5, 32($sp)\n"
"	stq	$6, 40($sp)\n"
"	stq	$7, 48($sp)\n"
"	stq	$8, 56($sp)\n"
"	.mask	0x40001fc, 0\n"
"	.prologue 2\n"
"	br	$gp, .+4\n"
"	ldgp	$gp, 0($gp)\n"
"	bsr	$26, int_\\name !samegp\n"
"	ldq	$26, 0($sp)\n"
"	ldq	$2, 8($sp)\n"
"	ldq	$3, 16($sp)\n"
"	ldq	$4, 24($sp)\n"
"	ldq	$5, 32($sp)\n"
"	ldq	$6, 40($sp)\n"
"	ldq	$7, 48($sp)\n"
"	ldq	$8, 56($sp)\n"
"	addq	$sp, 64, $sp\n"
"	ret\n"
"	.end	\\name\n"
".endm\n"
"	VMStoUNIX	crb_dispatch\n"
"	VMStoUNIX	crb_fixup\n"
);
