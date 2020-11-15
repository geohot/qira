/* Declarations common the the C portions of the QEMU PALcode console.

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

#ifndef PROTOS_H
#define PROTOS_H 1

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>


/*
 * Call_Pal functions.
 */

static inline void wrent(void *cb, unsigned long which)
{
  register void *a0 __asm__("$16") = cb;
  register unsigned long a1 __asm__("$17") = which;

  asm volatile ("call_pal 0x34"
		: "+r"(a0), "+r"(a1)
		: : "$1", "$22", "$23", "$24", "$25");
}

static inline unsigned long swpipl(unsigned long newipl)
{
  register unsigned long v0 __asm__("$0");
  register unsigned long a0 __asm__("$16") = newipl;

  asm volatile ("call_pal 0x35"
		: "=r"(v0), "+r"(a0)
		: : "$1", "$22", "$23", "$24", "$25");

  return v0;
}

static inline unsigned long rdps(void)
{
  register unsigned long v0 __asm__("$0");

  asm volatile ("call_pal 0x36"
		: "=r"(v0) : : "$1", "$22", "$23", "$24", "$25");

  return v0;
}

static inline void wrkgp(void)
{
  asm volatile ("mov $29, $16\n\tcall_pal 0x37"
		: : : "$16", "$1", "$22", "$23", "$24", "$25");
}

static inline unsigned long wtint(unsigned long skip)
{
  register unsigned long v0 __asm__("$0");
  register unsigned long a0 __asm__("$16") = skip;

  asm volatile ("call_pal 0x3e"
		: "=r"(v0), "+r"(a0)
		: : "$1", "$22", "$23", "$24", "$25");

  return v0;
}

/* 
 * Cserve functions.
 */

static inline unsigned long ldq_p(unsigned long addr)
{
  register unsigned long v0 __asm__("$0");
  register unsigned long a0 __asm__("$16") = 1;
  register unsigned long a1 __asm__("$17") = addr;

  asm volatile ("call_pal 9"
		: "=r"(v0), "+r"(a0), "+r"(a1) :
		: "$18", "$19", "$20", "$21");

  return v0;
}

static inline unsigned long stq_p(unsigned long port, unsigned long val)
{
  register unsigned long v0 __asm__("$0");
  register unsigned long a0 __asm__("$16") = 2;
  register unsigned long a1 __asm__("$17") = port;
  register unsigned long a2 __asm__("$18") = val;

  asm volatile ("call_pal 9"
		: "=r"(v0), "+r"(a0), "+r"(a1), "+r"(a2) :
		: "$19", "$20", "$21");

  return v0;
}

static inline unsigned long get_wall_time(void)
{
  register unsigned long v0 __asm__("$0");
  register unsigned long a0 __asm__("$16") = 3;

  asm("call_pal 9" : "=r"(v0), "+r"(a0) : : "$17", "$18", "$19", "$20", "$21");

  return v0;
}

static inline unsigned long get_alarm(void)
{
  register unsigned long v0 __asm__("$0");
  register unsigned long a0 __asm__("$16") = 4;

  asm("call_pal 9" : "=r"(v0), "+r"(a0) : : "$17", "$18", "$19", "$20", "$21");

  return v0;
}

static inline void set_alarm_rel(unsigned long nsec)
{
  register unsigned long a0 __asm__("$16") = 5;
  register unsigned long a1 __asm__("$17") = nsec;

  asm volatile ("call_pal 9"
		: "+r"(a0), "+r"(a1)
		: : "$0", "$18", "$19", "$20", "$21");
}

static inline void set_alarm_abs(unsigned long nsec)
{
  register unsigned long a0 __asm__("$16") = 6;
  register unsigned long a1 __asm__("$17") = nsec;

  asm volatile ("call_pal 9"
		: "+r"(a0), "+r"(a1)
		: : "$0", "$18", "$19", "$20", "$21");
}

/*
 * I/O functions
 */

extern void *pci_io_base;
extern void *pci_mem_base;

static inline uint8_t inb(unsigned long port)
{
  return *(volatile uint8_t *)(pci_io_base + port);
}

static inline uint16_t inw(unsigned long port)
{
  return *(volatile uint16_t *)(pci_io_base + port);
}

static inline uint32_t inl(unsigned long port)
{
  return *(volatile uint32_t *)(pci_io_base + port);
}

static inline void outb(uint8_t val, unsigned long port)
{
  *(volatile uint8_t *)(pci_io_base + port) = val;
}

static inline void outw(uint16_t val, unsigned long port)
{
  *(volatile uint16_t *)(pci_io_base + port) = val;
}

static inline void outl(uint32_t val, unsigned long port)
{
  *(volatile uint32_t *)(pci_io_base + port) = val;
}

/*
 * CRB functions
 */

extern unsigned long crb_dispatch(long select, long a1, long a2,
                                  long a3, long a4);
extern unsigned long crb_fixup(unsigned long vptptr, unsigned long hwrpb);

/*
 * The Console
 */

extern bool have_vga;

extern void do_console(void);
extern void entInt(void);

/*
 * Utils
 */

extern int printf(const char *, ...);
extern void ndelay(unsigned long nsec);

static inline void udelay(unsigned long msec)
{
  ndelay(msec * 1000);
}

/*
 * Initialization
 */
extern void ps2port_setup(void);
extern void pci_setup(void);
extern void vgahw_init(void);

#endif /* PROTOS_H */
