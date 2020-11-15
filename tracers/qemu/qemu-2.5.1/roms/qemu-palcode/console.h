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

#ifndef CONSOLE_H
#define CONSOLE_H 1

#define CRB_GETC		0x01
#define CRB_PUTS		0x02
#define CRB_RESET_TERM		0x03
#define CRB_SET_TERM_INT	0x04
#define CRB_SET_TERM_CTL	0x05
#define CRB_PROCESS_KEYCODE	0x06

#define CRB_OPEN		0x10
#define CRB_CLOSE		0x11
#define CRB_IOCTL		0x12
#define CRB_READ		0x13
#define CRB_WRITE		0x14

#define CRB_SET_ENV		0x20
#define CRB_RESET_ENV		0x21
#define CRB_GET_ENV		0x22
#define CRB_SAVE_ENV		0x23

#define CRB_PSWITCH		0x30

extern unsigned long crb_getc(long unit);
extern unsigned long crb_process_keycode(long unit, long keycode, long again);
extern unsigned long crb_puts(long unit, const char *buf, unsigned long length);
extern unsigned long crb_reset_term(long unit);

extern unsigned long crb_open(const char *devstr,  unsigned long length);
extern unsigned long crb_close(long channel);
extern unsigned long crb_read(long channel, unsigned long length,
                              char *buf, unsigned long block);
extern unsigned long crb_write(long channel, unsigned long length,
                               const char *buf, unsigned long block);

extern unsigned long crb_get_env(unsigned long id, char *buf,
                                 unsigned long length);
extern unsigned long crb_set_env(unsigned long id, const char *buf,
                                 unsigned long length);

#endif /* CONSOLE_H */
