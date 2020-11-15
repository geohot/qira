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
 * $Id: data.h,v 1.7 1998/11/02 22:08:58 rob Exp $
 */

  signed  char d_getsb(register const unsigned char *);
unsigned  char d_getub(register const unsigned char *);
  signed short d_getsw(register const unsigned char *);
unsigned short d_getuw(register const unsigned char *);
  signed  long d_getsl(register const unsigned char *);
unsigned  long d_getul(register const unsigned char *);

void d_putsb(register unsigned char *, register   signed  char);
void d_putub(register unsigned char *, register unsigned  char);
void d_putsw(register unsigned char *, register   signed short);
void d_putuw(register unsigned char *, register unsigned short);
void d_putsl(register unsigned char *, register   signed  long);
void d_putul(register unsigned char *, register unsigned  long);

void d_fetchsb(register const unsigned char **, register   signed  char *);
void d_fetchub(register const unsigned char **, register unsigned  char *);
void d_fetchsw(register const unsigned char **, register   signed short *);
void d_fetchuw(register const unsigned char **, register unsigned short *);
void d_fetchsl(register const unsigned char **, register   signed  long *);
void d_fetchul(register const unsigned char **, register unsigned  long *);

void d_storesb(register unsigned char **, register   signed  char);
void d_storeub(register unsigned char **, register unsigned  char);
void d_storesw(register unsigned char **, register   signed short);
void d_storeuw(register unsigned char **, register unsigned short);
void d_storesl(register unsigned char **, register   signed  long);
void d_storeul(register unsigned char **, register unsigned  long);

void d_fetchstr(const unsigned char **, char *, unsigned);
void d_storestr(unsigned char **, const char *, unsigned);

int d_relstring(const char *, const char *);

time_t d_ltime(unsigned long);
unsigned long d_mtime(time_t);
