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
 * $Id: record.h,v 1.7 1998/11/02 22:09:08 rob Exp $
 */

void r_packcatkey(const CatKeyRec *, byte *, unsigned int *);
void r_unpackcatkey(const byte *, CatKeyRec *);

void r_packextkey(const ExtKeyRec *, byte *, unsigned int *);
void r_unpackextkey(const byte *, ExtKeyRec *);

int r_comparecatkeys(const CatKeyRec *, const CatKeyRec *);
int r_compareextkeys(const ExtKeyRec *, const ExtKeyRec *);

void r_packcatdata(const CatDataRec *, byte *, unsigned int *);
void r_unpackcatdata(const byte *, CatDataRec *);

void r_packextdata(const ExtDataRec *, byte *, unsigned int *);
void r_unpackextdata(const byte *, ExtDataRec *);

void r_makecatkey(CatKeyRec *, unsigned long, const char *);
void r_makeextkey(ExtKeyRec *, int, unsigned long, unsigned int);

void r_packcatrec(const CatKeyRec *, const CatDataRec *,
		  byte *, unsigned int *);
void r_packextrec(const ExtKeyRec *, const ExtDataRec *,
		  byte *, unsigned int *);

void r_packdirent(CatDataRec *, const hfsdirent *);
void r_unpackdirent(unsigned long, const char *,
		    const CatDataRec *, hfsdirent *);
