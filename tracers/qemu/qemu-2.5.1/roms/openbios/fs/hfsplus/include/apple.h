/*
 * libhfsp - library for reading and writing Macintosh HFS+ volumes
 *
 * This file contains defintions that are special for Apple.
 * The names match the defintions found in Apple Header files.
 *
 * Copyright (C) 2000 Klaus Halfmann <khalfmann@libra.de>
 * Original code 1996-1998 by Robert Leslie <rob@mars.rog>
 * other work 2000 from Brad Boyer (flar@pants.nu)
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
 * $Id: apple.h,v 1.2 2000/09/08 14:55:08 hasi Exp $
 */

typedef signed char	    Char;
typedef unsigned char	    UChar;
typedef signed char	    SInt8;
typedef unsigned char	    UInt8;
typedef signed short	    SInt16;
typedef unsigned short	    UInt16;
typedef signed long	    SInt32;
typedef unsigned long	    UInt32;
typedef unsigned long	    OSType;
typedef unsigned long long  UInt64;

/* A point, normally used by Quickdraw,
 * but found in Finderinformation, too
 */
typedef struct {
  SInt16	v;		/* vertical coordinate */
  SInt16	h;		/* horizontal coordinate */
} Point;

/* A rectancle, normally used by Quickdraw,
 * but found in Finderinformation, too.
 */
typedef struct {
  SInt16	top;		/* top edge of rectangle */
  SInt16	left;		/* left edge */
  SInt16	bottom;		/* bottom edge */
  SInt16	right;		/* right edge */
} Rect;

/* Information about the location and size of a folder
 * used by the Finder.
 */
typedef struct {
  Rect		frRect;		/* folder's rectangle */
  SInt16	frFlags;	/* flags */
  Point		frLocation;	/* folder's location */
  SInt16	frView;		/* folder's view */
} DInfo;

/* Extended folder information used by the Finder ...
 */
typedef struct {
  Point		frScroll;	/* scroll position */
  SInt32	frOpenChain;	/* directory ID chain of open folders */
  SInt16	frUnused;	/* reserved */
  SInt16	frComment;	/* comment ID */
  SInt32	frPutAway;	/* directory ID */
} DXInfo;

/* Finder information for a File
 */
typedef struct {
  OSType	fdType;		/* file type */
  OSType	fdCreator;	/* file's creator */
  SInt16	fdFlags;	/* flags */
  Point		fdLocation;	/* file's location */
  SInt16	fdFldr;		/* file's window */
} FInfo;

/* Extendend Finder Information for a file
 */
typedef struct {
  SInt16	fdIconID;	/* icon ID */
  SInt16	fdUnused[4];	/* reserved */
  SInt16	fdComment;	/* comment ID */
  SInt32	fdPutAway;	/* home directory ID */
} FXInfo;

/* Flagvalues for FInfo and DInfo */
# define HFS_FNDR_ISONDESK              (1 <<  0)
# define HFS_FNDR_COLOR                 0x0e
# define HFS_FNDR_COLORRESERVED         (1 <<  4)
# define HFS_FNDR_REQUIRESSWITCHLAUNCH  (1 <<  5)
# define HFS_FNDR_ISSHARED              (1 <<  6)
# define HFS_FNDR_HASNOINITS            (1 <<  7)
# define HFS_FNDR_HASBEENINITED         (1 <<  8)
# define HFS_FNDR_RESERVED              (1 <<  9)
# define HFS_FNDR_HASCUSTOMICON         (1 << 10)
# define HFS_FNDR_ISSTATIONERY          (1 << 11)
# define HFS_FNDR_NAMELOCKED            (1 << 12)
# define HFS_FNDR_HASBUNDLE             (1 << 13)
# define HFS_FNDR_ISINVISIBLE           (1 << 14)
# define HFS_FNDR_ISALIAS               (1 << 15)
