/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 * Common definitions for Berkeley Fast File System.
 */

/*
 * Compatibility definitions for disk IO.
 */

/*
 * Disk devices do all IO in 512-byte blocks.
 */
#define	DEV_BSIZE	512

/*
 * Conversion between bytes and disk blocks.
 */
#define	btodb(byte_offset)	((byte_offset) >> 9)
#define	dbtob(block_number)	((block_number) << 9)

typedef struct _quad_
  {
    unsigned int val[2];	/* 2 int values make... */
  }
quad;				/* an 8-byte item */

typedef unsigned int mach_time_t;	/* an unsigned int */
typedef unsigned int mach_daddr_t;	/* an unsigned int */
typedef unsigned int mach_off_t;	/* another unsigned int */

typedef unsigned short mach_uid_t;
typedef unsigned short mach_gid_t;
typedef unsigned int mach_ino_t;

#define	NBBY	8

/*
 * The file system is made out of blocks of at most MAXBSIZE units,
 * with smaller units (fragments) only in the last direct block.
 * MAXBSIZE primarily determines the size of buffers in the buffer
 * pool.  It may be made larger without any effect on existing
 * file systems; however, making it smaller may make some file
 * systems unmountable.
 *
 * Note that the disk devices are assumed to have DEV_BSIZE "sectors"
 * and that fragments must be some multiple of this size.
 */
#define	MAXBSIZE	8192
#define	MAXFRAG		8

/*
 * MAXPATHLEN defines the longest permissible path length
 * after expanding symbolic links.
 *
 * MAXSYMLINKS defines the maximum number of symbolic links
 * that may be expanded in a path name.  It should be set
 * high enough to allow all legitimate uses, but halt infinite
 * loops reasonably quickly.
 */

#define	MAXPATHLEN	1024
#define	MAXSYMLINKS	8
