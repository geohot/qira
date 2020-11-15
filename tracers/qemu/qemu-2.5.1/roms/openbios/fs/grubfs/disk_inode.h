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
 * Copyright (c) 1982, 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *	@(#)inode.h	7.5 (Berkeley) 7/3/89
 */

#ifndef	_BOOT_UFS_DISK_INODE_H_
#define	_BOOT_UFS_DISK_INODE_H_

/*
 * The I node is the focus of all file activity in the BSD Fast File System.
 * There is a unique inode allocated for each active file,
 * each current directory, each mounted-on file, text file, and the root.
 * An inode is 'named' by its dev/inumber pair. (iget/iget.c)
 * Data in icommon is read in from permanent inode on volume.
 */

#define	FFS_NDADDR	12	/* direct addresses in inode */
#define	FFS_NIADDR	3	/* indirect addresses in inode */

#define	FFS_MAX_FASTLINK_SIZE	((FFS_NDADDR + FFS_NIADDR) \
				 * sizeof (mach_daddr_t))

struct icommon
  {
    unsigned short ic_mode;	/*  0: mode and type of file */
    short ic_nlink;		/*  2: number of links to file */
    mach_uid_t ic_uid;		/*  4: owner's user id */
    mach_gid_t ic_gid;		/*  6: owner's group id */
    quad ic_size;		/*  8: number of bytes in file */
    mach_time_t ic_atime;	/* 16: time last accessed */
    int ic_atspare;
    mach_time_t ic_mtime;	/* 24: time last modified */
    int ic_mtspare;
    mach_time_t ic_ctime;	/* 32: last time inode changed */
    int ic_ctspare;
    union
      {
	struct
	  {
	    mach_daddr_t Mb_db[FFS_NDADDR];	/* 40: disk block addresses */
	    mach_daddr_t Mb_ib[FFS_NIADDR];	/* 88: indirect blocks */
	  }
	ic_Mb;
	char ic_Msymlink[FFS_MAX_FASTLINK_SIZE];
	/* 40: symbolic link name */
      }
    ic_Mun;
#define	ic_db		ic_Mun.ic_Mb.Mb_db
#define	ic_ib		ic_Mun.ic_Mb.Mb_ib
#define	ic_symlink	ic_Mun.ic_Msymlink
    int ic_flags;		/* 100: status, currently unused */
    int ic_blocks;		/* 104: blocks actually held */
    int ic_gen;			/* 108: generation number */
    int ic_spare[4];		/* 112: reserved, currently unused */
  };

/*
 *	Same structure, but on disk.
 */
struct dinode
  {
    union
      {
	struct icommon di_com;
	char di_char[128];
      }
    di_un;
  };
#define	di_ic	di_un.di_com

#endif /* _BOOT_UFS_DISK_INODE_H_ */
