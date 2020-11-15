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

#ifndef	_BOOT_UFS_DISK_INODE_FFS_H_
#define	_BOOT_UFS_DISK_INODE_FFS_H_

#define	NDADDR	FFS_NDADDR
#define	NIADDR	FFS_NIADDR

#define	MAX_FASTLINK_SIZE	FFS_MAX_FASTLINK_SIZE

#define	IC_FASTLINK	0x0001	/* Symbolic link in inode */

#define	i_mode		ic_mode
#define	i_nlink		ic_nlink
#define	i_uid		ic_uid
#define	i_gid		ic_gid
#if	defined(BYTE_MSF) && BYTE_MSF
#define	i_size		ic_size.val[1]
#else /* BYTE_LSF */
#define	i_size		ic_size.val[0]
#endif
#define	i_db		ic_db
#define	i_ib		ic_ib
#define	i_atime		ic_atime
#define	i_mtime		ic_mtime
#define	i_ctime		ic_ctime
#define i_blocks	ic_blocks
#define	i_rdev		ic_db[0]
#define	i_symlink	ic_symlink
#define i_flags		ic_flags
#define i_gen		ic_gen

/* modes */
#define	IFMT	0xf000		/* type of file */
#define	IFCHR	0x2000		/* character special */
#define	IFDIR	0x4000		/* directory */
#define	IFBLK	0x6000		/* block special */
#define	IFREG	0x8000		/* regular */
#define	IFLNK	0xa000		/* symbolic link */
#define	IFSOCK	0xc000		/* socket */


#define	ISUID		0x0800	/* set user id on execution */
#define	ISGID		0x0400	/* set group id on execution */
#define	ISVTX		0x0200	/* save swapped text even after use */
#define	IREAD		0x0100	/* read, write, execute permissions */
#define	IWRITE		0x0080
#define	IEXEC		0x0040

#ifdef EEK
#define f_fs		u.ffs.ffs_fs
#define i_ic		u.ffs.ffs_ic
#define f_nindir	u.ffs.ffs_nindir
#define f_blk		u.ffs.ffs_blk
#define f_blksize	u.ffs.ffs_blksize
#define f_blkno		u.ffs.ffs_blkno
#endif /* EEK */

#endif	/* _BOOT_UFS_DISK_INODE_FFS_H_ */
