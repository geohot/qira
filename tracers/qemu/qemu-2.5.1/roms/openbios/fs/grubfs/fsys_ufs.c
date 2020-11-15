/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (c) 2000, 2001  Free Software Foundation, Inc.
 *  Copyright (c) 2005  Rink Springer
 *
 *  This file is based on FreeBSD 5.4-RELEASE's /sys/boot/common/ufsread.c,
 *  and has some minor patches so it'll work with Cromwell/GRUB.
 *
 */
/*-
 * Copyright (c) 2002 McAfee, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Marshall
 * Kirk McKusick and McAfee Research,, the Security Research Division of
 * McAfee, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as
 * part of the DARPA CHATS research program
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*-
 * Copyright (c) 1998 Robert Nordier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are freely
 * permitted provided that the above copyright notice and this
 * paragraph and the following disclaimer are duplicated in all
 * such forms.
 *
 * This software is provided "AS IS" and without any express or
 * implied warranties, including, without limitation, the implied
 * warranties of merchantability and fitness for a particular
 * purpose.
 */
#ifdef FSYS_UFS

#include "asm/types.h"

#include "shared.h"
#include "filesys.h"

#include "ufs_dinode.h"
#include "ufs_fs.h"

#ifdef __i386__
/* XXX: Revert to old (broken for over 1.5Tb filesystems) version of cgbase
   (see sys/ufs/ffs/fs.h rev 1.39) so that i386 boot loader (boot2) can
   support both UFS1 and UFS2 again. */
#undef cgbase
#define cgbase(fs, c)   ((ufs2_daddr_t)((fs)->fs_fpg * (c)))
#endif

/*
 * We use 4k `virtual' blocks for filesystem data, whatever the actual
 * filesystem block size. FFS blocks are always a multiple of 4k.
 */
#define VBLKSHIFT	12
#define VBLKSIZE	(1 << VBLKSHIFT)
#define VBLKMASK	(VBLKSIZE - 1)
#define DBPERVBLK	(VBLKSIZE / DEV_BSIZE)
#define INDIRPERVBLK(fs) (NINDIR(fs) / ((fs)->fs_bsize >> VBLKSHIFT))
#define IPERVBLK(fs)	(INOPB(fs) / ((fs)->fs_bsize >> VBLKSHIFT))
#define INO_TO_VBA(fs, ipervblk, x) \
    (fsbtodb(fs, cgimin(fs, ino_to_cg(fs, x))) + \
    (((x) % (fs)->fs_ipg) / (ipervblk) * DBPERVBLK))
#define INO_TO_VBO(ipervblk, x) ((x) % ipervblk)
#define FS_TO_VBA(fs, fsb, off) (fsbtodb(fs, fsb) + \
    ((off) / VBLKSIZE) * DBPERVBLK)
#define FS_TO_VBO(fs, fsb, off) ((off) & VBLKMASK)

/* Buffers that must not span a 64k boundary. */
struct dmadat {
	char blkbuf[VBLKSIZE];	/* filesystem blocks */
	char indbuf[VBLKSIZE];	/* indir blocks */
	char sbbuf[SBLOCKSIZE];	/* superblock */
	char secbuf[DEV_BSIZE];	/* for MBR/disklabel */
};
static struct dmadat *dmadat = (struct dmadat*)FSYS_BUF;

#define SUPERBLOCK ((struct fs*)dmadat->sbbuf)

ino_t lookup(const char *);
ssize_t fsread(ino_t, void *, size_t);

static int dsk_meta;
static uint32_t fs_off;
static ino_t cur_ino = 0;

static inline int
dskread (void* buf, unsigned lba, unsigned nblk)
{
	return !devread (lba, 0, nblk * DEV_BSIZE, buf) ? -1 : 0;
}

#if defined(UFS2_ONLY)
#define DIP(field) dp2.field
#elif defined(UFS1_ONLY)
#define DIP(field) dp1.field
#else
#define DIP(field) fs->fs_magic == FS_UFS1_MAGIC ? dp1.field : dp2.field
#endif

static __inline int
fsfind(const char *name, ino_t * ino)
{
	char buf[DEV_BSIZE];
	struct ufs_dirent *d;
	char *s;
	ssize_t n;
#ifndef UFS2_ONLY
	static struct ufs1_dinode dp1;
#endif
#ifndef UFS1_ONLY
	static struct ufs2_dinode dp2;
#endif
	char* blkbuf = dmadat->blkbuf;
	struct fs* fs = (struct fs *)dmadat->sbbuf;

	fs_off = 0;
	while ((n = fsread(*ino, buf, DEV_BSIZE)) > 0)
		for (s = buf; s < buf + DEV_BSIZE;) {
			d = (void *)s;
			if (!strcmp(name, d->d_name)) {
				*ino = d->d_fileno;

				/* below is for grub, which wants the file size
				 */
				n = IPERVBLK(fs);
				if (dskread(blkbuf, INO_TO_VBA(fs, n, (*ino)), DBPERVBLK))
					return -1;
				n = INO_TO_VBO(n, (*ino));
#if defined(UFS1_ONLY)
				dp1 = ((struct ufs1_dinode *)blkbuf)[n];
#elif defined(UFS2_ONLY)
				dp2 = ((struct ufs2_dinode *)blkbuf)[n];
#else
				if (fs->fs_magic == FS_UFS1_MAGIC)
					dp1 = ((struct ufs1_dinode *)blkbuf)[n];
				else
					dp2 = ((struct ufs2_dinode *)blkbuf)[n];
#endif

				filemax = DIP(di_size);
				return d->d_type;
			}
			s += d->d_reclen;
		}
	return 0;
}

ino_t
lookup(const char *path)
{
	char name[MAXNAMLEN + 1];
	const char *s;
	ino_t ino;
	ssize_t n;
	int dt;

	ino = ROOTINO;
	dt = DT_DIR;
	name[0] = '/';
	name[1] = '\0';
	for (;;) {
		if (*path == '/')
			path++;
		if (!*path)
			break;
		for (s = path; *s && *s != '/'; s++);
		if ((n = s - path) > MAXNAMLEN)
			return 0;
		memcpy(name, path, n);
		name[n] = 0;
		if (dt != DT_DIR) {
			printk("%s: not a directory.\n", name);
			return (0);
		}
		if ((dt = fsfind(name, &ino)) <= 0)
			break;
		path = s;
	}
	return dt == DT_REG ? ino : 0;
}

/*
 * Possible superblock locations ordered from most to least likely.
 */
static const int sblock_try[] = SBLOCKSEARCH;

ssize_t
fsread(ino_t inode, void *buf, size_t nbyte)
{
#ifndef UFS2_ONLY
	static struct ufs1_dinode dp1;
#endif
#ifndef UFS1_ONLY
	static struct ufs2_dinode dp2;
#endif
	static ino_t inomap;
	char *blkbuf;
	void *indbuf;
	struct fs *fs;
	char *s;
	size_t n, nb, size, off, vboff;
	ufs_lbn_t lbn;
	ufs2_daddr_t addr, vbaddr;
	static ufs2_daddr_t blkmap, indmap;
	unsigned int u;


	blkbuf = dmadat->blkbuf;
	indbuf = dmadat->indbuf;
	fs = (struct fs *)dmadat->sbbuf;
	if (!dsk_meta) {
		inomap = 0;
		for (n = 0; sblock_try[n] != -1; n++) {
			if (dskread(fs, sblock_try[n] / DEV_BSIZE,
			    SBLOCKSIZE / DEV_BSIZE))
				return -1;
			if ((
#if defined(UFS1_ONLY)
			     fs->fs_magic == FS_UFS1_MAGIC
#elif defined(UFS2_ONLY)
			    (fs->fs_magic == FS_UFS2_MAGIC &&
			    fs->fs_sblockloc == sblock_try[n])
#else
			     fs->fs_magic == FS_UFS1_MAGIC ||
			    (fs->fs_magic == FS_UFS2_MAGIC &&
			    fs->fs_sblockloc == sblock_try[n])
#endif
			    ) &&
			    fs->fs_bsize <= MAXBSIZE &&
			    fs->fs_bsize >= sizeof(struct fs))
				break;
		}
		if (sblock_try[n] == -1) {
			printk("Not ufs\n");
			return -1;
		}
		dsk_meta++;
	}
	if (!inode)
		return 0;
	if (inomap != inode) {
		n = IPERVBLK(fs);
		if (dskread(blkbuf, INO_TO_VBA(fs, n, inode), DBPERVBLK))
			return -1;
		n = INO_TO_VBO(n, inode);
#if defined(UFS1_ONLY)
		dp1 = ((struct ufs1_dinode *)blkbuf)[n];
#elif defined(UFS2_ONLY)
		dp2 = ((struct ufs2_dinode *)blkbuf)[n];
#else
		if (fs->fs_magic == FS_UFS1_MAGIC)
			dp1 = ((struct ufs1_dinode *)blkbuf)[n];
		else
			dp2 = ((struct ufs2_dinode *)blkbuf)[n];
#endif
		inomap = inode;
		fs_off = 0;
		blkmap = indmap = 0;
	}
	s = buf;
	size = DIP(di_size);
	n = size - fs_off;
	if (nbyte > n)
		nbyte = n;
	nb = nbyte;
	while (nb) {
		lbn = lblkno(fs, fs_off);
		off = blkoff(fs, fs_off);
		if (lbn < NDADDR) {
			addr = DIP(di_db[lbn]);
		} else if (lbn < NDADDR + NINDIR(fs)) {
			n = INDIRPERVBLK(fs);
			addr = DIP(di_ib[0]);
			u = (unsigned int)(lbn - NDADDR) / (n * DBPERVBLK);
			vbaddr = fsbtodb(fs, addr) + u;
			if (indmap != vbaddr) {
				if (dskread(indbuf, vbaddr, DBPERVBLK))
					return -1;
				indmap = vbaddr;
			}
			n = (lbn - NDADDR) & (n - 1);
#if defined(UFS1_ONLY)
			addr = ((ufs1_daddr_t *)indbuf)[n];
#elif defined(UFS2_ONLY)
			addr = ((ufs2_daddr_t *)indbuf)[n];
#else
			if (fs->fs_magic == FS_UFS1_MAGIC)
				addr = ((ufs1_daddr_t *)indbuf)[n];
			else
				addr = ((ufs2_daddr_t *)indbuf)[n];
#endif
		} else {
			return -1;
		}
		vbaddr = fsbtodb(fs, addr) + (off >> VBLKSHIFT) * DBPERVBLK;
		vboff = off & VBLKMASK;
		n = sblksize(fs, size, lbn) - (off & ~VBLKMASK);
		if (n > VBLKSIZE)
			n = VBLKSIZE;
		if (blkmap != vbaddr) {
			if (dskread(blkbuf, vbaddr, n >> DEV_BSHIFT))
				return -1;
			blkmap = vbaddr;
		}
		n -= vboff;
		if (n > nb)
			n = nb;
		memcpy(s, blkbuf + vboff, n);
		s += n;
		fs_off += n;
		nb -= n;
	}
	return nbyte;
}

int
ufs_mount (void)
{
  int i, retval = 0;

  /*
   * We don't care about stuff being in disklabels or not. If the magic
   * matches, we're good to go.
   */
  for (i = 0; sblock_try[i] != -1; ++i)
  {
	if (! (part_length < (sblock_try[i] + (SBLOCKSIZE / DEV_BSIZE))
		 || ! devread (0, sblock_try[i], SBLOCKSIZE, (char *) SUPERBLOCK)))
	    {
		if (
#if defined(UFS1_ONLY)
		     SUPERBLOCK->fs_magic == FS_UFS1_MAGIC
#elif defined(UFS2_ONLY)
		    (SUPERBLOCK->fs_magic == FS_UFS2_MAGIC &&
		     SUPERBLOCK->fs_sblockloc == sblock_try[i])
#else
		     SUPERBLOCK->fs_magic == FS_UFS1_MAGIC ||
		    (SUPERBLOCK->fs_magic == FS_UFS2_MAGIC &&
		     SUPERBLOCK->fs_sblockloc == sblock_try[i])
#endif
		) {
			retval = 1; break;
		}
	    }
  }
  return retval;
}

int
ufs_read (char *buf, int len)
{
	return fsread(cur_ino, buf, len);
}

int
ufs_dir (char *dirname)
{
	cur_ino = lookup(dirname);
	return cur_ino & 0xffffffff;
}

int
ufs_embed (int* start_sector, int needed_sectors)
{
	/* TODO; unused by Cromwell */
	return 0;
}

#endif /* FSYS_UFS */
