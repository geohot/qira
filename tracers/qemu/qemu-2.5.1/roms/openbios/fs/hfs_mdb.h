/*
 *   Creation Date: <2000/09/03 23:04:27 samuel>
 *   Time-stamp: <2000/09/04 01:23:55 samuel>
 *
 *	<hfs_mdb.h>
 *
 *	HFS Master Directory Block (MDB)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_HFS_MDB
#define _H_HFS_MDB

#include "libc/byteorder.h"

typedef unsigned char hfs_char_t;
typedef unsigned char hfs_ushort_t[2];
typedef unsigned char hfs_uint_t[4];

static inline unsigned short hfs_get_ushort(hfs_ushort_t addr)
{
	return __be16_to_cpu(*((unsigned short *)(addr)));
}

static inline unsigned int hfs_get_uint(hfs_uint_t addr)
{
	return __be32_to_cpu(*((unsigned int *)(addr)));
}

/*
 * The HFS Master Directory Block (MDB).
 *
 * Also known as the Volume Information Block (VIB), this structure is
 * the HFS equivalent of a superblock.
 *
 * Reference: _Inside Macintosh: Files_ pages 2-59 through 2-62
 *
 * modified for HFS Extended
 */

typedef struct hfs_mdb {
	hfs_ushort_t	drSigWord;	/* Signature word indicating fs type */
	hfs_uint_t	drCrDate;	/* fs creation date/time */
	hfs_uint_t	drLsMod;	/* fs modification date/time */
	hfs_ushort_t	drAtrb;		/* fs attributes */
	hfs_ushort_t	drNmFls;	/* number of files in root directory */
	hfs_ushort_t	drVBMSt;	/* location (in 512-byte blocks)
					   of the volume bitmap */
	hfs_ushort_t	drAllocPtr;	/* location (in allocation blocks)
					   to begin next allocation search */
	hfs_ushort_t	drNmAlBlks;	/* number of allocation blocks */
	hfs_uint_t	drAlBlkSiz;	/* bytes in an allocation block */
	hfs_uint_t	drClpSiz;	/* clumpsize, the number of bytes to
					   allocate when extending a file */
	hfs_ushort_t	drAlBlSt;	/* location (in 512-byte blocks)
					   of the first allocation block */
	hfs_uint_t	drNxtCNID;	/* CNID to assign to the next
					   file or directory created */
	hfs_ushort_t	drFreeBks;	/* number of free allocation blocks */
	hfs_char_t	drVN[28];	/* the volume label */
	hfs_uint_t	drVolBkUp;	/* fs backup date/time */
	hfs_ushort_t	drVSeqNum;	/* backup sequence number */
	hfs_uint_t	drWrCnt;	/* fs write count */
	hfs_uint_t	drXTClpSiz;	/* clumpsize for the extents B-tree */
	hfs_uint_t	drCTClpSiz;	/* clumpsize for the catalog B-tree */
	hfs_ushort_t	drNmRtDirs;	/* number of directories in
					   the root directory */
	hfs_uint_t	drFilCnt;	/* number of files in the fs */
	hfs_uint_t	drDirCnt;	/* number of directories in the fs */
	hfs_char_t	drFndrInfo[32];	/* data used by the Finder */
	hfs_ushort_t	drEmbedSigWord;	/* embedded volume signature */
	hfs_uint_t	drEmbedExtent;  /* starting block number (xdrStABN)
					   and number of allocation blocks
					   (xdrNumABlks) occupied by embedded
					   volume */
	hfs_uint_t	drXTFlSize;	/* bytes in the extents B-tree */
	hfs_char_t	drXTExtRec[12];	/* extents B-tree's first 3 extents */
	hfs_uint_t	drCTFlSize;	/* bytes in the catalog B-tree */
	hfs_char_t	drCTExtRec[12];	/* catalog B-tree's first 3 extents */
} hfs_mdb_t;

#define HFS_PLUS_SIGNATURE	0x482b		/* 'H+' */
#define HFS_SIGNATURE		0x4244		/* HFS / embedded HFS+ */


typedef struct hfs_plus_mdb
{
	unsigned short	signature;
	unsigned short	version;
	unsigned int	attributes;
	unsigned int	lastMountedVersion;
	unsigned int	reserved;

	unsigned int	createDate;
	unsigned int	modifyDate;
	unsigned int	backupDate;
	unsigned int	checkedDate;

	unsigned int	fileCount;
	unsigned int	folderCount;

	unsigned int	blockSize;
	unsigned int	totalBlocks;
	unsigned int	freeBlocks;

	unsigned int	nextAllocation;
	unsigned int	rsrcClumpSize;
	unsigned int	dataClumpSize;

	/* ... there are more fields here ... */
} hfs_plus_mdb_t;


#endif   /* _H_HFS_MDB */
