/*
 *   Creation Date: <1999/07/06 15:45:12 samuel>
 *   Time-stamp: <2002/10/20 16:31:48 samuel>
 *
 *	<partition_table.h>
 *
 *	Headers describing the partition table
 *
 *   Copyright (C) 1999, 2002 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_PARTITION_TABLE
#define _H_PARTITION_TABLE

/* This information is based upon IM vol V. */

#define DESC_MAP_SIGNATURE	0x4552
#define DESC_PART_SIGNATURE	0x504d

enum {
	kPartitionAUXIsValid         = 0x00000001,
	kPartitionAUXIsAllocated     = 0x00000002,
	kPartitionAUXIsInUse         = 0x00000004,
	kPartitionAUXIsBootValid     = 0x00000008,
	kPartitionAUXIsReadable      = 0x00000010,
	kPartitionAUXIsWriteable     = 0x00000020,
	kPartitionAUXIsBootCodePositionIndependent = 0x00000040,
	kPartitionISMountedAtStartup = 0x40000000,
	kPartitionIsStartup          = 0x80000000,
	kPartitionIsChainCompatible  = 0x00000100,
	kPartitionIsRealDeviceDriver = 0x00000200,
	kPartitionCanChainToNext     = 0x00000400,
};

typedef struct {
	u32		ddBlock;		/* first block of driver */
	u16		ddSize;			/* driver size in blocks */
	s16		ddType;			/* 1 & -1 for SCSI */
} driver_entry_t;

typedef struct { /* Block 0 of a device */
	u16		sbSig;			/* always 0x4552 */
	u16		sbBlockSize;		/* 512 */
	s32		sbBlkCount;		/* #blocks on device */
	u16		sbDevType;    		/* 0 */
	u16		sbDevID;      		/* 0 */
	u32		sbData;      		/* 0 */
	s16		sbDrvrCount;		/* #driver descriptors */

	/* driver entries goes here */
	driver_entry_t	drivers[61] __attribute__ ((packed));

	u16		filler1;
	u32		filler2;
} desc_map_t;

typedef struct { /* Partition descriptor */
	u16		pmSig;			/* always 0x504d 'PM' */
	u16		pmSigPad;		/* 0 */
	u32		pmMapBlkCnt;		/* #blocks in partition map */
	u32		pmPyPartStart;		/* first physical block of part. */
	u32		pmPartBlkCnt;		/* #blocks in partition */
	char		pmPartName[32];		/* partition name */
	char		pmPartType[32];		/* partition type */

	/* these fields may or may not be used */
	u32		pmLgDataStart;
	u32		pmDataCnt;
	u32		pmPartStatus;
	u32		pmLgBootStart;
	u32		pmBootSize;
	u32		pmBootLoad;
	u32		pmBootLoad2;
	u32		pmBootEntry;
	u32		pmBootEntry2;
	u32		pmBootCksum;
	char		pmProcessor[16];

	char		filler[376];		/* might contain extra information */
} part_entry_t;


#endif   /* _H_PARTITION_TABLE */
