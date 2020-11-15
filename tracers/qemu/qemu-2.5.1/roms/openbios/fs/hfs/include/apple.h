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
 * $Id: apple.h,v 1.1 1998/04/11 08:27:11 rob Exp $
 */

typedef signed char	Char;
typedef unsigned char	UChar;
typedef signed char	SignedByte;
typedef signed short	Integer;
typedef unsigned short	UInteger;
typedef signed long	LongInt;
typedef unsigned long	ULongInt;
typedef char		Str15[16];
typedef char		Str31[32];
typedef long		OSType;

typedef struct {
  Integer	sbSig;		/* device signature (should be 0x4552) */
  Integer	sbBlkSize;	/* block size of the device (in bytes) */
  LongInt	sbBlkCount;	/* number of blocks on the device */
  Integer	sbDevType;	/* reserved */
  Integer	sbDevId;	/* reserved */
  LongInt	sbData;		/* reserved */
  Integer	sbDrvrCount;	/* number of driver descriptor entries */
  LongInt	ddBlock;	/* first driver's starting block */
  Integer	ddSize;		/* size of the driver, in 512-byte blocks */
  Integer	ddType;		/* driver operating system type (MacOS = 1) */
  Integer	ddPad[243];	/* additional drivers, if any */
} Block0;

typedef struct {
  Integer	pmSig;		/* partition signature (0x504d or 0x5453) */
  Integer	pmSigPad;	/* reserved */
  LongInt	pmMapBlkCnt;	/* number of blocks in partition map */
  LongInt	pmPyPartStart;	/* first physical block of partition */
  LongInt	pmPartBlkCnt;	/* number of blocks in partition */
  Char		pmPartName[33];	/* partition name */
  Char		pmParType[33];	/* partition type */
  LongInt	pmLgDataStart;	/* first logical block of data area */
  LongInt	pmDataCnt;	/* number of blocks in data area */
  LongInt	pmPartStatus;	/* partition status information */
  LongInt	pmLgBootStart;	/* first logical block of boot code */
  LongInt	pmBootSize;	/* size of boot code, in bytes */
  LongInt	pmBootAddr;	/* boot code load address */
  LongInt	pmBootAddr2;	/* reserved */
  LongInt	pmBootEntry;	/* boot code entry point */
  LongInt	pmBootEntry2;	/* reserved */
  LongInt	pmBootCksum;	/* boot code checksum */
  Char		pmProcessor[17];/* processor type */
  Integer	pmPad[188];	/* reserved */
} Partition;

typedef struct {
  Integer	bbID;		/* boot blocks signature */
  LongInt	bbEntry;	/* entry point to boot code */
  Integer	bbVersion;	/* boot blocks version number */
  Integer	bbPageFlags;	/* used internally */
  Str15		bbSysName;	/* System filename */
  Str15		bbShellName;	/* Finder filename */
  Str15		bbDbg1Name;	/* debugger filename */
  Str15		bbDbg2Name;	/* debugger filename */
  Str15		bbScreenName;	/* name of startup screen */
  Str15		bbHelloName;	/* name of startup program */
  Str15		bbScrapName;	/* name of system scrap file */
  Integer	bbCntFCBs;	/* number of FCBs to allocate */
  Integer	bbCntEvts;	/* number of event queue elements */
  LongInt	bb128KSHeap;	/* system heap size on 128K Mac */
  LongInt	bb256KSHeap;	/* used internally */
  LongInt	bbSysHeapSize;	/* system heap size on all machines */
  Integer	filler;		/* reserved */
  LongInt	bbSysHeapExtra;	/* additional system heap space */
  LongInt	bbSysHeapFract;	/* fraction of RAM for system heap */
} BootBlkHdr;

typedef struct {
  UInteger	xdrStABN;	/* first allocation block */
  UInteger	xdrNumABlks;	/* number of allocation blocks */
} ExtDescriptor;

typedef ExtDescriptor ExtDataRec[3];

typedef struct {
  SignedByte	xkrKeyLen;	/* key length */
  SignedByte	xkrFkType;	/* fork type (0x00/0xff == data/resource */
  ULongInt	xkrFNum;	/* file number */
  UInteger	xkrFABN;	/* starting file allocation block */
} ExtKeyRec;

typedef struct {
  SignedByte	ckrKeyLen;	/* key length */
  SignedByte	ckrResrv1;	/* reserved */
  ULongInt	ckrParID;	/* parent directory ID */
  Str31		ckrCName;	/* catalog node name */
} CatKeyRec;

typedef struct {
  Integer	v;		/* vertical coordinate */
  Integer	h;		/* horizontal coordinate */
} Point;

typedef struct {
  Integer	top;		/* top edge of rectangle */
  Integer	left;		/* left edge */
  Integer	bottom;		/* bottom edge */
  Integer	right;		/* right edge */
} Rect;

typedef struct {
  Rect		frRect;		/* folder's rectangle */
  Integer	frFlags;	/* flags */
  Point		frLocation;	/* folder's location */
  Integer	frView;		/* folder's view */
} DInfo;

typedef struct {
  Point		frScroll;	/* scroll position */
  LongInt	frOpenChain;	/* directory ID chain of open folders */
  Integer	frUnused;	/* reserved */
  Integer	frComment;	/* comment ID */
  LongInt	frPutAway;	/* directory ID */
} DXInfo;

typedef struct {
  OSType	fdType;		/* file type */
  OSType	fdCreator;	/* file's creator */
  Integer	fdFlags;	/* flags */
  Point		fdLocation;	/* file's location */
  Integer	fdFldr;		/* file's window */
} FInfo;

typedef struct {
  Integer	fdIconID;	/* icon ID */
  Integer	fdUnused[4];	/* reserved */
  Integer	fdComment;	/* comment ID */
  LongInt	fdPutAway;	/* home directory ID */
} FXInfo;

typedef struct {
  Integer	drSigWord;	/* volume signature (0x4244 for HFS) */
  LongInt	drCrDate;	/* date and time of volume creation */
  LongInt	drLsMod;	/* date and time of last modification */
  Integer	drAtrb;		/* volume attributes */
  UInteger	drNmFls;	/* number of files in root directory */
  UInteger	drVBMSt;	/* first block of volume bit map (always 3) */
  UInteger	drAllocPtr;	/* start of next allocation search */
  UInteger	drNmAlBlks;	/* number of allocation blocks in volume */
  ULongInt	drAlBlkSiz;	/* size (in bytes) of allocation blocks */
  ULongInt	drClpSiz;	/* default clump size */
  UInteger	drAlBlSt;	/* first allocation block in volume */
  LongInt	drNxtCNID;	/* next unused catalog node ID (dir/file ID) */
  UInteger	drFreeBks;	/* number of unused allocation blocks */
  char		drVN[28];	/* volume name (1-27 chars) */
  LongInt	drVolBkUp;	/* date and time of last backup */
  Integer	drVSeqNum;	/* volume backup sequence number */
  ULongInt	drWrCnt;	/* volume write count */
  ULongInt	drXTClpSiz;	/* clump size for extents overflow file */
  ULongInt	drCTClpSiz;	/* clump size for catalog file */
  UInteger	drNmRtDirs;	/* number of directories in root directory */
  ULongInt	drFilCnt;	/* number of files in volume */
  ULongInt	drDirCnt;	/* number of directories in volume */
  LongInt	drFndrInfo[8];	/* information used by the Finder */
  UInteger	drEmbedSigWord;	/* type of embedded volume */
  ExtDescriptor	drEmbedExtent;	/* location of embedded volume */
  ULongInt	drXTFlSize;	/* size (in bytes) of extents overflow file */
  ExtDataRec	drXTExtRec;	/* first extent record for extents file */
  ULongInt	drCTFlSize;	/* size (in bytes) of catalog file */
  ExtDataRec	drCTExtRec;	/* first extent record for catalog file */
} MDB;

typedef enum {
  cdrDirRec  = 1,
  cdrFilRec  = 2,
  cdrThdRec  = 3,
  cdrFThdRec = 4
} CatDataType;

typedef struct {
  SignedByte	cdrType;	/* record type */
  SignedByte	cdrResrv2;	/* reserved */
  union {
    struct {  /* cdrDirRec */
      Integer	dirFlags;	/* directory flags */
      UInteger	dirVal;		/* directory valence */
      ULongInt	dirDirID;	/* directory ID */
      LongInt	dirCrDat;	/* date and time of creation */
      LongInt	dirMdDat;	/* date and time of last modification */
      LongInt	dirBkDat;	/* date and time of last backup */
      DInfo	dirUsrInfo;	/* Finder information */
      DXInfo	dirFndrInfo;	/* additional Finder information */
      LongInt	dirResrv[4];	/* reserved */
    } dir;
    struct {  /* cdrFilRec */
      SignedByte
		filFlags;	/* file flags */
      SignedByte
		filTyp;		/* file type */
      FInfo	filUsrWds;	/* Finder information */
      ULongInt	filFlNum;	/* file ID */
      UInteger	filStBlk;	/* first alloc block of data fork */
      ULongInt	filLgLen;	/* logical EOF of data fork */
      ULongInt	filPyLen;	/* physical EOF of data fork */
      UInteger	filRStBlk;	/* first alloc block of resource fork */
      ULongInt	filRLgLen;	/* logical EOF of resource fork */
      ULongInt	filRPyLen;	/* physical EOF of resource fork */
      LongInt	filCrDat;	/* date and time of creation */
      LongInt	filMdDat;	/* date and time of last modification */
      LongInt	filBkDat;	/* date and time of last backup */
      FXInfo	filFndrInfo;	/* additional Finder information */
      UInteger	filClpSize;	/* file clump size */
      ExtDataRec
		filExtRec;	/* first data fork extent record */
      ExtDataRec
		filRExtRec;	/* first resource fork extent record */
      LongInt	filResrv;	/* reserved */
    } fil;
    struct {  /* cdrThdRec */
      LongInt	thdResrv[2];	/* reserved */
      ULongInt	thdParID;	/* parent ID for this directory */
      Str31	thdCName;	/* name of this directory */
    } dthd;
    struct {  /* cdrFThdRec */
      LongInt	fthdResrv[2];	/* reserved */
      ULongInt	fthdParID;	/* parent ID for this file */
      Str31	fthdCName;	/* name of this file */
    } fthd;
  } u;
} CatDataRec;

typedef struct {
  ULongInt	ndFLink;	/* forward link */
  ULongInt	ndBLink;	/* backward link */
  SignedByte	ndType;		/* node type */
  SignedByte	ndNHeight;	/* node level */
  UInteger	ndNRecs;	/* number of records in node */
  Integer	ndResv2;	/* reserved */
} NodeDescriptor;

enum {
  ndIndxNode = (SignedByte) 0x00,
  ndHdrNode  = (SignedByte) 0x01,
  ndMapNode  = (SignedByte) 0x02,
  ndLeafNode = (SignedByte) 0xff
};

typedef struct {
  UInteger	bthDepth;	/* current depth of tree */
  ULongInt	bthRoot;	/* number of root node */
  ULongInt	bthNRecs;	/* number of leaf records in tree */
  ULongInt	bthFNode;	/* number of first leaf node */
  ULongInt	bthLNode;	/* number of last leaf node */
  UInteger	bthNodeSize;	/* size of a node */
  UInteger	bthKeyLen;	/* maximum length of a key */
  ULongInt	bthNNodes;	/* total number of nodes in tree */
  ULongInt	bthFree;	/* number of free nodes */
  SignedByte	bthResv[76];	/* reserved */
} BTHdrRec;
