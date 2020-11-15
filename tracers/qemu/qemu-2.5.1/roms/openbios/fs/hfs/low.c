/*
 * libhfs - library for reading and writing Macintosh HFS volumes
 * Copyright (C) 1996-1998, 2001 Robert Leslie
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
 * $Id: low.c,v 1.8 1998/11/02 22:09:03 rob Exp $
 */

#include "config.h"
#include "libhfs.h"
#include "low.h"
#include "data.h"
#include "block.h"
#include "file.h"

/*
 * NAME:	low->getpmentry()
 * DESCRIPTION:	read a partition map entry
 */
int l_getpmentry(hfsvol *vol, Partition *map, unsigned long bnum)
{
  block b;
  const byte *ptr = b;
  int i;

  if (b_readpb(vol, bnum, &b, 1) == -1)
    goto fail;

  d_fetchsw(&ptr, &map->pmSig);
  d_fetchsw(&ptr, &map->pmSigPad);
  d_fetchsl(&ptr, &map->pmMapBlkCnt);
  d_fetchsl(&ptr, &map->pmPyPartStart);
  d_fetchsl(&ptr, &map->pmPartBlkCnt);

  strncpy((char *) map->pmPartName, (const char *) ptr, 32);
  map->pmPartName[32] = 0;
  ptr += 32;

  strncpy((char *) map->pmParType, (const char *) ptr, 32);
  map->pmParType[32] = 0;
  ptr += 32;

  d_fetchsl(&ptr, &map->pmLgDataStart);
  d_fetchsl(&ptr, &map->pmDataCnt);
  d_fetchsl(&ptr, &map->pmPartStatus);
  d_fetchsl(&ptr, &map->pmLgBootStart);
  d_fetchsl(&ptr, &map->pmBootSize);
  d_fetchsl(&ptr, &map->pmBootAddr);
  d_fetchsl(&ptr, &map->pmBootAddr2);
  d_fetchsl(&ptr, &map->pmBootEntry);
  d_fetchsl(&ptr, &map->pmBootEntry2);
  d_fetchsl(&ptr, &map->pmBootCksum);

  strncpy((char *) map->pmProcessor, (const char *) ptr, 16);
  map->pmProcessor[16] = 0;
  ptr += 16;

  for (i = 0; i < 188; ++i)
    d_fetchsw(&ptr, &map->pmPad[i]);

  ASSERT(ptr - b == HFS_BLOCKSZ);

  return 0;

fail:
  return -1;
}


/*
 * NAME:	low->getmdb()
 * DESCRIPTION:	read a master directory block
 */
int l_getmdb(hfsvol *vol, MDB *mdb, int backup)
{
  block b;
  const byte *ptr = b;
  int i;

  if (b_readlb(vol, backup ? vol->vlen - 2 : 2, &b) == -1)
    goto fail;

  d_fetchsw(&ptr, &mdb->drSigWord);
  d_fetchsl(&ptr, &mdb->drCrDate);
  d_fetchsl(&ptr, &mdb->drLsMod);
  d_fetchsw(&ptr, &mdb->drAtrb);
  d_fetchuw(&ptr, &mdb->drNmFls);
  d_fetchuw(&ptr, &mdb->drVBMSt);
  d_fetchuw(&ptr, &mdb->drAllocPtr);
  d_fetchuw(&ptr, &mdb->drNmAlBlks);
  d_fetchul(&ptr, &mdb->drAlBlkSiz);
  d_fetchul(&ptr, &mdb->drClpSiz);
  d_fetchuw(&ptr, &mdb->drAlBlSt);
  d_fetchsl(&ptr, &mdb->drNxtCNID);
  d_fetchuw(&ptr, &mdb->drFreeBks);

  d_fetchstr(&ptr, mdb->drVN, sizeof(mdb->drVN));

  ASSERT(ptr - b == 64);

  d_fetchsl(&ptr, &mdb->drVolBkUp);
  d_fetchsw(&ptr, &mdb->drVSeqNum);
  d_fetchul(&ptr, &mdb->drWrCnt);
  d_fetchul(&ptr, &mdb->drXTClpSiz);
  d_fetchul(&ptr, &mdb->drCTClpSiz);
  d_fetchuw(&ptr, &mdb->drNmRtDirs);
  d_fetchul(&ptr, &mdb->drFilCnt);
  d_fetchul(&ptr, &mdb->drDirCnt);

  for (i = 0; i < 8; ++i)
    d_fetchsl(&ptr, &mdb->drFndrInfo[i]);

  ASSERT(ptr - b == 124);

  d_fetchuw(&ptr, &mdb->drEmbedSigWord);
  d_fetchuw(&ptr, &mdb->drEmbedExtent.xdrStABN);
  d_fetchuw(&ptr, &mdb->drEmbedExtent.xdrNumABlks);

  d_fetchul(&ptr, &mdb->drXTFlSize);

  for (i = 0; i < 3; ++i)
    {
      d_fetchuw(&ptr, &mdb->drXTExtRec[i].xdrStABN);
      d_fetchuw(&ptr, &mdb->drXTExtRec[i].xdrNumABlks);
    }

  ASSERT(ptr - b == 146);

  d_fetchul(&ptr, &mdb->drCTFlSize);

  for (i = 0; i < 3; ++i)
    {
      d_fetchuw(&ptr, &mdb->drCTExtRec[i].xdrStABN);
      d_fetchuw(&ptr, &mdb->drCTExtRec[i].xdrNumABlks);
    }

  ASSERT(ptr - b == 162);

  return 0;

fail:
  return -1;
}
