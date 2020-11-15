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
 * $Id: record.c,v 1.9 1998/11/02 22:09:07 rob Exp $
 */

#include "config.h"
#include "libhfs.h"
#include "record.h"
#include "data.h"

/*
 * NAME:	record->packcatkey()
 * DESCRIPTION:	pack a catalog record key
 */
void r_packcatkey(const CatKeyRec *key, byte *pkey, unsigned int *len)
{
  const byte *start = pkey;

  d_storesb(&pkey, key->ckrKeyLen);
  d_storesb(&pkey, key->ckrResrv1);
  d_storeul(&pkey, key->ckrParID);

  d_storestr(&pkey, key->ckrCName, sizeof(key->ckrCName));

  if (len)
    *len = HFS_RECKEYSKIP(start);
}

/*
 * NAME:	record->unpackcatkey()
 * DESCRIPTION:	unpack a catalog record key
 */
void r_unpackcatkey(const byte *pkey, CatKeyRec *key)
{
  d_fetchsb(&pkey, &key->ckrKeyLen);
  d_fetchsb(&pkey, &key->ckrResrv1);
  d_fetchul(&pkey, &key->ckrParID);

  d_fetchstr(&pkey, key->ckrCName, sizeof(key->ckrCName));
}

/*
 * NAME:	record->packextkey()
 * DESCRIPTION:	pack an extents record key
 */
void r_packextkey(const ExtKeyRec *key, byte *pkey, unsigned int *len)
{
  const byte *start = pkey;

  d_storesb(&pkey, key->xkrKeyLen);
  d_storesb(&pkey, key->xkrFkType);
  d_storeul(&pkey, key->xkrFNum);
  d_storeuw(&pkey, key->xkrFABN);

  if (len)
    *len = HFS_RECKEYSKIP(start);
}

/*
 * NAME:	record->unpackextkey()
 * DESCRIPTION:	unpack an extents record key
 */
void r_unpackextkey(const byte *pkey, ExtKeyRec *key)
{
  d_fetchsb(&pkey, &key->xkrKeyLen);
  d_fetchsb(&pkey, &key->xkrFkType);
  d_fetchul(&pkey, &key->xkrFNum);
  d_fetchuw(&pkey, &key->xkrFABN);
}

/*
 * NAME:	record->comparecatkeys()
 * DESCRIPTION:	compare two (packed) catalog record keys
 */
int r_comparecatkeys(const CatKeyRec *key1, const CatKeyRec *key2)
{
  int diff;

  diff = key1->ckrParID - key2->ckrParID;
  if (diff)
    return diff;

  return d_relstring(key1->ckrCName, key2->ckrCName);
}

/*
 * NAME:	record->compareextkeys()
 * DESCRIPTION:	compare two (packed) extents record keys
 */
int r_compareextkeys(const ExtKeyRec *key1, const ExtKeyRec *key2)
{
  int diff;

  diff = key1->xkrFNum - key2->xkrFNum;
  if (diff)
    return diff;

  diff = (unsigned char) key1->xkrFkType -
         (unsigned char) key2->xkrFkType;
  if (diff)
    return diff;

  return key1->xkrFABN - key2->xkrFABN;
}

/*
 * NAME:	record->packcatdata()
 * DESCRIPTION:	pack catalog record data
 */
void r_packcatdata(const CatDataRec *data, byte *pdata, unsigned int *len)
{
  const byte *start = pdata;
  int i;

  d_storesb(&pdata, data->cdrType);
  d_storesb(&pdata, data->cdrResrv2);

  switch (data->cdrType)
    {
    case cdrDirRec:
      d_storesw(&pdata, data->u.dir.dirFlags);
      d_storeuw(&pdata, data->u.dir.dirVal);
      d_storeul(&pdata, data->u.dir.dirDirID);
      d_storesl(&pdata, data->u.dir.dirCrDat);
      d_storesl(&pdata, data->u.dir.dirMdDat);
      d_storesl(&pdata, data->u.dir.dirBkDat);

      d_storesw(&pdata, data->u.dir.dirUsrInfo.frRect.top);
      d_storesw(&pdata, data->u.dir.dirUsrInfo.frRect.left);
      d_storesw(&pdata, data->u.dir.dirUsrInfo.frRect.bottom);
      d_storesw(&pdata, data->u.dir.dirUsrInfo.frRect.right);
      d_storesw(&pdata, data->u.dir.dirUsrInfo.frFlags);
      d_storesw(&pdata, data->u.dir.dirUsrInfo.frLocation.v);
      d_storesw(&pdata, data->u.dir.dirUsrInfo.frLocation.h);
      d_storesw(&pdata, data->u.dir.dirUsrInfo.frView);

      d_storesw(&pdata, data->u.dir.dirFndrInfo.frScroll.v);
      d_storesw(&pdata, data->u.dir.dirFndrInfo.frScroll.h);
      d_storesl(&pdata, data->u.dir.dirFndrInfo.frOpenChain);
      d_storesw(&pdata, data->u.dir.dirFndrInfo.frUnused);
      d_storesw(&pdata, data->u.dir.dirFndrInfo.frComment);
      d_storesl(&pdata, data->u.dir.dirFndrInfo.frPutAway);

      for (i = 0; i < 4; ++i)
	d_storesl(&pdata, data->u.dir.dirResrv[i]);

      break;

    case cdrFilRec:
      d_storesb(&pdata, data->u.fil.filFlags);
      d_storesb(&pdata, data->u.fil.filTyp);

      d_storesl(&pdata, data->u.fil.filUsrWds.fdType);
      d_storesl(&pdata, data->u.fil.filUsrWds.fdCreator);
      d_storesw(&pdata, data->u.fil.filUsrWds.fdFlags);
      d_storesw(&pdata, data->u.fil.filUsrWds.fdLocation.v);
      d_storesw(&pdata, data->u.fil.filUsrWds.fdLocation.h);
      d_storesw(&pdata, data->u.fil.filUsrWds.fdFldr);

      d_storeul(&pdata, data->u.fil.filFlNum);

      d_storeuw(&pdata, data->u.fil.filStBlk);
      d_storeul(&pdata, data->u.fil.filLgLen);
      d_storeul(&pdata, data->u.fil.filPyLen);

      d_storeuw(&pdata, data->u.fil.filRStBlk);
      d_storeul(&pdata, data->u.fil.filRLgLen);
      d_storeul(&pdata, data->u.fil.filRPyLen);

      d_storesl(&pdata, data->u.fil.filCrDat);
      d_storesl(&pdata, data->u.fil.filMdDat);
      d_storesl(&pdata, data->u.fil.filBkDat);

      d_storesw(&pdata, data->u.fil.filFndrInfo.fdIconID);
      for (i = 0; i < 4; ++i)
	d_storesw(&pdata, data->u.fil.filFndrInfo.fdUnused[i]);
      d_storesw(&pdata, data->u.fil.filFndrInfo.fdComment);
      d_storesl(&pdata, data->u.fil.filFndrInfo.fdPutAway);

      d_storeuw(&pdata, data->u.fil.filClpSize);

      for (i = 0; i < 3; ++i)
	{
	  d_storeuw(&pdata, data->u.fil.filExtRec[i].xdrStABN);
	  d_storeuw(&pdata, data->u.fil.filExtRec[i].xdrNumABlks);
	}

      for (i = 0; i < 3; ++i)
	{
	  d_storeuw(&pdata, data->u.fil.filRExtRec[i].xdrStABN);
	  d_storeuw(&pdata, data->u.fil.filRExtRec[i].xdrNumABlks);
	}

      d_storesl(&pdata, data->u.fil.filResrv);

      break;

    case cdrThdRec:
      for (i = 0; i < 2; ++i)
	d_storesl(&pdata, data->u.dthd.thdResrv[i]);

      d_storeul(&pdata, data->u.dthd.thdParID);

      d_storestr(&pdata, data->u.dthd.thdCName,
		 sizeof(data->u.dthd.thdCName));

      break;

    case cdrFThdRec:
      for (i = 0; i < 2; ++i)
	d_storesl(&pdata, data->u.fthd.fthdResrv[i]);

      d_storeul(&pdata, data->u.fthd.fthdParID);

      d_storestr(&pdata, data->u.fthd.fthdCName,
		 sizeof(data->u.fthd.fthdCName));

      break;

    default:
      ASSERT(0);
    }

  if (len)
    *len += pdata - start;
}

/*
 * NAME:	record->unpackcatdata()
 * DESCRIPTION:	unpack catalog record data
 */
void r_unpackcatdata(const byte *pdata, CatDataRec *data)
{
  int i;

  d_fetchsb(&pdata, &data->cdrType);
  d_fetchsb(&pdata, &data->cdrResrv2);

  switch (data->cdrType)
    {
    case cdrDirRec:
      d_fetchsw(&pdata, &data->u.dir.dirFlags);
      d_fetchuw(&pdata, &data->u.dir.dirVal);
      d_fetchul(&pdata, &data->u.dir.dirDirID);
      d_fetchsl(&pdata, &data->u.dir.dirCrDat);
      d_fetchsl(&pdata, &data->u.dir.dirMdDat);
      d_fetchsl(&pdata, &data->u.dir.dirBkDat);

      d_fetchsw(&pdata, &data->u.dir.dirUsrInfo.frRect.top);
      d_fetchsw(&pdata, &data->u.dir.dirUsrInfo.frRect.left);
      d_fetchsw(&pdata, &data->u.dir.dirUsrInfo.frRect.bottom);
      d_fetchsw(&pdata, &data->u.dir.dirUsrInfo.frRect.right);
      d_fetchsw(&pdata, &data->u.dir.dirUsrInfo.frFlags);
      d_fetchsw(&pdata, &data->u.dir.dirUsrInfo.frLocation.v);
      d_fetchsw(&pdata, &data->u.dir.dirUsrInfo.frLocation.h);
      d_fetchsw(&pdata, &data->u.dir.dirUsrInfo.frView);

      d_fetchsw(&pdata, &data->u.dir.dirFndrInfo.frScroll.v);
      d_fetchsw(&pdata, &data->u.dir.dirFndrInfo.frScroll.h);
      d_fetchsl(&pdata, &data->u.dir.dirFndrInfo.frOpenChain);
      d_fetchsw(&pdata, &data->u.dir.dirFndrInfo.frUnused);
      d_fetchsw(&pdata, &data->u.dir.dirFndrInfo.frComment);
      d_fetchsl(&pdata, &data->u.dir.dirFndrInfo.frPutAway);

      for (i = 0; i < 4; ++i)
	d_fetchsl(&pdata, &data->u.dir.dirResrv[i]);

      break;

    case cdrFilRec:
      d_fetchsb(&pdata, &data->u.fil.filFlags);
      d_fetchsb(&pdata, &data->u.fil.filTyp);

      d_fetchsl(&pdata, &data->u.fil.filUsrWds.fdType);
      d_fetchsl(&pdata, &data->u.fil.filUsrWds.fdCreator);
      d_fetchsw(&pdata, &data->u.fil.filUsrWds.fdFlags);
      d_fetchsw(&pdata, &data->u.fil.filUsrWds.fdLocation.v);
      d_fetchsw(&pdata, &data->u.fil.filUsrWds.fdLocation.h);
      d_fetchsw(&pdata, &data->u.fil.filUsrWds.fdFldr);

      d_fetchul(&pdata, &data->u.fil.filFlNum);

      d_fetchuw(&pdata, &data->u.fil.filStBlk);
      d_fetchul(&pdata, &data->u.fil.filLgLen);
      d_fetchul(&pdata, &data->u.fil.filPyLen);

      d_fetchuw(&pdata, &data->u.fil.filRStBlk);
      d_fetchul(&pdata, &data->u.fil.filRLgLen);
      d_fetchul(&pdata, &data->u.fil.filRPyLen);

      d_fetchsl(&pdata, &data->u.fil.filCrDat);
      d_fetchsl(&pdata, &data->u.fil.filMdDat);
      d_fetchsl(&pdata, &data->u.fil.filBkDat);

      d_fetchsw(&pdata, &data->u.fil.filFndrInfo.fdIconID);
      for (i = 0; i < 4; ++i)
	d_fetchsw(&pdata, &data->u.fil.filFndrInfo.fdUnused[i]);
      d_fetchsw(&pdata, &data->u.fil.filFndrInfo.fdComment);
      d_fetchsl(&pdata, &data->u.fil.filFndrInfo.fdPutAway);

      d_fetchuw(&pdata, &data->u.fil.filClpSize);

      for (i = 0; i < 3; ++i)
	{
	  d_fetchuw(&pdata, &data->u.fil.filExtRec[i].xdrStABN);
	  d_fetchuw(&pdata, &data->u.fil.filExtRec[i].xdrNumABlks);
	}

      for (i = 0; i < 3; ++i)
	{
	  d_fetchuw(&pdata, &data->u.fil.filRExtRec[i].xdrStABN);
	  d_fetchuw(&pdata, &data->u.fil.filRExtRec[i].xdrNumABlks);
	}

      d_fetchsl(&pdata, &data->u.fil.filResrv);

      break;

    case cdrThdRec:
      for (i = 0; i < 2; ++i)
	d_fetchsl(&pdata, &data->u.dthd.thdResrv[i]);

      d_fetchul(&pdata, &data->u.dthd.thdParID);

      d_fetchstr(&pdata, data->u.dthd.thdCName,
		 sizeof(data->u.dthd.thdCName));

      break;

    case cdrFThdRec:
      for (i = 0; i < 2; ++i)
	d_fetchsl(&pdata, &data->u.fthd.fthdResrv[i]);

      d_fetchul(&pdata, &data->u.fthd.fthdParID);

      d_fetchstr(&pdata, data->u.fthd.fthdCName,
		 sizeof(data->u.fthd.fthdCName));

      break;

    default:
      ASSERT(0);
    }
}

/*
 * NAME:	record->packextdata()
 * DESCRIPTION:	pack extent record data
 */
void r_packextdata(const ExtDataRec *data, byte *pdata, unsigned int *len)
{
  const byte *start = pdata;
  int i;

  for (i = 0; i < 3; ++i)
    {
      d_storeuw(&pdata, (*data)[i].xdrStABN);
      d_storeuw(&pdata, (*data)[i].xdrNumABlks);
    }

  if (len)
    *len += pdata - start;
}

/*
 * NAME:	record->unpackextdata()
 * DESCRIPTION:	unpack extent record data
 */
void r_unpackextdata(const byte *pdata, ExtDataRec *data)
{
  int i;

  for (i = 0; i < 3; ++i)
    {
      d_fetchuw(&pdata, &(*data)[i].xdrStABN);
      d_fetchuw(&pdata, &(*data)[i].xdrNumABlks);
    }
}

/*
 * NAME:	record->makecatkey()
 * DESCRIPTION:	construct a catalog record key
 */
void r_makecatkey(CatKeyRec *key, unsigned long parid, const char *name)
{
  int len;

  len = strlen(name) + 1;

  key->ckrKeyLen = 0x05 + len + (len & 1);
  key->ckrResrv1 = 0;
  key->ckrParID  = parid;

  strcpy(key->ckrCName, name);
}

/*
 * NAME:	record->makeextkey()
 * DESCRIPTION:	construct an extents record key
 */
void r_makeextkey(ExtKeyRec *key,
		  int fork, unsigned long fnum, unsigned int fabn)
{
  key->xkrKeyLen = 0x07;
  key->xkrFkType = fork;
  key->xkrFNum   = fnum;
  key->xkrFABN   = fabn;
}

/*
 * NAME:	record->packcatrec()
 * DESCRIPTION:	create a packed catalog record
 */
void r_packcatrec(const CatKeyRec *key, const CatDataRec *data,
		  byte *precord, unsigned int *len)
{
  r_packcatkey(key, precord, len);
  r_packcatdata(data, HFS_RECDATA(precord), len);
}

/*
 * NAME:	record->packextrec()
 * DESCRIPTION:	create a packed extents record
 */
void r_packextrec(const ExtKeyRec *key, const ExtDataRec *data,
		  byte *precord, unsigned int *len)
{
  r_packextkey(key, precord, len);
  r_packextdata(data, HFS_RECDATA(precord), len);
}

/*
 * NAME:	record->packdirent()
 * DESCRIPTION:	make changes to a catalog record
 */
void r_packdirent(CatDataRec *data, const hfsdirent *ent)
{
  switch (data->cdrType)
    {
    case cdrDirRec:
      data->u.dir.dirCrDat = d_mtime(ent->crdate);
      data->u.dir.dirMdDat = d_mtime(ent->mddate);
      data->u.dir.dirBkDat = d_mtime(ent->bkdate);

      data->u.dir.dirUsrInfo.frFlags      = ent->fdflags;
      data->u.dir.dirUsrInfo.frLocation.v = ent->fdlocation.v;
      data->u.dir.dirUsrInfo.frLocation.h = ent->fdlocation.h;

      data->u.dir.dirUsrInfo.frRect.top    = ent->u.dir.rect.top;
      data->u.dir.dirUsrInfo.frRect.left   = ent->u.dir.rect.left;
      data->u.dir.dirUsrInfo.frRect.bottom = ent->u.dir.rect.bottom;
      data->u.dir.dirUsrInfo.frRect.right  = ent->u.dir.rect.right;

      break;

    case cdrFilRec:
      if (ent->flags & HFS_ISLOCKED)
	data->u.fil.filFlags |=  (1 << 0);
      else
	data->u.fil.filFlags &= ~(1 << 0);

      data->u.fil.filCrDat = d_mtime(ent->crdate);
      data->u.fil.filMdDat = d_mtime(ent->mddate);
      data->u.fil.filBkDat = d_mtime(ent->bkdate);

      data->u.fil.filUsrWds.fdFlags      = ent->fdflags;
      data->u.fil.filUsrWds.fdLocation.v = ent->fdlocation.v;
      data->u.fil.filUsrWds.fdLocation.h = ent->fdlocation.h;

      data->u.fil.filUsrWds.fdType =
	d_getsl((const unsigned char *) ent->u.file.type);
      data->u.fil.filUsrWds.fdCreator =
	d_getsl((const unsigned char *) ent->u.file.creator);

      break;
    }
}

/*
 * NAME:	record->unpackdirent()
 * DESCRIPTION:	unpack catalog information into hfsdirent structure
 */
void r_unpackdirent(unsigned long parid, const char *name,
		    const CatDataRec *data, hfsdirent *ent)
{
  strcpy(ent->name, name);
  ent->parid = parid;

  switch (data->cdrType)
    {
    case cdrDirRec:
      ent->flags = HFS_ISDIR;
      ent->cnid  = data->u.dir.dirDirID;

      ent->crdate = d_ltime(data->u.dir.dirCrDat);
      ent->mddate = d_ltime(data->u.dir.dirMdDat);
      ent->bkdate = d_ltime(data->u.dir.dirBkDat);

      ent->fdflags      = data->u.dir.dirUsrInfo.frFlags;
      ent->fdlocation.v = data->u.dir.dirUsrInfo.frLocation.v;
      ent->fdlocation.h = data->u.dir.dirUsrInfo.frLocation.h;

      ent->u.dir.valence = data->u.dir.dirVal;

      ent->u.dir.rect.top    = data->u.dir.dirUsrInfo.frRect.top;
      ent->u.dir.rect.left   = data->u.dir.dirUsrInfo.frRect.left;
      ent->u.dir.rect.bottom = data->u.dir.dirUsrInfo.frRect.bottom;
      ent->u.dir.rect.right  = data->u.dir.dirUsrInfo.frRect.right;

      break;

    case cdrFilRec:
      ent->flags = (data->u.fil.filFlags & (1 << 0)) ? HFS_ISLOCKED : 0;
      ent->cnid  = data->u.fil.filFlNum;

      ent->crdate = d_ltime(data->u.fil.filCrDat);
      ent->mddate = d_ltime(data->u.fil.filMdDat);
      ent->bkdate = d_ltime(data->u.fil.filBkDat);

      ent->fdflags      = data->u.fil.filUsrWds.fdFlags;
      ent->fdlocation.v = data->u.fil.filUsrWds.fdLocation.v;
      ent->fdlocation.h = data->u.fil.filUsrWds.fdLocation.h;

      ent->u.file.dsize = data->u.fil.filLgLen;
      ent->u.file.rsize = data->u.fil.filRLgLen;

      d_putsl((unsigned char *) ent->u.file.type,
	      data->u.fil.filUsrWds.fdType);
      d_putsl((unsigned char *) ent->u.file.creator,
	     data->u.fil.filUsrWds.fdCreator);

      ent->u.file.type[4] = ent->u.file.creator[4] = 0;

      break;
    }
}
