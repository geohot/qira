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
 * $Id: file.c,v 1.9 1998/11/02 22:08:59 rob Exp $
 */

#include "config.h"
#include "libhfs.h"
#include "file.h"
#include "btree.h"
#include "record.h"
#include "volume.h"

/*
 * NAME:	file->init()
 * DESCRIPTION:	initialize file structure
 */
void f_init(hfsfile *file, hfsvol *vol, long cnid, const char *name)
{
  int i;

  file->vol   = vol;
  file->parid = 0;

  strcpy(file->name, name);

  file->cat.cdrType          = cdrFilRec;
  file->cat.cdrResrv2        = 0;

  file->cat.u.fil.filFlags   = 0;
  file->cat.u.fil.filTyp     = 0;

  file->cat.u.fil.filUsrWds.fdType       = 0;
  file->cat.u.fil.filUsrWds.fdCreator    = 0;
  file->cat.u.fil.filUsrWds.fdFlags      = 0;
  file->cat.u.fil.filUsrWds.fdLocation.v = 0;
  file->cat.u.fil.filUsrWds.fdLocation.h = 0;
  file->cat.u.fil.filUsrWds.fdFldr       = 0;

  file->cat.u.fil.filFlNum   = cnid;
  file->cat.u.fil.filStBlk   = 0;
  file->cat.u.fil.filLgLen   = 0;
  file->cat.u.fil.filPyLen   = 0;
  file->cat.u.fil.filRStBlk  = 0;
  file->cat.u.fil.filRLgLen  = 0;
  file->cat.u.fil.filRPyLen  = 0;
  file->cat.u.fil.filCrDat   = 0;
  file->cat.u.fil.filMdDat   = 0;
  file->cat.u.fil.filBkDat   = 0;

  file->cat.u.fil.filFndrInfo.fdIconID = 0;
  for (i = 0; i < 4; ++i)
    file->cat.u.fil.filFndrInfo.fdUnused[i] = 0;
  file->cat.u.fil.filFndrInfo.fdComment = 0;
  file->cat.u.fil.filFndrInfo.fdPutAway = 0;

  file->cat.u.fil.filClpSize = 0;

  for (i = 0; i < 3; ++i)
    {
      file->cat.u.fil.filExtRec[i].xdrStABN     = 0;
      file->cat.u.fil.filExtRec[i].xdrNumABlks  = 0;

      file->cat.u.fil.filRExtRec[i].xdrStABN    = 0;
      file->cat.u.fil.filRExtRec[i].xdrNumABlks = 0;
    }

  file->cat.u.fil.filResrv   = 0;

  f_selectfork(file, fkData);

  file->flags = 0;

  file->prev  = NULL;
  file->next  = NULL;
}

/*
 * NAME:	file->selectfork()
 * DESCRIPTION:	choose a fork for file operations
 */
void f_selectfork(hfsfile *file, int fork)
{
  file->fork = fork;

  memcpy(&file->ext, fork == fkData ?
	 &file->cat.u.fil.filExtRec : &file->cat.u.fil.filRExtRec,
	 sizeof(ExtDataRec));

  file->fabn = 0;
  file->pos  = 0;
}

/*
 * NAME:	file->getptrs()
 * DESCRIPTION:	make pointers to the current fork's lengths and extents
 */
void f_getptrs(hfsfile *file, ExtDataRec **extrec,
	       unsigned long **lglen, unsigned long **pylen)
{
  if (file->fork == fkData)
    {
      if (extrec)
	*extrec = &file->cat.u.fil.filExtRec;
      if (lglen)
	*lglen  = &file->cat.u.fil.filLgLen;
      if (pylen)
	*pylen  = &file->cat.u.fil.filPyLen;
    }
  else
    {
      if (extrec)
	*extrec = &file->cat.u.fil.filRExtRec;
      if (lglen)
	*lglen  = &file->cat.u.fil.filRLgLen;
      if (pylen)
	*pylen  = &file->cat.u.fil.filRPyLen;
    }
}

/*
 * NAME:	file->doblock()
 * DESCRIPTION:	read or write a numbered block from a file
 */
int f_doblock(hfsfile *file, unsigned long num, block *bp,
	      int (*func)(hfsvol *, unsigned int, unsigned int, block *))
{
  unsigned int abnum;
  unsigned int blnum;
  unsigned int fabn;
  int i;

  abnum = num / file->vol->lpa;
  blnum = num % file->vol->lpa;

  /* locate the appropriate extent record */

  fabn = file->fabn;

  if (abnum < fabn)
    {
      ExtDataRec *extrec;

      f_getptrs(file, &extrec, NULL, NULL);

      fabn = file->fabn = 0;
      memcpy(&file->ext, extrec, sizeof(ExtDataRec));
    }
  else
    abnum -= fabn;

  while (1)
    {
      unsigned int n;

      for (i = 0; i < 3; ++i)
	{
	  n = file->ext[i].xdrNumABlks;

	  if (abnum < n)
	    return func(file->vol, file->ext[i].xdrStABN + abnum, blnum, bp);

	  fabn  += n;
	  abnum -= n;
	}

      if (v_extsearch(file, fabn, &file->ext, NULL) <= 0)
	goto fail;

      file->fabn = fabn;
    }

fail:
  return -1;
}
