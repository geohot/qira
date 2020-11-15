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
 * $Id: volume.c,v 1.12 1998/11/02 22:09:10 rob Exp $
 */

#include "config.h"
#include "libhfs.h"
#include "volume.h"
#include "data.h"
#include "block.h"
#include "low.h"
#include "medium.h"
#include "file.h"
#include "btree.h"
#include "record.h"
#include "os.h"

#include "libc/byteorder.h"

/*
 * NAME:	vol->init()
 * DESCRIPTION:	initialize volume structure
 */
void v_init(hfsvol *vol, int flags)
{
  btree *ext = &vol->ext;
  btree *cat = &vol->cat;

  vol->os_fd       = 0;
  vol->flags      = flags & HFS_VOL_OPT_MASK;

  vol->pnum       = -1;
  vol->vstart     = 0;
  vol->vlen       = 0;
  vol->lpa        = 0;

  vol->cache      = NULL;

  vol->vbm        = NULL;
  vol->vbmsz      = 0;

  f_init(&ext->f, vol, HFS_CNID_EXT, "extents overflow");

  ext->map        = NULL;
  ext->mapsz      = 0;
  ext->flags      = 0;

  ext->keyunpack  = (keyunpackfunc)  r_unpackextkey;
  ext->keycompare = (keycomparefunc) r_compareextkeys;

  f_init(&cat->f, vol, HFS_CNID_CAT, "catalog");

  cat->map        = NULL;
  cat->mapsz      = 0;
  cat->flags      = 0;

  cat->keyunpack  = (keyunpackfunc)  r_unpackcatkey;
  cat->keycompare = (keycomparefunc) r_comparecatkeys;

  vol->cwd        = HFS_CNID_ROOTDIR;

  vol->refs       = 0;
  vol->files      = NULL;
  vol->dirs       = NULL;

  vol->prev       = NULL;
  vol->next       = NULL;
}

/*
 * NAME:	vol->open()
 * DESCRIPTION:	open volume source and lock against concurrent updates
 */
int v_open(hfsvol *vol, int os_fd )
{
  if (vol->flags & HFS_VOL_OPEN)
    ERROR(EINVAL, "volume already open");

  vol->flags |= HFS_VOL_OPEN;
  vol->os_fd = os_fd;

  /* initialize volume block cache (OK to fail) */

  if (! (vol->flags & HFS_OPT_NOCACHE) &&
      b_init(vol) != -1)
    vol->flags |= HFS_VOL_USINGCACHE;

  return 0;

fail:
  return -1;
}

/*
 * NAME:	vol->close()
 * DESCRIPTION:	close access path to volume source
 */
int v_close(hfsvol *vol)
{
  int result = 0;

  if (! (vol->flags & HFS_VOL_OPEN))
    goto done;

  if ((vol->flags & HFS_VOL_USINGCACHE) &&
      b_finish(vol) == -1)
    result = -1;

  vol->flags &= ~(HFS_VOL_OPEN | HFS_VOL_MOUNTED | HFS_VOL_USINGCACHE);

  /* free dynamically allocated structures */

  FREE(vol->vbm);

  vol->vbm   = NULL;
  vol->vbmsz = 0;

  FREE(vol->ext.map);
  FREE(vol->cat.map);

  vol->ext.map = NULL;
  vol->cat.map = NULL;

done:
  return result;
}

/*
 * NAME:	vol->same()
 * DESCRIPTION:	return 1 iff path is same as open volume
 */
int v_same(hfsvol *vol, int os_fd )
{
  return vol->os_fd == os_fd;
}

/*
 * NAME:	vol->geometry()
 * DESCRIPTION:	determine volume location and size (possibly in a partition)
 */
int v_geometry(hfsvol *vol, int pnum)
{
  Partition map;
  unsigned long bnum = 0;
  int found;

  vol->pnum = pnum;

  if (pnum == 0)
    {
      vol->vstart = 0;
      vol->vlen   = b_size(vol);

      if (vol->vlen == 0)
	goto fail;
    }
  else
    {
      while (pnum--)
	{
	  found = m_findpmentry(vol, "Apple_HFS", &map, &bnum);
	  if (found == -1 || ! found)
	    goto fail;
	}

      vol->vstart = map.pmPyPartStart;
      vol->vlen   = map.pmPartBlkCnt;

      if (map.pmDataCnt)
	{
	  if ((unsigned long) map.pmLgDataStart +
	      (unsigned long) map.pmDataCnt > vol->vlen)
	    ERROR(EINVAL, "partition data overflows partition");

	  vol->vstart += (unsigned long) map.pmLgDataStart;
	  vol->vlen    = map.pmDataCnt;
	}

      if (vol->vlen == 0)
	ERROR(EINVAL, "volume partition is empty");
    }

  if (vol->vlen < 800 * (1024 >> HFS_BLOCKSZ_BITS))
    ERROR(EINVAL, "volume is smaller than 800K");

  return 0;

fail:
  return -1;
}

/*
 * NAME:	vol->readmdb()
 * DESCRIPTION:	load Master Directory Block into memory
 */
int v_readmdb(hfsvol *vol)
{
  if (l_getmdb(vol, &vol->mdb, 0) == -1)
    goto fail;

  if (vol->mdb.drSigWord != HFS_SIGWORD)
    {
      if (vol->mdb.drSigWord == HFS_SIGWORD_MFS)
	ERROR(EINVAL, "MFS volume format not supported");
      else
	ERROR(EINVAL, "not a Macintosh HFS volume");
    }

  if (vol->mdb.drAlBlkSiz % HFS_BLOCKSZ != 0)
    ERROR(EINVAL, "bad volume allocation block size");

  vol->lpa = vol->mdb.drAlBlkSiz >> HFS_BLOCKSZ_BITS;

  /* extents pseudo-file structs */

  vol->ext.f.cat.u.fil.filStBlk = vol->mdb.drXTExtRec[0].xdrStABN;
  vol->ext.f.cat.u.fil.filLgLen = vol->mdb.drXTFlSize;
  vol->ext.f.cat.u.fil.filPyLen = vol->mdb.drXTFlSize;

  vol->ext.f.cat.u.fil.filCrDat = vol->mdb.drCrDate;
  vol->ext.f.cat.u.fil.filMdDat = vol->mdb.drLsMod;

  memcpy(&vol->ext.f.cat.u.fil.filExtRec,
	 &vol->mdb.drXTExtRec, sizeof(ExtDataRec));

  f_selectfork(&vol->ext.f, fkData);

  /* catalog pseudo-file structs */

  vol->cat.f.cat.u.fil.filStBlk = vol->mdb.drCTExtRec[0].xdrStABN;
  vol->cat.f.cat.u.fil.filLgLen = vol->mdb.drCTFlSize;
  vol->cat.f.cat.u.fil.filPyLen = vol->mdb.drCTFlSize;

  vol->cat.f.cat.u.fil.filCrDat = vol->mdb.drCrDate;
  vol->cat.f.cat.u.fil.filMdDat = vol->mdb.drLsMod;

  memcpy(&vol->cat.f.cat.u.fil.filExtRec,
	 &vol->mdb.drCTExtRec, sizeof(ExtDataRec));

  f_selectfork(&vol->cat.f, fkData);

  return 0;

fail:
  return -1;
}

/*
 * NAME:	vol->readvbm()
 * DESCRIPTION:	read volume bitmap into memory
 */
int v_readvbm(hfsvol *vol)
{
  unsigned int vbmst = vol->mdb.drVBMSt;
  unsigned int vbmsz = (vol->mdb.drNmAlBlks + 0x0fff) >> 12;
  block *bp;

  ASSERT(vol->vbm == 0);

  if (vol->mdb.drAlBlSt - vbmst < vbmsz)
    ERROR(EIO, "volume bitmap collides with volume data");

  vol->vbm = ALLOC(block, vbmsz);
  if (vol->vbm == NULL)
    ERROR(ENOMEM, NULL);

  vol->vbmsz = vbmsz;

  for (bp = vol->vbm; vbmsz--; ++bp)
    {
      if (b_readlb(vol, vbmst++, bp) == -1)
	goto fail;
    }

  return 0;

fail:
  FREE(vol->vbm);

  vol->vbm   = NULL;
  vol->vbmsz = 0;

  return -1;
}

/*
 * NAME:	vol->mount()
 * DESCRIPTION:	load volume information into memory
 */
int v_mount(hfsvol *vol)
{
  /* read the MDB, volume bitmap, and extents/catalog B*-tree headers */

  if (v_readmdb(vol) == -1 ||
      v_readvbm(vol) == -1 ||
      bt_readhdr(&vol->ext) == -1 ||
      bt_readhdr(&vol->cat) == -1)
    goto fail;

  if (vol->mdb.drAtrb & HFS_ATRB_SLOCKED)
    vol->flags |= HFS_VOL_READONLY;
  else if (vol->flags & HFS_VOL_READONLY)
    vol->mdb.drAtrb |= HFS_ATRB_HLOCKED;
  else
    vol->mdb.drAtrb &= ~HFS_ATRB_HLOCKED;

  vol->flags |= HFS_VOL_MOUNTED;

  return 0;

fail:
  return -1;
}

/*
 * NAME:	vol->catsearch()
 * DESCRIPTION:	search catalog tree
 */
int v_catsearch(hfsvol *vol, unsigned long parid, const char *name,
		CatDataRec *data, char *cname, node *np)
{
  CatKeyRec key;
  byte pkey[HFS_CATKEYLEN];
  const byte *ptr;
  node n;
  int found;

  if (np == NULL)
    np = &n;

  r_makecatkey(&key, parid, name);
  r_packcatkey(&key, pkey, NULL);

  found = bt_search(&vol->cat, pkey, np);
  if (found <= 0)
    return found;

  ptr = HFS_NODEREC(*np, np->rnum);

  if (cname)
    {
      r_unpackcatkey(ptr, &key);
      strcpy(cname, key.ckrCName);
    }

  if (data)
    r_unpackcatdata(HFS_RECDATA(ptr), data);

  return 1;
}

/*
 * NAME:	vol->extsearch()
 * DESCRIPTION:	search extents tree
 */
int v_extsearch(hfsfile *file, unsigned int fabn,
		ExtDataRec *data, node *np)
{
  ExtKeyRec key;
  ExtDataRec extsave;
  unsigned int fabnsave;
  byte pkey[HFS_EXTKEYLEN];
  const byte *ptr;
  node n;
  int found;

  if (np == NULL)
    np = &n;

  r_makeextkey(&key, file->fork, file->cat.u.fil.filFlNum, fabn);
  r_packextkey(&key, pkey, NULL);

  /* in case bt_search() clobbers these */

  memcpy(&extsave, &file->ext, sizeof(ExtDataRec));
  fabnsave = file->fabn;

  found = bt_search(&file->vol->ext, pkey, np);

  memcpy(&file->ext, &extsave, sizeof(ExtDataRec));
  file->fabn = fabnsave;

  if (found <= 0)
    return found;

  if (data)
    {
      ptr = HFS_NODEREC(*np, np->rnum);
      r_unpackextdata(HFS_RECDATA(ptr), data);
    }

  return 1;
}

/*
 * NAME:	vol->getthread()
 * DESCRIPTION:	retrieve catalog thread information for a file or directory
 */
int v_getthread(hfsvol *vol, unsigned long id,
		CatDataRec *thread, node *np, int type)
{
  CatDataRec rec;
  int found;

  if (thread == NULL)
    thread = &rec;

  found = v_catsearch(vol, id, "", thread, NULL, np);
  if (found == 1 && thread->cdrType != type)
    ERROR(EIO, "bad thread record");

  return found;

fail:
  return -1;
}


/*
 * NAME:	vol->resolve()
 * DESCRIPTION:	translate a pathname; return catalog information
 */
int v_resolve(hfsvol **vol, const char *path,
              CatDataRec *data, unsigned long *parid, char *fname, node *np)
{
  unsigned long dirid;
  char name[HFS_MAX_FLEN + 1], *nptr;
  int found = 0;

  if (*path == 0)
    ERROR(ENOENT, "empty path");

  if (parid)
    *parid = 0;

  nptr = strchr(path, ':');

  if (*path == ':' || nptr == NULL)
    {
      dirid = (*vol)->cwd;  /* relative path */

      if (*path == ':')
	++path;

      if (*path == 0)
	{
          found = v_getdthread(*vol, dirid, data, NULL);
	  if (found == -1)
	    goto fail;

	  if (found)
	    {
	      if (parid)
		*parid = data->u.dthd.thdParID;

	      found = v_catsearch(*vol, data->u.dthd.thdParID,
				  data->u.dthd.thdCName, data, fname, np);
	      if (found == -1)
		goto fail;
	    }

	  goto done;
	}
    }
  else
    {
      hfsvol *check;

      dirid = HFS_CNID_ROOTPAR;  /* absolute path */

      if (nptr - path > HFS_MAX_VLEN)
        ERROR(ENAMETOOLONG, NULL);

      strncpy(name, path, nptr - path);
      name[nptr - path] = 0;

      for (check = hfs_mounts; check; check = check->next)
	{
	  if (d_relstring(check->mdb.drVN, name) == 0)
	    {
	      *vol = check;
	      break;
	    }
	}
    }

  while (1)
    {
      while (*path == ':')
	{
	  ++path;

          found = v_getdthread(*vol, dirid, data, NULL);
	  if (found == -1)
	    goto fail;
	  else if (! found)
	    goto done;

	  dirid = data->u.dthd.thdParID;
	}

      if (*path == 0)
	{
          found = v_getdthread(*vol, dirid, data, NULL);
	  if (found == -1)
	    goto fail;

	  if (found)
	    {
	      if (parid)
		*parid = data->u.dthd.thdParID;

	      found = v_catsearch(*vol, data->u.dthd.thdParID,
				  data->u.dthd.thdCName, data, fname, np);
	      if (found == -1)
		goto fail;
	    }

	  goto done;
	}

      nptr = name;
      while (nptr < name + sizeof(name) - 1 && *path && *path != ':')
	*nptr++ = *path++;

      if (*path && *path != ':')
        ERROR(ENAMETOOLONG, NULL);

      *nptr = 0;
      if (*path == ':')
	++path;

      if (parid)
	*parid = dirid;

      found = v_catsearch(*vol, dirid, name, data, fname, np);
      if (found == -1)
	goto fail;

      if (! found)
	{
	  if (*path && parid)
	    *parid = 0;

	  if (*path == 0 && fname)
	    strcpy(fname, name);

	  goto done;
	}

      switch (data->cdrType)
	{
	case cdrDirRec:
	  if (*path == 0)
	    goto done;

	  dirid = data->u.dir.dirDirID;
	  break;

	case cdrFilRec:
	  if (*path == 0)
	    goto done;

	  ERROR(ENOTDIR, "invalid pathname");

	default:
	  ERROR(EIO, "unexpected catalog record");
	}
    }

done:
  return found;

fail:
  return -1;
}

/* Determine whether the volume is a HFS volume */
int
v_probe(int fd, long long offset)
{
	MDB *mdb;

	mdb = (MDB*)malloc(2 * 512);
	os_seek_offset( fd, 2 * 512 + offset );
	os_read(fd, mdb, 2, 9);

	if (__be16_to_cpu(mdb->drSigWord) != HFS_SIGWORD) {
		free(mdb);
		return 0;
	}

	free(mdb);
	return -1;
}
