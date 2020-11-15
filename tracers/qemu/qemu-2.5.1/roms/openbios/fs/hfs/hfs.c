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
 * $Id: hfs.c,v 1.15 1998/11/02 22:09:00 rob Exp $
 */

#include "config.h"
#include "libhfs.h"
#include "data.h"
#include "block.h"
#include "medium.h"
#include "file.h"
#include "btree.h"
#include "node.h"
#include "record.h"
#include "volume.h"

const char *hfs_error = "no error";	/* static error string */

hfsvol *hfs_mounts;			/* linked list of mounted volumes */

static
hfsvol *curvol;				/* current volume */


/*
 * NAME:	getvol()
 * DESCRIPTION:	validate a volume reference
 */
static
int getvol(hfsvol **vol)
{
  if (*vol == NULL)
    {
      if (curvol == NULL)
	ERROR(EINVAL, "no volume is current");

      *vol = curvol;
    }

  return 0;

fail:
  return -1;
}

/* High-Level Volume Routines ============================================== */

/*
 * NAME:	hfs->mount()
 * DESCRIPTION:	open an HFS volume; return volume descriptor or 0 (error)
 */
hfsvol *hfs_mount( int os_fd, int pnum)
{
  hfsvol *vol, *check;
  int mode = HFS_MODE_RDONLY;

  /* see if the volume is already mounted */
  for (check = hfs_mounts; check; check = check->next)
    {
      if (check->pnum == pnum && v_same(check, os_fd) == 1)
	{
	    vol = check;
	    goto done;
	}
    }

  vol = ALLOC(hfsvol, 1);
  if (vol == NULL)
    ERROR(ENOMEM, NULL);

  v_init(vol, mode);

  vol->flags |= HFS_VOL_READONLY;
  if( v_open(vol, os_fd) == -1 )
	  goto fail;

  /* mount the volume */

  if (v_geometry(vol, pnum) == -1 ||
      v_mount(vol) == -1)
    goto fail;

  /* add to linked list of volumes */

  vol->prev = NULL;
  vol->next = hfs_mounts;

  if (hfs_mounts)
    hfs_mounts->prev = vol;

  hfs_mounts = vol;

done:
  ++vol->refs;
  curvol = vol;

  return vol;

fail:
  if (vol)
    {
      v_close(vol);
      FREE(vol);
    }

  return NULL;
}


/*
 * NAME:	hfs->umount()
 * DESCRIPTION:	close an HFS volume
 */
int hfs_umount(hfsvol *vol)
{
  int result = 0;

  if (getvol(&vol) == -1)
    goto fail;

  if (--vol->refs)
    {
      goto done;
    }

  /* close all open files and directories */

  while (vol->files)
    {
      if (hfs_close(vol->files) == -1)
	result = -1;
    }

  while (vol->dirs)
    {
      if (hfs_closedir(vol->dirs) == -1)
	result = -1;
    }

  /* close medium */

  if (v_close(vol) == -1)
    result = -1;

  /* remove from linked list of volumes */

  if (vol->prev)
    vol->prev->next = vol->next;
  if (vol->next)
    vol->next->prev = vol->prev;

  if (vol == hfs_mounts)
    hfs_mounts = vol->next;
  if (vol == curvol)
    curvol = NULL;

  FREE(vol);

done:
  return result;

fail:
  return -1;
}

/*
 * NAME:	hfs->umountall()
 * DESCRIPTION:	unmount all mounted volumes
 */
void hfs_umountall(void)
{
  while (hfs_mounts)
    hfs_umount(hfs_mounts);
}

/*
 * NAME:	hfs->getvol()
 * DESCRIPTION:	return a pointer to a mounted volume
 */
hfsvol *hfs_getvol(const char *name)
{
  hfsvol *vol;

  if (name == NULL)
    return curvol;

  for (vol = hfs_mounts; vol; vol = vol->next)
    {
      if (d_relstring(name, vol->mdb.drVN) == 0)
	return vol;
    }

  return NULL;
}

/*
 * NAME:	hfs->setvol()
 * DESCRIPTION:	change the current volume
 */
void hfs_setvol(hfsvol *vol)
{
  curvol = vol;
}

/*
 * NAME:	hfs->vstat()
 * DESCRIPTION:	return volume statistics
 */
int hfs_vstat(hfsvol *vol, hfsvolent *ent)
{
  if (getvol(&vol) == -1)
    goto fail;

  strcpy(ent->name, vol->mdb.drVN);

  ent->flags     = (vol->flags & HFS_VOL_READONLY) ? HFS_ISLOCKED : 0;

  ent->totbytes  = vol->mdb.drNmAlBlks * vol->mdb.drAlBlkSiz;
  ent->freebytes = vol->mdb.drFreeBks  * vol->mdb.drAlBlkSiz;

  ent->alblocksz = vol->mdb.drAlBlkSiz;
  ent->clumpsz   = vol->mdb.drClpSiz;

  ent->numfiles  = vol->mdb.drFilCnt;
  ent->numdirs   = vol->mdb.drDirCnt;

  ent->crdate    = d_ltime(vol->mdb.drCrDate);
  ent->mddate    = d_ltime(vol->mdb.drLsMod);
  ent->bkdate    = d_ltime(vol->mdb.drVolBkUp);

  ent->blessed   = vol->mdb.drFndrInfo[0];

  return 0;

fail:
  return -1;
}


/* High-Level Directory Routines =========================================== */

/*
 * NAME:	hfs->chdir()
 * DESCRIPTION:	change current HFS directory
 */
int hfs_chdir(hfsvol *vol, const char *path)
{
  CatDataRec data;

  if (getvol(&vol) == -1 ||
      v_resolve(&vol, path, &data, NULL, NULL, NULL) <= 0)
    goto fail;

  if (data.cdrType != cdrDirRec)
    ERROR(ENOTDIR, NULL);

  vol->cwd = data.u.dir.dirDirID;

  return 0;

fail:
  return -1;
}

/*
 * NAME:	hfs->getcwd()
 * DESCRIPTION:	return the current working directory ID
 */
unsigned long hfs_getcwd(hfsvol *vol)
{
  if (getvol(&vol) == -1)
    return 0;

  return vol->cwd;
}

/*
 * NAME:	hfs->setcwd()
 * DESCRIPTION:	set the current working directory ID
 */
int hfs_setcwd(hfsvol *vol, unsigned long id)
{
  if (getvol(&vol) == -1)
    goto fail;

  if (id == vol->cwd)
    goto done;

  /* make sure the directory exists */

  if (v_getdthread(vol, id, NULL, NULL) <= 0)
    goto fail;

  vol->cwd = id;

done:
  return 0;

fail:
  return -1;
}

/*
 * NAME:	hfs->dirinfo()
 * DESCRIPTION:	given a directory ID, return its (name and) parent ID
 */
int hfs_dirinfo(hfsvol *vol, unsigned long *id, char *name)
{
  CatDataRec thread;

  if (getvol(&vol) == -1 ||
      v_getdthread(vol, *id, &thread, NULL) <= 0)
    goto fail;

  *id = thread.u.dthd.thdParID;

  if (name)
    strcpy(name, thread.u.dthd.thdCName);

  return 0;

fail:
  return -1;
}

/*
 * NAME:	hfs->opendir()
 * DESCRIPTION:	prepare to read the contents of a directory
 */
hfsdir *hfs_opendir(hfsvol *vol, const char *path)
{
  hfsdir *dir = NULL;
  CatKeyRec key;
  CatDataRec data;
  byte pkey[HFS_CATKEYLEN];

  if (getvol(&vol) == -1)
    goto fail;

  dir = ALLOC(hfsdir, 1);
  if (dir == NULL)
    ERROR(ENOMEM, NULL);

  dir->vol = vol;

  if (*path == 0)
    {
      /* meta-directory containing root dirs from all mounted volumes */

      dir->dirid = 0;
      dir->vptr  = hfs_mounts;
    }
  else
    {
      if (v_resolve(&vol, path, &data, NULL, NULL, NULL) <= 0)
	goto fail;

      if (data.cdrType != cdrDirRec)
        ERROR(ENOTDIR, NULL);

      dir->dirid = data.u.dir.dirDirID;
      dir->vptr  = NULL;

      r_makecatkey(&key, dir->dirid, "");
      r_packcatkey(&key, pkey, NULL);

      if (bt_search(&vol->cat, pkey, &dir->n) <= 0)
	goto fail;
    }

  dir->prev = NULL;
  dir->next = vol->dirs;

  if (vol->dirs)
    vol->dirs->prev = dir;

  vol->dirs = dir;

  return dir;

fail:
  FREE(dir);
  return NULL;
}

/*
 * NAME:	hfs->readdir()
 * DESCRIPTION:	return the next entry in the directory
 */
int hfs_readdir(hfsdir *dir, hfsdirent *ent)
{
  CatKeyRec key;
  CatDataRec data;
  const byte *ptr;

  if (dir->dirid == 0)
    {
      hfsvol *vol;
      char cname[HFS_MAX_FLEN + 1];

      for (vol = hfs_mounts; vol; vol = vol->next)
	{
	  if (vol == dir->vptr)
	    break;
	}

      if (vol == NULL)
	ERROR(ENOENT, "no more entries");

      if (v_getdthread(vol, HFS_CNID_ROOTDIR, &data, NULL) <= 0 ||
	  v_catsearch(vol, HFS_CNID_ROOTPAR, data.u.dthd.thdCName,
                      &data, cname, NULL) <= 0)
	goto fail;

      r_unpackdirent(HFS_CNID_ROOTPAR, cname, &data, ent);

      dir->vptr = vol->next;

      goto done;
    }

  if (dir->n.rnum == -1)
    ERROR(ENOENT, "no more entries");

  while (1)
    {
      ++dir->n.rnum;

      while (dir->n.rnum >= dir->n.nd.ndNRecs)
	{
	  if (dir->n.nd.ndFLink == 0)
	    {
	      dir->n.rnum = -1;
	      ERROR(ENOENT, "no more entries");
	    }

	  if (bt_getnode(&dir->n, dir->n.bt, dir->n.nd.ndFLink) == -1)
	    {
	      dir->n.rnum = -1;
	      goto fail;
	    }

	  dir->n.rnum = 0;
	}

      ptr = HFS_NODEREC(dir->n, dir->n.rnum);

      r_unpackcatkey(ptr, &key);

      if (key.ckrParID != dir->dirid)
	{
	  dir->n.rnum = -1;
	  ERROR(ENOENT, "no more entries");
	}

      r_unpackcatdata(HFS_RECDATA(ptr), &data);

      switch (data.cdrType)
	{
	case cdrDirRec:
	case cdrFilRec:
	  r_unpackdirent(key.ckrParID, key.ckrCName, &data, ent);
	  goto done;

	case cdrThdRec:
	case cdrFThdRec:
	  break;

	default:
	  dir->n.rnum = -1;
	  ERROR(EIO, "unexpected directory entry found");
	}
    }

done:
  return 0;

fail:
  return -1;
}

/*
 * NAME:	hfs->closedir()
 * DESCRIPTION:	stop reading a directory
 */
int hfs_closedir(hfsdir *dir)
{
  hfsvol *vol = dir->vol;

  if (dir->prev)
    dir->prev->next = dir->next;
  if (dir->next)
    dir->next->prev = dir->prev;
  if (dir == vol->dirs)
    vol->dirs = dir->next;

  FREE(dir);

  return 0;
}

/* High-Level File Routines ================================================ */

/*
 * NAME:	hfs->open()
 * DESCRIPTION:	prepare a file for I/O
 */
hfsfile *hfs_open(hfsvol *vol, const char *path)
{
  hfsfile *file = NULL;

  if (getvol(&vol) == -1)
    goto fail;

  file = ALLOC(hfsfile, 1);
  if (file == NULL)
    ERROR(ENOMEM, NULL);

  if (v_resolve(&vol, path, &file->cat, &file->parid, file->name, NULL) <= 0)
    goto fail;

  if (file->cat.cdrType != cdrFilRec)
    ERROR(EISDIR, NULL);

  /* package file handle for user */

  file->vol   = vol;
  file->flags = 0;

  f_selectfork(file, fkData);

  file->prev = NULL;
  file->next = vol->files;

  if (vol->files)
    vol->files->prev = file;

  vol->files = file;

  return file;

fail:
  FREE(file);
  return NULL;
}

/*
 * NAME:	hfs->setfork()
 * DESCRIPTION:	select file fork for I/O operations
 */
int hfs_setfork(hfsfile *file, int fork)
{
  int result = 0;

  f_selectfork(file, fork ? fkRsrc : fkData);

  return result;
}

/*
 * NAME:	hfs->getfork()
 * DESCRIPTION:	return the current fork for I/O operations
 */
int hfs_getfork(hfsfile *file)
{
  return file->fork != fkData;
}

/*
 * NAME:	hfs->read()
 * DESCRIPTION:	read from an open file
 */
unsigned long hfs_read(hfsfile *file, void *buf, unsigned long len)
{
  unsigned long *lglen, count;
  byte *ptr = buf;

  f_getptrs(file, NULL, &lglen, NULL);

  if (file->pos + len > *lglen)
    len = *lglen - file->pos;

  count = len;
  while (count)
    {
      unsigned long bnum, offs, chunk;

      bnum  = file->pos >> HFS_BLOCKSZ_BITS;
      offs  = file->pos & (HFS_BLOCKSZ - 1);

      chunk = HFS_BLOCKSZ - offs;
      if (chunk > count)
	chunk = count;

      if (offs == 0 && chunk == HFS_BLOCKSZ)
	{
	  if (f_getblock(file, bnum, (block *) ptr) == -1)
	    goto fail;
	}
      else
	{
	  block b;

	  if (f_getblock(file, bnum, &b) == -1)
	    goto fail;

	  memcpy(ptr, b + offs, chunk);
	}

      ptr += chunk;

      file->pos += chunk;
      count     -= chunk;
    }

  return len;

fail:
  return -1;
}

/*
 * NAME:	hfs->seek()
 * DESCRIPTION:	change file seek pointer
 */
unsigned long hfs_seek(hfsfile *file, long offset, int from)
{
  unsigned long *lglen, newpos;

  f_getptrs(file, NULL, &lglen, NULL);

  switch (from)
    {
    case HFS_SEEK_SET:
      newpos = (offset < 0) ? 0 : offset;
      break;

    case HFS_SEEK_CUR:
      if (offset < 0 && (unsigned long) -offset > file->pos)
	newpos = 0;
      else
	newpos = file->pos + offset;
      break;

    case HFS_SEEK_END:
      if (offset < 0 && (unsigned long) -offset > *lglen)
	newpos = 0;
      else
	newpos = *lglen + offset;
      break;

    default:
      ERROR(EINVAL, NULL);
    }

  if (newpos > *lglen)
    newpos = *lglen;

  file->pos = newpos;

  return newpos;

fail:
  return -1;
}

/*
 * NAME:	hfs->close()
 * DESCRIPTION:	close a file
 */
int hfs_close(hfsfile *file)
{
  hfsvol *vol = file->vol;
  int result = 0;

  if (file->prev)
    file->prev->next = file->next;
  if (file->next)
    file->next->prev = file->prev;
  if (file == vol->files)
    vol->files = file->next;

  FREE(file);

  return result;
}

/* High-Level Catalog Routines ============================================= */

/*
 * NAME:	hfs->stat()
 * DESCRIPTION:	return catalog information for an arbitrary path
 */
int hfs_stat(hfsvol *vol, const char *path, hfsdirent *ent)
{
  CatDataRec data;
  unsigned long parid;
  char name[HFS_MAX_FLEN + 1];

  if (getvol(&vol) == -1 ||
      v_resolve(&vol, path, &data, &parid, name, NULL) <= 0)
    goto fail;

  r_unpackdirent(parid, name, &data, ent);

  return 0;

fail:
  return -1;
}

/*
 * NAME:	hfs->fstat()
 * DESCRIPTION:	return catalog information for an open file
 */
int hfs_fstat(hfsfile *file, hfsdirent *ent)
{
  r_unpackdirent(file->parid, file->name, &file->cat, ent);

  return 0;
}

/*
 * NAME:	hfs->probe()
 * DESCRIPTION:	return whether a HFS filesystem is present at the given offset
 */
int hfs_probe(int fd, long long offset)
{
  return v_probe(fd, offset);
}
