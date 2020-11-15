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
 * $Id: btree.c,v 1.10 1998/11/02 22:08:54 rob Exp $
 */

#include "config.h"

#include "libhfs.h"
#include "btree.h"
#include "data.h"
#include "file.h"
#include "block.h"
#include "node.h"

/*
 * NAME:	btree->getnode()
 * DESCRIPTION:	retrieve a numbered node from a B*-tree file
 */
int bt_getnode(node *np, btree *bt, unsigned long nnum)
{
  block *bp = &np->data;
  const byte *ptr;
  int i;

  np->bt   = bt;
  np->nnum = nnum;

# if 0
  fprintf(stderr, "BTREE: GET vol \"%s\" btree \"%s\" node %lu\n",
	  bt->f.vol->mdb.drVN, bt->f.name, np->nnum);
# endif

  /* verify the node exists and is marked as in-use */

  if (nnum > 0 && nnum >= bt->hdr.bthNNodes)
    ERROR(EIO, "read nonexistent b*-tree node");
  else if (bt->map && ! BMTST(bt->map, nnum))
    ERROR(EIO, "read unallocated b*-tree node");

  if (f_getblock(&bt->f, nnum, bp) == -1)
    goto fail;

  ptr = *bp;

  d_fetchul(&ptr, &np->nd.ndFLink);
  d_fetchul(&ptr, &np->nd.ndBLink);
  d_fetchsb(&ptr, &np->nd.ndType);
  d_fetchsb(&ptr, &np->nd.ndNHeight);
  d_fetchuw(&ptr, &np->nd.ndNRecs);
  d_fetchsw(&ptr, &np->nd.ndResv2);

  if (np->nd.ndNRecs > HFS_MAX_NRECS)
    ERROR(EIO, "too many b*-tree node records");

  i = np->nd.ndNRecs + 1;

  ptr = *bp + HFS_BLOCKSZ - (2 * i);

  while (i--)
    d_fetchuw(&ptr, &np->roff[i]);

  return 0;

fail:
  return -1;
}


/*
 * NAME:	btree->readhdr()
 * DESCRIPTION:	read the header node of a B*-tree
 */
int bt_readhdr(btree *bt)
{
  const byte *ptr;
  byte *map = NULL;
  int i;
  unsigned long nnum;

  if (bt_getnode(&bt->hdrnd, bt, 0) == -1)
    goto fail;

  if (bt->hdrnd.nd.ndType != ndHdrNode ||
      bt->hdrnd.nd.ndNRecs != 3 ||
      bt->hdrnd.roff[0] != 0x00e ||
      bt->hdrnd.roff[1] != 0x078 ||
      bt->hdrnd.roff[2] != 0x0f8 ||
      bt->hdrnd.roff[3] != 0x1f8)
    ERROR(EIO, "malformed b*-tree header node");

  /* read header record */

  ptr = HFS_NODEREC(bt->hdrnd, 0);

  d_fetchuw(&ptr, &bt->hdr.bthDepth);
  d_fetchul(&ptr, &bt->hdr.bthRoot);
  d_fetchul(&ptr, &bt->hdr.bthNRecs);
  d_fetchul(&ptr, &bt->hdr.bthFNode);
  d_fetchul(&ptr, &bt->hdr.bthLNode);
  d_fetchuw(&ptr, &bt->hdr.bthNodeSize);
  d_fetchuw(&ptr, &bt->hdr.bthKeyLen);
  d_fetchul(&ptr, &bt->hdr.bthNNodes);
  d_fetchul(&ptr, &bt->hdr.bthFree);

  for (i = 0; i < 76; ++i)
    d_fetchsb(&ptr, &bt->hdr.bthResv[i]);

  if (bt->hdr.bthNodeSize != HFS_BLOCKSZ)
    ERROR(EINVAL, "unsupported b*-tree node size");

  /* read map record; construct btree bitmap */
  /* don't set bt->map until we're done, since getnode() checks it */

  map = ALLOC(byte, HFS_MAP1SZ);
  if (map == NULL)
    ERROR(ENOMEM, NULL);

  memcpy(map, HFS_NODEREC(bt->hdrnd, 2), HFS_MAP1SZ);
  bt->mapsz = HFS_MAP1SZ;

  /* read continuation map records, if any */

  nnum = bt->hdrnd.nd.ndFLink;

  while (nnum)
    {
      node n;
      byte *newmap;

      if (bt_getnode(&n, bt, nnum) == -1)
	goto fail;

      if (n.nd.ndType != ndMapNode ||
	  n.nd.ndNRecs != 1 ||
	  n.roff[0] != 0x00e ||
	  n.roff[1] != 0x1fa)
	ERROR(EIO, "malformed b*-tree map node");

      newmap = REALLOC(map, byte, bt->mapsz + HFS_MAPXSZ);
      if (newmap == NULL)
	ERROR(ENOMEM, NULL);

      map = newmap;

      memcpy(map + bt->mapsz, HFS_NODEREC(n, 0), HFS_MAPXSZ);
      bt->mapsz += HFS_MAPXSZ;

      nnum = n.nd.ndFLink;
    }

  bt->map = map;

  return 0;

fail:
  FREE(map);
  return -1;
}


/*
 * NAME:	btree->search()
 * DESCRIPTION:	locate a data record given a search key
 */
int bt_search(btree *bt, const byte *key, node *np)
{
  int found = 0;
  unsigned long nnum;

  nnum = bt->hdr.bthRoot;

  if (nnum == 0)
    ERROR(ENOENT, NULL);

  while (1)
    {
      const byte *rec;

      if (bt_getnode(np, bt, nnum) == -1)
	{
	  found = -1;
	  goto fail;
	}

      found = n_search(np, key);

      switch (np->nd.ndType)
	{
	case ndIndxNode:
	  if (np->rnum == -1)
            ERROR(ENOENT, NULL);

	  rec  = HFS_NODEREC(*np, np->rnum);
	  nnum = d_getul(HFS_RECDATA(rec));

	  break;

	case ndLeafNode:
	  if (! found)
            ERROR(ENOENT, NULL);

	  goto done;

	default:
	  found = -1;
	  ERROR(EIO, "unexpected b*-tree node");
	}
    }

done:
fail:
  return found;
}
