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
 * $Id: node.c,v 1.9 1998/11/02 22:09:05 rob Exp $
 */

#include "config.h"
#include "libhfs.h"
#include "node.h"
#include "data.h"
#include "btree.h"

/*
 * NAME:	node->search()
 * DESCRIPTION:	locate a record in a node, or the record it should follow
 */
int n_search(node *np, const byte *pkey)
{
  const btree *bt = np->bt;
  byte key1[HFS_MAX_KEYLEN], key2[HFS_MAX_KEYLEN];
  int i, comp = -1;

  bt->keyunpack(pkey, key2);

  for (i = np->nd.ndNRecs; i--; )
    {
      const byte *rec;

      rec = HFS_NODEREC(*np, i);

      if (HFS_RECKEYLEN(rec) == 0)
	continue;  /* deleted record */

      bt->keyunpack(rec, key1);
      comp = bt->keycompare(key1, key2);

      if (comp <= 0)
	break;
    }

  np->rnum = i;

  return comp == 0;
}
