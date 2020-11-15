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
 * $Id: medium.c,v 1.4 1998/11/02 22:09:04 rob Exp $
 */

#include "config.h"
#include "libhfs.h"
#include "block.h"
#include "low.h"
#include "medium.h"


/*
 * NAME:	medium->findpmentry()
 * DESCRIPTION:	locate a partition map entry
 */
int m_findpmentry(hfsvol *vol, const char *type,
		  Partition *map, unsigned long *start)
{
  unsigned long bnum;
  int found = 0;

  if (start && *start > 0)
    {
      bnum = *start;

      if (bnum++ >= (unsigned long) map->pmMapBlkCnt)
	ERROR(EINVAL, "partition not found");
    }
  else
    bnum = 1;

  while (1)
    {
      if (l_getpmentry(vol, map, bnum) == -1)
	{
	  found = -1;
	  goto fail;
	}

      if (map->pmSig != HFS_PM_SIGWORD)
	{
	  found = -1;

	  if (map->pmSig == HFS_PM_SIGWORD_OLD)
	    ERROR(EINVAL, "old partition map format not supported");
	  else
	    ERROR(EINVAL, "invalid partition map");
	}

      if (strcmp((char *) map->pmParType, type) == 0)
	{
	  found = 1;
	  goto done;
	}

      if (bnum++ >= (unsigned long) map->pmMapBlkCnt)
	ERROR(EINVAL, "partition not found");
    }

done:
  if (start)
    *start = bnum;

fail:
  return found;
}
