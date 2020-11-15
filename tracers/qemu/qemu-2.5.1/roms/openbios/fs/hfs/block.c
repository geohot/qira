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
* $Id: block.c,v 1.11 1998/11/02 22:08:52 rob Exp $
*/

#include "config.h"

#include "libhfs.h"
#include "volume.h"
#include "block.h"
#include "os.h"

#define INUSE(b)	((b)->flags & HFS_BUCKET_INUSE)
#define DIRTY(b)	((b)->flags & HFS_BUCKET_DIRTY)

/*
 * NAME:	block->init()
 * DESCRIPTION:	initialize a volume's block cache
 */
int b_init(hfsvol *vol)
{
  bcache *cache;
  int i;

  ASSERT(vol->cache == 0);

  cache = ALLOC(bcache, 1);
  if (cache == NULL)
    ERROR(ENOMEM, NULL);

  vol->cache = cache;

  cache->vol    = vol;
  cache->tail   = &cache->chain[HFS_CACHESZ - 1];

  cache->hits   = 0;
  cache->misses = 0;

  for (i = 0; i < HFS_CACHESZ; ++i)
    {
      bucket *b = &cache->chain[i];

      b->flags = 0;
      b->count = 0;

      b->bnum  = 0;
      b->data  = &cache->pool[i];

      b->cnext = b + 1;
      b->cprev = b - 1;

      b->hnext = NULL;
      b->hprev = NULL;
    }

  cache->chain[0].cprev = cache->tail;
  cache->tail->cnext    = &cache->chain[0];

  for (i = 0; i < HFS_HASHSZ; ++i)
    cache->hash[i] = NULL;

  return 0;

fail:
  return -1;
}

# ifdef DEBUG
/*
 * NAME:	block->showstats()
 * DESCRIPTION:	output cache hit/miss ratio
 */
void b_showstats(const bcache *cache)
{
  fprintf(stderr, "BLOCK: CACHE vol 0x%lx \"%s\" hit/miss ratio = %.3f\n",
	  (unsigned long) cache->vol, cache->vol->mdb.drVN,
	  (float) cache->hits / (float) cache->misses);
}

/*
 * NAME:	block->dumpcache()
 * DESCRIPTION:	dump the cache tables for a volume
 */
void b_dumpcache(const bcache *cache)
{
  const bucket *b;
  int i;

  fprintf(stderr, "BLOCK CACHE DUMP:\n");

  for (i = 0, b = cache->tail->cnext; i < HFS_CACHESZ; ++i, b = b->cnext)
    {
      if (INUSE(b))
	{
	  fprintf(stderr, "\t %lu", b->bnum);
	  if (DIRTY(b))
	    fprintf(stderr, "*");

	  fprintf(stderr, ":%u", b->count);
	}
    }

  fprintf(stderr, "\n");

  fprintf(stderr, "BLOCK HASH DUMP:\n");

  for (i = 0; i < HFS_HASHSZ; ++i)
    {
      int seen = 0;

      for (b = cache->hash[i]; b; b = b->hnext)
	{
	  if (! seen)
	    fprintf(stderr, "  %d:", i);

	  if (INUSE(b))
	    {
	      fprintf(stderr, " %lu", b->bnum);
	      if (DIRTY(b))
		fprintf(stderr, "*");

	      fprintf(stderr, ":%u", b->count);
	    }

	  seen = 1;
	}

      if (seen)
	fprintf(stderr, "\n");
    }
}
# endif

/*
 * NAME:	fillchain()
 * DESCRIPTION:	fill a chain of bucket buffers with a single read
 */
static
int fillchain(hfsvol *vol, bucket **bptr, unsigned int *count)
{
  bucket *blist[HFS_BLOCKBUFSZ], **start = bptr;
  unsigned long bnum=-2;	// XXX
  unsigned int len, i;

  for (len = 0; len < HFS_BLOCKBUFSZ &&
	 (unsigned int) (bptr - start) < *count; ++bptr)
    {
      if (INUSE(*bptr))
	continue;

      if (len > 0 && (*bptr)->bnum != bnum)
	break;

      blist[len++] = *bptr;
      bnum = (*bptr)->bnum + 1;
    }

  *count = bptr - start;

  if (len == 0)
    goto done;
  else if (len == 1)
    {
      if (b_readpb(vol, vol->vstart + blist[0]->bnum,
		   blist[0]->data, 1) == -1)
	goto fail;
    }
  else
    {
      block buffer[HFS_BLOCKBUFSZ];

      if (b_readpb(vol, vol->vstart + blist[0]->bnum, buffer, len) == -1)
	goto fail;

      for (i = 0; i < len; ++i)
	memcpy(blist[i]->data, buffer[i], HFS_BLOCKSZ);
    }

  for (i = 0; i < len; ++i)
    {
      blist[i]->flags |=  HFS_BUCKET_INUSE;
      blist[i]->flags &= ~HFS_BUCKET_DIRTY;
    }

done:
  return 0;

fail:
  return -1;
}


/*
 * NAME:	compare()
 * DESCRIPTION:	comparison function for qsort of cache bucket pointers
 */
static
int compare(const bucket **b1, const bucket **b2)
{
  long diff;

  diff = (*b1)->bnum - (*b2)->bnum;

  if (diff < 0)
    return -1;
  else if (diff > 0)
    return 1;
  else
    return 0;
}

/*
 * NAME:	dobuckets()
 * DESCRIPTION:	fill or flush an array of cache buckets to a volume
 */
static
int dobuckets(hfsvol *vol, bucket **chain, unsigned int len,
	      int (*func)(hfsvol *, bucket **, unsigned int *))
{
  unsigned int count, i;
  int result = 0;

  qsort(chain, len, sizeof(*chain),
	(int (*)(const void *, const void *)) compare);

  for (i = 0; i < len; i += count)
    {
      count = len - i;
      if (func(vol, chain + i, &count) == -1)
	result = -1;
    }

  return result;
}

# define fillbuckets(vol, chain, len)	dobuckets(vol, chain, len, fillchain)

/*
 * NAME:	block->finish()
 * DESCRIPTION:	commit and free a volume's block cache
 */
int b_finish(hfsvol *vol)
{
  int result = 0;

  if (vol->cache == NULL)
    goto done;

# ifdef DEBUG
  b_dumpcache(vol->cache);
# endif

  FREE(vol->cache);
  vol->cache = NULL;

done:
  return result;
}

/*
 * NAME:	findbucket()
 * DESCRIPTION:	locate a bucket in the cache, and/or its hash slot
 */
static
bucket *findbucket(bcache *cache, unsigned long bnum, bucket ***hslot)
{
  bucket *b;

  *hslot = &cache->hash[bnum & (HFS_HASHSZ - 1)];

  for (b = **hslot; b; b = b->hnext)
    {
      if (INUSE(b) && b->bnum == bnum)
	break;
    }

  return b;
}

/*
 * NAME:	reuse()
 * DESCRIPTION:	free a bucket for reuse, flushing if necessary
 */
static
int reuse(bcache *cache, bucket *b, unsigned long bnum)
{
  bucket *bptr;
  int i;

# ifdef DEBUG
  if (INUSE(b))
    fprintf(stderr, "BLOCK: CACHE reusing bucket containing "
	    "vol 0x%lx block %lu:%u\n",
	    (unsigned long) cache->vol, b->bnum, b->count);
# endif

  if (INUSE(b) && DIRTY(b))
    {
      /* flush most recently unused buckets */

      for (bptr = b, i = 0; i < HFS_BLOCKBUFSZ; ++i)
	{
	  bptr = bptr->cprev;
	}
    }

  b->flags &= ~HFS_BUCKET_INUSE;
  b->count  = 1;
  b->bnum   = bnum;

  return 0;
}

/*
 * NAME:	cplace()
 * DESCRIPTION:	move a bucket to an appropriate place near head of the chain
 */
static
void cplace(bcache *cache, bucket *b)
{
  bucket *p;

  for (p = cache->tail->cnext; p->count > 1; p = p->cnext)
    --p->count;

  b->cnext->cprev = b->cprev;
  b->cprev->cnext = b->cnext;

  if (cache->tail == b)
    cache->tail = b->cprev;

  b->cprev = p->cprev;
  b->cnext = p;

  p->cprev->cnext = b;
  p->cprev = b;
}

/*
 * NAME:	hplace()
 * DESCRIPTION:	move a bucket to the head of its hash slot
 */
static
void hplace(bucket **hslot, bucket *b)
{
  if (*hslot != b)
    {
      if (b->hprev)
	*b->hprev = b->hnext;
      if (b->hnext)
	b->hnext->hprev = b->hprev;

      b->hprev = hslot;
      b->hnext = *hslot;

      if (*hslot)
	(*hslot)->hprev = &b->hnext;

      *hslot = b;
    }
}

/*
 * NAME:	getbucket()
 * DESCRIPTION:	fetch a bucket from the cache, or an empty one to be filled
 */
static
bucket *getbucket(bcache *cache, unsigned long bnum, int fill)
{
  bucket **hslot, *b, *p, *bptr,
    *chain[HFS_BLOCKBUFSZ], **slots[HFS_BLOCKBUFSZ];

  b = findbucket(cache, bnum, &hslot);

  if (b)
    {
      /* cache hit; move towards head of cache chain */

      ++cache->hits;

      if (++b->count > b->cprev->count &&
	  b != cache->tail->cnext)
	{
	  p = b->cprev;

	  p->cprev->cnext = b;
	  b->cnext->cprev = p;

	  p->cnext = b->cnext;
	  b->cprev = p->cprev;

	  p->cprev = b;
	  b->cnext = p;

	  if (cache->tail == b)
	    cache->tail = p;
	}
    }
  else
    {
      /* cache miss; reuse least-used cache bucket */

      ++cache->misses;

      b = cache->tail;

      if (reuse(cache, b, bnum) == -1)
	goto fail;

      if (fill)
	{
	  unsigned int len = 0;

	  chain[len]   = b;
	  slots[len++] = hslot;

	  for (bptr = b->cprev;
	       len < (HFS_BLOCKBUFSZ >> 1) && ++bnum < cache->vol->vlen;
	       bptr = bptr->cprev)
	    {
	      if (findbucket(cache, bnum, &hslot))
		break;

	      if (reuse(cache, bptr, bnum) == -1)
		goto fail;

	      chain[len]   = bptr;
	      slots[len++] = hslot;
	    }

	  if (fillbuckets(cache->vol, chain, len) == -1)
	    goto fail;

	  while (--len)
	    {
	      cplace(cache, chain[len]);
	      hplace(slots[len], chain[len]);
	    }

	  hslot = slots[0];
	}

      /* move bucket to appropriate place in chain */

      cplace(cache, b);
    }

  /* insert at front of hash chain */

  hplace(hslot, b);

  return b;

fail:
  return NULL;
}

/*
 * NAME:	block->readpb()
 * DESCRIPTION:	read blocks from the physical medium (bypassing cache)
 */
int b_readpb(hfsvol *vol, unsigned long bnum, block *bp, unsigned int blen)
{
  unsigned long nblocks;

# ifdef DEBUG
  fprintf(stderr, "BLOCK: READ vol 0x%lx block %lu",
	  (unsigned long) vol, bnum);
  if (blen > 1)
    fprintf(stderr, "+%u[..%lu]\n", blen - 1, bnum + blen - 1);
  else
    fprintf(stderr, "\n");
# endif

  nblocks = os_seek(vol->os_fd, bnum, HFS_BLOCKSZ_BITS );
  if (nblocks == (unsigned long) -1)
    goto fail;

  if (nblocks != bnum)
    ERROR(EIO, "block seek failed for read");

  nblocks = os_read(vol->os_fd, bp, blen, HFS_BLOCKSZ_BITS);
  if (nblocks == (unsigned long) -1)
    goto fail;

  if (nblocks != blen)
    ERROR(EIO, "incomplete block read");

  return 0;

fail:
  return -1;
}


/*
 * NAME:	block->readlb()
 * DESCRIPTION:	read a logical block from a volume (or from the cache)
 */
int b_readlb(hfsvol *vol, unsigned long bnum, block *bp)
{
  if (vol->vlen > 0 && bnum >= vol->vlen)
    ERROR(EIO, "read nonexistent logical block");

  if (vol->cache)
    {
      bucket *b;

      b = getbucket(vol->cache, bnum, 1);
      if (b == NULL)
	goto fail;

      memcpy(bp, b->data, HFS_BLOCKSZ);
    }
  else
    {
      if (b_readpb(vol, vol->vstart + bnum, bp, 1) == -1)
	goto fail;
    }

  return 0;

fail:
  return -1;
}

/*
 * NAME:	block->readab()
 * DESCRIPTION:	read a block from an allocation block from a volume
 */
int b_readab(hfsvol *vol, unsigned int anum, unsigned int index, block *bp)
{
  /* verify the allocation block exists and is marked as in-use */

  if (anum >= vol->mdb.drNmAlBlks)
    ERROR(EIO, "read nonexistent allocation block");
  else if (vol->vbm && ! BMTST(vol->vbm, anum))
    ERROR(EIO, "read unallocated block");

  return b_readlb(vol, vol->mdb.drAlBlSt + anum * vol->lpa + index, bp);

fail:
  return -1;
}


/*
 * NAME:	block->size()
 * DESCRIPTION:	return the number of physical blocks on a volume's medium
 */
unsigned long b_size(hfsvol *vol)
{
  unsigned long low, high, mid;
  block b;

  high = os_seek(vol->os_fd, -1, HFS_BLOCKSZ_BITS);

  if (high != (unsigned long) -1 && high > 0)
    return high;

  /* manual size detection: first check there is at least 1 block in medium */

  if (b_readpb(vol, 0, &b, 1) == -1)
    ERROR(EIO, "size of medium indeterminable or empty");

  for (low = 0, high = 2880;
       high > 0 && b_readpb(vol, high - 1, &b, 1) != -1;
       high <<= 1)
    low = high - 1;

  if (high == 0)
    ERROR(EIO, "size of medium indeterminable or too large");

  /* common case: 1440K floppy */

  if (low == 2879 && b_readpb(vol, 2880, &b, 1) == -1)
    return 2880;

  /* binary search for other sizes */

  while (low < high - 1)
    {
      mid = (low + high) >> 1;

      if (b_readpb(vol, mid, &b, 1) == -1)
	high = mid;
      else
	low = mid;
    }

  return low + 1;

fail:
  return 0;
}
