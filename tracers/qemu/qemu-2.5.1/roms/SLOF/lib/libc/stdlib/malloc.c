/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/


#include "stddef.h"
#include "stdlib.h"
#include "unistd.h"
#include "malloc_defs.h"


static int clean(void);


/* act points to the end of the initialized heap and the start of uninitialized heap */
static char *act;

/* Pointers to start and end of heap: */
static char *heap_start, *heap_end;


/*
 * Standard malloc function
 */
void *
malloc(size_t size)
{
	char *header;
	void *data;
	size_t blksize;         /* size of memory block including the chunk */

	blksize = size + sizeof(struct chunk);

	/* has malloc been called for the first time? */
	if (act == 0) {
		size_t initsize;
		/* add some space so we have a good initial playground */
		initsize = (blksize + 0x1000) & ~0x0fff;
		/* get initial memory region with sbrk() */
		heap_start = sbrk(initsize);
		if (heap_start == (void*)-1)
			return NULL;
		heap_end = heap_start + initsize;
		act = heap_start;
	}

	header = act;
	data = act + sizeof(struct chunk);

	/* Check if there is space left in the uninitialized part of the heap */
	if (act + blksize > heap_end) {
		//search at begin of heap
		header = heap_start;

		while ((((struct chunk *) header)->inuse != 0
		        || ((struct chunk *) header)->length < size)
		       && header < act) {
			header = header + sizeof(struct chunk)
			         + ((struct chunk *) header)->length;
		}

		// check if heap is full
		if (header >= act) {
			if (clean()) {
				// merging of free blocks succeeded, so try again
				return malloc(size);
			} else if (sbrk(blksize) == heap_end) {
				// succeeded to get more memory, so try again
				heap_end += blksize;
				return malloc(size);
			} else {
				// No more memory available
				return 0;
			}
		}

		// Check if we need to split this memory block into two
		if (((struct chunk *) header)->length > blksize) {
			//available memory is too big
			int alt;

			alt = ((struct chunk *) header)->length;
			((struct chunk *) header)->inuse = 1;
			((struct chunk *) header)->length = size;
			data = header + sizeof(struct chunk);

			//mark the rest of the heap
			header = data + size;
			((struct chunk *) header)->inuse = 0;
			((struct chunk *) header)->length =
			    alt - blksize;
		} else {
			//new memory matched exactly in available memory
			((struct chunk *) header)->inuse = 1;
			data = header + sizeof(struct chunk);
		}

	} else {

		((struct chunk *) header)->inuse = 1;
		((struct chunk *) header)->length = size;

		act += blksize;
	}

	return data;
}


/*
 * Merge free memory blocks in initialized heap if possible
 */
static int
clean(void)
{
	char *header;
	char *firstfree = 0;
	char check = 0;

	header = heap_start;
	//if (act == 0)		// This should never happen
	//	act = heap_end;

	while (header < act) {

		if (((struct chunk *) header)->inuse == 0) {
			if (firstfree == 0) {
				/* First free block in a row, only save address */
				firstfree = header;

			} else {
				/* more than one free block in a row, merge them! */
				((struct chunk *) firstfree)->length +=
				    ((struct chunk *) header)->length +
				    sizeof(struct chunk);
				check = 1;
			}
		} else {
			firstfree = 0;

		}

		header = header + sizeof(struct chunk)
		         + ((struct chunk *) header)->length;

	}

	return check;
}
