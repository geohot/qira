/******************************************************************************
 * Copyright (c) 2013 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/
/*
 * All functions concerning interface to slof
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <helpers.h>

#undef DEBUG
//#define DEBUG
#ifdef DEBUG
#define dprintf(_x ...) do { printf ("%s: ", __func__); printf(_x); } while (0);
#else
#define dprintf(_x ...)
#endif

#define DEFAULT_BLOCK_SIZE 4096

#define BM_WORD_SIZE (sizeof(unsigned long))
#define BM_WORD_BITS (BM_WORD_SIZE * 8)

struct bitmap {
	unsigned long start;
	unsigned long size;
	unsigned long bm_size;
	unsigned long block_size;
	unsigned long free_blocks;
	unsigned long bmw[];
};

#define BIT(x)   (1UL << x)
#define BM_WORD(bmw, n) (bmw[n/BM_WORD_BITS])
#define BM_WORD_MODULO(n)  (n % BM_WORD_BITS)
#define BM_NUM_BITS(reqsize, bsize)     ((reqsize / bsize) + (reqsize % bsize? 1 : 0))

void bm_clear_bit(unsigned long *bmw, int n)
{
	BM_WORD(bmw, n) &= ~BIT(BM_WORD_MODULO(n));
}

void bm_set_bit(unsigned long *bmw, int n)
{
	BM_WORD(bmw, n) |= BIT(BM_WORD_MODULO(n));
}

bool bm_test_bit(unsigned long *bmw, int n)
{
#ifdef DEBUG
	//printf("BMW %x, bitpos %d, value %d\n", &BM_WORD(bmw, n), n, !!(BM_WORD(bmw, n) & BIT(BM_WORD_MODULO(n))));
#endif
	return !!(BM_WORD(bmw, n) & BIT(BM_WORD_MODULO(n)));
}

/* Improvement: can use FFS routines to get faster results */
int bm_find_bits(struct bitmap *bm, unsigned int n_bits)
{
	unsigned int i, j, total_bits;
	int found = -1;
	dprintf("Finding %d bits set\n", n_bits);
	total_bits = BM_NUM_BITS(bm->size, bm->block_size);
	for(i = 0; i < total_bits; i++) {
		if (!bm_test_bit(bm->bmw, i))
			continue;
		/* we have hit the boundary now, give up */
		if (i + n_bits > total_bits)
			break;
		/* Lets find if we have consecutive bits set */
		for(j = i; j < (i + n_bits); j++) {
			if (!bm_test_bit(bm->bmw, (j)))
				break;
		}
		/* Got it */
		if (j == (i + n_bits)) {
			found = i;
			break;
		}
	}
	return found;
}

void SLOF_bm_print(unsigned long handle)
{
	struct bitmap *bm;
	unsigned int i;

	if (!handle)
		return;

	bm = (struct bitmap *) handle;
	printf("BITMAP: start %lx, size %ld, blocksize %ld\n\n",
		bm->start, bm->size, bm->block_size);
	printf("0                 16                32                48              63\n");
	for(i = 0; i < BM_NUM_BITS(bm->size, bm->block_size); i++) {
		if (i > 0 && (i % 64 == 0))
			printf("\n");
		else if (i > 0 && (i % 8 == 0))
			printf(" ");
		printf("%d", bm_test_bit(bm->bmw, i));
	}
	printf("\n\n");
}

unsigned long SLOF_bm_allocator_init(unsigned long start, unsigned long size,
				unsigned long blocksize)
{
	struct bitmap *bm;
	unsigned long alloc_size, bm_size, n_bits;

	dprintf("enter start %x, size %d, block-size %d\n", start, size, blocksize);

	if (!size)
		return 0;
	if (!blocksize)
		blocksize = DEFAULT_BLOCK_SIZE;

	n_bits = BM_NUM_BITS(size, blocksize);
	bm_size = (n_bits / BM_WORD_BITS) + ((n_bits % BM_WORD_BITS)? 1 : 0);
	alloc_size = sizeof(struct bitmap) + bm_size * BM_WORD_SIZE;
	dprintf("Size %ld, blocksize %ld, bm_size %ld, alloc_size %ld\n",
		size, blocksize, bm_size, alloc_size);
	bm = (struct bitmap *) SLOF_alloc_mem(alloc_size);
	if (!bm)
		return 0;
	bm->start = start;
	bm->size = size;
	bm->bm_size = bm_size;
	bm->block_size = blocksize;
	bm->free_blocks = n_bits;
	memset(bm->bmw, 0xFF, bm_size*BM_WORD_SIZE);
	return (unsigned long)bm;
}

unsigned long SLOF_bm_alloc(unsigned long handle, unsigned long size)
{
	struct bitmap *bm;
	unsigned long n_bits;
	unsigned long addr;
	unsigned int i;
	int bitpos;

	if (!handle)
		return -1;

	bm = (struct bitmap *) handle;

	n_bits = BM_NUM_BITS(size, bm->block_size);
	if (n_bits > bm->free_blocks)
		return -1;

	bitpos = bm_find_bits(bm, n_bits);
	if (bitpos == -1)
		return -1;

	dprintf("BMW %d, bitpos %d\n", i, bitpos);
	dprintf("size %d, block_size %d, n_bits %d\n", size, bm->block_size, n_bits);
	for(i = bitpos; i < (bitpos + n_bits); i++) {
#ifdef DEBUG
		if (!bm_test_bit(bm->bmw, i))
			dprintf("Warning: Bit already in use: %d\n", i);
#endif
		bm_clear_bit(bm->bmw, i);
	}
	bm->free_blocks -= n_bits;
	addr = bm->start + bitpos * bm->block_size;
	dprintf("BMW %d, bitpos %d addr %lx free_blocks %d\n", i, bitpos, addr, bm->free_blocks);
	return addr;
}

void SLOF_bm_free(unsigned long handle, unsigned long ptr, unsigned long size)
{
	struct bitmap *bm;
	unsigned long bitpos, n_bits;
	unsigned long addr;
	unsigned int i;

	if (!handle)
		return;

	bm = (struct bitmap *) handle;
	addr = (unsigned long ) ptr;
	n_bits = BM_NUM_BITS(size, bm->block_size);
	if (addr < bm->start || (bm->start + bm->size) < (addr + size)) {
		printf("Error: Bitmap start %lx, size %ld, requested address %lx, size %ld\n",
			bm->start, bm->size, addr, size);
		return;
	}
	bitpos = (addr - bm->start) / bm->block_size;
	bm->free_blocks += n_bits;

#ifdef DEBUG
	dprintf("addr %lx, bitpos %d\n", addr, bitpos);
	dprintf("size %d, block_size %d, n_bits %d, free_blocks %d\n", size, bm->block_size, n_bits, bm->free_blocks);
	if (addr % bm->block_size) {
		dprintf("Warning: Address not aligned addr %lx\n", addr);
	}
#endif

	for(i = bitpos; i < (bitpos + n_bits); i++) {
#ifdef DEBUG
		if (bm_test_bit(bm->bmw, i))
			dprintf("Warning: Bit already set: %d\n", i);
#endif
		bm_set_bit(bm->bmw, i);
	}

	return;
}
