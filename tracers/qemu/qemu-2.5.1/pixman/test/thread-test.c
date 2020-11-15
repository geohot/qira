#include "utils.h"

#ifndef HAVE_PTHREADS

int main ()
{
    printf ("Skipped thread-test - pthreads not supported\n");
    return 0;
}

#else

#include <stdlib.h>
#include <pthread.h>

typedef struct
{
    int       thread_no;
    uint32_t *dst_buf;
    prng_t    prng_state;
} info_t;

static const pixman_op_t operators[] = 
{
    PIXMAN_OP_SRC,
    PIXMAN_OP_OVER,
    PIXMAN_OP_ADD,
    PIXMAN_OP_CLEAR,
    PIXMAN_OP_SRC,
    PIXMAN_OP_DST,
    PIXMAN_OP_OVER,
    PIXMAN_OP_OVER_REVERSE,
    PIXMAN_OP_IN,
    PIXMAN_OP_IN_REVERSE,
    PIXMAN_OP_OUT,
    PIXMAN_OP_OUT_REVERSE,
    PIXMAN_OP_ATOP,
    PIXMAN_OP_ATOP_REVERSE,
    PIXMAN_OP_XOR,
    PIXMAN_OP_ADD,
    PIXMAN_OP_SATURATE,
    PIXMAN_OP_DISJOINT_CLEAR,
    PIXMAN_OP_DISJOINT_SRC,
    PIXMAN_OP_DISJOINT_DST,
    PIXMAN_OP_DISJOINT_OVER,
    PIXMAN_OP_DISJOINT_OVER_REVERSE,
    PIXMAN_OP_DISJOINT_IN,
    PIXMAN_OP_DISJOINT_IN_REVERSE,
    PIXMAN_OP_DISJOINT_OUT,
    PIXMAN_OP_DISJOINT_OUT_REVERSE,
    PIXMAN_OP_DISJOINT_ATOP,
    PIXMAN_OP_DISJOINT_ATOP_REVERSE,
    PIXMAN_OP_DISJOINT_XOR,
    PIXMAN_OP_CONJOINT_CLEAR,
    PIXMAN_OP_CONJOINT_SRC,
    PIXMAN_OP_CONJOINT_DST,
    PIXMAN_OP_CONJOINT_OVER,
    PIXMAN_OP_CONJOINT_OVER_REVERSE,
    PIXMAN_OP_CONJOINT_IN,
    PIXMAN_OP_CONJOINT_IN_REVERSE,
    PIXMAN_OP_CONJOINT_OUT,
    PIXMAN_OP_CONJOINT_OUT_REVERSE,
    PIXMAN_OP_CONJOINT_ATOP,
    PIXMAN_OP_CONJOINT_ATOP_REVERSE,
    PIXMAN_OP_CONJOINT_XOR,
    PIXMAN_OP_MULTIPLY,
    PIXMAN_OP_SCREEN,
    PIXMAN_OP_OVERLAY,
    PIXMAN_OP_DARKEN,
    PIXMAN_OP_LIGHTEN,
    PIXMAN_OP_COLOR_DODGE,
    PIXMAN_OP_COLOR_BURN,
    PIXMAN_OP_HARD_LIGHT,
    PIXMAN_OP_DIFFERENCE,
    PIXMAN_OP_EXCLUSION,
};

static const pixman_format_code_t formats[] =
{
    PIXMAN_a8r8g8b8,
    PIXMAN_r5g6b5,
    PIXMAN_a8,
    PIXMAN_a4,
    PIXMAN_a1,
    PIXMAN_b5g6r5,
    PIXMAN_r8g8b8a8,
    PIXMAN_a4r4g4b4
};

#define N_ROUNDS 8192

#define RAND_ELT(arr)							\
    arr[prng_rand_r(&info->prng_state) % ARRAY_LENGTH (arr)]

#define DEST_WIDTH (7)

static void *
thread (void *data)
{
    info_t *info = data;
    uint32_t crc32 = 0x0;
    uint32_t src_buf[64];
    pixman_image_t *dst_img, *src_img;
    int i;

    prng_srand_r (&info->prng_state, info->thread_no);

    for (i = 0; i < N_ROUNDS; ++i)
    {
	pixman_op_t op;
	int rand1, rand2;

	prng_randmemset_r (&info->prng_state, info->dst_buf,
			   DEST_WIDTH * sizeof (uint32_t), 0);
	prng_randmemset_r (&info->prng_state, src_buf,
			   sizeof (src_buf), 0);

	src_img = pixman_image_create_bits (
	    RAND_ELT (formats), 4, 4, src_buf, 16);
	dst_img = pixman_image_create_bits (
	    RAND_ELT (formats), DEST_WIDTH, 1, info->dst_buf,
	    DEST_WIDTH * sizeof (uint32_t));

	image_endian_swap (src_img);
	image_endian_swap (dst_img);
	
	rand2 = prng_rand_r (&info->prng_state) % 4;
	rand1 = prng_rand_r (&info->prng_state) % 4;
	op = RAND_ELT (operators);

	pixman_image_composite32 (
	    op,
	    src_img, NULL, dst_img,
	    rand1, rand2, 0, 0, 0, 0, DEST_WIDTH, 1);

	crc32 = compute_crc32_for_image (crc32, dst_img);

	pixman_image_unref (src_img);
	pixman_image_unref (dst_img);
    }

    return (void *)(uintptr_t)crc32;
}

static inline uint32_t
byteswap32 (uint32_t x)
{
    return ((x & ((uint32_t)0xFF << 24)) >> 24) |
           ((x & ((uint32_t)0xFF << 16)) >>  8) |
           ((x & ((uint32_t)0xFF <<  8)) <<  8) |
           ((x & ((uint32_t)0xFF <<  0)) << 24);
}

int
main (void)
{
    uint32_t dest[16 * DEST_WIDTH];
    info_t info[16] = { { 0 } };
    pthread_t threads[16];
    void *retvals[16];
    uint32_t crc32s[16], crc32;
    int i;

    for (i = 0; i < 16; ++i)
    {
	info[i].thread_no = i;
	info[i].dst_buf = &dest[i * DEST_WIDTH];
    }

    for (i = 0; i < 16; ++i)
	pthread_create (&threads[i], NULL, thread, &info[i]);

    for (i = 0; i < 16; ++i)
	pthread_join (threads[i], &retvals[i]);

    for (i = 0; i < 16; ++i)
    {
	crc32s[i] = (uintptr_t)retvals[i];

	if (is_little_endian())
	    crc32s[i] = byteswap32 (crc32s[i]);
    }

    crc32 = compute_crc32 (0, crc32s, sizeof crc32s);

#define EXPECTED 0xE299B18E

    if (crc32 != EXPECTED)
    {
	printf ("thread-test failed. Got checksum 0x%08X, expected 0x%08X\n",
		crc32, EXPECTED);
	return 1;
    }

    return 0;
}

#endif

