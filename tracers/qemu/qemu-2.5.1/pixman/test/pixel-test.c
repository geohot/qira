/*
 * Copyright © 2013 Soeren Sandmann
 * Copyright © 2013 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h> /* abort() */
#include <math.h>
#include <time.h>
#include "utils.h"

typedef struct pixel_combination_t pixel_combination_t;
struct pixel_combination_t
{
    pixman_op_t			op;
    pixman_format_code_t	src_format;
    uint32_t			src_pixel;
    pixman_format_code_t	dest_format;
    uint32_t			dest_pixel;
};

static const pixel_combination_t regressions[] =
{
    { PIXMAN_OP_OVER,
      PIXMAN_a8r8g8b8,	0x0f00c300,
      PIXMAN_x14r6g6b6,	0x003c0,
    },
    { PIXMAN_OP_DISJOINT_XOR,
      PIXMAN_a4r4g4b4,	0xd0c0,
      PIXMAN_a8r8g8b8,	0x5300ea00,
    },
    { PIXMAN_OP_OVER,
      PIXMAN_a8r8g8b8,	0x20c6bf00,
      PIXMAN_r5g6b5,	0xb9ff
    },
    { PIXMAN_OP_OVER,
      PIXMAN_a8r8g8b8,	0x204ac7ff,
      PIXMAN_r5g6b5,	0xc1ff
    },
    { PIXMAN_OP_OVER_REVERSE,
      PIXMAN_r5g6b5,	0xffc3,
      PIXMAN_a8r8g8b8,	0x102d00dd
    },
    { PIXMAN_OP_OVER_REVERSE,
      PIXMAN_r5g6b5,	0x1f00,
      PIXMAN_a8r8g8b8,	0x1bdf0c89
    },
    { PIXMAN_OP_OVER_REVERSE,
      PIXMAN_r5g6b5,	0xf9d2,
      PIXMAN_a8r8g8b8,	0x1076bcf7
    },
    { PIXMAN_OP_OVER_REVERSE,
      PIXMAN_r5g6b5,	0x00c3,
      PIXMAN_a8r8g8b8,	0x1bfe9ae5
    },
    { PIXMAN_OP_OVER_REVERSE,
      PIXMAN_r5g6b5,	0x09ff,
      PIXMAN_a8r8g8b8,	0x0b00c16c
    },
    { PIXMAN_OP_DISJOINT_ATOP,
      PIXMAN_a2r2g2b2,	0xbc,
      PIXMAN_a8r8g8b8,	0x9efff1ff
    },
    { PIXMAN_OP_DISJOINT_ATOP,
      PIXMAN_a4r4g4b4,	0xae5f,
      PIXMAN_a8r8g8b8,	0xf215b675
    },
    { PIXMAN_OP_DISJOINT_ATOP_REVERSE,
      PIXMAN_a8r8g8b8,	0xce007980,
      PIXMAN_a8r8g8b8,	0x80ffe4ad
    },
    { PIXMAN_OP_DISJOINT_XOR,
      PIXMAN_a8r8g8b8,	0xb8b07bea,
      PIXMAN_a4r4g4b4,	0x939c
    },
    { PIXMAN_OP_CONJOINT_ATOP_REVERSE,
      PIXMAN_r5g6b5,	0x0063,
      PIXMAN_a8r8g8b8,	0x10bb1ed7,
    },
};

static void
fill (pixman_image_t *image, uint32_t pixel)
{
    uint8_t *data = (uint8_t *)pixman_image_get_data (image);
    int bytes_per_pixel = PIXMAN_FORMAT_BPP (pixman_image_get_format (image)) / 8;
    int n_bytes = pixman_image_get_stride (image) * pixman_image_get_height (image);
    int i;

    switch (bytes_per_pixel)
    {
    case 4:
	for (i = 0; i < n_bytes / 4; ++i)
	    ((uint32_t *)data)[i] = pixel;
	break;

    case 2:
	pixel &= 0xffff;
	for (i = 0; i < n_bytes / 2; ++i)
	    ((uint16_t *)data)[i] = pixel;
	break;

    case 1:
	pixel &= 0xff;
	for (i = 0; i < n_bytes; ++i)
	    ((uint8_t *)data)[i] = pixel;
	break;

    default:
	assert (0);
	break;
    }
}

static uint32_t
access (pixman_image_t *image, int x, int y)
{
    int bytes_per_pixel;
    int stride;
    uint32_t result;
    uint8_t *location;

    if (x < 0 || x >= image->bits.width || y < 0 || y >= image->bits.height)
        return 0;

    bytes_per_pixel = PIXMAN_FORMAT_BPP (image->bits.format) / 8;
    stride = image->bits.rowstride * 4;

    location = (uint8_t *)image->bits.bits + y * stride + x * bytes_per_pixel;

    if (bytes_per_pixel == 4)
        result = *(uint32_t *)location;
    else if (bytes_per_pixel == 2)
        result = *(uint16_t *)location;
    else if (bytes_per_pixel == 1)
        result = *(uint8_t *)location;
    else
	assert (0);

    return result;
}

static pixman_bool_t
verify (int test_no, const pixel_combination_t *combination, int size)
{
    pixman_image_t *src, *dest;
    pixel_checker_t src_checker, dest_checker;
    color_t source_color, dest_color, reference_color;
    pixman_bool_t result = TRUE;
    int i, j;

    /* Compute reference color */
    pixel_checker_init (&src_checker, combination->src_format);
    pixel_checker_init (&dest_checker, combination->dest_format);
    pixel_checker_convert_pixel_to_color (
	&src_checker, combination->src_pixel, &source_color);
    pixel_checker_convert_pixel_to_color (
	&dest_checker, combination->dest_pixel, &dest_color);
    do_composite (combination->op,
		  &source_color, NULL, &dest_color,
		  &reference_color, FALSE);

    src = pixman_image_create_bits (
	combination->src_format, size, size, NULL, -1);
    dest = pixman_image_create_bits (
	combination->dest_format, size, size, NULL, -1);

    fill (src, combination->src_pixel);
    fill (dest, combination->dest_pixel);

    pixman_image_composite32 (
	combination->op, src, NULL, dest, 0, 0, 0, 0, 0, 0, size, size);

    for (j = 0; j < size; ++j)
    {
	for (i = 0; i < size; ++i)
	{
	    uint32_t computed = access (dest, i, j);
	    int32_t a, r, g, b;

	    if (!pixel_checker_check (&dest_checker, computed, &reference_color))
	    {
		printf ("----------- Test %d failed ----------\n", test_no);

		printf ("   operator:         %s\n", operator_name (combination->op));
		printf ("   src format:       %s\n", format_name (combination->src_format));
		printf ("   dest format:      %s\n", format_name (combination->dest_format));
                printf (" - source ARGB:      %f  %f  %f  %f   (pixel: %8x)\n",
                        source_color.a, source_color.r, source_color.g, source_color.b,
                        combination->src_pixel);
		pixel_checker_split_pixel (&src_checker, combination->src_pixel,
					   &a, &r, &g, &b);
                printf ("                     %8d  %8d  %8d  %8d\n", a, r, g, b);

                printf (" - dest ARGB:        %f  %f  %f  %f   (pixel: %8x)\n",
                        dest_color.a, dest_color.r, dest_color.g, dest_color.b,
                        combination->dest_pixel);
		pixel_checker_split_pixel (&dest_checker, combination->dest_pixel,
					   &a, &r, &g, &b);
                printf ("                     %8d  %8d  %8d  %8d\n", a, r, g, b);

                pixel_checker_split_pixel (&dest_checker, computed, &a, &r, &g, &b);
                printf (" - expected ARGB:    %f  %f  %f  %f\n",
                        reference_color.a, reference_color.r, reference_color.g, reference_color.b);

                pixel_checker_get_min (&dest_checker, &reference_color, &a, &r, &g, &b);
                printf ("   min acceptable:   %8d  %8d  %8d  %8d\n", a, r, g, b);

                pixel_checker_split_pixel (&dest_checker, computed, &a, &r, &g, &b);
                printf ("   got:              %8d  %8d  %8d  %8d   (pixel: %8x)\n", a, r, g, b, computed);

                pixel_checker_get_max (&dest_checker, &reference_color, &a, &r, &g, &b);
                printf ("   max acceptable:   %8d  %8d  %8d  %8d\n", a, r, g, b);

		result = FALSE;
		goto done;
	    }
	}
    }

done:
    pixman_image_unref (src);
    pixman_image_unref (dest);

    return result;
}

int
main (int argc, char **argv)
{
    int result = 0;
    int i, j;

    for (i = 0; i < ARRAY_LENGTH (regressions); ++i)
    {
	const pixel_combination_t *combination = &(regressions[i]);

	for (j = 1; j < 34; ++j)
	{
	    if (!verify (i, combination, j))
	    {
		result = 1;
		break;
	    }
	}
    }

    return result;
}
