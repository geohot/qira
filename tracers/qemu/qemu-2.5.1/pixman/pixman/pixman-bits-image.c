/*
 * Copyright © 2000 Keith Packard, member of The XFree86 Project, Inc.
 *             2005 Lars Knoll & Zack Rusin, Trolltech
 *             2008 Aaron Plattner, NVIDIA Corporation
 * Copyright © 2000 SuSE, Inc.
 * Copyright © 2007, 2009 Red Hat, Inc.
 * Copyright © 2008 André Tupinambá <andrelrt@gmail.com>
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of Keith Packard not be used in
 * advertising or publicity pertaining to distribution of the software without
 * specific, written prior permission.  Keith Packard makes no
 * representations about the suitability of this software for any purpose.  It
 * is provided "as is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS, IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pixman-private.h"
#include "pixman-combine32.h"
#include "pixman-inlines.h"

static uint32_t *
_pixman_image_get_scanline_generic_float (pixman_iter_t * iter,
					  const uint32_t *mask)
{
    pixman_iter_get_scanline_t fetch_32 = iter->data;
    uint32_t *buffer = iter->buffer;

    fetch_32 (iter, NULL);

    pixman_expand_to_float ((argb_t *)buffer, buffer, PIXMAN_a8r8g8b8, iter->width);

    return iter->buffer;
}

/* Fetch functions */

static force_inline uint32_t
fetch_pixel_no_alpha (bits_image_t *image,
		      int x, int y, pixman_bool_t check_bounds)
{
    if (check_bounds &&
	(x < 0 || x >= image->width || y < 0 || y >= image->height))
    {
	return 0;
    }

    return image->fetch_pixel_32 (image, x, y);
}

typedef uint32_t (* get_pixel_t) (bits_image_t *image,
				  int x, int y, pixman_bool_t check_bounds);

static force_inline uint32_t
bits_image_fetch_pixel_nearest (bits_image_t   *image,
				pixman_fixed_t  x,
				pixman_fixed_t  y,
				get_pixel_t	get_pixel)
{
    int x0 = pixman_fixed_to_int (x - pixman_fixed_e);
    int y0 = pixman_fixed_to_int (y - pixman_fixed_e);

    if (image->common.repeat != PIXMAN_REPEAT_NONE)
    {
	repeat (image->common.repeat, &x0, image->width);
	repeat (image->common.repeat, &y0, image->height);

	return get_pixel (image, x0, y0, FALSE);
    }
    else
    {
	return get_pixel (image, x0, y0, TRUE);
    }
}

static force_inline uint32_t
bits_image_fetch_pixel_bilinear (bits_image_t   *image,
				 pixman_fixed_t  x,
				 pixman_fixed_t  y,
				 get_pixel_t	 get_pixel)
{
    pixman_repeat_t repeat_mode = image->common.repeat;
    int width = image->width;
    int height = image->height;
    int x1, y1, x2, y2;
    uint32_t tl, tr, bl, br;
    int32_t distx, disty;

    x1 = x - pixman_fixed_1 / 2;
    y1 = y - pixman_fixed_1 / 2;

    distx = pixman_fixed_to_bilinear_weight (x1);
    disty = pixman_fixed_to_bilinear_weight (y1);

    x1 = pixman_fixed_to_int (x1);
    y1 = pixman_fixed_to_int (y1);
    x2 = x1 + 1;
    y2 = y1 + 1;

    if (repeat_mode != PIXMAN_REPEAT_NONE)
    {
	repeat (repeat_mode, &x1, width);
	repeat (repeat_mode, &y1, height);
	repeat (repeat_mode, &x2, width);
	repeat (repeat_mode, &y2, height);

	tl = get_pixel (image, x1, y1, FALSE);
	bl = get_pixel (image, x1, y2, FALSE);
	tr = get_pixel (image, x2, y1, FALSE);
	br = get_pixel (image, x2, y2, FALSE);
    }
    else
    {
	tl = get_pixel (image, x1, y1, TRUE);
	tr = get_pixel (image, x2, y1, TRUE);
	bl = get_pixel (image, x1, y2, TRUE);
	br = get_pixel (image, x2, y2, TRUE);
    }

    return bilinear_interpolation (tl, tr, bl, br, distx, disty);
}

static force_inline uint32_t
bits_image_fetch_pixel_convolution (bits_image_t   *image,
				    pixman_fixed_t  x,
				    pixman_fixed_t  y,
				    get_pixel_t     get_pixel)
{
    pixman_fixed_t *params = image->common.filter_params;
    int x_off = (params[0] - pixman_fixed_1) >> 1;
    int y_off = (params[1] - pixman_fixed_1) >> 1;
    int32_t cwidth = pixman_fixed_to_int (params[0]);
    int32_t cheight = pixman_fixed_to_int (params[1]);
    int32_t i, j, x1, x2, y1, y2;
    pixman_repeat_t repeat_mode = image->common.repeat;
    int width = image->width;
    int height = image->height;
    int srtot, sgtot, sbtot, satot;

    params += 2;

    x1 = pixman_fixed_to_int (x - pixman_fixed_e - x_off);
    y1 = pixman_fixed_to_int (y - pixman_fixed_e - y_off);
    x2 = x1 + cwidth;
    y2 = y1 + cheight;

    srtot = sgtot = sbtot = satot = 0;

    for (i = y1; i < y2; ++i)
    {
	for (j = x1; j < x2; ++j)
	{
	    int rx = j;
	    int ry = i;

	    pixman_fixed_t f = *params;

	    if (f)
	    {
		uint32_t pixel;

		if (repeat_mode != PIXMAN_REPEAT_NONE)
		{
		    repeat (repeat_mode, &rx, width);
		    repeat (repeat_mode, &ry, height);

		    pixel = get_pixel (image, rx, ry, FALSE);
		}
		else
		{
		    pixel = get_pixel (image, rx, ry, TRUE);
		}

		srtot += (int)RED_8 (pixel) * f;
		sgtot += (int)GREEN_8 (pixel) * f;
		sbtot += (int)BLUE_8 (pixel) * f;
		satot += (int)ALPHA_8 (pixel) * f;
	    }

	    params++;
	}
    }

    satot = (satot + 0x8000) >> 16;
    srtot = (srtot + 0x8000) >> 16;
    sgtot = (sgtot + 0x8000) >> 16;
    sbtot = (sbtot + 0x8000) >> 16;

    satot = CLIP (satot, 0, 0xff);
    srtot = CLIP (srtot, 0, 0xff);
    sgtot = CLIP (sgtot, 0, 0xff);
    sbtot = CLIP (sbtot, 0, 0xff);

    return ((satot << 24) | (srtot << 16) | (sgtot <<  8) | (sbtot));
}

static uint32_t
bits_image_fetch_pixel_separable_convolution (bits_image_t *image,
                                              pixman_fixed_t x,
                                              pixman_fixed_t y,
                                              get_pixel_t    get_pixel)
{
    pixman_fixed_t *params = image->common.filter_params;
    pixman_repeat_t repeat_mode = image->common.repeat;
    int width = image->width;
    int height = image->height;
    int cwidth = pixman_fixed_to_int (params[0]);
    int cheight = pixman_fixed_to_int (params[1]);
    int x_phase_bits = pixman_fixed_to_int (params[2]);
    int y_phase_bits = pixman_fixed_to_int (params[3]);
    int x_phase_shift = 16 - x_phase_bits;
    int y_phase_shift = 16 - y_phase_bits;
    int x_off = ((cwidth << 16) - pixman_fixed_1) >> 1;
    int y_off = ((cheight << 16) - pixman_fixed_1) >> 1;
    pixman_fixed_t *y_params;
    int srtot, sgtot, sbtot, satot;
    int32_t x1, x2, y1, y2;
    int32_t px, py;
    int i, j;

    /* Round x and y to the middle of the closest phase before continuing. This
     * ensures that the convolution matrix is aligned right, since it was
     * positioned relative to a particular phase (and not relative to whatever
     * exact fraction we happen to get here).
     */
    x = ((x >> x_phase_shift) << x_phase_shift) + ((1 << x_phase_shift) >> 1);
    y = ((y >> y_phase_shift) << y_phase_shift) + ((1 << y_phase_shift) >> 1);

    px = (x & 0xffff) >> x_phase_shift;
    py = (y & 0xffff) >> y_phase_shift;

    y_params = params + 4 + (1 << x_phase_bits) * cwidth + py * cheight;

    x1 = pixman_fixed_to_int (x - pixman_fixed_e - x_off);
    y1 = pixman_fixed_to_int (y - pixman_fixed_e - y_off);
    x2 = x1 + cwidth;
    y2 = y1 + cheight;

    srtot = sgtot = sbtot = satot = 0;

    for (i = y1; i < y2; ++i)
    {
        pixman_fixed_48_16_t fy = *y_params++;
        pixman_fixed_t *x_params = params + 4 + px * cwidth;

        if (fy)
        {
            for (j = x1; j < x2; ++j)
            {
                pixman_fixed_t fx = *x_params++;
		int rx = j;
		int ry = i;

                if (fx)
                {
                    pixman_fixed_t f;
                    uint32_t pixel;

                    if (repeat_mode != PIXMAN_REPEAT_NONE)
                    {
                        repeat (repeat_mode, &rx, width);
                        repeat (repeat_mode, &ry, height);

                        pixel = get_pixel (image, rx, ry, FALSE);
                    }
                    else
                    {
                        pixel = get_pixel (image, rx, ry, TRUE);
		    }

                    f = (fy * fx + 0x8000) >> 16;

                    srtot += (int)RED_8 (pixel) * f;
                    sgtot += (int)GREEN_8 (pixel) * f;
                    sbtot += (int)BLUE_8 (pixel) * f;
                    satot += (int)ALPHA_8 (pixel) * f;
                }
            }
	}
    }

    satot = (satot + 0x8000) >> 16;
    srtot = (srtot + 0x8000) >> 16;
    sgtot = (sgtot + 0x8000) >> 16;
    sbtot = (sbtot + 0x8000) >> 16;

    satot = CLIP (satot, 0, 0xff);
    srtot = CLIP (srtot, 0, 0xff);
    sgtot = CLIP (sgtot, 0, 0xff);
    sbtot = CLIP (sbtot, 0, 0xff);

    return ((satot << 24) | (srtot << 16) | (sgtot <<  8) | (sbtot));
}

static force_inline uint32_t
bits_image_fetch_pixel_filtered (bits_image_t *image,
				 pixman_fixed_t x,
				 pixman_fixed_t y,
				 get_pixel_t    get_pixel)
{
    switch (image->common.filter)
    {
    case PIXMAN_FILTER_NEAREST:
    case PIXMAN_FILTER_FAST:
	return bits_image_fetch_pixel_nearest (image, x, y, get_pixel);
	break;

    case PIXMAN_FILTER_BILINEAR:
    case PIXMAN_FILTER_GOOD:
    case PIXMAN_FILTER_BEST:
	return bits_image_fetch_pixel_bilinear (image, x, y, get_pixel);
	break;

    case PIXMAN_FILTER_CONVOLUTION:
	return bits_image_fetch_pixel_convolution (image, x, y, get_pixel);
	break;

    case PIXMAN_FILTER_SEPARABLE_CONVOLUTION:
        return bits_image_fetch_pixel_separable_convolution (image, x, y, get_pixel);
        break;

    default:
        break;
    }

    return 0;
}

static uint32_t *
bits_image_fetch_affine_no_alpha (pixman_iter_t *  iter,
				  const uint32_t * mask)
{
    pixman_image_t *image  = iter->image;
    int             offset = iter->x;
    int             line   = iter->y++;
    int             width  = iter->width;
    uint32_t *      buffer = iter->buffer;

    pixman_fixed_t x, y;
    pixman_fixed_t ux, uy;
    pixman_vector_t v;
    int i;

    /* reference point is the center of the pixel */
    v.vector[0] = pixman_int_to_fixed (offset) + pixman_fixed_1 / 2;
    v.vector[1] = pixman_int_to_fixed (line) + pixman_fixed_1 / 2;
    v.vector[2] = pixman_fixed_1;

    if (image->common.transform)
    {
	if (!pixman_transform_point_3d (image->common.transform, &v))
	    return iter->buffer;

	ux = image->common.transform->matrix[0][0];
	uy = image->common.transform->matrix[1][0];
    }
    else
    {
	ux = pixman_fixed_1;
	uy = 0;
    }

    x = v.vector[0];
    y = v.vector[1];

    for (i = 0; i < width; ++i)
    {
	if (!mask || mask[i])
	{
	    buffer[i] = bits_image_fetch_pixel_filtered (
		&image->bits, x, y, fetch_pixel_no_alpha);
	}

	x += ux;
	y += uy;
    }

    return buffer;
}

/* General fetcher */
static force_inline uint32_t
fetch_pixel_general (bits_image_t *image, int x, int y, pixman_bool_t check_bounds)
{
    uint32_t pixel;

    if (check_bounds &&
	(x < 0 || x >= image->width || y < 0 || y >= image->height))
    {
	return 0;
    }

    pixel = image->fetch_pixel_32 (image, x, y);

    if (image->common.alpha_map)
    {
	uint32_t pixel_a;

	x -= image->common.alpha_origin_x;
	y -= image->common.alpha_origin_y;

	if (x < 0 || x >= image->common.alpha_map->width ||
	    y < 0 || y >= image->common.alpha_map->height)
	{
	    pixel_a = 0;
	}
	else
	{
	    pixel_a = image->common.alpha_map->fetch_pixel_32 (
		image->common.alpha_map, x, y);

	    pixel_a = ALPHA_8 (pixel_a);
	}

	pixel &= 0x00ffffff;
	pixel |= (pixel_a << 24);
    }

    return pixel;
}

static uint32_t *
bits_image_fetch_general (pixman_iter_t  *iter,
			  const uint32_t *mask)
{
    pixman_image_t *image  = iter->image;
    int             offset = iter->x;
    int             line   = iter->y++;
    int             width  = iter->width;
    uint32_t *      buffer = iter->buffer;

    pixman_fixed_t x, y, w;
    pixman_fixed_t ux, uy, uw;
    pixman_vector_t v;
    int i;

    /* reference point is the center of the pixel */
    v.vector[0] = pixman_int_to_fixed (offset) + pixman_fixed_1 / 2;
    v.vector[1] = pixman_int_to_fixed (line) + pixman_fixed_1 / 2;
    v.vector[2] = pixman_fixed_1;

    if (image->common.transform)
    {
	if (!pixman_transform_point_3d (image->common.transform, &v))
	    return buffer;

	ux = image->common.transform->matrix[0][0];
	uy = image->common.transform->matrix[1][0];
	uw = image->common.transform->matrix[2][0];
    }
    else
    {
	ux = pixman_fixed_1;
	uy = 0;
	uw = 0;
    }

    x = v.vector[0];
    y = v.vector[1];
    w = v.vector[2];

    for (i = 0; i < width; ++i)
    {
	pixman_fixed_t x0, y0;

	if (!mask || mask[i])
	{
	    if (w != 0)
	    {
		x0 = ((pixman_fixed_48_16_t)x << 16) / w;
		y0 = ((pixman_fixed_48_16_t)y << 16) / w;
	    }
	    else
	    {
		x0 = 0;
		y0 = 0;
	    }

	    buffer[i] = bits_image_fetch_pixel_filtered (
		&image->bits, x0, y0, fetch_pixel_general);
	}

	x += ux;
	y += uy;
	w += uw;
    }

    return buffer;
}

static void
replicate_pixel_32 (bits_image_t *   bits,
		    int              x,
		    int              y,
		    int              width,
		    uint32_t *       buffer)
{
    uint32_t color;
    uint32_t *end;

    color = bits->fetch_pixel_32 (bits, x, y);

    end = buffer + width;
    while (buffer < end)
	*(buffer++) = color;
}

static void
replicate_pixel_float (bits_image_t *   bits,
		       int              x,
		       int              y,
		       int              width,
		       uint32_t *       b)
{
    argb_t color;
    argb_t *buffer = (argb_t *)b;
    argb_t *end;

    color = bits->fetch_pixel_float (bits, x, y);

    end = buffer + width;
    while (buffer < end)
	*(buffer++) = color;
}

static void
bits_image_fetch_untransformed_repeat_none (bits_image_t *image,
                                            pixman_bool_t wide,
                                            int           x,
                                            int           y,
                                            int           width,
                                            uint32_t *    buffer)
{
    uint32_t w;

    if (y < 0 || y >= image->height)
    {
	memset (buffer, 0, width * (wide? sizeof (argb_t) : 4));
	return;
    }

    if (x < 0)
    {
	w = MIN (width, -x);

	memset (buffer, 0, w * (wide ? sizeof (argb_t) : 4));

	width -= w;
	buffer += w * (wide? 4 : 1);
	x += w;
    }

    if (x < image->width)
    {
	w = MIN (width, image->width - x);

	if (wide)
	    image->fetch_scanline_float (image, x, y, w, buffer, NULL);
	else
	    image->fetch_scanline_32 (image, x, y, w, buffer, NULL);

	width -= w;
	buffer += w * (wide? 4 : 1);
	x += w;
    }

    memset (buffer, 0, width * (wide ? sizeof (argb_t) : 4));
}

static void
bits_image_fetch_untransformed_repeat_normal (bits_image_t *image,
                                              pixman_bool_t wide,
                                              int           x,
                                              int           y,
                                              int           width,
                                              uint32_t *    buffer)
{
    uint32_t w;

    while (y < 0)
	y += image->height;

    while (y >= image->height)
	y -= image->height;

    if (image->width == 1)
    {
	if (wide)
	    replicate_pixel_float (image, 0, y, width, buffer);
	else
	    replicate_pixel_32 (image, 0, y, width, buffer);

	return;
    }

    while (width)
    {
	while (x < 0)
	    x += image->width;
	while (x >= image->width)
	    x -= image->width;

	w = MIN (width, image->width - x);

	if (wide)
	    image->fetch_scanline_float (image, x, y, w, buffer, NULL);
	else
	    image->fetch_scanline_32 (image, x, y, w, buffer, NULL);

	buffer += w * (wide? 4 : 1);
	x += w;
	width -= w;
    }
}

static uint32_t *
bits_image_fetch_untransformed_32 (pixman_iter_t * iter,
				   const uint32_t *mask)
{
    pixman_image_t *image  = iter->image;
    int             x      = iter->x;
    int             y      = iter->y;
    int             width  = iter->width;
    uint32_t *      buffer = iter->buffer;

    if (image->common.repeat == PIXMAN_REPEAT_NONE)
    {
	bits_image_fetch_untransformed_repeat_none (
	    &image->bits, FALSE, x, y, width, buffer);
    }
    else
    {
	bits_image_fetch_untransformed_repeat_normal (
	    &image->bits, FALSE, x, y, width, buffer);
    }

    iter->y++;
    return buffer;
}

static uint32_t *
bits_image_fetch_untransformed_float (pixman_iter_t * iter,
				      const uint32_t *mask)
{
    pixman_image_t *image  = iter->image;
    int             x      = iter->x;
    int             y      = iter->y;
    int             width  = iter->width;
    uint32_t *      buffer = iter->buffer;

    if (image->common.repeat == PIXMAN_REPEAT_NONE)
    {
	bits_image_fetch_untransformed_repeat_none (
	    &image->bits, TRUE, x, y, width, buffer);
    }
    else
    {
	bits_image_fetch_untransformed_repeat_normal (
	    &image->bits, TRUE, x, y, width, buffer);
    }

    iter->y++;
    return buffer;
}

typedef struct
{
    pixman_format_code_t	format;
    uint32_t			flags;
    pixman_iter_get_scanline_t	get_scanline_32;
    pixman_iter_get_scanline_t  get_scanline_float;
} fetcher_info_t;

static const fetcher_info_t fetcher_info[] =
{
    { PIXMAN_any,
      (FAST_PATH_NO_ALPHA_MAP			|
       FAST_PATH_ID_TRANSFORM			|
       FAST_PATH_NO_CONVOLUTION_FILTER		|
       FAST_PATH_NO_PAD_REPEAT			|
       FAST_PATH_NO_REFLECT_REPEAT),
      bits_image_fetch_untransformed_32,
      bits_image_fetch_untransformed_float
    },

    /* Affine, no alpha */
    { PIXMAN_any,
      (FAST_PATH_NO_ALPHA_MAP | FAST_PATH_HAS_TRANSFORM | FAST_PATH_AFFINE_TRANSFORM),
      bits_image_fetch_affine_no_alpha,
      _pixman_image_get_scanline_generic_float
    },

    /* General */
    { PIXMAN_any,
      0,
      bits_image_fetch_general,
      _pixman_image_get_scanline_generic_float
    },

    { PIXMAN_null },
};

static void
bits_image_property_changed (pixman_image_t *image)
{
    _pixman_bits_image_setup_accessors (&image->bits);
}

void
_pixman_bits_image_src_iter_init (pixman_image_t *image, pixman_iter_t *iter)
{
    pixman_format_code_t format = image->common.extended_format_code;
    uint32_t flags = image->common.flags;
    const fetcher_info_t *info;

    for (info = fetcher_info; info->format != PIXMAN_null; ++info)
    {
	if ((info->format == format || info->format == PIXMAN_any)	&&
	    (info->flags & flags) == info->flags)
	{
	    if (iter->iter_flags & ITER_NARROW)
	    {
		iter->get_scanline = info->get_scanline_32;
	    }
	    else
	    {
		iter->data = info->get_scanline_32;
		iter->get_scanline = info->get_scanline_float;
	    }
	    return;
	}
    }

    /* Just in case we somehow didn't find a scanline function */
    iter->get_scanline = _pixman_iter_get_scanline_noop;
}

static uint32_t *
dest_get_scanline_narrow (pixman_iter_t *iter, const uint32_t *mask)
{
    pixman_image_t *image  = iter->image;
    int             x      = iter->x;
    int             y      = iter->y;
    int             width  = iter->width;
    uint32_t *	    buffer = iter->buffer;

    image->bits.fetch_scanline_32 (&image->bits, x, y, width, buffer, mask);
    if (image->common.alpha_map)
    {
	uint32_t *alpha;

	if ((alpha = malloc (width * sizeof (uint32_t))))
	{
	    int i;

	    x -= image->common.alpha_origin_x;
	    y -= image->common.alpha_origin_y;

	    image->common.alpha_map->fetch_scanline_32 (
		image->common.alpha_map, x, y, width, alpha, mask);

	    for (i = 0; i < width; ++i)
	    {
		buffer[i] &= ~0xff000000;
		buffer[i] |= (alpha[i] & 0xff000000);
	    }

	    free (alpha);
	}
    }

    return iter->buffer;
}

static uint32_t *
dest_get_scanline_wide (pixman_iter_t *iter, const uint32_t *mask)
{
    bits_image_t *  image  = &iter->image->bits;
    int             x      = iter->x;
    int             y      = iter->y;
    int             width  = iter->width;
    argb_t *	    buffer = (argb_t *)iter->buffer;

    image->fetch_scanline_float (
	image, x, y, width, (uint32_t *)buffer, mask);
    if (image->common.alpha_map)
    {
	argb_t *alpha;

	if ((alpha = malloc (width * sizeof (argb_t))))
	{
	    int i;

	    x -= image->common.alpha_origin_x;
	    y -= image->common.alpha_origin_y;

	    image->common.alpha_map->fetch_scanline_float (
		image->common.alpha_map, x, y, width, (uint32_t *)alpha, mask);

	    for (i = 0; i < width; ++i)
		buffer[i].a = alpha[i].a;

	    free (alpha);
	}
    }

    return iter->buffer;
}

static void
dest_write_back_narrow (pixman_iter_t *iter)
{
    bits_image_t *  image  = &iter->image->bits;
    int             x      = iter->x;
    int             y      = iter->y;
    int             width  = iter->width;
    const uint32_t *buffer = iter->buffer;

    image->store_scanline_32 (image, x, y, width, buffer);

    if (image->common.alpha_map)
    {
	x -= image->common.alpha_origin_x;
	y -= image->common.alpha_origin_y;

	image->common.alpha_map->store_scanline_32 (
	    image->common.alpha_map, x, y, width, buffer);
    }

    iter->y++;
}

static void
dest_write_back_wide (pixman_iter_t *iter)
{
    bits_image_t *  image  = &iter->image->bits;
    int             x      = iter->x;
    int             y      = iter->y;
    int             width  = iter->width;
    const uint32_t *buffer = iter->buffer;

    image->store_scanline_float (image, x, y, width, buffer);

    if (image->common.alpha_map)
    {
	x -= image->common.alpha_origin_x;
	y -= image->common.alpha_origin_y;

	image->common.alpha_map->store_scanline_float (
	    image->common.alpha_map, x, y, width, buffer);
    }

    iter->y++;
}

void
_pixman_bits_image_dest_iter_init (pixman_image_t *image, pixman_iter_t *iter)
{
    if (iter->iter_flags & ITER_NARROW)
    {
	if ((iter->iter_flags & (ITER_IGNORE_RGB | ITER_IGNORE_ALPHA)) ==
	    (ITER_IGNORE_RGB | ITER_IGNORE_ALPHA))
	{
	    iter->get_scanline = _pixman_iter_get_scanline_noop;
	}
	else
	{
	    iter->get_scanline = dest_get_scanline_narrow;
	}
	
	iter->write_back = dest_write_back_narrow;
    }
    else
    {
	iter->get_scanline = dest_get_scanline_wide;
	iter->write_back = dest_write_back_wide;
    }
}

static uint32_t *
create_bits (pixman_format_code_t format,
             int                  width,
             int                  height,
             int *		  rowstride_bytes,
	     pixman_bool_t	  clear)
{
    int stride;
    size_t buf_size;
    int bpp;

    /* what follows is a long-winded way, avoiding any possibility of integer
     * overflows, of saying:
     * stride = ((width * bpp + 0x1f) >> 5) * sizeof (uint32_t);
     */

    bpp = PIXMAN_FORMAT_BPP (format);
    if (_pixman_multiply_overflows_int (width, bpp))
	return NULL;

    stride = width * bpp;
    if (_pixman_addition_overflows_int (stride, 0x1f))
	return NULL;

    stride += 0x1f;
    stride >>= 5;

    stride *= sizeof (uint32_t);

    if (_pixman_multiply_overflows_size (height, stride))
	return NULL;

    buf_size = (size_t)height * stride;

    if (rowstride_bytes)
	*rowstride_bytes = stride;

    if (clear)
	return calloc (buf_size, 1);
    else
	return malloc (buf_size);
}

pixman_bool_t
_pixman_bits_image_init (pixman_image_t *     image,
                         pixman_format_code_t format,
                         int                  width,
                         int                  height,
                         uint32_t *           bits,
                         int                  rowstride,
			 pixman_bool_t	      clear)
{
    uint32_t *free_me = NULL;

    if (!bits && width && height)
    {
	int rowstride_bytes;

	free_me = bits = create_bits (format, width, height, &rowstride_bytes, clear);

	if (!bits)
	    return FALSE;

	rowstride = rowstride_bytes / (int) sizeof (uint32_t);
    }

    _pixman_image_init (image);

    image->type = BITS;
    image->bits.format = format;
    image->bits.width = width;
    image->bits.height = height;
    image->bits.bits = bits;
    image->bits.free_me = free_me;
    image->bits.read_func = NULL;
    image->bits.write_func = NULL;
    image->bits.rowstride = rowstride;
    image->bits.indexed = NULL;

    image->common.property_changed = bits_image_property_changed;

    _pixman_image_reset_clip_region (image);

    return TRUE;
}

static pixman_image_t *
create_bits_image_internal (pixman_format_code_t format,
			    int                  width,
			    int                  height,
			    uint32_t *           bits,
			    int                  rowstride_bytes,
			    pixman_bool_t	 clear)
{
    pixman_image_t *image;

    /* must be a whole number of uint32_t's
     */
    return_val_if_fail (
	bits == NULL || (rowstride_bytes % sizeof (uint32_t)) == 0, NULL);

    return_val_if_fail (PIXMAN_FORMAT_BPP (format) >= PIXMAN_FORMAT_DEPTH (format), NULL);

    image = _pixman_image_allocate ();

    if (!image)
	return NULL;

    if (!_pixman_bits_image_init (image, format, width, height, bits,
				  rowstride_bytes / (int) sizeof (uint32_t),
				  clear))
    {
	free (image);
	return NULL;
    }

    return image;
}

/* If bits is NULL, a buffer will be allocated and initialized to 0 */
PIXMAN_EXPORT pixman_image_t *
pixman_image_create_bits (pixman_format_code_t format,
                          int                  width,
                          int                  height,
                          uint32_t *           bits,
                          int                  rowstride_bytes)
{
    return create_bits_image_internal (
	format, width, height, bits, rowstride_bytes, TRUE);
}


/* If bits is NULL, a buffer will be allocated and _not_ initialized */
PIXMAN_EXPORT pixman_image_t *
pixman_image_create_bits_no_clear (pixman_format_code_t format,
				   int                  width,
				   int                  height,
				   uint32_t *           bits,
				   int                  rowstride_bytes)
{
    return create_bits_image_internal (
	format, width, height, bits, rowstride_bytes, FALSE);
}
