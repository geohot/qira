/*
* Basic BMP data process and Raw picture data handle functions.
* Could be used to adjust pixel data format, get infomation, etc.
*
* Copyright (C) 2011 Wayne Xia <xiawenc@cn.ibm.com>
*
* This work is licensed under the terms of the GNU LGPLv3.
*/
#include "malloc.h" // malloc_tmphigh
#include "string.h" // memcpy
#include "util.h" // struct bmp_decdata

struct bmp_decdata {
    struct tagRGBQUAD *quadp;
    unsigned char *datap;
    int width;
    int height;
    int bpp;
};

#define bmp_load4byte(addr) (*(u32 *)(addr))
#define bmp_load2byte(addr) (*(u16 *)(addr))

typedef struct tagBITMAPFILEHEADER {
    u8 bfType[2];
    u8 bfSize[4];
    u8 bfReserved1[2];
    u8 bfReserved2[2];
    u8 bfOffBits[4];
} BITMAPFILEHEADER, tagBITMAPFILEHEADER;

typedef struct tagBITMAPINFOHEADER {
    u8 biSize[4];
    u8 biWidth[4];
    u8 biHeight[4];
    u8 biPlanes[2];
    u8 biBitCount[2];
    u8 biCompression[4];
    u8 biSizeImage[4];
    u8 biXPelsPerMeter[4];
    u8 biYPelsPerMeter[4];
    u8 biClrUsed[4];
    u8 biClrImportant[4];
} BITMAPINFOHEADER, tagBITMAPINFOHEADER;

typedef struct tagRGBQUAD {
    u8 rgbBlue;
    u8 rgbGreen;
    u8 rgbRed;
    u8 rgbReserved;
} RGBQUAD, tagRGBQUAD;

/* flat picture data adjusting function
* description:
*   switch the vertical line sequence
*   arrange horizontal pixel data, add extra space in the dest buffer
*       for every line
*/
static void raw_data_format_adjust_24bpp(u8 *src, u8 *dest, int width,
                                        int height, int bytes_per_line_dest)
{
    int bytes_per_line_src = 3 * width;
    int i;
    for (i = 0 ; i < height ; i++) {
        memcpy(dest + i * bytes_per_line_dest,
           src + (height - 1 - i) * bytes_per_line_src, bytes_per_line_src);
    }
}

/* allocate decdata struct */
struct bmp_decdata *bmp_alloc(void)
{
    struct bmp_decdata *bmp = malloc_tmphigh(sizeof(*bmp));
    return bmp;
}

/* extract information from bmp file data */
int bmp_decode(struct bmp_decdata *bmp, unsigned char *data, int data_size)
{
    if (data_size < 54)
        return 1;

    u16 bmp_filehead = bmp_load2byte(data + 0);
    if (bmp_filehead != 0x4d42)
        return 2;
    u32 bmp_recordsize = bmp_load4byte(data + 2);
    if (bmp_recordsize != data_size)
        return 3;
    u32 bmp_dataoffset = bmp_load4byte(data + 10);
    bmp->datap = (unsigned char *)data + bmp_dataoffset;
    bmp->width = bmp_load4byte(data + 18);
    bmp->height = bmp_load4byte(data + 22);
    bmp->bpp = bmp_load2byte(data + 28);
    return 0;
}

/* get bmp properties */
void bmp_get_size(struct bmp_decdata *bmp, int *width, int *height)
{
    *width = bmp->width;
    *height = bmp->height;
}

/* flush flat picture data to *pc */
int bmp_show(struct bmp_decdata *bmp, unsigned char *pic, int width
             , int height, int depth, int bytes_per_line_dest)
{
    if (bmp->datap == pic)
        return 0;
    /* now only support 24bpp bmp file */
    if ((depth == 24) && (bmp->bpp == 24)) {
        raw_data_format_adjust_24bpp(bmp->datap, pic, width, height,
                                        bytes_per_line_dest);
        return 0;
    }
    return 1;
}
