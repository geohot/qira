// Initialize the VGA console and possibly show a boot splash image.
//
// Copyright (C) 2009-2010  coresystems GmbH
// Copyright (C) 2010  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "bregs.h" // struct bregs
#include "config.h" // CONFIG_*
#include "farptr.h" // FLATPTR_TO_SEG
#include "malloc.h" // free
#include "output.h" // dprintf
#include "romfile.h" // romfile_loadfile
#include "stacks.h" // call16_int
#include "std/vbe.h" // struct vbe_info
#include "string.h" // memset
#include "util.h" // enable_bootsplash


/****************************************************************
 * Helper functions
 ****************************************************************/

// Call int10 vga handler.
static void
call16_int10(struct bregs *br)
{
    br->flags = F_IF;
    start_preempt();
    call16_int(0x10, br);
    finish_preempt();
}


/****************************************************************
 * VGA text / graphics console
 ****************************************************************/

void
enable_vga_console(void)
{
    dprintf(1, "Turning on vga text mode console\n");
    struct bregs br;

    /* Enable VGA text mode */
    memset(&br, 0, sizeof(br));
    br.ax = 0x0003;
    call16_int10(&br);

    // Write to screen.
    printf("SeaBIOS (version %s)\n", VERSION);
    display_uuid();
}

static int
find_videomode(struct vbe_info *vesa_info, struct vbe_mode_info *mode_info
               , int width, int height, int bpp_req)
{
    dprintf(3, "Finding vesa mode with dimensions %d/%d\n", width, height);
    u16 *videomodes = SEGOFF_TO_FLATPTR(vesa_info->video_mode);
    for (;; videomodes++) {
        u16 videomode = *videomodes;
        if (videomode == 0xffff) {
            dprintf(1, "Unable to find vesa video mode dimensions %d/%d\n"
                    , width, height);
            return -1;
        }
        struct bregs br;
        memset(&br, 0, sizeof(br));
        br.ax = 0x4f01;
        br.cx = videomode;
        br.di = FLATPTR_TO_OFFSET(mode_info);
        br.es = FLATPTR_TO_SEG(mode_info);
        call16_int10(&br);
        if (br.ax != 0x4f) {
            dprintf(1, "get_mode failed.\n");
            continue;
        }
        if (mode_info->xres != width
            || mode_info->yres != height)
            continue;
        u8 depth = mode_info->bits_per_pixel;
        if (bpp_req == 0) {
            if (depth != 16 && depth != 24 && depth != 32)
                continue;
        } else {
            if (depth != bpp_req)
                continue;
        }
        return videomode;
    }
}

static int BootsplashActive;

void
enable_bootsplash(void)
{
    if (!CONFIG_BOOTSPLASH)
        return;
    /* splash picture can be bmp or jpeg file */
    dprintf(3, "Checking for bootsplash\n");
    u8 type = 0; /* 0 means jpg, 1 means bmp, default is 0=jpg */
    int filesize;
    u8 *filedata = romfile_loadfile("bootsplash.jpg", &filesize);
    if (!filedata) {
        filedata = romfile_loadfile("bootsplash.bmp", &filesize);
        if (!filedata)
            return;
        type = 1;
    }
    dprintf(3, "start showing bootsplash\n");

    u8 *picture = NULL; /* data buff used to be flushed to the video buf */
    struct jpeg_decdata *jpeg = NULL;
    struct bmp_decdata *bmp = NULL;
    struct vbe_info *vesa_info = malloc_tmplow(sizeof(*vesa_info));
    struct vbe_mode_info *mode_info = malloc_tmplow(sizeof(*mode_info));
    if (!vesa_info || !mode_info) {
        warn_noalloc();
        goto done;
    }

    /* Check whether we have a VESA 2.0 compliant BIOS */
    memset(vesa_info, 0, sizeof(struct vbe_info));
    vesa_info->signature = VBE2_SIGNATURE;
    struct bregs br;
    memset(&br, 0, sizeof(br));
    br.ax = 0x4f00;
    br.di = FLATPTR_TO_OFFSET(vesa_info);
    br.es = FLATPTR_TO_SEG(vesa_info);
    call16_int10(&br);
    if (vesa_info->signature != VESA_SIGNATURE) {
        dprintf(1,"No VBE2 found.\n");
        goto done;
    }

    /* Print some debugging information about our card. */
    char *vendor = SEGOFF_TO_FLATPTR(vesa_info->oem_vendor_string);
    char *product = SEGOFF_TO_FLATPTR(vesa_info->oem_product_string);
    dprintf(3, "VESA %d.%d\nVENDOR: %s\nPRODUCT: %s\n",
            vesa_info->version>>8, vesa_info->version&0xff,
            vendor, product);

    int ret, width, height;
    int bpp_require = 0;
    if (type == 0) {
        jpeg = jpeg_alloc();
        if (!jpeg) {
            warn_noalloc();
            goto done;
        }
        /* Parse jpeg and get image size. */
        dprintf(5, "Decoding bootsplash.jpg\n");
        ret = jpeg_decode(jpeg, filedata);
        if (ret) {
            dprintf(1, "jpeg_decode failed with return code %d...\n", ret);
            goto done;
        }
        jpeg_get_size(jpeg, &width, &height);
    } else {
        bmp = bmp_alloc();
        if (!bmp) {
            warn_noalloc();
            goto done;
        }
        /* Parse bmp and get image size. */
        dprintf(5, "Decoding bootsplash.bmp\n");
        ret = bmp_decode(bmp, filedata, filesize);
        if (ret) {
            dprintf(1, "bmp_decode failed with return code %d...\n", ret);
            goto done;
        }
        bmp_get_size(bmp, &width, &height);
        bpp_require = 24;
    }
    /* jpeg would use 16 or 24 bpp video mode, BMP use 24bpp mode only */

    // Try to find a graphics mode with the corresponding dimensions.
    int videomode = find_videomode(vesa_info, mode_info, width, height,
                                       bpp_require);
    if (videomode < 0) {
        dprintf(1, "failed to find a videomode with %dx%d %dbpp (0=any).\n",
                    width, height, bpp_require);
        goto done;
    }
    void *framebuffer = (void *)mode_info->phys_base;
    int depth = mode_info->bits_per_pixel;
    dprintf(3, "mode: %04x\n", videomode);
    dprintf(3, "framebuffer: %p\n", framebuffer);
    dprintf(3, "bytes per scanline: %d\n", mode_info->bytes_per_scanline);
    dprintf(3, "bits per pixel: %d\n", depth);

    // Allocate space for image and decompress it.
    int imagesize = height * mode_info->bytes_per_scanline;
    picture = malloc_tmphigh(imagesize);
    if (!picture) {
        warn_noalloc();
        goto done;
    }

    if (type == 0) {
        dprintf(5, "Decompressing bootsplash.jpg\n");
        ret = jpeg_show(jpeg, picture, width, height, depth,
                            mode_info->bytes_per_scanline);
        if (ret) {
            dprintf(1, "jpeg_show failed with return code %d...\n", ret);
            goto done;
        }
    } else {
        dprintf(5, "Decompressing bootsplash.bmp\n");
        ret = bmp_show(bmp, picture, width, height, depth,
                           mode_info->bytes_per_scanline);
        if (ret) {
            dprintf(1, "bmp_show failed with return code %d...\n", ret);
            goto done;
        }
    }

    /* Switch to graphics mode */
    dprintf(5, "Switching to graphics mode\n");
    memset(&br, 0, sizeof(br));
    br.ax = 0x4f02;
    br.bx = videomode | VBE_MODE_LINEAR_FRAME_BUFFER;
    call16_int10(&br);
    if (br.ax != 0x4f) {
        dprintf(1, "set_mode failed.\n");
        goto done;
    }

    /* Show the picture */
    dprintf(5, "Showing bootsplash picture\n");
    iomemcpy(framebuffer, picture, imagesize);
    dprintf(5, "Bootsplash copy complete\n");
    BootsplashActive = 1;

done:
    free(filedata);
    free(picture);
    free(vesa_info);
    free(mode_info);
    free(jpeg);
    free(bmp);
    return;
}

void
disable_bootsplash(void)
{
    if (!CONFIG_BOOTSPLASH || !BootsplashActive)
        return;
    BootsplashActive = 0;
    enable_vga_console();
}
