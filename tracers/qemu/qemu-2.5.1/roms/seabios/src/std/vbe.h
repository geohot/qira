#ifndef __VBE_H
#define __VBE_H

#include "types.h" // u8

#define VESA_SIGNATURE 0x41534556 // VESA
#define VBE2_SIGNATURE 0x32454256 // VBE2

struct vbe_info {
    u32 signature;
    u16 version;
    struct segoff_s oem_string;
    u32 capabilities;
    struct segoff_s video_mode;
    u16 total_memory;
    u16 oem_revision;
    struct segoff_s oem_vendor_string;
    struct segoff_s oem_product_string;
    struct segoff_s oem_revision_string;
    u8 reserved[222];
} PACKED;

struct vbe_mode_info {
    /* VBE */
    u16 mode_attributes;
    u8 winA_attributes;
    u8 winB_attributes;
    u16 win_granularity;
    u16 win_size;
    u16 winA_seg;
    u16 winB_seg;
    struct segoff_s win_func_ptr;
    u16 bytes_per_scanline;
    /* VBE 1.2 */
    u16 xres;
    u16 yres;
    u8 xcharsize;
    u8 ycharsize;
    u8 planes;
    u8 bits_per_pixel;
    u8 banks;
    u8 mem_model;
    u8 bank_size;
    u8 pages;
    u8 reserved0;
    /* Direct Color */
    u8 red_size;
    u8 red_pos;
    u8 green_size;
    u8 green_pos;
    u8 blue_size;
    u8 blue_pos;
    u8 alpha_size;
    u8 alpha_pos;
    u8 directcolor_info;
    /* VBE 2.0 */
    u32 phys_base;
    u32 reserved1;
    u16 reserved2;
    /* VBE 3.0 */
    u16 linear_bytes_per_scanline;
    u8 bank_pages;
    u8 linear_pages;
    u8 linear_red_size;
    u8 linear_red_pos;
    u8 linear_green_size;
    u8 linear_green_pos;
    u8 linear_blue_size;
    u8 linear_blue_pos;
    u8 linear_alpha_size;
    u8 linear_alpha_pos;
    u32 pixclock_max;
    u8 reserved[190];
} PACKED;

struct vbe_crtc_info {
    u16 horiz_total;
    u16 horiz_sync_start;
    u16 horiz_sync_end;
    u16 vert_total;
    u16 vert_sync_start;
    u16 vert_sync_end;
    u8 flags;
    u32 pixclock;
    u16 refresh_rate;
    u8 reserved[40];
} PACKED;

/* VBE Return Status Info */
/* AL */
#define VBE_RETURN_STATUS_SUPPORTED                      0x4F
#define VBE_RETURN_STATUS_UNSUPPORTED                    0x00
/* AH */
#define VBE_RETURN_STATUS_SUCCESSFULL                    0x00
#define VBE_RETURN_STATUS_FAILED                         0x01
#define VBE_RETURN_STATUS_NOT_SUPPORTED                  0x02
#define VBE_RETURN_STATUS_INVALID                        0x03

/* VBE Mode Numbers */

#define VBE_MODE_VESA_DEFINED                            0x0100
#define VBE_MODE_REFRESH_RATE_USE_CRTC                   0x0800
#define VBE_MODE_LINEAR_FRAME_BUFFER                     0x4000
#define VBE_MODE_PRESERVE_DISPLAY_MEMORY                 0x8000

#define VBE_VESA_MODE_END_OF_LIST                        0xFFFF

/* Capabilities */

#define VBE_CAPABILITY_8BIT_DAC                          0x0001
#define VBE_CAPABILITY_NOT_VGA_COMPATIBLE                0x0002
#define VBE_CAPABILITY_RAMDAC_USE_BLANK_BIT              0x0004
#define VBE_CAPABILITY_STEREOSCOPIC_SUPPORT              0x0008
#define VBE_CAPABILITY_STEREO_VIA_VESA_EVC               0x0010

/* Mode Attributes */

#define VBE_MODE_ATTRIBUTE_SUPPORTED                     0x0001
#define VBE_MODE_ATTRIBUTE_EXTENDED_INFORMATION_AVAILABLE  0x0002
#define VBE_MODE_ATTRIBUTE_TTY_BIOS_SUPPORT              0x0004
#define VBE_MODE_ATTRIBUTE_COLOR_MODE                    0x0008
#define VBE_MODE_ATTRIBUTE_GRAPHICS_MODE                 0x0010
#define VBE_MODE_ATTRIBUTE_NOT_VGA_COMPATIBLE            0x0020
#define VBE_MODE_ATTRIBUTE_NO_VGA_COMPATIBLE_WINDOW      0x0040
#define VBE_MODE_ATTRIBUTE_LINEAR_FRAME_BUFFER_MODE      0x0080
#define VBE_MODE_ATTRIBUTE_DOUBLE_SCAN_MODE              0x0100
#define VBE_MODE_ATTRIBUTE_INTERLACE_MODE                0x0200
#define VBE_MODE_ATTRIBUTE_HARDWARE_TRIPLE_BUFFER        0x0400
#define VBE_MODE_ATTRIBUTE_HARDWARE_STEREOSCOPIC_DISPLAY 0x0800
#define VBE_MODE_ATTRIBUTE_DUAL_DISPLAY_START_ADDRESS    0x1000

#define VBE_MODE_ATTTRIBUTE_LFB_ONLY                     ( VBE_MODE_ATTRIBUTE_NO_VGA_COMPATIBLE_WINDOW | VBE_MODE_ATTRIBUTE_LINEAR_FRAME_BUFFER_MODE )

/* Window attributes */

#define VBE_WINDOW_ATTRIBUTE_RELOCATABLE                 0x01
#define VBE_WINDOW_ATTRIBUTE_READABLE                    0x02
#define VBE_WINDOW_ATTRIBUTE_WRITEABLE                   0x04

/* Memory model */

#define VBE_MEMORYMODEL_TEXT_MODE                        0x00
#define VBE_MEMORYMODEL_CGA_GRAPHICS                     0x01
#define VBE_MEMORYMODEL_HERCULES_GRAPHICS                0x02
#define VBE_MEMORYMODEL_PLANAR                           0x03
#define VBE_MEMORYMODEL_PACKED_PIXEL                     0x04
#define VBE_MEMORYMODEL_NON_CHAIN_4_256                  0x05
#define VBE_MEMORYMODEL_DIRECT_COLOR                     0x06
#define VBE_MEMORYMODEL_YUV                              0x07

/* DirectColorModeInfo */

#define VBE_DIRECTCOLOR_COLOR_RAMP_PROGRAMMABLE          0x01
#define VBE_DIRECTCOLOR_RESERVED_BITS_AVAILABLE          0x02

#endif
