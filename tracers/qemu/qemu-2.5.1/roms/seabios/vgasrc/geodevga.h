// Geode GX2/LX VGA functions
//
// Copyright (C) 2009 Chris Kindt
//
// Writen for Google Summer of Code 2009 for the coreboot project
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#ifndef  GEODEVGA_H
#define  GEODEVGA_H

#define VRC_INDEX                       0xAC1C  // Index register
#define VRC_DATA                        0xAC1E  // Data register
#define VR_UNLOCK                       0xFC53  // Virtual register unlock code

// Graphics-specific registers:
#define OEM_BAR0                        0x50
#define OEM_BAR1                        0x54
#define OEM_BAR2                        0x58
#define OEM_BAR3                        0x5C

#define DC_LOCK_LOCK                    0x00000000
#define DC_LOCK_UNLOCK                  0x00004758

/* LX MSRs */
#define MSR_GLIU0                       (1 << 28)
#define MSR_GLIU0_BASE4                 (MSR_GLIU0 + 0x23)  /* LX */
#define GLIU0_P2D_BM_4                  (MSR_GLIU0 + 0x24)  /* GX2 */
#define GLIU0_P2D_RO                    (MSR_GLIU0 + 0x29)
#define GLIU0_IOD_BM_0                  (MSR_GLIU0 + 0xE0)
#define GLIU0_IOD_BM_1                  (MSR_GLIU0 + 0xE1)
#define DC_SPARE                        0x80000011
#define VP_MSR_CONFIG_GX2               0xc0002001  /* GX2 */
#define VP_MSR_CONFIG_LX                0x48002001  /* LX */
#define VP_MSR_PADSEL                   0x48002011

#define VP_MSR_PADSEL_TFT_SEL_LOW       0xDFFFFFFF
#define VP_MSR_PADSEL_TFT_SEL_HIGH      0x0000003F

/* VP_MSR_CONFIG bits */
#define VP_MSR_CONFIG_FMT_CRT           (0)
#define VP_MSR_CONFIG_FMT_FP            (1 << 3)
#define VP_MSR_CONFIG_FPC               (1 << 15)
#define VP_MSR_CONFIG_FMT               ((1 << 3) | (1 << 4) | (1 << 5))


/* DC REG OFFSET */
#define DC_UNLOCK                       0x0
#define DC_GENERAL_CFG                  0x4
#define DC_DISPLAY_CFG                  0x8
#define DC_FB_ST_OFFSET                 0x10
#define DC_CB_ST_OFFSET                 0x14
#define DC_CURS_ST_OFFSET               0x18
#define DC_GLIU0_MEM_OFFSET             0x84

/* VP REG OFFSET */
#define VP_VCFG                         0x0
#define VP_DCFG                         0x8
#define VP_MISC                         0x50

/* FP REG OFFSET */
#define FP_PT1                          0x00
#define FP_PT2                          0x08
#define FP_PM                           0x10


/* DC bits */
#define DC_GENERAL_CFG_VGAE             (1 << 7)
#define DC_DISPLAY_CFG_GDEN             (1 << 3)
#define DC_DISPLAY_CFG_TRUP             (1 << 6)

/* VP bits */
#define VP_DCFG_CRT_EN                  (1 << 0)
#define VP_DCFG_HSYNC_EN                (1 << 1)
#define VP_DCFG_VSYNC_EN                (1 << 2)
#define VP_DCFG_DAC_BL_EN               (1 << 3)
#define VP_DCFG_CRT_SKEW                (1 << 16)
#define VP_DCFG_BYP_BOTH                (1 << 0)

/* FP bits */
#define FP_PM_P                         (1 << 24)       /* panel power ctl */
#define FP_PT2_SCRC                     (1 << 27)       /* panel shift clock retrace activity ctl  */

/* Mask */
#define DC_CFG_MSK                      0xf000a6

int geodevga_setup();

#endif
