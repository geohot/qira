// Geode GX2/LX VGA functions
//
// Copyright (C) 2009 Chris Kindt
//
// Written for Google Summer of Code 2009 for the coreboot project
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "farptr.h" // SET_FARVAR
#include "geodevga.h" // geodevga_setup
#include "hw/pci.h" // pci_config_readl
#include "hw/pci_regs.h" // PCI_BASE_ADDRESS_0
#include "output.h" // dprintf
#include "stdvga.h" // stdvga_crtc_write
#include "vgabios.h" // VGAREG_*


/****************************************************************
* MSR and High Mem access through VSA Virtual Register
****************************************************************/

static u64 geode_msr_read(u32 msrAddr)
{
    union u64_u32_u val;
    asm __volatile__ (
        "movw   $0x0AC1C, %%dx          \n"
        "movl   $0xFC530007, %%eax      \n"
        "outl   %%eax, %%dx             \n"
        "addb   $2, %%dl                \n"
        "inw    %%dx, %%ax              \n"
        : "=a" (val.lo), "=d"(val.hi)
        : "c"(msrAddr)
        : "cc"
    );

    dprintf(4, "%s(0x%08x) = 0x%08x-0x%08x\n"
            , __func__, msrAddr, val.hi, val.lo);
    return val.val;
}

static void geode_msr_mask(u32 msrAddr, u64 off, u64 on)
{
    union u64_u32_u uand, uor;
    uand.val = ~off;
    uor.val = on;

    dprintf(4, "%s(0x%08x, 0x%016llx, 0x%016llx)\n"
            , __func__, msrAddr, off, on);

    asm __volatile__ (
        "push   %%eax                   \n"
        "movw   $0x0AC1C, %%dx          \n"
        "movl   $0xFC530007, %%eax      \n"
        "outl   %%eax, %%dx             \n"
        "addb   $2, %%dl                \n"
        "pop    %%eax                   \n"
        "outw   %%ax, %%dx              \n"
        :
        : "c"(msrAddr), "S" (uand.hi), "D" (uand.lo), "b" (uor.hi), "a" (uor.lo)
        : "%edx","cc"
    );
}

static u32 geode_mem_read(u32 addr)
{
    u32 val;
    asm __volatile__ (
        "movw   $0x0AC1C, %%dx          \n"
        "movl   $0xFC530001, %%eax      \n"
        "outl   %%eax, %%dx             \n"
        "addb   $2, %%dl                \n"
        "inw    %%dx, %%ax              \n"
        : "=a" (val)
        : "b"(addr)
        : "cc"
    );

    return val;
}

static void geode_mem_mask(u32 addr, u32 off, u32 or)
{
    asm __volatile__ (
        "movw   $0x0AC1C, %%dx          \n"
        "movl   $0xFC530001, %%eax      \n"
        "outl   %%eax, %%dx             \n"
        "addb   $2, %%dl                \n"
        "outw   %%ax, %%dx              \n"
        :
        : "b"(addr), "S" (~off), "D" (or)
        : "%eax","cc"
    );
}

#define VP_FP_START     0x400

static u32 GeodeFB VAR16;
static u32 GeodeDC VAR16;
static u32 GeodeVP VAR16;

static u32 geode_dc_read(int reg)
{
    u32 val = geode_mem_read(GET_GLOBAL(GeodeDC) + reg);
    dprintf(4, "%s(0x%08x) = 0x%08x\n"
            , __func__, GET_GLOBAL(GeodeDC) + reg, val);
    return val;
}

static void geode_dc_write(int reg, u32 val)
{
    dprintf(4, "%s(0x%08x, 0x%08x)\n"
            , __func__, GET_GLOBAL(GeodeDC) + reg, val);
    geode_mem_mask(GET_GLOBAL(GeodeDC) + reg, ~0, val);
}

static void geode_dc_mask(int reg, u32 off, u32 on)
{
    dprintf(4, "%s(0x%08x, 0x%08x, 0x%08x)\n"
            , __func__, GET_GLOBAL(GeodeDC) + reg, off, on);
    geode_mem_mask(GET_GLOBAL(GeodeDC) + reg, off, on);
}

static u32 geode_vp_read(int reg)
{
    u32 val = geode_mem_read(GET_GLOBAL(GeodeVP) + reg);
    dprintf(4, "%s(0x%08x) = 0x%08x\n"
            , __func__, GET_GLOBAL(GeodeVP) + reg, val);
    return val;
}

static void geode_vp_write(int reg, u32 val)
{
    dprintf(4, "%s(0x%08x, 0x%08x)\n"
            , __func__, GET_GLOBAL(GeodeVP) + reg, val);
    geode_mem_mask(GET_GLOBAL(GeodeVP) + reg, ~0, val);
}

static void geode_vp_mask(int reg, u32 off, u32 on)
{
    dprintf(4, "%s(0x%08x, 0x%08x, 0x%08x)\n"
            , __func__, GET_GLOBAL(GeodeVP) + reg, off, on);
    geode_mem_mask(GET_GLOBAL(GeodeVP) + reg, off, on);
}

static u32 geode_fp_read(int reg)
{
    u32 val = geode_mem_read(GET_GLOBAL(GeodeVP) + VP_FP_START + reg);
    dprintf(4, "%s(0x%08x) = 0x%08x\n"
            , __func__, GET_GLOBAL(GeodeVP) + VP_FP_START + reg, val);
    return val;
}

static void geode_fp_write(int reg, u32 val)
{
    dprintf(4, "%s(0x%08x, 0x%08x)\n"
            , __func__, GET_GLOBAL(GeodeVP) + VP_FP_START + reg, val);
    geode_mem_mask(GET_GLOBAL(GeodeVP) + VP_FP_START + reg, ~0, val);
}

/****************************************************************
 * Helper functions
 ****************************************************************/

static int legacyio_check(void)
{
    int ret=0;
    u64 val;

    if (CONFIG_VGA_GEODEGX2)
        val = geode_msr_read(GLIU0_P2D_BM_4);
    else
        val = geode_msr_read(MSR_GLIU0_BASE4);
    if ((val & 0xffffffff) != 0x0A0fffe0)
        ret|=1;

    val = geode_msr_read(GLIU0_IOD_BM_0);
    if ((val & 0xffffffff) != 0x3c0ffff0)
        ret|=2;

    val = geode_msr_read(GLIU0_IOD_BM_1);
    if ((val & 0xffffffff) != 0x3d0ffff0)
        ret|=4;

    return ret;
}

static u32 framebuffer_size(void)
{
    /* We use the P2D_R0 msr to read out the number of pages.
     * One page has a size of 4k
     *
     * Bit      Name    Description
     * 39:20    PMAX    Physical Memory Address Max
     * 19:0     PMIX    Physical Memory Address Min
     *
     */
    u64 msr = geode_msr_read(GLIU0_P2D_RO);

    u32 pmax = (msr >> 20) & 0x000fffff;
    u32 pmin = msr & 0x000fffff;

    u32 val = pmax - pmin;
    val += 1;

    /* The page size is 4k */
    return (val << 12);
}

/****************************************************************
* Init Functions
****************************************************************/

static void geodevga_set_output_mode(void)
{
    u64 msr_addr;
    u64 msr;

    /* set output to crt and RGB/YUV */
    if (CONFIG_VGA_GEODEGX2)
        msr_addr = VP_MSR_CONFIG_GX2;
    else
        msr_addr = VP_MSR_CONFIG_LX;

    /* set output mode (RGB/YUV) */
    msr = geode_msr_read(msr_addr);
    msr &= ~VP_MSR_CONFIG_FMT;         // mask out FMT (bits 5:3)

    if (CONFIG_VGA_OUTPUT_PANEL || CONFIG_VGA_OUTPUT_CRT_PANEL) {
        msr |= VP_MSR_CONFIG_FMT_FP;   // flat panel

        if (CONFIG_VGA_OUTPUT_CRT_PANEL) {
            msr |= VP_MSR_CONFIG_FPC;  // simultaneous Flat Panel and CRT
            dprintf(1, "output: simultaneous Flat Panel and CRT\n");
        } else {
            msr &= ~VP_MSR_CONFIG_FPC; // no simultaneous Flat Panel and CRT
            dprintf(1, "ouput: flat panel\n");
        }
    } else {
        msr |= VP_MSR_CONFIG_FMT_CRT;  // CRT only
       dprintf(1, "output: CRT\n");
    }
    geode_msr_mask(msr_addr, ~msr, msr);
}

/* Set up the dc (display controller) portion of the geodelx
*  The dc provides hardware support for VGA graphics.
*/
static void dc_setup(void)
{
    dprintf(2, "DC_SETUP\n");

    geode_dc_write(DC_UNLOCK, DC_LOCK_UNLOCK);

    /* zero memory config */
    geode_dc_write(DC_FB_ST_OFFSET, 0x0);
    geode_dc_write(DC_CB_ST_OFFSET, 0x0);
    geode_dc_write(DC_CURS_ST_OFFSET, 0x0);

    geode_dc_mask(DC_DISPLAY_CFG, ~DC_CFG_MSK, DC_DISPLAY_CFG_GDEN|DC_DISPLAY_CFG_TRUP);
    geode_dc_write(DC_GENERAL_CFG, DC_GENERAL_CFG_VGAE);

    geode_dc_write(DC_UNLOCK, DC_LOCK_LOCK);
}

/* Setup the vp (video processor) portion of the geodelx
*  Under VGA modes the vp was handled by softvg from inside VSA2.
*  Without a softvg module, access is only available through a pci bar.
*  The High Mem Access virtual register is used to  configure the
*   pci mmio bar from 16bit friendly io space.
*/
static void vp_setup(void)
{
    dprintf(2,"VP_SETUP\n");

    geodevga_set_output_mode();

    /* Set mmio registers
    * there may be some timing issues here, the reads seem
    * to slow things down enough work reliably
    */

    u32 reg = geode_vp_read(VP_MISC);
    dprintf(1,"VP_SETUP VP_MISC=0x%08x\n",reg);
    geode_vp_write(VP_MISC, VP_DCFG_BYP_BOTH);
    reg = geode_vp_read(VP_MISC);
    dprintf(1,"VP_SETUP VP_MISC=0x%08x\n",reg);

    reg = geode_vp_read(VP_DCFG);
    dprintf(1,"VP_SETUP VP_DCFG=0x%08x\n",reg);
    geode_vp_mask(VP_DCFG, 0, VP_DCFG_CRT_EN|VP_DCFG_HSYNC_EN|VP_DCFG_VSYNC_EN|VP_DCFG_DAC_BL_EN|VP_DCFG_CRT_SKEW);
    reg = geode_vp_read(VP_DCFG);
    dprintf(1,"VP_SETUP VP_DCFG=0x%08x\n",reg);

    /* setup flat panel */
    if (CONFIG_VGA_OUTPUT_PANEL || CONFIG_VGA_OUTPUT_CRT_PANEL) {
        u64 msr;

        dprintf(1, "Setting up flat panel\n");
        /* write timing register */
        geode_fp_write(FP_PT1, 0x0);
        geode_fp_write(FP_PT2, FP_PT2_SCRC);

        /* set pad select for TFT/LVDS */
        msr  = VP_MSR_PADSEL_TFT_SEL_HIGH;
        msr  = msr << 32;
        msr |= VP_MSR_PADSEL_TFT_SEL_LOW;
        geode_msr_mask(VP_MSR_PADSEL, ~msr, msr);

        /* turn the panel on (if it isn't already) */
        reg = geode_fp_read(FP_PM);
        reg |= FP_PM_P;
        geode_fp_write(FP_PM, reg);
    }
}

static u8 geode_crtc_01[] VAR16 = {
    0x2d, 0x27, 0x28, 0x90, 0x29, 0x8e, 0xbf, 0x1f,
    0x00, 0x4f, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00,
    0x9b, 0x8d, 0x8f, 0x14, 0x1f, 0x97, 0xb9, 0xa3,
    0xff };
static u8 geode_crtc_03[] VAR16 = {
    0x5f, 0x4f, 0x50, 0x82, 0x51, 0x9e, 0xbf, 0x1f,
    0x00, 0x4f, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00,
    0x9b, 0x8d, 0x8f, 0x28, 0x1f, 0x97, 0xb9, 0xa3,
    0xff };
static u8 geode_crtc_04[] VAR16 = {
    0x2d, 0x27, 0x28, 0x90, 0x29, 0x8e, 0xbf, 0x1f,
    0x00, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9b, 0x8d, 0x8f, 0x14, 0x00, 0x97, 0xb9, 0xa2,
    0xff };
static u8 geode_crtc_05[] VAR16 = {
    0x2d, 0x27, 0x28, 0x90, 0x29, 0x8e, 0xbf, 0x1f,
    0x00, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9b, 0x8e, 0x8f, 0x14, 0x00, 0x97, 0xb9, 0xa2,
    0xff };
static u8 geode_crtc_06[] VAR16 = {
    0x5f, 0x4f, 0x50, 0x82, 0x51, 0x9e, 0xbf, 0x1f,
    0x00, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9b, 0x8d, 0x8f, 0x28, 0x00, 0x97, 0xb9, 0xc2,
    0xff };
static u8 geode_crtc_07[] VAR16 = {
    0x5f, 0x4f, 0x50, 0x82, 0x51, 0x9e, 0xbf, 0x1f,
    0x00, 0x4f, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00,
    0x9b, 0x8d, 0x8f, 0x28, 0x0f, 0x97, 0xb9, 0xa3,
    0xff };
static u8 geode_crtc_0d[] VAR16 = {
    0x2d, 0x27, 0x28, 0x90, 0x29, 0x8e, 0xbf, 0x1f,
    0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9b, 0x8d, 0x8f, 0x14, 0x00, 0x97, 0xb9, 0xe3,
    0xff };
static u8 geode_crtc_0e[] VAR16 = {
    0x5f, 0x4f, 0x50, 0x82, 0x51, 0x9e, 0xbf, 0x1f,
    0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9b, 0x8d, 0x8f, 0x28, 0x00, 0x97, 0xb9, 0xe3,
    0xff };
static u8 geode_crtc_0f[] VAR16 = {
    0x5f, 0x4f, 0x50, 0x82, 0x51, 0x9e, 0xbf, 0x1f,
    0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x83, 0x85, 0x5d, 0x28, 0x0f, 0x65, 0xb9, 0xe3,
    0xff };
static u8 geode_crtc_11[] VAR16 = {
    0x5f, 0x4f, 0x50, 0x82, 0x51, 0x9e, 0x0b, 0x3e,
    0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe9, 0x8b, 0xdf, 0x28, 0x00, 0xe7, 0x04, 0xe3,
    0xff };
static u8 geode_crtc_13[] VAR16 = {
    0x5f, 0x4f, 0x50, 0x82, 0x51, 0x9e, 0xbf, 0x1f,
    0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9b, 0x8d, 0x8f, 0x28, 0x40, 0x98, 0xb9, 0xa3,
    0xff };

int geodevga_setup(void)
{
    int ret = stdvga_setup();
    if (ret)
        return ret;

    dprintf(1,"GEODEVGA_SETUP\n");

    if ((ret=legacyio_check())) {
        dprintf(1,"GEODEVGA_SETUP legacyio_check=0x%x\n",ret);
    }

    // Updated timings from geode datasheets, table 6-53 in particular
    static u8 *new_crtc[] VAR16 = {
        geode_crtc_01, geode_crtc_01, geode_crtc_03, geode_crtc_03,
        geode_crtc_04, geode_crtc_05, geode_crtc_06, geode_crtc_07,
        0, 0, 0, 0, 0,
        geode_crtc_0d, geode_crtc_0e, geode_crtc_0f, geode_crtc_0f,
        geode_crtc_11, geode_crtc_11, geode_crtc_13 };
    int i;
    for (i=0; i<ARRAY_SIZE(new_crtc); i++) {
        u8 *crtc = GET_GLOBAL(new_crtc[i]);
        if (crtc)
            stdvga_override_crtc(i, crtc);
    }

    if (GET_GLOBAL(VgaBDF) < 0)
        // Device should be at 00:01.1
        SET_VGA(VgaBDF, pci_to_bdf(0, 1, 1));

    // setup geode struct which is used for register access
    SET_VGA(GeodeFB, pci_config_readl(GET_GLOBAL(VgaBDF), PCI_BASE_ADDRESS_0));
    SET_VGA(GeodeDC, pci_config_readl(GET_GLOBAL(VgaBDF), PCI_BASE_ADDRESS_2));
    SET_VGA(GeodeVP, pci_config_readl(GET_GLOBAL(VgaBDF), PCI_BASE_ADDRESS_3));

    dprintf(1, "fb addr: 0x%08x\n", GET_GLOBAL(GeodeFB));
    dprintf(1, "dc addr: 0x%08x\n", GET_GLOBAL(GeodeDC));
    dprintf(1, "vp addr: 0x%08x\n", GET_GLOBAL(GeodeVP));

    /* setup framebuffer */
    geode_dc_write(DC_UNLOCK, DC_LOCK_UNLOCK);

    /* read fb-bar from pci, then point dc to the fb base */
    u32 fb = GET_GLOBAL(GeodeFB);
    if (geode_dc_read(DC_GLIU0_MEM_OFFSET) != fb)
        geode_dc_write(DC_GLIU0_MEM_OFFSET, fb);

    geode_dc_write(DC_UNLOCK, DC_LOCK_LOCK);

    u32 fb_size = framebuffer_size(); // in byte
    dprintf(1, "%d KB of video memory at 0x%08x\n", fb_size / 1024, fb);

    /* update VBE variables */
    SET_VGA(VBE_framebuffer, fb);
    SET_VGA(VBE_total_memory, fb_size / 1024 / 64); // number of 64K blocks

    vp_setup();
    dc_setup();

    return 0;
}
