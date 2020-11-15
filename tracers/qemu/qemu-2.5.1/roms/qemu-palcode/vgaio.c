// VGA io port access
//
// Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2001-2008 the LGPL VGABios developers Team
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "protos.h"
#include "ioport.h"
#include "pci.h"
#include "pci_regs.h"
#include "pci_ids.h"
#include "vgatables.h"

#define GET_FARVAR(seg, ofs)		(ofs)
#define SET_FARVAR(seg, ofs, val)	((ofs) = (val))

static struct saveBDAstate BDA;

#define GET_BDA(field)			(BDA.field)
#define GET_GLOBAL(val)			(val)

// TODO
//  * replace direct in/out calls with wrapper functions


/****************************************************************
 * Attribute control
 ****************************************************************/

void
vgahw_screen_disable(void)
{
    inb(VGAREG_ACTL_RESET);
    outb(0x00, VGAREG_ACTL_ADDRESS);
}

void
vgahw_screen_enable(void)
{
    inb(VGAREG_ACTL_RESET);
    outb(0x20, VGAREG_ACTL_ADDRESS);
}

void
vgahw_set_border_color(u8 color)
{
    inb(VGAREG_ACTL_RESET);
    outb(0x00, VGAREG_ACTL_ADDRESS);
    u8 v1 = color & 0x0f;
    if (v1 & 0x08)
        v1 += 0x08;
    outb(v1, VGAREG_ACTL_WRITE_DATA);

    u8 v2 = color & 0x10;
    int i;
    for (i = 1; i < 4; i++) {
        outb(i, VGAREG_ACTL_ADDRESS);

        u8 cur = inb(VGAREG_ACTL_READ_DATA);
        cur &= 0xef;
        cur |= v2;
        outb(cur, VGAREG_ACTL_WRITE_DATA);
    }
    outb(0x20, VGAREG_ACTL_ADDRESS);
}

void
vgahw_set_overscan_border_color(u8 color)
{
    inb(VGAREG_ACTL_RESET);
    outb(0x11, VGAREG_ACTL_ADDRESS);
    outb(color, VGAREG_ACTL_WRITE_DATA);
    outb(0x20, VGAREG_ACTL_ADDRESS);
}

u8
vgahw_get_overscan_border_color(void)
{
    inb(VGAREG_ACTL_RESET);
    outb(0x11, VGAREG_ACTL_ADDRESS);
    u8 v = inb(VGAREG_ACTL_READ_DATA);
    inb(VGAREG_ACTL_RESET);
    outb(0x20, VGAREG_ACTL_ADDRESS);
    return v;
}

void
vgahw_set_palette(u8 palid)
{
    inb(VGAREG_ACTL_RESET);
    palid &= 0x01;
    int i;
    for (i = 1; i < 4; i++) {
        outb(i, VGAREG_ACTL_ADDRESS);

        u8 v = inb(VGAREG_ACTL_READ_DATA);
        v &= 0xfe;
        v |= palid;
        outb(v, VGAREG_ACTL_WRITE_DATA);
    }
    outb(0x20, VGAREG_ACTL_ADDRESS);
}

void
vgahw_set_single_palette_reg(u8 reg, u8 val)
{
    inb(VGAREG_ACTL_RESET);
    outb(reg, VGAREG_ACTL_ADDRESS);
    outb(val, VGAREG_ACTL_WRITE_DATA);
    outb(0x20, VGAREG_ACTL_ADDRESS);
}

u8
vgahw_get_single_palette_reg(u8 reg)
{
    inb(VGAREG_ACTL_RESET);
    outb(reg, VGAREG_ACTL_ADDRESS);
    u8 v = inb(VGAREG_ACTL_READ_DATA);
    inb(VGAREG_ACTL_RESET);
    outb(0x20, VGAREG_ACTL_ADDRESS);
    return v;
}

void
vgahw_set_all_palette_reg(u8 *data_far)
{
    inb(VGAREG_ACTL_RESET);
    int i;
    for (i = 0; i < 0x10; i++) {
        outb(i, VGAREG_ACTL_ADDRESS);
        u8 val = GET_FARVAR(seg, *data_far);
        outb(val, VGAREG_ACTL_WRITE_DATA);
        data_far++;
    }
    outb(0x11, VGAREG_ACTL_ADDRESS);
    outb(GET_FARVAR(seg, *data_far), VGAREG_ACTL_WRITE_DATA);
    outb(0x20, VGAREG_ACTL_ADDRESS);
}

void
vgahw_get_all_palette_reg(u8 *data_far)
{
    int i;
    for (i = 0; i < 0x10; i++) {
        inb(VGAREG_ACTL_RESET);
        outb(i, VGAREG_ACTL_ADDRESS);
        SET_FARVAR(seg, *data_far, inb(VGAREG_ACTL_READ_DATA));
        data_far++;
    }
    inb(VGAREG_ACTL_RESET);
    outb(0x11, VGAREG_ACTL_ADDRESS);
    SET_FARVAR(seg, *data_far, inb(VGAREG_ACTL_READ_DATA));
    inb(VGAREG_ACTL_RESET);
    outb(0x20, VGAREG_ACTL_ADDRESS);
}

void
vgahw_toggle_intensity(u8 flag)
{
    inb(VGAREG_ACTL_RESET);
    outb(0x10, VGAREG_ACTL_ADDRESS);
    u8 val = (inb(VGAREG_ACTL_READ_DATA) & 0xf7) | ((flag & 0x01) << 3);
    outb(val, VGAREG_ACTL_WRITE_DATA);
    outb(0x20, VGAREG_ACTL_ADDRESS);
}

void
vgahw_select_video_dac_color_page(u8 flag, u8 data)
{
    inb(VGAREG_ACTL_RESET);
    outb(0x10, VGAREG_ACTL_ADDRESS);
    u8 val = inb(VGAREG_ACTL_READ_DATA);
    if (!(flag & 0x01)) {
        // select paging mode
        val = (val & 0x7f) | (data << 7);
        outb(val, VGAREG_ACTL_WRITE_DATA);
        outb(0x20, VGAREG_ACTL_ADDRESS);
        return;
    }
    // select page
    inb(VGAREG_ACTL_RESET);
    outb(0x14, VGAREG_ACTL_ADDRESS);
    if (!(val & 0x80))
        data <<= 2;
    data &= 0x0f;
    outb(data, VGAREG_ACTL_WRITE_DATA);
    outb(0x20, VGAREG_ACTL_ADDRESS);
}

void
vgahw_read_video_dac_state(u8 *pmode, u8 *curpage)
{
    inb(VGAREG_ACTL_RESET);
    outb(0x10, VGAREG_ACTL_ADDRESS);
    u8 val1 = inb(VGAREG_ACTL_READ_DATA) >> 7;

    inb(VGAREG_ACTL_RESET);
    outb(0x14, VGAREG_ACTL_ADDRESS);
    u8 val2 = inb(VGAREG_ACTL_READ_DATA) & 0x0f;
    if (!(val1 & 0x01))
        val2 >>= 2;

    inb(VGAREG_ACTL_RESET);
    outb(0x20, VGAREG_ACTL_ADDRESS);

    *pmode = val1;
    *curpage = val2;
}


/****************************************************************
 * DAC control
 ****************************************************************/

void
vgahw_set_dac_regs(u8 *data_far, u8 start, int count)
{
    outb(start, VGAREG_DAC_WRITE_ADDRESS);
    while (count) {
        outb(GET_FARVAR(seg, *data_far), VGAREG_DAC_DATA);
        data_far++;
        outb(GET_FARVAR(seg, *data_far), VGAREG_DAC_DATA);
        data_far++;
        outb(GET_FARVAR(seg, *data_far), VGAREG_DAC_DATA);
        data_far++;
        count--;
    }
}

void
vgahw_get_dac_regs(u8 *data_far, u8 start, int count)
{
    outb(start, VGAREG_DAC_READ_ADDRESS);
    while (count) {
        SET_FARVAR(seg, *data_far, inb(VGAREG_DAC_DATA));
        data_far++;
        SET_FARVAR(seg, *data_far, inb(VGAREG_DAC_DATA));
        data_far++;
        SET_FARVAR(seg, *data_far, inb(VGAREG_DAC_DATA));
        data_far++;
        count--;
    }
}

void
vgahw_set_pel_mask(u8 val)
{
    outb(val, VGAREG_PEL_MASK);
}

u8
vgahw_get_pel_mask(void)
{
    return inb(VGAREG_PEL_MASK);
}

void
vgahw_save_dac_state(struct saveDACcolors *info)
{
    /* XXX: check this */
    SET_FARVAR(seg, info->rwmode, inb(VGAREG_DAC_STATE));
    SET_FARVAR(seg, info->peladdr, inb(VGAREG_DAC_WRITE_ADDRESS));
    SET_FARVAR(seg, info->pelmask, inb(VGAREG_PEL_MASK));
    vgahw_get_dac_regs(info->dac, 0, 256);
    SET_FARVAR(seg, info->color_select, 0);
}

void
vgahw_restore_dac_state(struct saveDACcolors *info)
{
    outb(GET_FARVAR(seg, info->pelmask), VGAREG_PEL_MASK);
    vgahw_set_dac_regs(info->dac, 0, 256);
    outb(GET_FARVAR(seg, info->peladdr), VGAREG_DAC_WRITE_ADDRESS);
}


/****************************************************************
 * Memory control
 ****************************************************************/

void
vgahw_sequ_write(u8 index, u8 value)
{
    outw((value<<8) | index, VGAREG_SEQU_ADDRESS);
}

void
vgahw_grdc_write(u8 index, u8 value)
{
    outw((value<<8) | index, VGAREG_GRDC_ADDRESS);
}

void
vgahw_set_text_block_specifier(u8 spec)
{
    outw((spec << 8) | 0x03, VGAREG_SEQU_ADDRESS);
}

void
get_font_access(void)
{
    outw(0x0100, VGAREG_SEQU_ADDRESS);
    outw(0x0402, VGAREG_SEQU_ADDRESS);
    outw(0x0704, VGAREG_SEQU_ADDRESS);
    outw(0x0300, VGAREG_SEQU_ADDRESS);
    outw(0x0204, VGAREG_GRDC_ADDRESS);
    outw(0x0005, VGAREG_GRDC_ADDRESS);
    outw(0x0406, VGAREG_GRDC_ADDRESS);
}

void
release_font_access(void)
{
    outw(0x0100, VGAREG_SEQU_ADDRESS);
    outw(0x0302, VGAREG_SEQU_ADDRESS);
    outw(0x0304, VGAREG_SEQU_ADDRESS);
    outw(0x0300, VGAREG_SEQU_ADDRESS);
    u16 v = (inw(VGAREG_READ_MISC_OUTPUT) & 0x01) ? 0x0e : 0x0a;
    outw((v << 8) | 0x06, VGAREG_GRDC_ADDRESS);
    outw(0x0004, VGAREG_GRDC_ADDRESS);
    outw(0x1005, VGAREG_GRDC_ADDRESS);
}


/****************************************************************
 * CRTC registers
 ****************************************************************/

static u16
get_crtc(void)
{
    return GET_BDA(crtc_address);
}

void
vgahw_set_cursor_shape(u8 start, u8 end)
{
    u16 crtc_addr = get_crtc();
    outb(0x0a, crtc_addr);
    outb(start, crtc_addr + 1);
    outb(0x0b, crtc_addr);
    outb(end, crtc_addr + 1);
}

void
vgahw_set_active_page(u16 address)
{
    u16 crtc_addr = get_crtc();
    outb(0x0c, crtc_addr);
    outb((address & 0xff00) >> 8, crtc_addr + 1);
    outb(0x0d, crtc_addr);
    outb(address & 0x00ff, crtc_addr + 1);
}

void
vgahw_set_cursor_pos(u16 address)
{
    u16 crtc_addr = get_crtc();
    outb(0x0e, crtc_addr);
    outb((address & 0xff00) >> 8, crtc_addr + 1);
    outb(0x0f, crtc_addr);
    outb(address & 0x00ff, crtc_addr + 1);
}

void
vgahw_set_scan_lines(u8 lines)
{
    u16 crtc_addr = get_crtc();
    outb(0x09, crtc_addr);
    u8 crtc_r9 = inb(crtc_addr + 1);
    crtc_r9 = (crtc_r9 & 0xe0) | (lines - 1);
    outb(crtc_r9, crtc_addr + 1);
}

// Get vertical display end
u16
vgahw_get_vde(void)
{
    u16 crtc_addr = get_crtc();
    outb(0x12, crtc_addr);
    u16 vde = inb(crtc_addr + 1);
    outb(0x07, crtc_addr);
    u8 ovl = inb(crtc_addr + 1);
    vde += (((ovl & 0x02) << 7) + ((ovl & 0x40) << 3) + 1);
    return vde;
}


/****************************************************************
 * Save/Restore/Set state
 ****************************************************************/

void
vgahw_save_state(struct saveVideoHardware *info)
{
    u16 crtc_addr = get_crtc();
    SET_FARVAR(seg, info->sequ_index, inb(VGAREG_SEQU_ADDRESS));
    SET_FARVAR(seg, info->crtc_index, inb(crtc_addr));
    SET_FARVAR(seg, info->grdc_index, inb(VGAREG_GRDC_ADDRESS));
    inb(VGAREG_ACTL_RESET);
    u16 ar_index = inb(VGAREG_ACTL_ADDRESS);
    SET_FARVAR(seg, info->actl_index, ar_index);
    SET_FARVAR(seg, info->feature, inb(VGAREG_READ_FEATURE_CTL));

    u16 i;
    for (i=0; i<4; i++) {
        outb(i+1, VGAREG_SEQU_ADDRESS);
        SET_FARVAR(seg, info->sequ_regs[i], inb(VGAREG_SEQU_DATA));
    }
    outb(0, VGAREG_SEQU_ADDRESS);
    SET_FARVAR(seg, info->sequ0, inb(VGAREG_SEQU_DATA));

    for (i=0; i<25; i++) {
        outb(i, crtc_addr);
        SET_FARVAR(seg, info->crtc_regs[i], inb(crtc_addr + 1));
    }

    for (i=0; i<20; i++) {
        inb(VGAREG_ACTL_RESET);
        outb(i | (ar_index & 0x20), VGAREG_ACTL_ADDRESS);
        SET_FARVAR(seg, info->actl_regs[i], inb(VGAREG_ACTL_READ_DATA));
    }
    inb(VGAREG_ACTL_RESET);

    for (i=0; i<9; i++) {
        outb(i, VGAREG_GRDC_ADDRESS);
        SET_FARVAR(seg, info->grdc_regs[i], inb(VGAREG_GRDC_DATA));
    }

    SET_FARVAR(seg, info->crtc_addr, crtc_addr);

    /* XXX: read plane latches */
    for (i=0; i<4; i++)
        SET_FARVAR(seg, info->plane_latch[i], 0);
}

void
vgahw_restore_state(struct saveVideoHardware *info)
{
    // Reset Attribute Ctl flip-flop
    inb(VGAREG_ACTL_RESET);

    u16 crtc_addr = GET_FARVAR(seg, info->crtc_addr);

    u16 i;
    for (i=0; i<4; i++) {
        outb(i+1, VGAREG_SEQU_ADDRESS);
        outb(GET_FARVAR(seg, info->sequ_regs[i]), VGAREG_SEQU_DATA);
    }
    outb(0, VGAREG_SEQU_ADDRESS);
    outb(GET_FARVAR(seg, info->sequ0), VGAREG_SEQU_DATA);

    // Disable CRTC write protection
    outw(0x0011, crtc_addr);
    // Set CRTC regs
    for (i=0; i<25; i++)
        if (i != 0x11) {
            outb(i, crtc_addr);
            outb(GET_FARVAR(seg, info->crtc_regs[i]), crtc_addr + 1);
        }
    // select crtc base address
    u16 v = inb(VGAREG_READ_MISC_OUTPUT) & ~0x01;
    if (crtc_addr == VGAREG_VGA_CRTC_ADDRESS)
        v |= 0x01;
    outb(v, VGAREG_WRITE_MISC_OUTPUT);

    // enable write protection if needed
    outb(0x11, crtc_addr);
    outb(GET_FARVAR(seg, info->crtc_regs[0x11]), crtc_addr + 1);

    // Set Attribute Ctl
    u16 ar_index = GET_FARVAR(seg, info->actl_index);
    inb(VGAREG_ACTL_RESET);
    for (i=0; i<20; i++) {
        outb(i | (ar_index & 0x20), VGAREG_ACTL_ADDRESS);
        outb(GET_FARVAR(seg, info->actl_regs[i]), VGAREG_ACTL_WRITE_DATA);
    }
    outb(ar_index, VGAREG_ACTL_ADDRESS);
    inb(VGAREG_ACTL_RESET);

    for (i=0; i<9; i++) {
        outb(i, VGAREG_GRDC_ADDRESS);
        outb(GET_FARVAR(seg, info->grdc_regs[i]), VGAREG_GRDC_DATA);
    }

    outb(GET_FARVAR(seg, info->sequ_index), VGAREG_SEQU_ADDRESS);
    outb(GET_FARVAR(seg, info->crtc_index), crtc_addr);
    outb(GET_FARVAR(seg, info->grdc_index), VGAREG_GRDC_ADDRESS);
    outb(GET_FARVAR(seg, info->feature), crtc_addr - 0x4 + 0xa);
}

void
vgahw_set_mode(struct VideoParam_s *vparam_g)
{
    // Reset Attribute Ctl flip-flop
    inb(VGAREG_ACTL_RESET);

    // Set Attribute Ctl
    u16 i;
    for (i = 0; i <= 0x13; i++) {
        outb(i, VGAREG_ACTL_ADDRESS);
        outb(GET_GLOBAL(vparam_g->actl_regs[i]), VGAREG_ACTL_WRITE_DATA);
    }
    outb(0x14, VGAREG_ACTL_ADDRESS);
    outb(0x00, VGAREG_ACTL_WRITE_DATA);

    // Set Sequencer Ctl
    outb(0, VGAREG_SEQU_ADDRESS);
    outb(0x03, VGAREG_SEQU_DATA);
    for (i = 1; i <= 4; i++) {
        outb(i, VGAREG_SEQU_ADDRESS);
        outb(GET_GLOBAL(vparam_g->sequ_regs[i - 1]), VGAREG_SEQU_DATA);
    }

    // Set Grafx Ctl
    for (i = 0; i <= 8; i++) {
        outb(i, VGAREG_GRDC_ADDRESS);
        outb(GET_GLOBAL(vparam_g->grdc_regs[i]), VGAREG_GRDC_DATA);
    }

    // Set CRTC address VGA or MDA
    u8 miscreg = GET_GLOBAL(vparam_g->miscreg);
    u16 crtc_addr = VGAREG_VGA_CRTC_ADDRESS;
    if (!(miscreg & 1))
        crtc_addr = VGAREG_MDA_CRTC_ADDRESS;

    // Disable CRTC write protection
    outw(0x0011, crtc_addr);
    // Set CRTC regs
    for (i = 0; i <= 0x18; i++) {
        outb(i, crtc_addr);
        outb(GET_GLOBAL(vparam_g->crtc_regs[i]), crtc_addr + 1);
    }

    // Set the misc register
    outb(miscreg, VGAREG_WRITE_MISC_OUTPUT);

    // Enable video
    outb(0x20, VGAREG_ACTL_ADDRESS);
    inb(VGAREG_ACTL_RESET);
}


/****************************************************************
 * Misc
 ****************************************************************/

void
vgahw_enable_video_addressing(u8 disable)
{
    u8 v = (disable & 1) ? 0x00 : 0x02;
    u8 v2 = inb(VGAREG_READ_MISC_OUTPUT) & ~0x02;
    outb(v | v2, VGAREG_WRITE_MISC_OUTPUT);
}

void
vgahw_init(void)
{
  struct vgamode_s *vmode_g;
  int bdf, max;

  foreachpci(bdf, max)
    {
      uint16_t class = pci_config_readw(bdf, PCI_CLASS_DEVICE);
      if (class == PCI_CLASS_DISPLAY_VGA)
        goto found;
    }
  return;

 found:
  have_vga = 1;

  vmode_g = find_vga_entry(3);

  vgahw_sequ_write(0, 1);	// Assert sync reset
  
  // Switch to color mode and enable CPU access 480 lines
  outb(0xc3, VGAREG_WRITE_MISC_OUTPUT);

  vgahw_sequ_write(0, 3);	// De-assert sync reset

  vgahw_set_mode(vmode_g->vparam);

  vgahw_sequ_write(4, 0x06); // disable odd/even + chain4
  vgahw_sequ_write(1, vmode_g->vparam->sequ_regs[1] | 0x20); // disable video
  vgahw_grdc_write(5, vmode_g->vparam->grdc_regs[5] & 0xef); // disable odd/even
  vgahw_grdc_write(6, 0x05); // set mem map to 0xa0000 and graphics mode
  vgahw_sequ_write(2, 0x04); // enable write plane 2

  {
    unsigned char *font_ptr = pci_mem_base + SEG_GRAPH*16;
    int i;

    for (i = 0; i < 0x100; i++)
      __builtin_memcpy(font_ptr + i*32, vgafont16 + i*16, 16);
  }

  {
    int i = vmode_g->dacsize / 3;
    vgahw_set_dac_regs(vmode_g->dac, 0, i);
  }

  vgahw_sequ_write(4, 0x2); // enable odd/even
  vgahw_set_mode(vmode_g->vparam);
}
