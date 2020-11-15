// Standard VGA IO port access
//
// Copyright (C) 2012  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "farptr.h" // GET_FARVAR
#include "stdvga.h" // stdvga_pelmask_read
#include "x86.h" // inb

u8
stdvga_pelmask_read(void)
{
    return inb(VGAREG_PEL_MASK);
}

void
stdvga_pelmask_write(u8 value)
{
    outb(value, VGAREG_PEL_MASK);
}


u8
stdvga_misc_read(void)
{
    return inb(VGAREG_READ_MISC_OUTPUT);
}

void
stdvga_misc_write(u8 value)
{
    outb(value, VGAREG_WRITE_MISC_OUTPUT);
}

void
stdvga_misc_mask(u8 off, u8 on)
{
    stdvga_misc_write((stdvga_misc_read() & ~off) | on);
}


u8
stdvga_sequ_read(u8 index)
{
    outb(index, VGAREG_SEQU_ADDRESS);
    return inb(VGAREG_SEQU_DATA);
}

void
stdvga_sequ_write(u8 index, u8 value)
{
    outw((value<<8) | index, VGAREG_SEQU_ADDRESS);
}

void
stdvga_sequ_mask(u8 index, u8 off, u8 on)
{
    outb(index, VGAREG_SEQU_ADDRESS);
    u8 v = inb(VGAREG_SEQU_DATA);
    outb((v & ~off) | on, VGAREG_SEQU_DATA);
}


u8
stdvga_grdc_read(u8 index)
{
    outb(index, VGAREG_GRDC_ADDRESS);
    return inb(VGAREG_GRDC_DATA);
}

void
stdvga_grdc_write(u8 index, u8 value)
{
    outw((value<<8) | index, VGAREG_GRDC_ADDRESS);
}

void
stdvga_grdc_mask(u8 index, u8 off, u8 on)
{
    outb(index, VGAREG_GRDC_ADDRESS);
    u8 v = inb(VGAREG_GRDC_DATA);
    outb((v & ~off) | on, VGAREG_GRDC_DATA);
}


u8
stdvga_crtc_read(u16 crtc_addr, u8 index)
{
    outb(index, crtc_addr);
    return inb(crtc_addr + 1);
}

void
stdvga_crtc_write(u16 crtc_addr, u8 index, u8 value)
{
    outw((value<<8) | index, crtc_addr);
}

void
stdvga_crtc_mask(u16 crtc_addr, u8 index, u8 off, u8 on)
{
    outb(index, crtc_addr);
    u8 v = inb(crtc_addr + 1);
    outb((v & ~off) | on, crtc_addr + 1);
}


u8
stdvga_attr_read(u8 index)
{
    inb(VGAREG_ACTL_RESET);
    u8 orig = inb(VGAREG_ACTL_ADDRESS);
    outb(index, VGAREG_ACTL_ADDRESS);
    u8 v = inb(VGAREG_ACTL_READ_DATA);
    inb(VGAREG_ACTL_RESET);
    outb(orig, VGAREG_ACTL_ADDRESS);
    return v;
}

void
stdvga_attr_write(u8 index, u8 value)
{
    inb(VGAREG_ACTL_RESET);
    u8 orig = inb(VGAREG_ACTL_ADDRESS);
    outb(index, VGAREG_ACTL_ADDRESS);
    outb(value, VGAREG_ACTL_WRITE_DATA);
    outb(orig, VGAREG_ACTL_ADDRESS);
}

void
stdvga_attr_mask(u8 index, u8 off, u8 on)
{
    inb(VGAREG_ACTL_RESET);
    u8 orig = inb(VGAREG_ACTL_ADDRESS);
    outb(index, VGAREG_ACTL_ADDRESS);
    u8 v = inb(VGAREG_ACTL_READ_DATA);
    outb((v & ~off) | on, VGAREG_ACTL_WRITE_DATA);
    outb(orig, VGAREG_ACTL_ADDRESS);
}

u8
stdvga_attrindex_read(void)
{
    inb(VGAREG_ACTL_RESET);
    return inb(VGAREG_ACTL_ADDRESS);
}

void
stdvga_attrindex_write(u8 value)
{
    inb(VGAREG_ACTL_RESET);
    outb(value, VGAREG_ACTL_ADDRESS);
}


void
stdvga_dac_read(u16 seg, u8 *data_far, u8 start, int count)
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
stdvga_dac_write(u16 seg, u8 *data_far, u8 start, int count)
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
