/*
 * <nvram.c>
 *
 * Open Hack'Ware BIOS NVRAM management routines.
 * 
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include "bios.h"

#define NVRAM_MAX_SIZE 0x2000
#define NVRAM_IO_BASE 0x0074

struct nvram_t {
    uint16_t io_base;
    uint16_t size;
};

/* NVRAM access */
static void NVRAM_set_byte (nvram_t *nvram, uint32_t addr, uint8_t value)
{
    NVRAM_write(nvram, addr, value);
}

static uint8_t NVRAM_get_byte (nvram_t *nvram, uint16_t addr)
{
    return NVRAM_read(nvram, addr);
}

static void NVRAM_set_word (nvram_t *nvram, uint16_t addr, uint16_t value)
{
    NVRAM_write(nvram, addr, value >> 8);
    NVRAM_write(nvram, addr + 1, value);
}

static uint16_t NVRAM_get_word (nvram_t *nvram, uint16_t addr)
{
    uint16_t tmp;

    tmp = NVRAM_read(nvram, addr) << 8;
    tmp |= NVRAM_read(nvram, addr + 1);

    return tmp;
}

static void NVRAM_set_lword (nvram_t *nvram, uint16_t addr, uint32_t value)
{
    NVRAM_write(nvram, addr, value >> 24);
    NVRAM_write(nvram, addr + 1, value >> 16);
    NVRAM_write(nvram, addr + 2, value >> 8);
    NVRAM_write(nvram, addr + 3, value);
}

static uint32_t NVRAM_get_lword (nvram_t *nvram, uint16_t addr)
{
    uint32_t tmp;

    tmp = NVRAM_read(nvram, addr) << 24;
    tmp |= NVRAM_read(nvram, addr + 1) << 16;
    tmp |= NVRAM_read(nvram, addr + 2) << 8;
    tmp |= NVRAM_read(nvram, addr + 3);

    return tmp;
}

static void NVRAM_set_string (nvram_t *nvram, uint32_t addr,
                              const unsigned char *str, uint32_t max)
{
    uint32_t i;

    for (i = 0; i < max && str[i] != '\0'; i++) {
        NVRAM_write(nvram, addr + i, str[i]);
    }
    NVRAM_write(nvram, addr + i, '\0');
}

static int NVRAM_get_string (nvram_t *nvram, uint8_t *dst,
                             uint16_t addr, int max)
{
    int i;

    memset(dst, 0, max);
    for (i = 0; i < max; i++) {
        dst[i] = NVRAM_get_byte(nvram, addr + i);
        if (dst[i] == '\0')
            break;
    }

    return i;
}

static uint16_t NVRAM_crc_update (uint16_t prev, uint16_t value)
{
    uint16_t tmp;
    uint16_t pd, pd1, pd2;

    tmp = prev >> 8;
    pd = prev ^ value;
    pd1 = pd & 0x000F;
    pd2 = ((pd >> 4) & 0x000F) ^ pd1;
    tmp ^= (pd1 << 3) | (pd1 << 8);
    tmp ^= pd2 | (pd2 << 7) | (pd2 << 12);

    return tmp;
}

static uint16_t NVRAM_compute_crc (nvram_t *nvram,
                                   uint32_t start, uint32_t count)
{
    uint32_t i;
    uint16_t crc = 0xFFFF;
    int odd;

    odd = count & 1;
    count &= ~1;
    for (i = 0; i != count; i++) {
        crc = NVRAM_crc_update(crc, NVRAM_get_word(nvram, start + i));
    }
    if (odd) {
        crc = NVRAM_crc_update(crc, NVRAM_get_byte(nvram, start + i) << 8);
    }

    return crc;
}

/* Format NVRAM for PREP target */
static int NVRAM_prep_format (nvram_t *nvram)
{
#define NVRAM_PREP_OSAREA_SIZE 512
#define NVRAM_PREP_CONFSIZE    1024
    uint16_t crc;
    
    /* NVRAM header */
    /* 0x00: NVRAM size in kB */
    NVRAM_set_word(nvram, 0x00, nvram->size >> 10);
    /* 0x02: NVRAM version */
    NVRAM_set_byte(nvram, 0x02, 0x01);
    /* 0x03: NVRAM revision */
    NVRAM_set_byte(nvram, 0x03, 0x01);
    /* 0x08: last OS */
    NVRAM_set_byte(nvram, 0x08, 0x00); /* Unknown */
    /* 0x09: endian */
    NVRAM_set_byte(nvram, 0x09, 'B');  /* Big-endian */
    /* 0x0A: OSArea usage */
    NVRAM_set_byte(nvram, 0x0A, 0x00); /* Empty */
    /* 0x0B: PM mode */
    NVRAM_set_byte(nvram, 0x0B, 0x00); /* Normal */
    /* Restart block description record */
    /* 0x0C: restart block version */
    NVRAM_set_word(nvram, 0x0C, 0x01);
    /* 0x0E: restart block revision */
    NVRAM_set_word(nvram, 0x0E, 0x01);
    /* 0x20: restart address */
    NVRAM_set_lword(nvram, 0x20, 0x00);
    /* 0x24: save area address */
    NVRAM_set_lword(nvram, 0x24, 0x00);
    /* 0x28: save area length */
    NVRAM_set_lword(nvram, 0x28, 0x00);
    /* 0x1C: checksum of restart block */
    crc = NVRAM_compute_crc(nvram, 0x0C, 32);
    NVRAM_set_word(nvram, 0x1C, crc);

    /* Security section */
    /* Set all to zero */
    /* 0xC4: pointer to global environment area */
    NVRAM_set_lword(nvram, 0xC4, 0x0100);
    /* 0xC8: size of global environment area */
    NVRAM_set_lword(nvram, 0xC8, nvram->size - NVRAM_PREP_OSAREA_SIZE -
                    NVRAM_PREP_CONFSIZE - 0x0100);
    /* 0xD4: pointer to configuration area */
    NVRAM_set_lword(nvram, 0xD4, nvram->size - NVRAM_PREP_CONFSIZE);
    /* 0xD8: size of configuration area */
    NVRAM_set_lword(nvram, 0xD8, NVRAM_PREP_CONFSIZE);
    /* 0xE8: pointer to OS specific area */
    NVRAM_set_lword(nvram, 0xE8, nvram->size - NVRAM_PREP_CONFSIZE
                    - NVRAM_PREP_OSAREA_SIZE);
    /* 0xD8: size of OS specific area */
    NVRAM_set_lword(nvram, 0xEC, NVRAM_PREP_OSAREA_SIZE);

    /* Configuration area */

    /* 0x04: checksum 0 => OS area   */
    crc = NVRAM_compute_crc(nvram, 0x00, nvram->size - NVRAM_PREP_CONFSIZE -
                            NVRAM_PREP_OSAREA_SIZE);
    NVRAM_set_word(nvram, 0x04, crc);
    /* 0x06: checksum of config area */
    crc = NVRAM_compute_crc(nvram, nvram->size - NVRAM_PREP_CONFSIZE,
                            NVRAM_PREP_CONFSIZE);
    NVRAM_set_word(nvram, 0x06, crc);

    return 0;
}

static uint8_t NVRAM_chrp_chksum (nvram_t *nvram, uint16_t pos)
{
    uint16_t sum, end;

    end = pos + 0x10;
    sum = NVRAM_get_byte(nvram, pos);
    for (pos += 2; pos < end; pos++) {
        sum += NVRAM_get_byte(nvram, pos);
    }
    while (sum > 0xFF) {
        sum = (sum & 0xFF) + (sum >> 8);
    }

    return sum;
}

static int NVRAM_chrp_format (unused nvram_t *nvram)
{
    uint8_t chksum;

    /* Mark NVRAM as free */
    NVRAM_set_byte(nvram, 0x00, 0x5A);
    NVRAM_set_byte(nvram, 0x01, 0x00);
    NVRAM_set_word(nvram, 0x02, 0x2000);
    NVRAM_set_string(nvram, 0x04, "wwwwwwwwwwww", 12);
    chksum = NVRAM_chrp_chksum(nvram, 0x00);
    NVRAM_set_byte(nvram, 0x01, chksum);

    return 0;
}

#if 0
static uint16_t NVRAM_mac99_chksum (nvram_t *nvram,
                                   uint16_t start, uint16_t len)
	int cnt;
	u32 low, high;

   	buffer += CORE99_ADLER_START;
	low = 1;
	high = 0;
	for (cnt=0; cnt<(NVRAM_SIZE-CORE99_ADLER_START); cnt++) {
		if ((cnt % 5000) == 0) {
			high  %= 65521UL;
			high %= 65521UL;
		}
		low += buffer[cnt];
		high += low;
	}
	low  %= 65521UL;
	high %= 65521UL;

	return (high << 16) | low;
{
    uint16_t pos;
    uint8_t tmp, sum;

    sum = 0;
    for (pos = start; pos < (start + len); pos++) {
        tmp = sum + NVRAM_get_byte(nvram, pos);
        if (tmp < sum)
            tmp++;
        sum = tmp;
    }

    return sum;
}
#endif

static int NVRAM_mac99_format (nvram_t *nvram)
{
    uint8_t chksum;

    /* Mark NVRAM as free */
    NVRAM_set_byte(nvram, 0x00, 0x5A);
    NVRAM_set_byte(nvram, 0x01, 0x00);
    NVRAM_set_word(nvram, 0x02, 0x2000);
    NVRAM_set_string(nvram, 0x04, "wwwwwwwwwwww", 12);
    chksum = NVRAM_chrp_chksum(nvram, 0x00);
    NVRAM_set_byte(nvram, 0x01, chksum);

    return 0;
}

static int NVRAM_pop_format (unused nvram_t *nvram)
{
    /* TODO */
    return -1;
}

/* Interface */
uint8_t NVRAM_read (nvram_t *nvram, uint32_t addr)
{
    outb(nvram->io_base + 0x00, addr);
    outb(nvram->io_base + 0x01, addr >> 8);

    return inb(NVRAM_IO_BASE + 0x03);
}

void NVRAM_write (nvram_t *nvram, uint32_t addr, uint8_t value)
{
    outb(nvram->io_base + 0x00, addr);
    outb(nvram->io_base + 0x01, addr >> 8);
    outb(nvram->io_base + 0x03, value);
}

uint16_t NVRAM_get_size (nvram_t *nvram)
{
    return nvram->size;
}

int NVRAM_format (nvram_t *nvram)
{
    int ret;

    {
        uint16_t pos;
        
        for (pos = 0; pos < nvram->size; pos += 4)
            NVRAM_set_lword(nvram, pos, 0);
    }
    switch (arch) {
    case ARCH_PREP:
        ret = NVRAM_prep_format(nvram);
        break;
    case ARCH_CHRP:
        ret = NVRAM_chrp_format(nvram);
        break;
    case ARCH_MAC99:
    case ARCH_HEATHROW: /* XXX: may be incorrect */
        ret = NVRAM_mac99_format(nvram);
        break;
    case ARCH_POP:
        ret = NVRAM_pop_format(nvram);
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}

/* HACK... */
extern int vga_width, vga_height, vga_depth;

static nvram_t global_nvram;

nvram_t *NVRAM_get_config (uint32_t *RAM_size, int *boot_device,
                           void **boot_image, uint32_t *boot_size,
                           void **cmdline, uint32_t *cmdline_size,
                           void **ramdisk, uint32_t *ramdisk_size)
{
    unsigned char sign[16];
    nvram_t *nvram;
    uint32_t lword;
    uint16_t NVRAM_size, crc;
    uint8_t byte;

#if 0
    nvram = malloc(sizeof(nvram_t));
    if (nvram == NULL)
        return NULL;
#else
    nvram = &global_nvram;
#endif
    nvram->io_base = NVRAM_IO_BASE;
    /* Pre-initialised NVRAM is not supported any more */
    if (NVRAM_get_string(nvram, sign, 0x00, 0x10) <= 0 ||
        strcmp(sign, "QEMU_BIOS") != 0) {
        ERROR("Wrong NVRAM signature %s\n", sign);
        return NULL;
    }
    /* Check structure version */
    lword = NVRAM_get_lword(nvram, 0x10);
    if (lword != 0x00000002) {
        ERROR("Wrong NVRAM structure version: %0x\n", lword);
        return NULL;
    }
    /* Check CRC */
    crc = NVRAM_compute_crc(nvram, 0x00, 0xF8);
    if (NVRAM_get_word(nvram, 0xFC) != crc) {
        ERROR("Invalid NVRAM structure CRC: %0x <=> %0x\n", crc,
              NVRAM_get_word(nvram, 0xFC));
        return NULL;
    }
    NVRAM_size = NVRAM_get_word(nvram, 0x14);
    if ((NVRAM_size & 0x100) != 0x00 || NVRAM_size < 0x400 ||
        NVRAM_size > 0x2000) {
        ERROR("Invalid NVRAM size: %d\n", NVRAM_size);
        return NULL;
    }
    nvram->size = NVRAM_size;
    if (NVRAM_get_string(nvram, sign, 0x20, 0x10) < 0) {
        ERROR("Unable to get architecture from NVRAM\n");
        return NULL;
    }
    if (strcmp(sign, "PREP") == 0) {
        arch = ARCH_PREP;
    } else if (strcmp(sign, "CHRP") == 0) {
        arch = ARCH_CHRP;
    } else if (strcmp(sign, "MAC99") == 0) {
        arch = ARCH_MAC99;
    } else if (strcmp(sign, "POP") == 0) {
        arch = ARCH_POP;
    } else if (strcmp(sign, "HEATHROW") == 0) {
        arch = ARCH_HEATHROW;
    } else {
        ERROR("Unknown PPC architecture: '%s'\n", sign);
        return NULL;
    }
    lword = NVRAM_get_lword(nvram, 0x30);
    *RAM_size = lword;
    byte = NVRAM_get_byte(nvram, 0x34);
    *boot_device = byte;
    /* Preloaded boot image */
    lword = NVRAM_get_lword(nvram, 0x38);
    *boot_image = (void *)lword;
    lword = NVRAM_get_lword(nvram, 0x3C);
    *boot_size = lword;
    /* Preloaded cmdline */
    lword = NVRAM_get_lword(nvram, 0x40);
    *cmdline = (void *)lword;
    lword = NVRAM_get_lword(nvram, 0x44);
    *cmdline_size = lword;
    /* Preloaded RAM disk */
    lword = NVRAM_get_lword(nvram, 0x48);
    *ramdisk = (void *)lword;
    lword = NVRAM_get_lword(nvram, 0x4C);
    *ramdisk_size = lword;
    /* Preloaded NVRAM image */
    lword = NVRAM_get_lword(nvram, 0x50);
    /* Display init geometry */
    lword = NVRAM_get_word(nvram, 0x54);
    vga_width = lword;
    lword = NVRAM_get_word(nvram, 0x56);
    vga_height = lword;
    lword = NVRAM_get_word(nvram, 0x58);
    vga_depth = lword;
    /* TODO: write it into NVRAM */

    return nvram;
}
