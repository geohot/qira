/*
 * <pckbd.c>
 *
 * Open Hack'Ware BIOS PC keyboard driver.
 * 
 *  Copyright (c) 2005 Jocelyn Mayer
 *
 *  This code is a rework (mostly simplification) from code
 *  proposed by Matthew Wood <mwood@realmsys.com>
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

/* IO definitions */
#define PCKBD_IO_BASE                   0x60
#define PCKBD_COMMAND_OFFSET            0x4
#define PCKBD_STATUS_OFFSET             0x4

/* Indexes for keyboard state */
#define SHIFT 0x1
#define CTRL  0x2
#define ALT   0x4

/* Scan codes */
#define L_SHIFT  0x2a
#define R_SHIFT  0x36
#define L_CTRL   0x1d
/* XXX: R_CTRL ? */
#define L_ALT    0x38
/* XXX: missing capslock */
/* XXX: TODO: add keypad/numlock ... (pc105 kbd) */

typedef struct kbdmap_t kbdmap_t;
struct kbdmap_t {
    char translate[8];
};

typedef struct pckbd_t pckbd_t;
struct pckbd_t {
    int modifiers;
    kbdmap_t *map;
    int maplen;
    int io_base;
};

/* XXX: should not be here cause it's locale dependent */
static kbdmap_t pc_map_us[] = {
    /* 0x00 */
    { {   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { { 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, }, },
    { {  '1',  '!',   -1,   -1,  '1',  '!',   -1,   -1, }, },
    { {  '2', '\'', '\'',   -1,   -1,  '2', '\'', '\'', }, },
    { {  '3',  '#',   -1,   -1,  '3',  '#',   -1,   -1, }, },
    { {  '4',  '$',   -1,   -1,  '4',  '$',   -1,   -1, }, },
    { {  '5',  '%',   -1,   -1,  '5',  '%',   -1,   -1, }, },
    { {  '6',  '^',   -1,   -1,  '6',  '^',   -1,   -1, }, },
    /* 0x08 */
    { {  '7',  '&',   -1,   -1,  '7',  '&',   -1,   -1, }, },
    { {  '8',  '*',   -1,   -1,  '8',  '*',   -1,   -1, }, },
    { {  '9',  '(',   -1,   -1,  '9',  '(',   -1,   -1, }, },
    { {  '0',  ')',   -1,   -1,  '0',  ')',   -1,   -1, }, },
    { {  '-',  '_',   -1,   -1,  '-',  '_',   -1,   -1, }, },
    { {  '=',  '+',   -1,   -1,  '=',  '+',   -1,   -1, }, },
    { { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, }, },
    { { 0x2a,   -1,   -1,   -1, 0x2a,   -1,   -1,   -1, }, },
    /* 0x10 */
    { {  'q',  'Q',   -1,   -1,  'q',  'Q',   -1,   -1, }, },
    { {  'w',  'W',   -1,   -1,  'w',  'W',   -1,   -1, }, },
    { {  'e',  'E',   -1,   -1,  'e',  'E',   -1,   -1, }, },
    { {  'r',  'R',   -1,   -1,  'r',  'R',   -1,   -1, }, },
    { {  't',  'T',   -1,   -1,  't',  'T',   -1,   -1, }, },
    { {  'y',  'Y',   -1,   -1,  'y',  'Y',   -1,   -1, }, },
    { {  'u',  'U',   -1,   -1,  'u',  'U',   -1,   -1, }, },
    { {  'i',  'I',   -1,   -1,  'i',  'I',   -1,   -1, }, },
    /* 0x18 */
    { {  'o',  'O',   -1,   -1,  'o',  'O',   -1,   -1, }, },
    { {  'p',  'P',   -1,   -1,  'p',  'P',   -1,   -1, }, },
    { {  '[',  '{', 0x1b, 0x1b,  '[',  '{', 0x1b, 0x1b, }, },
    { {  ']',  '}',   -1,   -1,  ']',  '}',   -1,   -1, }, },
    { { 0x0d, 0x0d, '\r', '\r', 0x0d, 0x0d, '\r', '\r', }, },
    { {   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { {  'a',  'A',   -1,   -1,  'a',  'A',   -1,   -1, }, },
    { {  's',  'S',   -1,   -1,  's',  'S',   -1,   -1, }, },
    /* 0x20 */
    { {  'd',  'D',   -1,   -1,  'd',  'D',   -1,   -1, }, },
    { {  'f',  'F',   -1,   -1,  'f',  'F',   -1,   -1, }, },
    { {  'g',  'G', 0x07, 0x07,  'g',  'G', 0x07, 0x07, }, },
    { {  'h',  'H', 0x08, 0x08,  'h',  'H', 0x08, 0x08, }, },
    { {  'j',  'J', '\r', '\r',  'j',  'J', '\r', '\r', }, },
    { {  'k',  'K',   -1,   -1,  'k',  'K',   -1,   -1, }, },
    { {  'l',  'L',   -1,   -1,  'l',  'L',   -1,   -1, }, },
    { {  ';',  ':',   -1,   -1,  ';',  ':',   -1,   -1, }, },
    /* 0x28 */
    { { '\'',  '"',   -1,   -1, '\'',  '"',   -1,   -1, }, },
    { {  '`',  '~',   -1,   -1,  '`',  '~',   -1,   -1, }, },
    { { 0x02,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { { '\\',  '|',   -1,   -1, '\\',  '|',   -1,   -1, }, },
    { {  'z',  'Z',   -1,   -1,  'z',  'Z',   -1,   -1, }, },
    { {  'x',  'X',   -1,   -1,  'x',  'X',   -1,   -1, }, },
    { {  'c',  'C',   -1,   -1,  'c',  'C',   -1,   -1, }, },
    { {  'v',  'V', 0x16, 0x16,  'v',  'V',   -1,   -1, }, },
    /* 0x30 */
    { {  'b',  'B',   -1,   -1,  'b',  'B',   -1,   -1, }, },
    { {  'n',  'N',   -1,   -1,  'n',  'N',   -1,   -1, }, },
    { {  'm',  'M', 0x0d, 0x0d,  'm',  'M', 0x0d, 0x0d, }, },
    { {  ',',  '<',   -1,   -1,  ',',  '<',   -1,   -1, }, },
    { {  '.',  '>',   -1,   -1,  '.',  '>',   -1,   -1, }, },
    { {  '/',  '?',   -1,   -1,  '/',  '?',   -1,   -1, }, },
    { {   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { {  '*',  '*',   -1,   -1,  '*',  '*',   -1,   -1, }, },
    /* 0x38 */
    { {   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { {  ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ', }, },
};

static int pckbd_open (unused void *private)
{
    return 0;
}

static int pckbd_close (unused void *private)
{
    return 0;
}

static int pckbd_readb (void *private)
{
    pckbd_t *kbd = private;
    int status, key, up, mod;
    int ret;

    for (ret = -1; ret < 0; ) {
        status = inb(kbd->io_base + PCKBD_STATUS_OFFSET);
        if (!(status & 1)) {
            /* No more data available */
            break;
        }
        key = inb(kbd->io_base);
        up = (key & 0x80) != 0;
        key &= ~0x80;
        switch (key) {
        case 0:
            break;
        case L_ALT:
            mod = ALT;
            goto set_modifiers;
        case L_SHIFT:
        case R_SHIFT:
            mod = SHIFT;
            goto set_modifiers;
        case L_CTRL:
#if 0 /* XXX: missing definition */
        case R_CTRL:
#endif
            mod = CTRL;
        set_modifiers:
            if (up)
                kbd->modifiers &= ~mod;
            else
                kbd->modifiers |= mod;
            break;
        default:
            /* We don't care about up events or unknown keys */
            if (!up && key < kbd->maplen)
                ret = kbd->map[key].translate[kbd->modifiers];
            break;
        }
    }

    return ret;
}

static cops_t pckbd_ops = {
    &pckbd_open,
    &pckbd_close,
    &pckbd_readb,
    NULL,
};

int pckbd_register (void)
{
    pckbd_t *kbd;

    kbd = malloc(sizeof(pckbd_t));
    if (kbd == NULL)
        return -1;
    memset(kbd, 0, sizeof(pckbd_t));
    /* Set IO base */
    /* XXX: should be a parameter... */
    kbd->io_base = PCKBD_IO_BASE;
    /* Set default keymap */
    kbd->map = pc_map_us;
    kbd->maplen = sizeof(pc_map_us) / sizeof(kbdmap_t);
    /* Reset modifiers state */
    kbd->modifiers = 0x00;
    chardev_register(CHARDEV_KBD, &pckbd_ops, kbd);

    return 0;
}
