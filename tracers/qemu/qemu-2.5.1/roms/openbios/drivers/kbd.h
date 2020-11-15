/*
 * <kbd.h>
 *
 * Open Hack'Ware BIOS generic keyboard management definitions.
 *
 *  Copyright (c) 2005 Jocelyn Mayer
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA, 02110-1301 USA
 */

#if !defined (__OHW_KBD_H__)
#define __OHW_KBD_H__
typedef struct kbd_t kbd_t;
typedef struct keymap_t keymap_t;
struct kbd_t {
    uint32_t mod_state;
    /* Modifier state
     *                0x00 kk ll rr
     *                   |  |  |  |
     * Not used for now -+  |  |  |
     * Locks ---------------+  |  |
     * Left modifiers ---------+  |
     * Right modifiers -----------+
     */
    int nb_keys;
    const keymap_t *keymap;
    const char **sequences;
};

/* Modifiers */
typedef enum {
    KBD_MOD_SHIFT   = 0x01,
    KBD_MOD_CTRL    = 0x02,
    KBD_MOD_ALT     = 0x04,
    KBD_MOD_CMD     = 0x08,
    KBD_MOD_OPT     = 0x10,
} kbd_modifiers;

/* Locks */
typedef enum {
    KBD_LCK_CAPS    = 0x01,
    KBD_LCK_NUM     = 0x02,
    KBD_LCK_SCROLL  = 0x04,
} kbd_locks;

/* Lock shifts */
typedef enum {
    KBD_SH_NONE     = -1,
    KBD_SH_CAPS     = 0,
    KBD_SH_NUML     = 1,
    KBD_SH_SCRL     = 2,
} kbd_lck_shifts;

enum {
    KBD_TYPE_REGULAR  = 0 << 24,
    KBD_TYPE_LMOD     = 1 << 24,
    KBD_TYPE_RMOD     = 2 << 24,
    KBD_TYPE_LOCK     = 3 << 24,
    KBD_TYPE_SEQUENCE = 4 << 24,
};

#define KBD_SEQUENCE(sequence)	(KBD_TYPE_SEQUENCE | (sequence))

#define KBD_MOD_MAP(mod) \
KBD_SH_NONE, { (mod), (mod), (mod), (mod), (mod), (mod), (mod), (mod), \
               (mod), (mod), (mod), (mod), (mod), (mod), (mod), (mod), \
               (mod), (mod), (mod), (mod), (mod), (mod), (mod), (mod), \
               (mod), (mod), (mod), (mod), (mod), (mod), (mod), (mod), }
#define KBD_MOD_MAP_LSHIFT KBD_MOD_MAP(KBD_TYPE_LMOD | KBD_MOD_SHIFT)
#define KBD_MOD_MAP_RSHIFT KBD_MOD_MAP(KBD_TYPE_RMOD | (KBD_MOD_SHIFT << 8))
#define KBD_MOD_MAP_LCTRL  KBD_MOD_MAP(KBD_TYPE_LMOD | KBD_MOD_CTRL)
#define KBD_MOD_MAP_RCTRL  KBD_MOD_MAP(KBD_TYPE_RMOD | (KBD_MOD_CTRL << 8))
#define KBD_MOD_MAP_LALT   KBD_MOD_MAP(KBD_TYPE_LMOD | KBD_MOD_ALT)
#define KBD_MOD_MAP_RALT   KBD_MOD_MAP(KBD_TYPE_RMOD | (KBD_MOD_ALT << 8))
#define KBD_MOD_MAP_LCMD   KBD_MOD_MAP(KBD_TYPE_LMOD | KBD_MOD_CMD)
#define KBD_MOD_MAP_RCMD   KBD_MOD_MAP(KBD_TYPE_RMOD | (KBD_MOD_CMD << 8))
#define KBD_MOD_MAP_LOPT   KBD_MOD_MAP(KBD_TYPE_LMOD | KBD_MOD_OPT)
#define KBD_MOD_MAP_ROPT   KBD_MOD_MAP(KBD_TYPE_RMOD | (KBD_MOD_OPT << 8))
#define KBD_MOD_MAP_CAPS   KBD_MOD_MAP(KBD_TYPE_LOCK | (KBD_LCK_CAPS << 16))
#define KBD_MOD_MAP_NUML   KBD_MOD_MAP(KBD_TYPE_LOCK | (KBD_LCK_NUML << 16))
#define KBD_MOD_MAP_SCROLL KBD_MOD_MAP(KBD_TYPE_LOCK | (KBD_LCK_SCRL << 16))
#define KBD_MAP_NONE KBD_MOD_MAP(-1)

/* Keymap definition */
struct keymap_t {
    /* Set the lock which applies to this key (if any) */
    int lck_shift;
    /* Key translations */
    uint32_t trans[32];
};

void *kbd_new (int len);
int kbd_set_keymap (kbd_t *kbd, int nb_keys, const keymap_t *keymap,
		    const char **sequences);
int kbd_translate_key (kbd_t *kbd, int keycode, int up_down, char *sequence);

#endif /* !defined (__OHW_KBD_H__) */
