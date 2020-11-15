/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/uaccess.h>
#include <ipxe/settings.h>

/** @file
 *
 * Video RAM dump
 *
 */

/** Video RAM base address */
#define VRAM_BASE 0xb8000

/** Video RAM length */
#define VRAM_LEN \
	( 80 /* columns */ * 25 /* rows */ * 2 /* bytes per character */ )

/**
 * Fetch video RAM setting
 *
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int vram_fetch ( void *data, size_t len ) {
	userptr_t vram = phys_to_user ( VRAM_BASE );

	/* Copy video RAM */
	if ( len > VRAM_LEN )
		len = VRAM_LEN;
	copy_from_user ( data, vram, 0, len );

	return VRAM_LEN;
}

/** Video RAM setting */
const struct setting vram_setting __setting ( SETTING_MISC, vram ) = {
	.name = "vram",
	.description = "Video RAM",
	.type = &setting_type_base64,
	.scope = &builtin_scope,
};

/** Video RAM built-in setting */
struct builtin_setting vram_builtin_setting __builtin_setting = {
	.setting = &vram_setting,
	.fetch = vram_fetch,
};
