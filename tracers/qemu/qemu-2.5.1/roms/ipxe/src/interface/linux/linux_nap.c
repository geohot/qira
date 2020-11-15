/*
 * Copyright (C) 2010 Piotr Jaroszyński <p.jaroszynski@gmail.com>
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
 */

FILE_LICENCE(GPL2_OR_LATER);

#include <ipxe/nap.h>

#include <linux_api.h>

/** @file
 *
 * iPXE CPU sleeping API for linux
 *
 */

/**
 * Sleep until next CPU interrupt
 *
 */
static void linux_cpu_nap(void)
{
	linux_usleep(0);
}

PROVIDE_NAP(linux, cpu_nap, linux_cpu_nap);
