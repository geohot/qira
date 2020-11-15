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

#include <ipxe/uaccess.h>

/** @file
 *
 * iPXE user access API for linux
 *
 */

PROVIDE_UACCESS_INLINE(linux, user_to_phys);
PROVIDE_UACCESS_INLINE(linux, virt_to_user);
PROVIDE_UACCESS_INLINE(linux, user_to_virt);
PROVIDE_UACCESS_INLINE(linux, userptr_add);
PROVIDE_UACCESS_INLINE(linux, memcpy_user);
PROVIDE_UACCESS_INLINE(linux, memmove_user);
PROVIDE_UACCESS_INLINE(linux, memset_user);
PROVIDE_UACCESS_INLINE(linux, strlen_user);
PROVIDE_UACCESS_INLINE(linux, memchr_user);
