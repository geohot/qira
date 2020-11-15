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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _HCI_LINUX_ARGS_H
#define _HCI_LINUX_ARGS_H

FILE_LICENCE(GPL2_OR_LATER);

/**
 * Save argc and argv for later access.
 *
 * To be called by linuxprefix
 */
extern __asmcall void save_args(int argc, char **argv);

#endif /* _HCI_LINUX_ARGS_H */
