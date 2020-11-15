/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

/** @file
 *
 * Linked lists
 *
 */

#include <ipxe/list.h>

void extern_list_add ( struct list_head *new, struct list_head *head ) {
	inline_list_add ( new, head );
}

void extern_list_add_tail ( struct list_head *new, struct list_head *head ) {
	inline_list_add_tail ( new, head );
}

void extern_list_del ( struct list_head *list ) {
	inline_list_del ( list );
}

int extern_list_empty ( const struct list_head *list ) {
	return inline_list_empty ( list );
}

int extern_list_is_singular ( const struct list_head *list ) {
	return inline_list_is_singular ( list );
}

int extern_list_is_last ( const struct list_head *list,
			  const struct list_head *head ) {
	return inline_list_is_last ( list, head );
}

void extern_list_cut_position ( struct list_head *new,
				struct list_head *list,
				struct list_head *entry ) {
	inline_list_cut_position ( new, list, entry );
}

void extern_list_splice ( const struct list_head *list,
			  struct list_head *entry ) {
	inline_list_splice ( list, entry );
}

void extern_list_splice_tail ( const struct list_head *list,
			       struct list_head *entry ) {
	inline_list_splice_tail ( list, entry );
}

void extern_list_splice_init ( struct list_head *list,
			       struct list_head *entry ) {
	inline_list_splice_init ( list, entry );
}

void extern_list_splice_tail_init ( struct list_head *list,
				    struct list_head *entry ) {
	inline_list_splice_tail_init ( list, entry );
}

int extern_list_contains ( struct list_head *entry,
			   struct list_head *head ) {
	return inline_list_contains ( entry, head );
}
