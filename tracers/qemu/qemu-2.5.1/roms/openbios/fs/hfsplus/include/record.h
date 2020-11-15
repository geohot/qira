/*
 * libhfs - library for reading and writing Macintosh HFS volumes.
 *
 * a record contains a key and a folder or file and is part
 * of a btree.
 *
 * Copyright (C) 2000 Klaus Halfmann <khalfmann@libra.de>
 * Original 1996-1998 Robert Leslie <rob@mars.org>
 * Additional work by  Brad Boyer (flar@pants.nu)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * $Id: record.h,v 1.10 2000/10/01 17:08:05 hasi Exp $
 */

/* Compare two cat_keys ... */
extern int record_key_compare(void* k1, void* k2);

/* Compare two extent_keys ... */
extern int record_extent_key_compare(void* k1, void* k2);

/* read a catalog key into a given buffer */
extern void* record_readkey(void* p, void* buf);

/* read an extent key into a given buffer */
extern void* record_extent_readkey(void* p, void* buf);

/* intialize the record to the first record of the tree
 * which is (per design) the root node.
 */
extern int record_init_root(record* r, btree* tree);

/* intialize the record to the folder given by cnid.
 */
extern int record_init_cnid(record* r, btree* tree, UInt32 cnid);

/* intialize the record to the first record of the parent.
 */
extern int record_init_parent(record* r, record* parent);

/* intialize the record by searching for the given string in the given folder.
 *
 * parent and r may be the same.
 */
extern int record_init_string_parent(record* r, record* parent, char* key);

/* move record up in folder hierarchy (if possible) */
extern int record_up(record* r);

/* move record foreward to next entry.
 *
 * In case of an error the value of *r is undefined !
 */
extern int record_next(record* r);

/* intialize the extent_record to the extent identified by
 * a given file */
extern int record_init_file(extent_record* r, btree* tree,
		    UInt8 forktype, UInt32 fileId, UInt32 blockindex);

/* move foreward to next entent record. */
extern int record_next_extent(extent_record *r);

#ifdef DEBUG
    /* Dump all the record information to stdout */
  extern void record_print(record* r);
#endif
