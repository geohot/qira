/*
 *  ISO 9660 filesystem backend for GRUB (GRand Unified Bootloader)
 *  including Rock Ridge Extensions support
 *
 *  Copyright (C) 1998, 1999  Kousuke Takai  <tak@kmc.kyoto-u.ac.jp>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
/*
 *  References:
 *	linux/fs/isofs/rock.[ch]
 *	mkisofs-1.11.1/diag/isoinfo.c
 *	mkisofs-1.11.1/iso9660.h
 *		(all are written by Eric Youngdale)
 */

/*
 * Modified by SONE Takeshi to work with FILO
 */

#ifndef _ISO9660_H_
#define _ISO9660_H_

#define ISO_SECTOR_BITS              (11)
#define ISO_SECTOR_SIZE              (1<<ISO_SECTOR_BITS)

#define	ISO_REGULAR	1	/* regular file	*/
#define	ISO_DIRECTORY	2	/* directory	*/
#define	ISO_OTHER	0	/* other file (with Rock Ridge) */

#define	RR_FLAG_PX	0x01	/* have POSIX file attributes */
#define	RR_FLAG_NM	0x08	/* have alternate file name   */

/* POSIX file attributes for Rock Ridge extensions */
#define	POSIX_S_IFMT	0xF000
#define	POSIX_S_IFREG	0x8000
#define	POSIX_S_IFDIR	0x4000

/* volume descriptor types */
#define ISO_VD_PRIMARY 1
#define ISO_VD_END 255

#define ISO_STANDARD_ID "CD001"

#ifndef ASM_FILE

typedef	union {
	uint8_t l,b;
}	iso_8bit_t;

typedef	struct __iso_16bit {
	uint16_t l, b;
} iso_16bit_t;

typedef	struct __iso_32bit {
	uint32_t l, b;
} iso_32bit_t;

typedef uint8_t		iso_date_t[7];

struct iso_directory_record {
	iso_8bit_t	length;
	iso_8bit_t	ext_attr_length;
	iso_32bit_t	extent;
	iso_32bit_t	size;
	iso_date_t	date;
	iso_8bit_t	flags;
	iso_8bit_t	file_unit_size;
	iso_8bit_t	interleave;
	iso_16bit_t	volume_seq_number;
	iso_8bit_t	name_len;
	uint8_t	name[1];
} __attribute__ ((packed));

struct iso_primary_descriptor {
	iso_8bit_t	type;
	uint8_t		id[5];
	iso_8bit_t	version;
	uint8_t		_unused1[1];
	uint8_t		system_id[32];
	uint8_t		volume_id[32];
	uint8_t		_unused2[8];
	iso_32bit_t	volume_space_size;
	uint8_t		_unused3[32];
	iso_16bit_t	volume_set_size;
	iso_16bit_t	volume_seq_number;
	iso_16bit_t	logical_block_size;
	iso_32bit_t	path_table_size;
	uint8_t		type_l_path_table[4];
	uint8_t		opt_type_l_path_table[4];
	uint8_t		type_m_path_table[4];
	uint8_t		opt_type_m_path_table[4];
	struct iso_directory_record root_directory_record;
	uint8_t		volume_set_id[128];
	uint8_t		publisher_id[128];
	uint8_t		preparer_id[128];
	uint8_t		application_id[128];
	uint8_t		copyright_file_id[37];
	uint8_t		abstract_file_id[37];
	uint8_t		bibliographic_file_id[37];
	uint8_t		creation_date[17];
	uint8_t		modification_date[17];
	uint8_t		expiration_date[17];
	uint8_t		effective_date[17];
	iso_8bit_t	file_structure_version;
	uint8_t		_unused4[1];
	uint8_t		application_data[512];
	uint8_t		_unused5[653];
} __attribute__ ((packed));

struct rock_ridge {
	uint16_t	signature;
	uint8_t		len;
	uint8_t		version;
	union {
	  struct CE {
	    iso_32bit_t	extent;
	    iso_32bit_t	offset;
	    iso_32bit_t	size;
	  } ce;
	  struct NM {
	    iso_8bit_t	flags;
	    uint8_t	name[0];
	  } nm;
	  struct PX {
	    iso_32bit_t	mode;
	    iso_32bit_t	nlink;
	    iso_32bit_t	uid;
	    iso_32bit_t	gid;
	  } px;
	  struct RR {
	    iso_8bit_t	flags;
	  } rr;
	} u;
} __attribute__ ((packed));

typedef	union RR_ptr {
	struct rock_ridge *rr;
	char		  *ptr;
	int		   i;
} RR_ptr_t;

#define CHECK2(ptr, c1, c2)                                             \
    (*(unsigned char *)(ptr) == (c1) &&                                 \
     *((unsigned char *)(ptr) + 1) == (c2))
#define	CHECK4(ptr, c1, c2, c3, c4)                                     \
    (*(unsigned char *)(ptr) == (c1) &&                                 \
     *((unsigned char *)(ptr) + 1) == (c2) &&                           \
     *((unsigned char *)(ptr) + 2) == (c3) &&                           \
     *((unsigned char *)(ptr) + 3) == (c4))

#endif /* !ASM_FILE */

#endif /* _ISO9660_H_ */
