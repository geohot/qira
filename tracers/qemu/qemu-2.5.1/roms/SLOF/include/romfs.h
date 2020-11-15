/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/
#ifndef ROMFS_H
#define ROMFS_H

#define RFS_T_SIZE	0x00
#define RFS_T_FLAGS	0x08
#define RFS_T_FILEADDR	0x10
#define RFS_T_NEXT	0x18
#define RFS_T_NAME	0x20
#define RFS_T_DATA	0x28

#define RFS_H_NEXT	0x00
#define RFS_H_SIZE	0x08
#define RFS_H_FLAGS	0x10
#define RFS_H_DATA	0x18
#define RFS_H_NAME	0x20

#define ROMFS_HDR_NEXT (0 * 8)
#define ROMFS_HDR_LEN  (1 * 8)
#define ROMFS_HDR_FLAG (2 * 8)
#define ROMFS_HDR_DPTR (3 * 8)
#define ROMFS_HDR_NAME (4 * 8)

#ifndef  __ASSEMBLER__
/* no not change except if you change romfs.S */
struct romfs_t {
	unsigned long	size;
	unsigned long	flags;
	unsigned long	fileaddr;
	unsigned long	nexfile;
	unsigned char	*namep;
	unsigned char	*datap;
};

struct romfs_lookup_t {
	unsigned long	addr_header;
	unsigned long	addr_data;
	unsigned long	size_data;
	unsigned long	flags;
};

int romfs_stat(char *filename, struct romfs_t *hnd);

int romfs_stat_file(char *filename, struct romfs_t *hnd);

int c_romfs_lookup(char *filename, unsigned long rombase,
		struct romfs_lookup_t *ret);

#endif		/*  __ASSEMBLER__ */
#endif		/* ROMFS_H */
