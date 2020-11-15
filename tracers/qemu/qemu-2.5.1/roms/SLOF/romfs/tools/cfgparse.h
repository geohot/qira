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
#ifndef CFGPARSE_H
#define CFGPARSE_H

#include <byteswap.h>
#include <endian.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_be64(x)	(x)
#else
#define cpu_to_be64(x)	bswap_64(x)
#endif

struct ffs_chain_t {
	int count;
	unsigned int romfs_size;
	struct ffs_header_t *first;
};

#define FLAG_LLFW 1		/* low level firmware at fix offs in romfs */

#define needs_fix_offset(hdr) ((hdr)->flags & FLAG_LLFW)

struct ffs_header_t {
	unsigned long long flags;
	unsigned long long romaddr;
	char *token;
	char *imagefile;
	int imagefile_length;
	struct ffs_header_t *linked_to;
	struct ffs_header_t *next;
	unsigned long long save_data;
	unsigned long long save_data_len;
	int save_data_valid;

	unsigned long long addr;	/* tmp */
	int hdrsize;		/* tmp */
	int tokensize;		/* tmp */
	int ffsize;		/* tmp */
};

void dump_fs_contents(struct ffs_chain_t *chain);
void find_duplicates(struct ffs_chain_t *chain);
void free_chain_memory(struct ffs_chain_t *chain);

int read_config(int conf_file, struct ffs_chain_t *ffs_chain);
int reorder_ffs_chain(struct ffs_chain_t *fs);
int build_ffs(struct ffs_chain_t *fs, const char *outfile, int notime);
#endif
