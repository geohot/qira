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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <cfgparse.h>
#include <createcrc.h>

#define FFS_TARGET_HEADER_SIZE (4 * 8)

extern int verbose;

#define pad8_num(x) (((x) + 7) & ~7)

static int
file_exist(const char *name, int errdisp)
{
	struct stat fileinfo;

	memset((void *) &fileinfo, 0, sizeof(struct stat));
	if (stat(name, &fileinfo) != 0) {
		if (0 != errdisp) {
			perror(name);
		}
		return 0;
	}
	if (S_ISREG(fileinfo.st_mode)) {
		return 1;
	}
	return 0;
}

static int
file_getsize(const char *name)
{
	int rc;
	struct stat fi;

	rc = stat(name, &fi);
	if (rc != 0)
		return -1;
	return fi.st_size;
}

static int
ffshdr_compare(const void *_a, const void *_b)
{
	const struct ffs_header_t *a = *(struct ffs_header_t * const *) _a;
	const struct ffs_header_t *b = *(struct ffs_header_t * const *) _b;

	if (a->romaddr == b->romaddr)
		return 0;
	if (a->romaddr > b->romaddr)
		return 1;
	return -1;
}

static void
hdr_print(struct ffs_header_t *hdr)
{
	printf("hdr: %p\n", hdr);
	printf("\taddr:      %08llx token:    %s\n"
	       "\tflags:     %08llx romaddr:  %08llx image_len: %08x\n"
	       "\tsave_len:  %08llx ffsize:   %08x hdrsize:   %08x\n"
	       "\ttokensize: %08x\n",
	       hdr->addr, hdr->token, hdr->flags, hdr->romaddr,
	       hdr->imagefile_length, hdr->save_data_len,
	       hdr->ffsize, hdr->hdrsize, hdr->tokensize);
}

int
reorder_ffs_chain(struct ffs_chain_t *fs)
{
	int i, j;
	int free_space;
	unsigned long long addr;
	struct ffs_header_t *hdr;
	int fix, flx, res, tab_size = fs->count;
	struct ffs_header_t *fix_tab[tab_size];	/* fixed offset */
	struct ffs_header_t *flx_tab[tab_size];	/* flexible offset */
	struct ffs_header_t *res_tab[tab_size];	/* result */

	/* determine size data to be able to do the reordering */
	for (hdr = fs->first; hdr; hdr = hdr->next) {
		if (hdr->linked_to)
			hdr->imagefile_length = 0;
		else
			hdr->imagefile_length = file_getsize(hdr->imagefile);
		if (hdr->imagefile_length == -1)
			return -1;

		hdr->tokensize = pad8_num(strlen(hdr->token) + 1);
		hdr->hdrsize = FFS_TARGET_HEADER_SIZE + hdr->tokensize;
		hdr->ffsize =
		    hdr->hdrsize + pad8_num(hdr->imagefile_length) + 8;
	}

	memset(res_tab, 0, tab_size * sizeof(struct ffs_header_t *));
	memset(fix_tab, 0, tab_size * sizeof(struct ffs_header_t *));
	memset(flx_tab, 0, tab_size * sizeof(struct ffs_header_t *));

	/* now start with entries having fixed offs, reorder if needed */
	for (fix = 0, flx = 0, hdr = fs->first; hdr; hdr = hdr->next)
		if (needs_fix_offset(hdr))
			fix_tab[fix++] = hdr;
		else
			flx_tab[flx++] = hdr;
	qsort(fix_tab, fix, sizeof(struct ffs_header_t *), ffshdr_compare);

	/*
	 * for fixed files we need to also remove the hdrsize from the
	 * free space because it placed in front of the romaddr
	 */
	for (addr = 0, res = 0, i = 0, j = 0; i < fix; i++) {
		fix_tab[i]->addr = fix_tab[i]->romaddr - fix_tab[i]->hdrsize;
		free_space = fix_tab[i]->addr - addr;

		/* insert as many flexible files as possible */
		for (; free_space > 0 && j < flx; j++) {
			if (flx_tab[j]->ffsize <= free_space) {	/* fits */
				flx_tab[j]->addr = addr;
				free_space -= flx_tab[j]->ffsize;
				addr += flx_tab[j]->ffsize;
				res_tab[res++] = flx_tab[j];
			} else
				break;
		}
		res_tab[res++] = fix_tab[i];
		addr = fix_tab[i]->romaddr + fix_tab[i]->ffsize -
		    fix_tab[i]->hdrsize;
	}
	/* at the end fill up the table with remaining flx entries */
	for (; j < flx; j++) {
		flx_tab[j]->addr = addr;
		addr += flx_tab[j]->ffsize;
		res_tab[res++] = flx_tab[j];
	}

	if (verbose) {
		printf("--- resulting order ---\n");
		for (i = 0; i < tab_size; i++)
			hdr_print(res_tab[i]);
	}

	/* to check if the requested romfs images is greater than
	 * the specified romfs_size it is necessary to add 8 for
	 * the CRC to the totalsize */
	addr += 8;

	/* sanity checking if user specified maximum romfs size */
	if ((fs->romfs_size != 0) && addr > fs->romfs_size) {
		fprintf(stderr, "[build_romfs] romfs_size specified as %d "
			"bytes, but %lld bytes need to be written.\n",
			fs->romfs_size, addr);
		return 1;
	}

	/* resort result list */
	for (i = 0; i < tab_size - 1; i++)
		res_tab[i]->next = res_tab[i + 1];
	res_tab[i]->next = NULL;
	fs->first = res_tab[0];
	return 0;
}

/**
 * allocate memory for a romfs file including header
 */
static unsigned char *
malloc_file(int hdrsz, int datasz, int *ffsz)
{
	void *tmp;

	/* complete file size is:
	 * header + 8byte aligned(data) + end of file marker (-1) */
	*ffsz = hdrsz + pad8_num(datasz) + 8;
	/* get the mem */
	tmp = malloc(*ffsz);

	if (!tmp)
		return NULL;

	memset(tmp, 0, *ffsz);

	return (unsigned char *) tmp;
}

static int
copy_file(struct ffs_header_t *hdr, unsigned char *ffile, int datasize,
	  int ffile_offset, int ffsize)
{
	int cnt = 0;
	int imgfd;
	int i;

	if (!file_exist(hdr->imagefile, 1)) {
		printf("access error to file: %s\n", hdr->imagefile);
		free(ffile);
		return -1;
	}

	imgfd = open(hdr->imagefile, O_RDONLY);
	if (0 >= imgfd) {
		perror(hdr->imagefile);
		free(ffile);
		return -1;
	}

	/* now copy file to file buffer */
	/* FIXME using fread might be a good idea so
	   that we do not need to deal with shortened
	   reads/writes. Also error handling looks
	   broken to me. Are we sure that all data is
	   read when exiting this loop? */
	while (1) {
		i = read(imgfd, ffile + ffile_offset, ffsize - ffile_offset);
		if (i <= 0)
			break;
		ffile_offset += i;
		cnt += i;
	}

	/* sanity check */
	if (cnt != datasize) {
		printf("BUG!!! copy error on image file [%s](e%d, g%d)\n",
		       hdr->imagefile, datasize, cnt);
		close(imgfd);
		free(ffile);
		return -1;
	}

	close(imgfd);

	return cnt;
}

static uint64_t
next_file_offset(struct ffs_header_t *hdr, int rom_pos, int ffsize)
{
	uint64_t tmp;

	/* no next file; end of filesystem */
	if (hdr->next == NULL)
		return 0;

	if (hdr->next->romaddr > 0) {
		/* the next file does not follow directly after the
		 * current file because it requested to be
		 * placed at a special address;
		 * we need to calculate the offset of the
		 * next file;
		 * the next file starts at hdr->next->romaddr which
		 * is the address requested by the user */
		tmp = hdr->next->romaddr;
		/* the next file starts, however, a bit earlier;
		 * we need to point at the header of the next file;
		 * therefore it is necessary to subtract the header size
		 * of the _next_ file */
		tmp -= FFS_TARGET_HEADER_SIZE;
		/* also remove the length of the filename of the _next_
		 * file */
		tmp -= pad8_num(strlen(hdr->next->token) + 1);
		/* and it needs to be relative to the current file */
		tmp -= rom_pos;
		return tmp;
	}

	/* if no special treatment is required the next file just
	 * follows after the current file;
	 * therefore just return the complete filesize as offset */
	return ffsize;
}

static int
next_file_address(struct ffs_header_t *hdr, unsigned int rom_pos, int hdrsize,
		  unsigned int num_files)
{
	/* check if file wants a specific address */
	void *tmp;

	if ((hdr->flags & FLAG_LLFW) == 0)
		/* flag to get a specific address has been set */
		return rom_pos;

	if (hdr->romaddr == 0)
		/* if the requested address is 0 then
		 * something is not right; ignore the flag */
		return rom_pos;

	/* check if romaddress is below current position */
	if (hdr->romaddr < (rom_pos + hdrsize)) {
		printf("[%s] ERROR: requested impossible " "romaddr of %llx\n",
		       hdr->token, hdr->romaddr);
		return -1;
	}

	/* spin offset to new position */
	if (pad8_num(hdr->romaddr) != hdr->romaddr) {
		printf("BUG!!!! pad8_num(hdr->romaddr) != hdr->romaddr\n");
		return -1;
	}

	tmp = malloc(hdr->romaddr - rom_pos - hdrsize);

	if (!tmp)
		return -1;

	memset(tmp, 0, hdr->romaddr - rom_pos - hdrsize);
	if (buildDataStream(tmp, hdr->romaddr - rom_pos - hdrsize)) {
		free(tmp);
		printf("write failed\n");
		return -1;
	}

	free(tmp);

	if (!num_files)
		printf("\nWARNING: The filesystem will have no entry header!\n"
		       "         It is still usable but you need to find\n"
		       "         the FS by yourself in the image.\n\n");

	return hdr->romaddr - hdrsize;
}

int
build_ffs(struct ffs_chain_t *fs, const char *outfile, int notime)
{
	int ofdCRC;
	int ffsize, datasize, i;
	int tokensize, hdrsize, ffile_offset, hdrbegin;
	struct ffs_header_t *hdr;
	unsigned char *ffile;
	unsigned int rom_pos = 0;
	unsigned int num_files = 0;
	uint64_t tmp;

	if (NULL == fs->first) {
		return 1;
	}
	hdr = fs->first;

	/* check output file and open it for creation */
	if (file_exist(outfile, 0)) {
		printf("Output file (%s) will be overwritten\n", outfile);
	}

	while (hdr) {

		if (hdr->linked_to) {
			printf("\nBUG!!! links not supported anymore\n");
			return 1;
		}

		/* add +1 to strlen for zero termination */
		tokensize = pad8_num(strlen(hdr->token) + 1);
		hdrsize = FFS_TARGET_HEADER_SIZE + tokensize;
		datasize = file_getsize(hdr->imagefile);

		if (datasize == -1) {
			perror(hdr->imagefile);
			return 1;
		}

		ffile_offset = 0;
		ffile = malloc_file(hdrsize, datasize, &ffsize);

		if (NULL == ffile) {
			perror("alloc mem for ffile");
			return 1;
		}

		/* check if file wants a specific address */
		rom_pos = next_file_address(hdr, rom_pos, hdrsize, num_files);
		hdrbegin = rom_pos;

		if (hdrbegin == -1) {
			/* something went wrong */
			free(ffile);
			return 1;
		}

		/* write header ******************************************* */
		/* next addr ********************************************** */
		tmp = next_file_offset(hdr, rom_pos, ffsize);

		*(uint64_t *) (ffile + ffile_offset) = cpu_to_be64(tmp);
		rom_pos += 8;
		ffile_offset += 8;

		/* length ************************************************* */
		hdr->save_data_len = datasize;

		*(uint64_t *) (ffile + ffile_offset) = cpu_to_be64(datasize);
		rom_pos += 8;
		ffile_offset += 8;

		/* flags ************************************************** */
		*(uint64_t *) (ffile + ffile_offset) = cpu_to_be64(hdr->flags);
		rom_pos += 8;
		ffile_offset += 8;

		/* datapointer ******************************************** */

		//save-data pointer is relative to rombase
		hdr->save_data = hdrbegin + hdrsize;
		hdr->save_data_valid = 1;
		//changed pointers to be relative to file:
		tmp = hdr->save_data - hdrbegin;

		*(uint64_t *) (ffile + ffile_offset) = cpu_to_be64(tmp);
		rom_pos += 8;
		ffile_offset += 8;

		/* name (token) ******************************************* */
		memset(ffile + ffile_offset, 0, tokensize);
		strcpy((char *) ffile + ffile_offset, hdr->token);
		rom_pos += tokensize;
		ffile_offset += tokensize;

		/* image file ********************************************* */
		i = copy_file(hdr, ffile, datasize, ffile_offset, ffsize);

		if (i == -1)
			return 1;

		/* pad file */
		rom_pos += i + pad8_num(datasize) - datasize;
		ffile_offset += i + pad8_num(datasize) - datasize;

		/* limiter ************************************************ */
		*(uint64_t *) (ffile + ffile_offset) = -1;
		rom_pos += 8;
		ffile_offset += 8;

		if (buildDataStream(ffile, ffsize) != 0) {
			printf
			    ("Failed while processing file '%s' (size = %d bytes)\n",
			     hdr->imagefile, datasize);
			return 1;
		}
		free(ffile);
		hdr = hdr->next;
		num_files++;
	}

	/*
	 * FIXME Current limination seems to be about 4MiB.
	 */
	ofdCRC = open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (0 > ofdCRC) {
		perror(outfile);
		return 1;
	}
	i = writeDataStream(ofdCRC, notime);
	close(ofdCRC);

	if (i)
		return 1;
	return 0;
}
