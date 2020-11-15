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
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <cfgparse.h>

static int inbetween_white(char *s, int max, char **start, char **end,
			   char **next);
static int add_header(struct ffs_chain_t *, struct ffs_header_t *);

static int glob_come_from_cr = 0;

static int
find_next_entry(int file, struct ffs_chain_t *chain)
{
#define MAX_LINE_SIZE 1024
	char lnbuf[MAX_LINE_SIZE], b0 = 0, b1 = 0;
	char *start, *end, *next;
	struct ffs_header_t *hdr;	//, *hdr2;
	int lc, rc;
	char c;

	/* search for new config line */
	if (0 == glob_come_from_cr) {
		while (1 == (rc = read(file, &c, 1))) {
			//printf("b0=%c b1=%c c=%c\n",
			//              b0, b1, c);
			b0 = b1;
			b1 = c;
			/* this looks for starting sign "<CR>[^#]" */
			if (((0x0a == b0) || (0x0d == b0)) &&
			    (('#' != b1) && (0x0a != b1) && (0x0d != b1))) {
				break;
			}
		}
	} else {
		/* normalize */
		while (1 == (rc = read(file, &c, 1))) {
			//printf("read c=%c\n", c);
			if ((0x0a != c) && (0x0d != c)) {
				break;
			}
		}
		glob_come_from_cr = 0;
		//printf("debug: glob_come_from_cr = 0\n");
	}
	if (1 != rc) {
		return 1;
	}

	/* now buffer it until end of line */
	memset((void *) lnbuf, 0, MAX_LINE_SIZE);
	lnbuf[0] = c;
	lc = 1;
	while ((1 == read(file, &(lnbuf[lc]), 1)) && (lc < MAX_LINE_SIZE)) {
		//printf("read lnbuf=%c\n", lnbuf[lc]);
		if ((0x0a == lnbuf[lc]) || (0x0d == lnbuf[lc])) {
			glob_come_from_cr = 1;
			//printf("debug: glob_come_from_cr = 1\n");
			break;
		}
		lc++;
	}

	/* allocate header */
	hdr = malloc(sizeof(struct ffs_header_t));
	if (NULL == hdr) {
		perror("alloc memory");
		return 2;
	}
	memset((void *) hdr, 0, sizeof(struct ffs_header_t));

	/* attach header to chain */
	if (0 != add_header(chain, hdr)) {
		return 2;
	}

	/**********************************************************/
	/* extract token name *********************************** */
	start = NULL;
	if (inbetween_white(lnbuf, MAX_LINE_SIZE, &start, &end, &next) != 0) {
		printf("parsing error 1");
		return 2;
	}
	/* get memory for it */
	hdr->token = malloc(end - start + 1);
	if (NULL == hdr->token) {
		return 2;
	}
	/* set string */
	strncpy(hdr->token, start, end - start + 1);
	hdr->token[end - start] = 0;

	/**********************************************************/
	/* extract file name *********************************** */
	if (NULL == next) {
		return 2;
	}
	start = next;
	if (inbetween_white(lnbuf, MAX_LINE_SIZE, &start, &end, &next) != 0) {
		printf("parsing error 1");
		return 2;
	}

	/* get memory for it */
	hdr->imagefile = malloc(end - start + 1);
	if (NULL == hdr->imagefile) {
		return 2;
	}

	/* check if file is existing */

	/* set string */
	strncpy(hdr->imagefile, start, end - start + 1);
	hdr->imagefile[end - start] = 0;

	/* check if entry is linked to another header */
	if (':' == *start) {
		printf
		    ("\nERROR: links are removed as feature in this version\n");
		return 2;

		/*
		   start++;
		   if (0 != find_entry_by_token(chain, hdr->imagefile+1, &hdr2)) {
		   printf("[%s]: link to [%s] not found\n", 
		   hdr->token, hdr->imagefile+1);
		   dump_fs_contents(chain);
		   return 2;
		   }
		   hdr->linked_to = hdr2;
		 */
	}

	/**********************************************************/
	/* extract flags name *********************************** */
	if (NULL == next) {
		return 2;
	}
	start = next;
	if (inbetween_white(lnbuf, MAX_LINE_SIZE, &start, &end, &next) != 0) {
		printf("parsing error 1");
		return 2;
	}
	hdr->flags = strtoul(start, NULL, 16);

	/**********************************************************/
	/* extract rom start name *********************************** */
	if (NULL == next) {
		return 2;
	}
	start = next;
	if (inbetween_white(lnbuf, MAX_LINE_SIZE, &start, &end, &next) != 0) {
		printf("parsing error 1");
		return 2;
	}
	if ('-' == *start) {
		/* this means not specific address request for data */
		hdr->romaddr = 0;
	} else {
		/* data has to begin at specific address */
		hdr->romaddr = strtoul(start, NULL, 16);
	}

	return 0;
}

int
read_config(int conf_file, struct ffs_chain_t *ffs_chain)
{
	int rc;

	while (1) {
		rc = find_next_entry(conf_file, ffs_chain);
		if (rc != 0)
			break;
	}
	return rc;
}

static int
inbetween_white(char *s, int max, char **start, char **end, char **next)
{
	int pos = 0, posalt;

	if (NULL != *start) {
		pos = *start - s;
		s = *start;
	}

	/* wind to first non white */
	while (pos < max) {
		if ((' ' == *s) || ('	' == *s)) {
			s++;
			pos++;
			continue;
		}
		break;
	}
	if (pos >= max) {
		/* no non-white found */
		return 1;
	}

	/* assign start */
	*start = s;

	/* wind to end of non white or end of buffer */
	posalt = pos;
	while (pos < max) {
		if ((' ' == *s) || ('	' == *s) ||
		    (0x0a == *s) || (0x0d == *s)) {
			break;
		}
		s++;
		pos++;
	}

	if (pos == posalt) {
		return 1;
	}

	*end = s;

	if ((pos + 1) >= max) {
		*next = NULL;
	} else {
		*next = s;
	}

	return 0;
}

int
add_header(struct ffs_chain_t *chain, struct ffs_header_t *hdr)
{
	struct ffs_header_t *next;

	if (NULL == chain->first) {
		chain->count = 1;
		chain->first = hdr;
		return 0;
	}
	next = chain->first;

	/* find last */
	while (NULL != next->next) {
		next = next->next;
	}
	next->next = hdr;
	chain->count++;

	return 0;
}

void
dump_fs_contents(struct ffs_chain_t *chain)
{
	struct ffs_header_t *next;

	if (NULL == chain->first) {
		printf("no contents in fs\n");
		return;
	}
	next = chain->first;

	while (1) {
		if (NULL != next->token) {
			printf("Token [%s] ", next->token);
		} else {
			printf(" [not-set], ");
		}

		if (NULL != next->imagefile) {
			printf(" <%s>, ", next->imagefile);
		} else {
			printf(" file<not-set>, ");
		}

		printf("flags<%llx>, ", next->flags);
		printf("romaddr<%llx>, ", next->romaddr);

		if (NULL != next->linked_to) {
			printf("linked to [%s]", next->linked_to->token);
		}

		printf("\n");
		if (NULL == next->next) {
			break;
		}

		next = next->next;
	}

}

void
free_chain_memory(struct ffs_chain_t *chain)
{
	struct ffs_header_t *hdr, *next_hdr;

	if (NULL != chain->first) {
		hdr = chain->first;
		chain->first = NULL;
	} else {
		return;
	}

	while (NULL != hdr) {
		//printf("%p  ", hdr);
		if (NULL != hdr->token) {
			//printf("free up %s\n", hdr->token);
			free(hdr->token);
		}
		if (NULL != hdr->imagefile) {
			free(hdr->imagefile);
		}
		next_hdr = hdr->next;
		free(hdr);
		hdr = next_hdr;
	}
}


/*
 * Detect duplicate entries in the romfs list
 */
void
find_duplicates(struct ffs_chain_t *chain)
{
	struct ffs_header_t *act, *sub;

	if (NULL == chain->first) {
		printf("no contents in fs\n");
		return;
	}
	act = chain->first;

	do {
		sub = act->next;
		while (sub != NULL) {

			if (act->token == NULL || sub->token == NULL) {
				printf("find_duplicates: token not set!\n");
			} else if (strcmp(act->token, sub->token) == 0) {
				printf("*** NOTE: duplicate romfs file '%s'.\n",
				       act->token);
			}
			sub = sub->next;
		}

		act = act->next;

	} while (act != NULL);

}
