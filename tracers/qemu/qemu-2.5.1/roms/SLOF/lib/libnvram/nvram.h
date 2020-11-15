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

#ifndef __NVRAM_H
#define __NVRAM_H 1

/* data structures */

typedef struct {
	unsigned long addr;
	long len;
} partition_t;

/* macros */

#define DEBUG(x...)
// #define DEBUG(x...) printf(x);

#ifndef ALIGN
#define ALIGN(x, a) (((x) + ((a) - 1)) & ~((a) - 1))
#endif

#define NULL ((void *)0)

#define PARTITION_HEADER_SIZE 16


/* exported functions */

#define nvram_access_proto(type,name)			\
	type nvram_read_##name(unsigned int offset);		\
	void nvram_write_##name(unsigned int offset, type data);

nvram_access_proto(uint8_t,  byte)
nvram_access_proto(uint16_t, word)
nvram_access_proto(uint32_t, dword)
nvram_access_proto(uint64_t, qword)

/* nvram.c */

char *get_nvram_buffer(int len);
void free_nvram_buffer(char *buffer);
int nvramlog_printf(const char* fmt, ...);
partition_t get_partition(unsigned int type, char *name);
void erase_nvram(int offset, int len);
int wipe_partition(partition_t partition, int header_only);
partition_t new_nvram_partition(int type, char *name, int len);
int increase_nvram_partition_size(partition_t partition, int newsize);
int clear_nvram_partition(partition_t part);
int delete_nvram_partition(partition_t part);
void reset_nvram(void);
void wipe_nvram(void);
void nvram_debug(void);
void nvram_init(uint32_t store_token, uint32_t fetch_token,
		long nv_size, void* nvram_addr);
unsigned int get_nvram_size(void);

/* envvar.c */
char *get_env(partition_t part, char *envvar);
int add_env(partition_t part, char *envvar, char *value);
int del_env(partition_t part, char *envvar);
int set_env(partition_t part, char *envvar, char *value);

#endif
