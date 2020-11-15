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

#include "cache.h"
#include "nvram.h"
#include "../libhvcall/libhvcall.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <southbridge.h>
#include <nvramlog.h>
#include <byteorder.h>

#ifdef RTAS_NVRAM
static uint32_t fetch_token;
static uint32_t store_token;
static uint32_t NVRAM_LENGTH;
static char *nvram_buffer; /* use buffer allocated by SLOF code */
#else
#ifndef NVRAM_LENGTH
#define NVRAM_LENGTH	0x10000
#endif
/*
 * This is extremely ugly, but still better than implementing 
 * another sbrk() around it.
 */
static char nvram_buffer[NVRAM_LENGTH];
#endif

static uint8_t nvram_buffer_locked=0x00;

void nvram_init(uint32_t _fetch_token, uint32_t _store_token, 
		long _nvram_length, void* nvram_addr)
{
#ifdef RTAS_NVRAM
	fetch_token = _fetch_token;
	store_token = _store_token;
	NVRAM_LENGTH = _nvram_length;
	nvram_buffer = nvram_addr;

	DEBUG("\nNVRAM: size=%d, fetch=%x, store=%x\n",
		NVRAM_LENGTH, fetch_token, store_token);
#endif
}


void asm_cout(long Character,long UART,long NVRAM);

#if defined(DISABLE_NVRAM)

static volatile uint8_t nvram[NVRAM_LENGTH]; /* FAKE */

#define nvram_access(type,size,name) 				\
	type nvram_read_##name(unsigned int offset)		\
	{							\
		type *pos;					\
		if (offset > (NVRAM_LENGTH - sizeof(type)))	\
			return 0;				\
		pos = (type *)(nvram+offset);			\
		return *pos;					\
	}							\
	void nvram_write_##name(unsigned int offset, type data)	\
	{							\
		type *pos;					\
		if (offset > (NVRAM_LENGTH - sizeof(type)))	\
			return;					\
		pos = (type *)(nvram+offset);			\
		*pos = data;					\
	}

#elif defined(RTAS_NVRAM)

static inline void nvram_fetch(unsigned int offset, void *buf, unsigned int len)
{
 	struct hv_rtas_call rtas = {
		.token = fetch_token,
		.nargs = 3,
		.nrets = 2,
		.argret = { offset, (uint32_t)(unsigned long)buf, len },
	};
	h_rtas(&rtas);
}

static inline void nvram_store(unsigned int offset, void *buf, unsigned int len)
{
	struct hv_rtas_call rtas = {
		.token = store_token,
		.nargs = 3,
		.nrets = 2,
		.argret = { offset, (uint32_t)(unsigned long)buf, len },
	};
	h_rtas(&rtas);
}

#define nvram_access(type,size,name) 				\
	type nvram_read_##name(unsigned int offset)		\
	{							\
		type val;					\
		if (offset > (NVRAM_LENGTH - sizeof(type)))	\
			return 0;				\
		nvram_fetch(offset, &val, size / 8);		\
		return val;					\
	}							\
	void nvram_write_##name(unsigned int offset, type data)	\
	{							\
		if (offset > (NVRAM_LENGTH - sizeof(type)))	\
			return;					\
		nvram_store(offset, &data, size / 8);		\
	}

#else	/* DISABLE_NVRAM */

static volatile uint8_t *nvram = (volatile uint8_t *)SB_NVRAM_adr;

#define nvram_access(type,size,name) 				\
	type nvram_read_##name(unsigned int offset)		\
	{							\
		type *pos;					\
		if (offset > (NVRAM_LENGTH - sizeof(type)))	\
			return 0;				\
		pos = (type *)(nvram+offset);			\
		return ci_read_##size(pos);			\
	}							\
	void nvram_write_##name(unsigned int offset, type data)	\
	{							\
		type *pos;					\
		if (offset > (NVRAM_LENGTH - sizeof(type)))	\
			return;					\
		pos = (type *)(nvram+offset);			\
		ci_write_##size(pos, data);			\
	}

#endif

/*
 * producer for nvram access functions. Since these functions are
 * basically all the same except for the used data types, produce 
 * them via the nvram_access macro to keep the code from bloating.
 */

nvram_access(uint8_t,   8, byte)
nvram_access(uint16_t, 16, word)
nvram_access(uint32_t, 32, dword)
nvram_access(uint64_t, 64, qword)



/**
 * This function is a minimal abstraction for our temporary
 * buffer. It should have been malloced, but since there is no
 * usable malloc, we go this route.
 *
 * @return pointer to temporary buffer
 */

char *get_nvram_buffer(int len)
{
	if(len>NVRAM_LENGTH)
		return NULL;

	if(nvram_buffer_locked)
		return NULL;

	nvram_buffer_locked = 0xff;

	return nvram_buffer;
}

/**
 * @param buffer pointer to the allocated buffer. This
 * is unused, but nice in case we ever get a real malloc
 */

void free_nvram_buffer(char *buffer __attribute__((unused)))
{
	nvram_buffer_locked = 0x00;
}

/**
 * @param fmt format string, like in printf
 * @param ... variable number of arguments
 */

int nvramlog_printf(const char* fmt, ...)
{
	char buff[256];
	int count, i;
	va_list ap;

	va_start(ap, fmt);
	count = vsprintf(buff, fmt, ap);
	va_end(ap);

	for (i=0; i<count; i++)
		asm_cout(buff[i], 0, 1);

	return count;
}

/**
 * @param offset start offset of the partition header
 */

static uint8_t get_partition_type(int offset)
{
	return nvram_read_byte(offset);
}

/**
 * @param offset start offset of the partition header
 */

static uint8_t get_partition_header_checksum(int offset)
{
	return nvram_read_byte(offset+1);
}

/**
 * @param offset start offset of the partition header
 */

static uint16_t get_partition_len(int offset)
{
	return nvram_read_word(offset+2);
}

/**
 * @param offset start offset of the partition header
 * @return static char array containing the partition name
 *
 * NOTE: If the partition name needs to be non-temporary, strdup 
 * and use the copy instead.
 */

static char * get_partition_name(int offset)
{
	static char name[12];
	int i;
	for (i=0; i<12; i++)
		name[i]=nvram_read_byte(offset+4+i);

	DEBUG("name: \"%s\"\n", name);
	return name;
}

static uint8_t calc_partition_header_checksum(int offset)
{
	uint16_t plainsum;
	uint8_t checksum;
	int i;

	plainsum = nvram_read_byte(offset);

	for (i=2; i<PARTITION_HEADER_SIZE; i++)
		plainsum+=nvram_read_byte(offset+i);

	checksum=(plainsum>>8)+(plainsum&0xff);

	return checksum;
}

static int calc_used_nvram_space(void)
{
	int walk, len;

	for (walk=0; walk<NVRAM_LENGTH;) {
		if(nvram_read_byte(walk) == 0 
		   || get_partition_header_checksum(walk) != 
				calc_partition_header_checksum(walk)) {
			/* If there's no valid entry, bail out */
			break;
		}

		len=get_partition_len(walk);
		DEBUG("... part len=%x, %x\n", len, len*16);

		if(!len) {
			/* If there's a partition type but no len, bail out.
			 * Don't bail out if type is 0. This can be used to
			 * find the offset of the first free byte.
			 */
			break;
		}

		walk += len * 16;
	}
	DEBUG("used nvram space: %d\n", walk);

	return walk;
}

/**
 *
 * @param type partition type. Set this to the partition type you are looking
 *             for. If there are several partitions with the same type, only
 *             the first partition with that type will be found.
 *             Set to -1 to ignore. Set to 0 to find free unpartitioned space.
 *
 * @param name partition name. Set this to the name of the partition you are
 *             looking for. If there are several partitions with the same name,
 *             only the first partition with that name will be found.
 *             Set to NULL to ignore.
 *
 * To disambiguate the partitions you should have a unique name if you plan to
 * have several partitions of the same type.
 *
 */

partition_t get_partition(unsigned int type, char *name)
{
	partition_t ret={0,-1};
	int walk, len;

	DEBUG("get_partition(%i, '%s')\n", type, name);

	for (walk=0; walk<NVRAM_LENGTH;) {
		// DEBUG("get_partition: walk=%x\n", walk);
		if(get_partition_header_checksum(walk) != 
				calc_partition_header_checksum(walk)) {
			/* If there's no valid entry, bail out */
			break;
		}

		len=get_partition_len(walk);
		if(type && !len) {
			/* If there's a partition type but no len, bail out.
			 * Don't bail out if type is 0. This can be used to
			 * find the offset of the first free byte.
			 */
			break;
		}

		/* Check if either type or name or both do not match. */
		if ( (type!=(unsigned int)-1 && type != get_partition_type(walk)) ||
			(name && strncmp(get_partition_name(walk), name, 12)) ) {
			/* We hit another partition. Continue
			 * at the end of this partition
			 */
			walk += len*16;
			continue;
		}

		ret.addr=walk+PARTITION_HEADER_SIZE;
		ret.len=(len*16)-PARTITION_HEADER_SIZE;
		break;
	}

	return ret;
}

void erase_nvram(int offset, int len)
{
	int i;

	for (i=offset; i<offset+len; i++)
		nvram_write_byte(i, 0);
}

void wipe_nvram(void)
{
	erase_nvram(0, NVRAM_LENGTH);
}

/**
 * @param partition   partition structure pointing to the partition to wipe.
 * @param header_only if header_only is != 0 only the partition header is
 *                    nulled out, not the whole partition.
 */

int wipe_partition(partition_t partition, int header_only)
{
	int pstart, len;

	pstart=partition.addr-PARTITION_HEADER_SIZE;
	
	len=PARTITION_HEADER_SIZE;

	if(!header_only)
		len += partition.len;

	erase_nvram(pstart, len);

	return 0;
}


static partition_t create_nvram_partition(int type, const char *name, int len)
{
	partition_t ret = { 0, 0 };
	int offset, plen;
	unsigned int i;

	plen = ALIGN(len+PARTITION_HEADER_SIZE, 16);

	DEBUG("Creating partition type=%x, name=%s, len=%d plen=%d\n",
			type, name, len, plen);

	offset = calc_used_nvram_space();

	if (NVRAM_LENGTH-(calc_used_nvram_space())<plen) {
		DEBUG("Not enough free space.\n");
		return ret;
	}

	DEBUG("Writing header.");

	nvram_write_byte(offset, type);
	nvram_write_word(offset+2, plen/16);

	for (i=0; i<strlen(name); i++)
		nvram_write_byte(offset+4+i, name[i]);

	nvram_write_byte(offset+1, calc_partition_header_checksum(offset));

	ret.addr = offset+PARTITION_HEADER_SIZE;
	ret.len = len;

	DEBUG("partition created: addr=%lx len=%lx\n", ret.addr, ret.len);

	return ret;
}

static int create_free_partition(void)
{
	int free_space;
	partition_t free_part;

	free_space = NVRAM_LENGTH - calc_used_nvram_space() - PARTITION_HEADER_SIZE;
	free_part = create_nvram_partition(0x7f, "free space", free_space);

	return (free_part.addr != 0);
}

partition_t new_nvram_partition(int type, char *name, int len)
{
	partition_t free_part, new_part = { 0, 0 };

	/* NOTE: Assume all free space is consumed by the "free space"
	 * partition. This means a partition can not be increased in the middle
	 * of reset_nvram, which is obviously not a big loss.
	 */

	free_part=get_partition(0x7f, NULL);
	if( free_part.len && free_part.len != -1)
		wipe_partition(free_part, 1);

	new_part = create_nvram_partition(type, name, len);

	if(new_part.len != len) {
		new_part.len = 0;
		new_part.addr = 0;
	}

	create_free_partition();

	return new_part;
}

/**
 * @param partition   partition structure pointing to the partition to wipe.
 */

int delete_nvram_partition(partition_t partition)
{
	int i;
	partition_t free_part;

	if(!partition.len || partition.len == -1)
		return 0;

	for (i=partition.addr+partition.len; i< NVRAM_LENGTH; i++) 
		nvram_write_byte(i - partition.len - PARTITION_HEADER_SIZE, nvram_read_byte(i));

	erase_nvram(NVRAM_LENGTH-partition.len-PARTITION_HEADER_SIZE, 
			partition.len-PARTITION_HEADER_SIZE);

	free_part=get_partition(0x7f, NULL);
	wipe_partition(free_part, 0);
	create_free_partition();

	return 1;
}

int clear_nvram_partition(partition_t part)
{
	if(!part.addr)
		return 0;

	erase_nvram(part.addr, part.len);

	return 1;
}


int increase_nvram_partition_size(partition_t partition, int newsize)
{
	partition_t free_part;
	int free_offset, end_offset, i;

	/* We don't support shrinking partitions (yet) */
	if (newsize < partition.len) {
		return 0;
	}

	/* NOTE: Assume all free space is consumed by the "free space"
	 * partition. This means a partition can not be increased in the middle
	 * of reset_nvram, which is obviously not a big loss.
	 */

	free_part=get_partition(0x7f, NULL);

	// FIXME: It could be 16 byte more. Also handle empty "free" partition.
	if (free_part.len == -1 || free_part.len < newsize - partition.len ) {
		return 0;
	}
	
	free_offset=free_part.addr - PARTITION_HEADER_SIZE; // first unused byte
	end_offset=partition.addr + partition.len; // last used byte of partition + 1

	if(free_offset > end_offset) {
		int j, bufferlen;
		char *overlap_buffer;

		bufferlen=free_offset - end_offset;

		overlap_buffer=get_nvram_buffer(bufferlen);
		if(!overlap_buffer) {
			return 0;
		}

		for (i=end_offset, j=0; i<free_offset; i++, j++)
			overlap_buffer[j]=nvram_read_byte(i);

		/* Only wipe the header. The free space partition is empty per
		 * definition
		 */

		wipe_partition(free_part, 1);

		for (i=partition.addr+newsize, j=0; i<(int)(partition.addr+newsize+bufferlen); i++, j++)
			nvram_write_byte(i, overlap_buffer[j]);

		free_nvram_buffer(overlap_buffer);
	} else {
		/* Only wipe the header. */
		wipe_partition(free_part, 1);
	}

	/* Clear the new partition space */
	erase_nvram(partition.addr+partition.len, newsize-partition.len);

	nvram_write_word(partition.addr - 16 + 2, newsize);

	create_free_partition();

	return 1;
}

static void init_cpulog_partition(partition_t cpulog)
{
	unsigned int offset=cpulog.addr;

	/* see board-xxx/include/nvramlog.h for information */
	nvram_write_word(offset+0, 0x40);  // offset
	nvram_write_word(offset+2, 0x00);  // flags
	nvram_write_dword(offset+4, 0x01); // pointer

}

void reset_nvram(void)
{
	partition_t cpulog0, cpulog1;
	struct {
		uint32_t prefix;
		uint64_t name;
	} __attribute__((packed)) header;

	DEBUG("Erasing NVRAM\n");
	erase_nvram(0, NVRAM_LENGTH);

	DEBUG("Creating CPU log partitions\n");
	header.prefix = be32_to_cpu(LLFW_LOG_BE0_NAME_PREFIX);
	header.name   = be64_to_cpu(LLFW_LOG_BE0_NAME);
	cpulog0=create_nvram_partition(LLFW_LOG_BE0_SIGNATURE, (char *)&header, 
			(LLFW_LOG_BE0_LENGTH*16)-PARTITION_HEADER_SIZE);

	header.prefix = be32_to_cpu(LLFW_LOG_BE1_NAME_PREFIX);
	header.name   = be64_to_cpu(LLFW_LOG_BE1_NAME);
	cpulog1=create_nvram_partition(LLFW_LOG_BE1_SIGNATURE, (char *)&header, 
			(LLFW_LOG_BE1_LENGTH*16)-PARTITION_HEADER_SIZE);

	DEBUG("Initializing CPU log partitions\n");
	init_cpulog_partition(cpulog0);
	init_cpulog_partition(cpulog1);

	nvramlog_printf("Creating common NVRAM partition\r\n");
	create_nvram_partition(0x70, "common", 0x01000-PARTITION_HEADER_SIZE);

	create_free_partition();
}

void nvram_debug(void)
{
#ifndef RTAS_NVRAM
	printf("\nNVRAM_BASE: %p\n", nvram);
	printf("NVRAM_LEN: 0x%x\n", NVRAM_LENGTH);
#endif
}

unsigned int get_nvram_size(void)
{
	return NVRAM_LENGTH;
}
