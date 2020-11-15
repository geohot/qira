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
#include "../libc/include/stdio.h"
#include "../libc/include/string.h"
#include "../libc/include/stdlib.h"
#include "nvram.h"

/* returns the offset of the first byte after the searched envvar */
static int get_past_env_pos(partition_t part, char *envvar)
{
	int offset, len;
	static char temp[256];
	uint8_t data;

	offset=part.addr;

	memset(temp, 0, 256);

	do {
		len=0;
		while((data=nvram_read_byte(offset++)) && len < 256) {
			temp[len++]=data;
		}
		if (!strncmp(envvar, temp, strlen(envvar))) {
			return offset;
		}
	} while (len);

	return -1;
}

/**
 * @param partition name of the envvar partition
 * @param envvar name of the environment variable
 * @return pointer to temporary string containing the value of envvar
 */

char *get_env(partition_t part, char *envvar)
{
	static char temp[256+1];
	int len, offset;
	uint8_t data;

	DEBUG("get_env %s... ", envvar);
	if(!part.addr) {
		/* ERROR: No environment variable partition */
		DEBUG("invalid partition.\n");
		return NULL;
	}

	offset=part.addr;

	do {
		len=0;
		while((data=nvram_read_byte(offset++)) && len < 256) {
			temp[len++]=data;
		}
		temp[len]=0;

		if (!strncmp(envvar, temp, strlen(envvar))) {
			int pos=0;
			while (temp[pos]!='=' && pos < len) pos++;
			// DEBUG("value='%s'\n", temp+pos+1); 
			return temp+pos+1;
		}
	} while (len);

	DEBUG("not found\n");
	return NULL;
}

static int find_last_envvar(partition_t part)
{
	uint8_t last, current;
	int offset;

	offset=part.addr;

	last=nvram_read_byte(part.addr);

	for (offset=part.addr; offset<(int)(part.addr+part.len); offset++) {
		current=nvram_read_byte(offset);
		if(!last && !current)
			return offset;

		last=current;
	}

	return -1;
}

int add_env(partition_t part, char *envvar, char *value)
{
	int freespace, last, len, offset;
	unsigned int i;

	/* Find offset where we can write */
	last = find_last_envvar(part);

	/* How much space do we have left? */
	freespace = part.addr+part.len-last;

	/* how long is the entry we want to write? */
	len = strlen(envvar) + strlen(value) + 2;

	if(freespace<len) {
		// TODO try to increase partition size
		return -1;
	}

	offset=last;

	for(i=0; i<strlen(envvar); i++)
		nvram_write_byte(offset++, envvar[i]);

	nvram_write_byte(offset++, '=');

	for(i=0; i<strlen(value); i++)
		nvram_write_byte(offset++, value[i]);

	return 0;
}

int del_env(partition_t part, char *envvar)
{
	int last, current, pos, i;
	char *buffer;

	if(!part.addr)
		return -1;

	last=find_last_envvar(part);
	current = pos = get_past_env_pos(part, envvar);
	
	// TODO is this really required?
	/* go back to non-0 value */
	current--;

	while (nvram_read_byte(current))
		current--;

	// TODO is this required?
	current++;

	buffer=get_nvram_buffer(last-pos);

	for (i=0; i<last-pos; i++)
		buffer[i]=nvram_read_byte(i+pos);

	for (i=0; i<last-pos; i++)
		nvram_write_byte(i+current, buffer[i]);

	free_nvram_buffer(buffer);

	erase_nvram(last, current+last-pos);

	return 0;
}

int set_env(partition_t part, char *envvar, char *value)
{
	char *oldvalue, *buffer;
	int last, current, buffersize, i;

	DEBUG("set_env %lx[%lx]: %s=%s\n", part.addr, part.len, envvar, value);

	if(!part.addr)
		return -1;

	/* Check whether the environment variable exists already */
	oldvalue = get_env(part, envvar);

	if(oldvalue==NULL)
		return add_env(part, envvar, value);


	/* The value did not change. So we succeeded! */
	if(!strncmp(oldvalue, value, strlen(value)+1))
		return 0;

	/* we need to overwrite environment variables, back them up first */

	// DEBUG("overwriting existing environment variable\n");

	/* allocate a buffer */
	last=find_last_envvar(part);
	current=get_past_env_pos(part, envvar);
	buffersize = last - current;
	buffer=get_nvram_buffer(buffersize);
	if(!buffer)
		return -1;

	for (i=0; i<buffersize; i++) {
		buffer[i] = nvram_read_byte(current+i);
	}

	/* walk back until the = */
	while (nvram_read_byte(current)!='=') {
		current--;
	}

	/* Start at envvar= */
	current++;

	/* Write the new value */
	for(i=0; i<(int)strlen(value); i++) {
		nvram_write_byte(current++, value[i]);
	}
	
	/* Write end of string marker */
	nvram_write_byte(current++, 0);

	/* Copy back the buffer */
	for (i=0; i<buffersize; i++) {
		nvram_write_byte(current++, buffer[i]);
	}

	free_nvram_buffer(buffer);

	/* If the new environment variable content is shorter than the old one,
	 * we need to erase the rest of the bytes 
	 */

	if (current<last) {
		for(i=current; i<last; i++) {
			nvram_write_byte(i, 0);
		}
	}

	return 0; /* success */
}

