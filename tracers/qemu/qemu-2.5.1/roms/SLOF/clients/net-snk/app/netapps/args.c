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
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "args.h"

/**
 * Returns pointer of the n'th argument within a string.
 *
 * @param  arg_str    string with arguments, separated with ','
 * @param  index      index of the requested arguments within arg_str
 * @return            pointer of argument[index] on success
 *                    NULL if index is out of range
 */
const char *
get_arg_ptr(const char *arg_str, unsigned int index)
{
	unsigned int i;

	for (i = 0; i < index; ++i) {
		for (; *arg_str != ',' && *arg_str != 0; ++arg_str);
		if (*arg_str == 0)
			return 0;
		++arg_str;
	}
	return arg_str;
}

/**
 * Returns number of arguments within a string.
 *
 * @param  arg_str    string with arguments, separated with ','
 * @return            number of arguments
 */
unsigned int
get_args_count(const char *arg_str)
{
	unsigned int count = 1;

	while ((arg_str = get_arg_ptr(arg_str, 1)) != 0)
		++count;
	return count;
}

/**
 * Returns the length of the first argument.
 *
 * @param  arg_str    string with arguments, separated with ','
 * @return            length of first argument
 */
unsigned int
get_arg_length(const char *arg_str)
{
	unsigned int i;

	for (i = 0; *arg_str != ',' && *arg_str != 0; ++i)
		++arg_str;
	return i;
}

/**
 * Copy the n'th argument within a string into a buffer in respect
 * to a limited buffer size
 *
 * @param  arg_str    string with arguments, separated with ','
 * @param  index      index of the requested arguments within arg_str
 * @param  buffer     pointer to the buffer
 * @param  length     size of the buffer
 * @return            pointer of buffer on success
 *                    NULL if index is out of range.
 */
char *
argncpy(const char *arg_str, unsigned int index, char *buffer,
	unsigned int length)
{
	const char *ptr = get_arg_ptr(arg_str, index);
	unsigned int len;

	if (!ptr)
		return 0;
	len = get_arg_length(ptr);
	if (!strncpy(buffer, ptr, length))
		return 0;
	buffer[len] = 0;
	return buffer;
}

/**
 * Converts "255.255.255.255" -> char[4] = { 0xff, 0xff, 0xff, 0xff }
 *
 * @param  str        string to be converted
 * @param  ip         in case of SUCCESS - 32-bit long IP
                      in case of FAULT - zero
 * @return            TRUE - IP converted successfully;
 *                    FALSE - error condition occurs (e.g. bad format)
 */
int
strtoip(const char *str, char ip[4])
{
	char octet[10];
	int res;
	unsigned int i = 0, len;

	while (*str != 0) {
		if (i > 3 || !isdigit(*str))
			return 0;
		if (strstr(str, ".") != NULL) {
			len = (int16_t) (strstr(str, ".") - str);
			if (len >= 10)
				return 0;
			strncpy(octet, str, len);
			octet[len] = 0;
			str += len;
		} else {
			strncpy(octet, str, 9);
			octet[9] = 0;
			str += strlen(octet);
		}
		res = strtol(octet, NULL, 10);
		if ((res > 255) || (res < 0))
			return 0;
		ip[i] = (char) res;
		i++;
		if (*str == '.')
			str++;
	}

	if (i != 4)
		return 0;
	return -1;
}
