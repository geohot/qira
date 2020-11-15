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
#include <stddef.h>
#include <unistd.h>
#include "iolib.h"

void uart_send_byte(unsigned char b)
{
	asm volatile ("":::"3","4","5","6","7");
	io_putchar(b);
}

/**
 * Standard write function for the libc.
 *
 * @param fd	file descriptor (should always be 1 or 2)
 * @param buf	pointer to the array with the output characters
 * @param count	number of bytes to be written
 * @return	the number of bytes that have been written successfully
 */
ssize_t write(int fd, const void *buf, size_t count)
{
	size_t i;
	char *ptr = (char *)buf;

	if (fd != 1 && fd != 2)
		return 0;

	for (i = 0; i < count; i++) {
		if (*ptr == '\n')
			uart_send_byte('\r');
		uart_send_byte(*ptr++);
	}

	return i;
}
