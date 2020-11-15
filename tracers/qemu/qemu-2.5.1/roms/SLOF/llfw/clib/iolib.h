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

#ifndef IOLIB_H
#define IOLIB_H

#include <stdint.h>

#define addr_t  	volatile unsigned int
#define addr8_t 	volatile unsigned char

extern void     halt_sys (unsigned int);

extern void     uart_send_byte(unsigned char b);
extern void     io_putchar(unsigned char);

#endif
