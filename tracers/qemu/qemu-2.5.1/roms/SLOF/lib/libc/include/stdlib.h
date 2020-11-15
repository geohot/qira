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

#ifndef _STDLIB_H
#define _STDLIB_H

#include "stddef.h"

#define RAND_MAX 32767


void *malloc(size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
void *memalign(size_t boundary, size_t size);

int atoi(const char *str);
long atol(const char *str);
unsigned long int strtoul(const char *nptr, char **endptr, int base);
long int strtol(const char *nptr, char **endptr, int base);

int rand(void);

#endif
