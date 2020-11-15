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
//
// Copyright 2002,2003,2004  Segher Boessenkool  <segher@kernel.crashing.org>
//


#ifndef _TYPES_H
#define _TYPES_H

#if 0
#include <stdint.h>

typedef uint8_t		type_c;		// 1 byte
typedef uint16_t	type_w;		// 2 bytes
typedef uint32_t	type_l;		// 4 bytes
typedef intptr_t	type_n;		// cell size
typedef uintptr_t	type_u;		// cell size
#else
typedef unsigned char	type_c;		// 1 byte
typedef unsigned short	type_w;		// 2 bytes
typedef unsigned int	type_l;		// 4 bytes
typedef long		type_n;		// cell size
typedef unsigned long	type_u;		// cell size
#endif

//#define CELLSIZE (sizeof(type_u) / sizeof(type_c))
#define CELLSIZE sizeof(type_u)

typedef union cell {
	type_n n;
	type_u u;
	void *a;
	type_c c[CELLSIZE];
	type_w w[CELLSIZE/2];
	type_l l[CELLSIZE/4];
} cell;


#endif /* _TYPES_H */
