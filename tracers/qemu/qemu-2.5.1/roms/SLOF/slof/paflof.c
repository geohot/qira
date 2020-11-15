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


#define XSTR(x) #x
#define ISTR(x,y) XSTR(x.y)
#undef unix

#include "paflof.h"
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <cache.h>
#include <allocator.h>

#include ISTR(TARG,h)

#define LAST_ELEMENT(x) x[sizeof x / sizeof x[0] - 1]

/* Hack to get around static inline issues */
#include "../lib/libhvcall/libhvcall.h"


extern char _start_OF[];

unsigned long fdt_start;
unsigned long romfs_base;
unsigned long epapr_magic;
unsigned long epapr_ima_size;		// ePAPR initially mapped area size
unsigned char hash_table[HASHSIZE*CELLSIZE];

#include ISTR(TARG,c)

// the actual engine
long engine(int mode, long param_1, long param_2)
{
	// For Exceptions:
	//	mode = ENGINE_MODE_PARAM_1 | MODE_PARAM_2
	//	(param_1 = error, param_2 = reason)
	//
	// For Push:
	//	mode = ENGINE_MODE_PARAM_1 | ENGINE_MODE_NOP
	//
	// For Pop:
	//	mode = ENGINE_MODE_NOP | ENGINE_MODE_POP
	//
	// For Evaluate:
	//	mode = ENGINE_MODE_PARAM_1 | MODE_PARAM_2 | ENGINE_MODE_EVAL
	//	(param_1 = strlen(string), param_2 = string)

	cell *restrict ip;
	cell *restrict cfa;
	static cell handler_stack[160];
	static cell c_return[2];
	static cell dummy;

	#include "prep.h"
	#include "dict.xt"

	static int init_engine = 0;
	if (init_engine == 0) {
		// one-time initialisation
		init_engine = 1;
		LAST_ELEMENT(xt_FORTH_X2d_WORDLIST).a = xt_LASTWORD;

		// stack-pointers
		dp = the_data_stack - 1;
		rp = handler_stack - 1;

		// return-address for "evaluate" personality
		dummy.a = &&over;
		c_return[1].a = &dummy;
	}

	if (mode & ENGINE_MODE_PARAM_2) {
		(++dp)->n = param_2;
	}
	if (mode & ENGINE_MODE_PARAM_1) {
		(++dp)->n = param_1;
	}

	if (mode & ENGINE_MODE_NOP ) {
		goto over;
	}

        if (mode & ENGINE_MODE_EVAL) {
		(++rp)->a = c_return;
		ip = xt_EVALUATE + 2 + ((10 + CELLSIZE - 1) / CELLSIZE);
	} else {
		ip = xt_SYSTHROW;
        }

	#include "prim.code"
	#include "board.code"
	#include ISTR(TARG,code)


	// Only reached in case of non-exception call
over:	if (mode & ENGINE_MODE_POP) {
		return ((dp--)->n);
	} else {
		return 0;
	}
}
