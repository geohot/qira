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

#ifndef __RTAS_H
#define __RTAS_H

#ifndef __ASSEMBLER__

#include <stddef.h>

typedef int rtas_arg_t;
typedef struct {
	int token;
	int nargs;
	int nret;
	rtas_arg_t args[16];
} rtas_args_t;

#else

#define RTAS_STACKSIZE 0x1000

#define RTAS_PARM_0 0x0c
#define RTAS_PARM_1 0x10
#define RTAS_PARM_2 0x14
#define RTAS_PARM_3 0x18
#define RTAS_PARM_4 0x1C
#define RTAS_PARM_5 0x20
#define RTAS_PARM_6 0x24
#define RTAS_PARM_7 0x28

#endif		/* __ASSEMBLER__ */
#endif		/* __RTAS_H */
