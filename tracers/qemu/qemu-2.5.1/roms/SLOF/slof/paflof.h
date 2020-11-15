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


extern long engine(int, long, long);

#define TIBSIZE 256

#define POCKETSIZE 256
#define NUMPOCKETS 16

#define HASHSIZE 0x1000

// engine mode bits
#define ENGINE_MODE_PARAM_1	0x0001
#define ENGINE_MODE_PARAM_2	0x0002
#define ENGINE_MODE_NOP		0x0004
#define ENGINE_MODE_EVAL	0x0008
#define ENGINE_MODE_POP		0x0010

// engine calls
#define forth_eval(s)	engine(ENGINE_MODE_PARAM_1|ENGINE_MODE_PARAM_2|ENGINE_MODE_EVAL,	\
				strlen((s)), (long)(s))
#define forth_eval_pop(s)	engine(ENGINE_MODE_PARAM_1|ENGINE_MODE_PARAM_2|ENGINE_MODE_EVAL|ENGINE_MODE_POP,	\
				strlen((s)), (long)(s))

#define forth_push(v)	engine(ENGINE_MODE_PARAM_1|ENGINE_MODE_NOP, v, 0)

#define forth_pop()	engine(ENGINE_MODE_NOP|ENGINE_MODE_POP, 0, 0)
