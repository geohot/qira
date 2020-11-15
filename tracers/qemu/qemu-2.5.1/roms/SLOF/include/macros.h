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

#define LOAD64(rn,name)			\
	lis     rn,name##@highest;	\
	ori     rn,rn,name##@higher;	\
	rldicr  rn,rn,32,31;		\
	oris    rn,rn,name##@h;		\
	ori     rn,rn,name##@l

#define LOAD32(rn, name)		\
	lis	rn,name##@h;		\
	ori	rn,rn,name##@l

// load 32 bit constant in little endian order
#define LOAD32le(rn,name) \
        lis     rn,(((name>>8)&0x00FF)|((name<<8)&0xFF00));  \
        ori     rn,rn,(((name>>24)&0x00FF)|((name>>8)&0xFF00))

// load 16 bit constant in little endian order
#define LOAD16le(rn,name) \
        li      rn,(((name>>8)&0x00FF)|((name<<8)&0xFF00))

#define ENTRY(func_name)              \
	.text;                        \
	.align  2;                    \
	.globl  .func_name;           \
        .func_name:                   \
	.globl  func_name;            \
        func_name:

#define C_ENTRY(func_name)			\
	.section	".text";		\
	.align 2;				\
	.globl func_name;			\
	.section	".opd","aw";		\
	.align 3;				\
 func_name:					\
	.quad	.func_name,.TOC.@tocbase,0;	\
	.previous;				\
	.size	func_name,24;			\
	.type	.func_name,@function;		\
	.globl	.func_name;			\
 .func_name:

#define ASM_ENTRY(fn)	\
	.globl	fn;	\
fn:

