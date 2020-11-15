/*
 *   Creation Date: <2003/12/19 00:20:11 samuel>
 *   Time-stamp: <2004/01/07 19:19:14 samuel>
 *
 *	<kernel.h>
 *
 *
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *                            Stefan Reinauer (stepan@openbios.org)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#ifndef _H_KERNEL
#define _H_KERNEL

#include "kernel/stack.h"
#include "asm/io.h"

/* Interrupt status */
#define FORTH_INTSTAT_CLR	0x0
#define FORTH_INTSTAT_STOP 	0x1
#define FORTH_INTSTAT_DBG  	0x2

extern volatile int 	interruptforth;
extern int		enterforth( xt_t xt );
extern void		panic(const char *error) __attribute__ ((noreturn));

extern xt_t		findword(const char *s1);
extern void		modules_init( void );
extern void		init_trampoline(ucell *t);
extern void		forth_init(void);

/* arch kernel hooks */
extern void 		exception(cell no);

#ifdef FCOMPILER
extern void		include_file( const char *str );
extern void		encode_file( const char *str );
extern int		get_inputbyte( void );
extern void		put_outputbyte( int c );
#endif

#ifndef BOOTSTRAP
#undef putchar
#undef getchar

extern int		putchar( int ch );
extern int		getchar( void );
#endif

extern int		availchar( void );

#endif   /* _H_KERNEL */
