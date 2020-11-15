/*
 *   Creation Date: <2004/08/28 17:50:12 stepan>
 *   Time-stamp: <2004/08/28 17:50:12 stepan>
 *
 *	<kernel.h>
 *
 *   Copyright (C) 2004 Stefan Reinauer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#ifndef __KERNEL_H__
#define __KERNEL_H__

/* misc.c */
extern void		fatal_error( const char *str );
extern void		exit( int status ) __attribute__ ((noreturn));

/* start.S */
extern void 		flush_icache_range( char *start, char *stop );
extern char		of_rtas_start[], of_rtas_end[];
extern void             call_elf( unsigned long arg1, unsigned long arg2, unsigned long elf_entry );

/* methods.c */
extern void		node_methods_init( const char *cpuname );

/* main.c */
extern void 		boot( void );

/* init.c */
extern void		entry( void );
extern void 		arch_of_init( void );
extern int		get_bool_res( const char *str );

/* tree.c */
extern void		devtree_init( void );


#endif   /* __KERNEL_H__ */
