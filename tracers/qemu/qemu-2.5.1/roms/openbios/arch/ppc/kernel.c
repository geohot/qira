/*
 *   Creation Date: <2003/10/25 14:07:17 samuel>
 *   Time-stamp: <2004/08/28 17:48:19 stepan>
 *
 *	<kernel.c>
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *   Copyright (C) 2003, 2004 Stefan Reinauer
 *
 *   Based upon unix.c (from OpenBIOS):
 *
 *   Copyright (C) 2003 Patrick Mauritz, Stefan Reinauer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "dict.h"
#include "libopenbios/bindings.h"
#include "kernel/stack.h"
#include "kernel/kernel.h"
#include "libc/string.h"
#include "kernel.h"

#define MEMORY_SIZE	(256*1024)	/* 256K ram for hosted system */
#define DICTIONARY_SIZE	(512*1024)	/* 512K for the dictionary   */

static ucell 		*memory;

/************************************************************************/
/*	F U N C T I O N S						*/
/************************************************************************/

int
forth_segv_handler( char *segv_addr )
{
	ucell addr = 0xdeadbeef;

	if( PC >= (ucell) dict && PC <= (ucell) dict + dicthead )
		addr = *(ucell *) PC;

	printk("panic: segmentation violation at %x\n", (int)segv_addr);
	printk("dict=0x%x here=0x%x(dict+0x%x) pc=0x%x(dict+0x%x)\n",
	       (int)dict, (int)(dict + dicthead), dicthead,
	       PC, PC - (ucell) dict);
	printk("dstackcnt=%d rstackcnt=%d instruction=%x\n",
	       dstackcnt, rstackcnt, addr);

#ifdef DEBUG_DSTACK
	printdstack();
#endif
#ifdef DEBUG_RSTACK
	printrstack();
#endif
	return -1;
}

/*
 * allocate memory and prepare engine for memory management.
 */

static void
init_memory( void )
{
	memory = malloc(MEMORY_SIZE);
	if( !memory )
		panic("panic: not enough memory on host system.\n");

	/* we push start and end of memory to the stack
	 * so that it can be used by the forth word QUIT
	 * to initialize the memory allocator
	 */

	PUSH( (ucell)memory );
	PUSH( (ucell)memory + MEMORY_SIZE );
}

int
initialize_forth( void )
{
	dict = malloc(DICTIONARY_SIZE);
	load_dictionary( forth_dictionary, sizeof(forth_dictionary) );
	forth_init();

	PUSH_xt( bind_noname_func(arch_of_init) );
	fword("PREPOST-initializer");

	PC = (ucell)findword("initialize-of");
	if( PC ) {
		init_memory();
		enterforth((xt_t)PC);
		free( memory );
	}
	free( dict );
	return 0;
}
