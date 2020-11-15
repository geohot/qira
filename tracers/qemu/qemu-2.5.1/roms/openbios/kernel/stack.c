/* tag: defines the stacks, program counter and ways to access those
 *
 * Copyright (C) 2003 Patrick Mauritz, Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */


#include "config.h"
#include "kernel/stack.h"
#include "cross.h"

#define dstacksize 512
int dstackcnt = 0;
cell dstack[dstacksize];

#define rstacksize 512
int rstackcnt = 0;
cell rstack[rstacksize];

/* Rstack value saved before entering forth interpreter in debugger */
int dbgrstackcnt = 0;

#if defined(CONFIG_DEBUG_DSTACK) || defined(FCOMPILER)
void printdstack(void)
{
	int i;
	printk("dstack:");
	for (i = 0; i <= dstackcnt; i++) {
		printk(" 0x%" FMT_CELL_x , dstack[i]);
	}
	printk("\n");
}
#endif
#if defined(CONFIG_DEBUG_RSTACK) || defined(FCOMPILER)
void printrstack(void)
{
	int i;
	printk("rstack:");
	for (i = 0; i <= rstackcnt; i++) {
		printk(" 0x%" FMT_CELL_x , rstack[i]);
	}
	printk("\n");
}
#endif
