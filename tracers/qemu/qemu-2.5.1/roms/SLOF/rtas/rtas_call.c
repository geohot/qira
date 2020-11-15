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

#include <stdint.h>
#include <rtas.h>
#include "rtas_table.h"


//#define _RTAS_TRACE
//#define _RTAS_COUNT_CALLS


#ifdef _RTAS_COUNT_CALLS
int rtas_callcount[0x40] __attribute__((aligned (16)));
#endif

/* rtas_config is used to store the run-time configuration flags (which are
 * provided by SLOF during instantiate-rtas) */
long rtas_config;


/* Prototype */
void rtas_call (rtas_args_t *rtas_args);


/* 
Function: rtas_call
	Input:
		rtas_args: pointer to RTAS arguments structure
	Output:
		
Decription: Handle RTAS call. This C function is called
		from the asm function rtas_entry.
*/

void
rtas_call (rtas_args_t *rtas_args)
{
	int idx;

#ifdef _RTAS_COUNT_CALLS
	/* Count how often every RTAS function is called. */
	if (rtas_args->token < (int)(sizeof(rtas_callcount)/sizeof(rtas_callcount[0]))) {
		static int callcount_initialized = 0;
		/* If the array is used the first time, we have to set all entries to 0 */
		if (!callcount_initialized) {
			unsigned int i;
			callcount_initialized = 1;
			for (i = 0; i < sizeof(rtas_callcount)/sizeof(rtas_callcount[0]); i++)
				rtas_callcount[i] = 0;
		}
		/* Increment the counter of the RTAS call */
		rtas_callcount[rtas_args->token] += 1;
	}
#endif

#ifdef _RTAS_TRACE
	unsigned int parCnt = rtas_args->nargs;
	unsigned int *pInt = rtas_args->args;
	printf("\n\r*** rtas_call=0x%x", rtas_args->token);
#ifdef _RTAS_COUNT_CALLS
	printf(" count=0x%x", rtas_callcount[rtas_args->token]);
#endif
	printf(" len=0x%x", parCnt);
	printf("\n\r ");
	while(parCnt--) {
		printf("0x%x ", *pInt++);
	}
#endif

	idx = rtas_args->token - 1;

	/* Check if there's a function for the token: */
	if (idx >= 0 && idx < rtas_func_tab_size
	    && rtas_func_tab[idx].func != NULL) {
		/* Now jump to the RTAS function: */
		rtas_func_tab[idx].func(rtas_args);
	}
	else {
		/* We didn't find a function - return error code: */
		rtas_args->args[rtas_args->nargs] = -1;
	}

}
