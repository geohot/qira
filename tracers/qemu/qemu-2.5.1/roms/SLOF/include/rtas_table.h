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

#ifndef __RTAS_TABLE_H
#define __RTAS_TABLE_H


typedef struct {
	char *name;
	void (*func)(rtas_args_t *args);
	unsigned long flags;
} rtas_funcdescr_t;


// Flags for the RTAS table:
#define RTAS_TBLFLG_INTERNAL 1


extern const rtas_funcdescr_t rtas_func_tab[];
extern const int rtas_func_tab_size;


#endif  // __RTAS_TABLE_H
