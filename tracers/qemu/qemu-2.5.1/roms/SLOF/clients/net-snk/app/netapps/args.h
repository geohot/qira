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

#ifndef _ARGS_H
#define _ARGS_H

const char *get_arg_ptr(const char *, unsigned int);
unsigned int get_args_count(const char *);
unsigned int get_arg_length(const char *);
char *argncpy(const char *, unsigned int, char *, unsigned int);
int strtoip(const char *, char[4]);

#endif				/* _ARGS_H */
