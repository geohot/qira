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

#ifndef _CTYPE_H
#define _CTYPE_H

int isdigit(int c);
int isxdigit(int c);
int isprint(int c);
int isspace(int c);

int tolower(int c);
int toupper(int c);

#endif
