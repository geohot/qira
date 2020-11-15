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

#ifndef FILEIO_H
#define FILEIO_H

#include <of.h>

#define FILEIO_TYPE_EMPTY   0
#define FILEIO_TYPE_FILE    1
#define FILEIO_TYPE_SOCKET  2

struct snk_fileio_type {
	int	  type;
	ihandle_t ih;
};
typedef struct snk_fileio_type snk_fileio_t;

#define FILEIO_MAX 32
extern snk_fileio_t fd_array[FILEIO_MAX];

#endif
