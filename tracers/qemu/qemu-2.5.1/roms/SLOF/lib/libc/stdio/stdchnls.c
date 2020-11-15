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


#include "stdio.h"

static char stdin_buffer[BUFSIZ], stdout_buffer[BUFSIZ];

FILE stdin_data = { .fd = 0, .mode = _IOLBF, .pos = 0,
		    .buf = stdin_buffer, .bufsiz = BUFSIZ };
FILE stdout_data = { .fd = 1, .mode = _IOLBF, .pos = 0,
		     .buf = stdout_buffer, .bufsiz = BUFSIZ };
FILE stderr_data = { .fd = 2, .mode = _IONBF, .pos = 0,
		     .buf = NULL, .bufsiz = 0 };
