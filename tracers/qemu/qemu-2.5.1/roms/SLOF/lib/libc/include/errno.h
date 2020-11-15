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

#ifndef _ERRNO_H
#define _ERRNO_H

extern int errno;

/*
 * Error number definitions
 */
#define EPERM		1	/* not permitted */
#define ENOENT		2	/* file or directory not found */
#define EIO		5	/* input/output error */
#define ENOMEM		12	/* not enough space */
#define EACCES		13	/* permission denied */
#define EFAULT		14	/* bad address */
#define EBUSY		16	/* resource busy */
#define EEXIST		17	/* file already exists */
#define ENODEV		19	/* device not found */
#define EINVAL		22	/* invalid argument */
#define EDOM		33	/* math argument out of domain of func */
#define ERANGE		34	/* math result not representable */

#endif
