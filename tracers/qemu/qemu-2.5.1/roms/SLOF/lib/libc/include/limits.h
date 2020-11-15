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

#ifndef _LIMITS_H
#define _LIMITS_H

#define 	UCHAR_MAX	255
#define 	SCHAR_MAX	127
#define 	SCHAR_MIN	(-128)

#define 	USHRT_MAX	65535
#define 	SHRT_MAX	32767
#define 	SHRT_MIN	(-32768)

#define 	UINT_MAX	(4294967295U)
#define 	INT_MAX 	2147483647
#define 	INT_MIN 	(-2147483648)

#define 	ULONG_MAX	((unsigned long)-1L)
#define 	LONG_MAX	(ULONG_MAX/2)
#define 	LONG_MIN	((-LONG_MAX)-1)

#endif
