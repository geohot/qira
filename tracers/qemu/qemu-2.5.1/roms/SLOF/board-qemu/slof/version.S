/******************************************************************************
 * Copyright (c) 2010, 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

/*
 * Print version information - in SLOF
 * This code is in a separate file so that it can be easily compiled during
 * each new build (for refreshing the build date).
 */

#include "termctrl.h"
#include <product.h>

.global print_version
print_version:
	.ascii	TERM_CTRL_RESET
	.ascii	TERM_CTRL_CRSOFF
	.ascii	TERM_CTRL_BRIGHT
	.ascii	PRODUCT_NAME
	.ascii  " Starting\r\n"
	.ascii  TERM_CTRL_RESET
	.ascii  " Build Date = ", __DATE__, " ", __TIME__
	.ascii	"\r\n"
	.ascii  " FW Version = " , RELEASE
	.ascii	"\r\n\0"
	.align	2
.global print_version_end
print_version_end:
