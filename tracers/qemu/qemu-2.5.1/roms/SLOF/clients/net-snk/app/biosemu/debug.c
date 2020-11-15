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

#include <cpu.h>

#include "debug.h"

uint32_t debug_flags = 0;

void
dump(uint8_t * addr, uint32_t len)
{
	printf("\n\r%s(%p, %x):\n", __FUNCTION__, addr, len);
	while (len) {
		unsigned int tmpCnt = len;
		unsigned char x;
		if (tmpCnt > 8)
			tmpCnt = 8;
		printf("\n\r%p: ", addr);
		// print hex
		while (tmpCnt--) {
			set_ci();
			x = *addr++;
			clr_ci();
			printf("%02x ", x);
		}
		tmpCnt = len;
		if (tmpCnt > 8)
			tmpCnt = 8;
		len -= tmpCnt;
		//reset addr ptr to print ascii
		addr = addr - tmpCnt;
		// print ascii
		while (tmpCnt--) {
			set_ci();
			x = *addr++;
			clr_ci();
			if ((x < 32) || (x >= 127)) {
				//non-printable char
				x = '.';
			}
			printf("%c", x);
		}
	}
	printf("\n");
}
