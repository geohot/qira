/******************************************************************************
 * Copyright (c) 2004, 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <macros.h>

	.section	".toc","aw"	# TOC entries are needed for relocation
.prom_entry_toc:
	.tc		_prom_entry[TC],_prom_entry


C_ENTRY(call_client_interface)
	ld	r4, .prom_entry_toc@toc(r2)	# Load prom entry point
	mflr	r0
	std	r0, 16(r1)
	ld	r4, 0(r4)
	stdu	r1, -128(r1)
	std	r2,40(r1)
	mtctr	r4
	bctrl
	ld	r2,40(r1)
	addi	r1, r1, 128
	ld	r0, 16(r1)
	mtlr	r0
	blr


C_ENTRY(rtas_call_entry)
	mtctr	r5
	bctr
