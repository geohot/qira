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
#ifndef BOOT_ABORT_H
#define BOOT_ABORT_H

/* boot abort function suitable for assembly */
#define BOOT_ABORT(cap, action, msg, numhint)		\
		li	r3, cap;			\
		li	r4, action;			\
		LOAD32(r5, msg);			\
		LOAD32(r6, numhint);			\
		bl	boot_abort

/* boot abort function suitable called from c (takes r3 as hint) */
#define BOOT_ABORT_R3HINT(cap, action, msg)		\
		mr	r6, r3;				\
		li	r3, cap;			\
		li	r4, action;			\
		LOAD32(r5, msg);			\
		bl	boot_abort

#define ABORT_CANIO	(1 << 0)
#define ABORT_NOIO	(1 << 1)

#define ALTBOOT		(1 << 0)
#define HALT		(1 << 1)

#endif
