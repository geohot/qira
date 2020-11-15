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

#if defined(CPU_CBEA)
#define TAKEOVERBASEADDRESS  0x0e000000
#elif defined(CPU_PPC970)
#define TAKEOVERBASEADDRESS  0x00000000
#else
#error no processor specified
#endif

#ifndef __ASSEMBLER__
int takeover(void);
#endif
