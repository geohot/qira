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
#ifndef _BIOSEMU_INTERRUPT_H_
#define _BIOSEMU_INTERRUPT_H_

void handleInterrupt(int intNum);

void runInt10(void);

void runInt13(void);

#endif
