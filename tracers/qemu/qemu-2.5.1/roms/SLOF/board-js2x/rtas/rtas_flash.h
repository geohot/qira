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

#include <southbridge.h>

#define FLASHSIZE FLASH_LENGTH
#define FLASH SB_FLASH_adr
#define BUFSIZE 4096
#define FLASH_BLOCK_SIZE 0x20000

void write_flash(unsigned long offset, unsigned char *data);
