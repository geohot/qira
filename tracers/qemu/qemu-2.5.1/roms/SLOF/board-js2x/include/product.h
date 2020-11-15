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

#ifndef _PRODUCT_H
#define _PRODUCT_H

/* This is also the name which is also put in the flash and should
 * therefore not excedd the length of 32 bytes */
#define PRODUCT_NAME "JS2XBlade"

/* Generic identifier used in the flash */
#define FLASHFS_MAGIC "magic123"

/* Magic identifying the platform */
#define FLASHFS_PLATFORM_MAGIC "JS2XBlade"

/* also used in the flash */
#define FLASHFS_PLATFORM_REVISION "1"

#define BOOT_MESSAGE  "Press \"s\" to enter Open Firmware.\r\n\r\n\0"

#endif
