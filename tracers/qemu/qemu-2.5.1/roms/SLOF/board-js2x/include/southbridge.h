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

#ifndef _SOUTHBRIDGE_H
#define _SOUTHBRIDGE_H


#define SB_FLASH_adr           (0xff000000)          // FLASH (EBC_CS0/Bank0)
#define SB_NVRAM_adr           (0xff800000)          // NonVolatile mapping
#define SB_NVRAM_FWONLY_adr    (0xff8FF000)          // NonVolatile mapping
#define NVRAM_LENGTH           0x100000
#define NVRAM_FWONLY_LENGTH    0x1000
#define SB_MAILBOX_adr         0

#define FLASH_LENGTH           0x400000

#define SB_IPMI_KCS_adr        0xF4000CA8            // IPMI KCS

#endif
