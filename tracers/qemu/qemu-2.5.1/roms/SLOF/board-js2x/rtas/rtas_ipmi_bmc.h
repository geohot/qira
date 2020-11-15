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

#ifndef __RTAS_IPMI_BMC_H
#define __RTAS_IPMI_BMC_H

#include <stddef.h>

short ipmi_set_flashside (short mode);
short ipmi_get_flashside (void);

#endif		/* __RTAS_IPMI_BMC_H */
