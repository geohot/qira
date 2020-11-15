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

#include <ctype.h>

int isxdigit(int ch)
{
  return ( 
      (ch >= '0' && ch <= '9') |
      (ch >= 'A' && ch <= 'F') |
      (ch >= 'a' && ch <= 'f') );
}
