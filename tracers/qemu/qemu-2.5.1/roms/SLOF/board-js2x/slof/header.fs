\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/


get-flash-base VALUE flash-addr

get-nvram-base CONSTANT nvram-base
get-nvram-size CONSTANT nvram-size
ff8f9000 CONSTANT sec-nvram-base  \ save area from phype.... not really known
2000 CONSTANT sec-nvram-size
