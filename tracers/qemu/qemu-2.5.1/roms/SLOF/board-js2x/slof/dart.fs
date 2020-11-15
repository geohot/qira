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


\ CPC9x5 DART.

new-device

s" dart" 2dup device-name device-type
u3? IF s" u3-dart" compatible THEN
u4? IF s" u4-dart" compatible THEN

0 encode-int  f8033000 encode-int+
0 encode-int+     7000 encode-int+ s" reg" property

: open  true ;
: close ;

\ Now clear and disable the DART.
20000000 f8033000 rl!

finish-device
