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


\ CPU node.  Pretty minimal...

( cpu# -- )
new-device  set-space

: pvr>name  s" PowerPC," rot 10 rshift CASE
            39 OF s" 970"   ENDOF
            3c OF s" 970FX" ENDOF
            44 OF 1 my-space 1 xor lshift cpu-mask @ and IF
                  s" 970MP" ELSE s" 970GX" THEN ENDOF
                  \ On GX CPUs, the sibling is missing, numbering is the same.
       dup dup OF 0 <# # # # # [char] # hold #> ENDOF ENDCASE $cat ;

pvr@ pvr>name device-name
s" cpu" device-type

my-space encode-int s" reg" property

tb-frequency  encode-int s" timebase-frequency" property
cpu-frequency encode-int s" clock-frequency" property

 8000 encode-int s" d-cache-size"      property
   80 encode-int s" d-cache-line-size" property
10000 encode-int s" i-cache-size"      property
   80 encode-int s" i-cache-line-size" property

: open  true ;
: close ;


finish-device
