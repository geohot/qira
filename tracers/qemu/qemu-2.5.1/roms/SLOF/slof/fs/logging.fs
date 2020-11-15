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

\ Words to write to nvram log

defer nvramlog-write-byte

: .nvramlog-write-byte ( byte -- )
#if defined(DISABLE_NVRAM) || defined(RTAS_NVRAM)
        drop
#else
        0 1 asm-cout
#endif
;

' .nvramlog-write-byte to nvramlog-write-byte

: nvramlog-write-string ( str len -- )
   dup 0> IF
      0 DO dup c@ 
      nvramlog-write-byte char+ LOOP
   ELSE
      drop
   THEN drop ;

: nvramlog-write-number ( number format -- )
  0 swap <# 0 ?DO # LOOP #> 
  nvramlog-write-string ;

: nvramlog-write-string-cr ( str len -- )
  nvramlog-write-string
  a nvramlog-write-byte d nvramlog-write-byte ;

\ as long as dual-emit is enabled
\ the string is written into NVRAM as well!!
: log-string ( str len -- ) type ;
