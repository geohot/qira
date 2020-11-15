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


: input  ( dev-str dev-len -- )
   open-dev ?dup IF
      \ Close old stdin:
      s" stdin" get-chosen IF
         decode-int nip nip ?dup IF close-dev THEN
      THEN
      \ Now set the new stdin:
      encode-int s" stdin"  set-chosen
   THEN
;

: output  ( dev-str dev-len -- )
   open-dev ?dup IF
      \ Close old stdout:
      s" stdout" get-chosen IF
         decode-int nip nip ?dup IF close-dev THEN
      THEN
      \ Now set the new stdout:
      encode-int s" stdout" set-chosen
   THEN
;

: io  ( dev-str dev-len -- )
   2dup input output
;


1 BUFFER: (term-io-char-buf)

: term-io-key  ( -- char )
   s" stdin" get-chosen IF
      decode-int nip nip dup 0= IF 0 EXIT THEN
      >r BEGIN
         (term-io-char-buf) 1 s" read" r@ $call-method
         0 >
      UNTIL
      (term-io-char-buf) c@
      r> drop
   ELSE
      [ ' key behavior compile, ]
   THEN
;

' term-io-key to key

\ this word will check what the current chosen input device is:
\ - if it is a serial device, it will use serial-key? to check for available input
\ - if it is a keyboard, it will check if the "key-available?" method is implemented (i.e. for usb-keyboard) and use that
\ - if it's an hv console, use hvterm-key?
\ otherwise it will always return false
: term-io-key?  ( -- true|false )
   s" stdin" get-chosen IF
      decode-int nip nip dup 0= IF drop 0 EXIT THEN \ return false and exit if no stdin set
      >r \ store ihandle on return stack
      s" device_type" r@ ihandle>phandle ( propstr len phandle )
      get-property ( true | data dlen false )
      IF
         \ device_type not found, return false and exit
         false
      ELSE
         1 - \ remove 1 from length to ignore null-termination char
         \ device_type found, check wether it is serial or keyboard
         2dup s" serial" str= IF
	    2drop serial-key? r> drop EXIT
	 THEN \ call serial-key, cleanup return-stack, exit
         2dup s" keyboard" str= IF 
            2drop ( )
            \ keyboard found, check for key-available? method, execute it or return false 
            s" key-available?" r@ ihandle>phandle find-method IF 
               drop s" key-available?" r@ $call-method  
            ELSE 
               false 
            THEN
            r> drop EXIT \ cleanup return-stack, exit
         THEN
         2drop r> drop false EXIT \ unknown device_type cleanup return-stack, return false
      THEN
   ELSE
      \ stdin not set, return false
      false
   THEN
;

' term-io-key? to key?
