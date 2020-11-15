\ *****************************************************************************
\ * Copyright (c) 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ PAPR hvterm console.  Enabled very early.

0 CONSTANT default-hvtermno
\ Buffer for pre-display
4096 CONSTANT disp-size
CREATE prevga-disp-buf 4096 allot
0 value disp-ptr
true value store-prevga?

: store-to-disp-buffer         ( ch  --  )
    prevga-disp-buf disp-ptr disp-size MOD + c!
    disp-ptr 1 + to disp-ptr
;

: hvterm-emit
    store-prevga? IF
	dup store-to-disp-buffer
    THEN
    default-hvtermno SWAP hv-putchar
;
: hvterm-key?  default-hvtermno hv-haschar ;
: hvterm-key   BEGIN hvterm-key? UNTIL default-hvtermno hv-getchar ;

' hvterm-emit to emit
' hvterm-key  to key
' hvterm-key? to key?

\ Override serial methods to make term-io.fs happy
: serial-emit hvterm-emit ;
: serial-key? hvterm-key? ;
: serial-key  hvterm-key  ;
