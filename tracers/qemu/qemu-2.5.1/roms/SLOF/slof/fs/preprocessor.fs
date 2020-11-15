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

: ([IF])
  BEGIN
    BEGIN parse-word dup 0= WHILE
      2drop refill
    REPEAT

    2dup s" [IF]" str= IF 1 throw THEN
    2dup s" [ELSE]" str= IF 2 throw THEN
    2dup s" [THEN]" str= IF 3 throw THEN
    s" \" str= IF linefeed parse 2drop THEN
  AGAIN
  ;

: [IF] ( flag -- )
  IF exit THEN
  1 BEGIN
    ['] ([IF]) catch 
    CASE
      1 OF 1+ ENDOF
      2 OF dup 1 = if 1- then ENDOF
      3 OF 1- ENDOF
    ENDCASE
    dup 0 <=
  UNTIL drop
; immediate

: [ELSE] 0 [COMPILE] [IF] ; immediate
: [THEN] ; immediate

